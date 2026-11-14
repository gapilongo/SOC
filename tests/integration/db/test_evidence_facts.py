"""``evidence_facts`` (migration 0021, AI-E3.2): the fact ledger under tenant RLS, append-only, with its rules."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, List

import asyncpg
import pytest

from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.db.errors import Conflict, ReferenceNotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.evidence_facts import EvidenceFactsRepo
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.ledger import LedgerEntry, ToolStep, build_entries, check_citations
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert, sha256_hex
from tests.unit.agents.investigation._support import TOOL, fact_tools, host_fact
from tests.unit.tools._support import Boom, Ctx, Handler, P

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
INSERT = (
    "INSERT INTO evidence_facts (tenant_id, alert_id, run_id, seq, fact_id, evidence_id, tool, tool_version, "
    "input_hash, outcome, complete, as_of, fact, content_hash) "
    "VALUES ($1, $2, 'r', $3, $4, $5, 'platform.example', 1, $6, $7, $8, now(), $9, $6)"
)


def ledger(repos: Repositories, tenant_id: str, alert_id: str) -> FactLedger:
    return FactLedger(tenant_id, alert_id, thread_id_for(tenant_id, alert_id), repos.evidence_facts, clock=lambda: NOW)


async def observe(run: FactLedger, evidence_id: str, handler: Handler) -> List[LedgerEntry]:
    tools = fact_tools(handler)
    result = await tools.call(Ctx(tenant_id=run.tenant_id, alert_id=run.alert_id), TOOL, P, agent="investigation")
    return list(await run.record(tool_step(evidence_id, tools.get(TOOL), result)))


async def test_a_second_tenant_can_neither_read_nor_cite_the_first_tenants_facts(db: Database, repos: Repositories) -> None:
    alert_a = await make_alert(repos, TENANT_A)
    [fact] = await observe(ledger(repos, TENANT_A, alert_a), "host", Handler(answer=(host_fact(),)))
    run_a = thread_id_for(TENANT_A, alert_a)

    # Tenant B names tenant A's alert and run: it reads nothing, so tenant A's id cites nothing there.
    intruder = FactLedger(TENANT_B, alert_a, run_a, repos.evidence_facts)
    assert await intruder.facts() == ()
    assert check_citations([fact.fact_id], await intruder.facts(), benign_claim=False) == [(fact.fact_id, "unknown_fact")]
    assert await repos.evidence_facts.list_for_run(TENANT_B, alert_a, run_a) == []
    assert await repos.evidence_facts.list_latest_run(TENANT_B, alert_a) == []
    # Nor can it add to that ledger: the alert is not tenant B's, and a row for tenant A is refused.
    with pytest.raises(ReferenceNotFound):
        await observe(intruder, "host", Handler(answer=(host_fact("FORGED"),)))
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.fetchval("SELECT count(*) FROM evidence_facts") == 0
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_B) as conn:
            await conn.execute(INSERT, TENANT_A, alert_a, 9, "host:9", "host", sha256_hex("x"), "empty", True, None)
    async with db.connection() as conn:
        async with conn.transaction():
            assert await conn.fetchval("SELECT count(*) FROM evidence_facts") == 0

    # Tenant A's ledger is as it was, and tenant B's own run starts at its own first id.
    assert [e.fact_id for e in await ledger(repos, TENANT_A, alert_a).facts()] == ["host:0"]
    alert_b = await make_alert(repos, TENANT_B)
    [own] = await observe(ledger(repos, TENANT_B, alert_b), "host", Handler(answer=(host_fact("B-HOST"),)))
    assert own.fact_id == "host:0" and own.content_hash != fact.content_hash
    assert [e.content_hash for e in await repos.evidence_facts.list_latest_run(TENANT_A, alert_a)] == [fact.content_hash]


async def test_the_ledger_is_append_only(db: Database, repos: Repositories, app_db: Database, app: Repositories) -> None:
    """No update or delete path: none in the repository, none for the runtime role, and a trigger for everyone."""
    alert_id = await make_alert(app, TENANT_A)
    [entry] = await observe(ledger(app, TENANT_A, alert_id), "host", Handler(answer=(host_fact(),)))
    assert {name for name in vars(EvidenceFactsRepo) if not name.startswith("_")} == {
        "append", "list_for_run", "list_latest_run"
    }

    statements = (
        "UPDATE evidence_facts SET outcome = 'success', complete = true",
        "UPDATE evidence_facts SET fact_id = 'host:7'",
        "DELETE FROM evidence_facts",
        "TRUNCATE evidence_facts",
    )
    for sql in statements:
        # The runtime role has no such privilege, with or without the bypass setting.
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with app_db.tenant_tx(TENANT_A) as conn:
                await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
                await conn.execute(sql)
        # The schema owner has the privilege; the trigger refuses it inside a tenant.
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="evidence_facts is append-only"):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(sql)
    # Even with the bypass on, a row is never rewritten.
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="evidence_facts is append-only"):
        async with db.system_tx() as conn:
            await conn.execute(statements[0])
    [stored] = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, thread_id_for(TENANT_A, alert_id))
    assert stored.model_dump(include=set(LedgerEntry.model_fields)) == entry.model_dump() and stored.intact

    # Retention and erasure (the schema owner, bypass on) remove the rows with their alert.
    async with db.system_tx() as conn:
        await conn.execute("DELETE FROM alerts WHERE tenant_id = $1 AND id = $2", TENANT_A, alert_id)
        assert await conn.fetchval("SELECT count(*) FROM evidence_facts") == 0


async def test_the_table_refuses_a_row_that_breaks_the_ledgers_rules(db: Database, repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    digest = sha256_hex("in")
    bound = {**host_fact().model_dump(mode="json", exclude_none=True), "id": "host:0", "provenance": {"input_hash": digest}}
    broken: List[Any] = [
        (0, "host:0", "host", digest, "empty", True, bound),                        # a fact on an empty call
        (0, "host:0", "host", digest, "failed", True, None),                        # a failed call that is complete
        (0, "host:0", "host", digest, "success", True, {**bound, "id": "host:1"}),  # the fact carries another id
        (0, "host:0", "host", digest, "success", True, {k: v for k, v in bound.items() if k != "id"}),
        (0, "host:0", "host", digest, "success", True, {**bound, "provenance": {"input_hash": sha256_hex("other")}}),
        (0, "host:0", "host", digest, "success", True, {k: v for k, v in bound.items() if k != "provenance"}),
        (0, "host:0", "other", digest, "success", True, None),                     # the id names another evidence id
        (0, "anything", "host", digest, "success", True, None),                    # not an id the ledger mints
        (0, "host:0", "host", "not-a-hash", "success", True, None),
        (0, "host:0", "host", digest, "unknown", True, None),
    ]
    for row in broken:
        with pytest.raises(asyncpg.CheckViolationError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(INSERT, TENANT_A, alert_id, *row)
    async with db.tenant_tx(TENANT_A) as conn:  # the same statement with a fact that is bound to its row
        assert await conn.execute(INSERT, TENANT_A, alert_id, 7, "host:7", "host", digest, "success", True, {**bound, "id": "host:7"}) == "INSERT 0 1"

    # An id is minted once in a run: a second entry under it is refused, whoever built it.
    run_id = thread_id_for(TENANT_A, alert_id)
    entries = build_entries(ToolStep("host", TOOL, 1, digest, digest, "empty", True), [], NOW)
    assert await repos.evidence_facts.append(TENANT_A, alert_id, run_id, entries) == 1
    with pytest.raises(Conflict):
        await repos.evidence_facts.append(TENANT_A, alert_id, run_id, entries)
    assert [e.fact_id for e in await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)] == ["host:0"]


async def test_a_run_reads_back_what_it_recorded_and_continues_after_it(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    run = ledger(repos, TENANT_A, alert_id)
    recorded = [
        *await observe(run, "host", Handler(answer=(host_fact("a"), host_fact("b")))),
        *await observe(run, "fanout", Handler(answer=())),
        *await observe(run, "lineage", Boom()),
    ]

    resumed = ledger(repos, TENANT_A, alert_id)  # a new process picks the run up from the table
    stored = await resumed.facts()
    assert [e.fact_id for e in stored] == ["host:0", "host:1", "fanout:0", "lineage:0"]
    assert [(e.outcome, e.complete, e.reason) for e in stored[2:]] == [("empty", True, None), ("failed", False, "error:RuntimeError")]
    assert [e.model_dump(include=set(LedgerEntry.model_fields)) for e in stored] == [e.model_dump() for e in recorded]
    assert all(e.intact for e in stored) and [e.citable_as_benign_evidence for e in stored] == [True, True, False, False]
    rows = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run.run_id)
    assert [(row.seq, row.run_id, row.tenant_id) for row in rows] == [(n, run.run_id, TENANT_A) for n in range(4)]
    [more] = await observe(resumed, "host", Handler(answer=(host_fact("c"),)))
    assert more.fact_id == "host:2"

    # Two writers of one run cannot mint the same id: the table refuses the second, which then reads the
    # run again and takes the next number.
    racing = ledger(repos, TENANT_A, alert_id)
    assert len(await racing.facts()) == 5
    [ahead] = await observe(resumed, "host", Handler(answer=(host_fact("d"),)))
    with pytest.raises(Conflict):
        await observe(racing, "host", Handler(answer=(host_fact("e"),)))
    [behind] = await observe(racing, "host", Handler(answer=(host_fact("e"),)))
    assert (ahead.fact_id, behind.fact_id) == ("host:3", "host:4")

    # The alert's newest run with a ledger is the one the investigation view reads.
    later = FactLedger(TENANT_A, alert_id, "rerun/2", repos.evidence_facts)
    await observe(later, "host", Handler(answer=(host_fact("d"),)))
    assert {(e.run_id, e.fact_id) for e in await repos.evidence_facts.list_latest_run(TENANT_A, alert_id)} == {("rerun/2", "host:0")}
