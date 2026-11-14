"""``evidence_facts`` (migration 0021, AI-E3.2): the fact ledger under tenant RLS, append-only, with its rules."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, List

import asyncpg
import pytest

from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.db.errors import Conflict, ReferenceNotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.evidence_facts import EvidenceFactsRepo
from lg_sotf.domain.ledger import MAX_RUN_ENTRIES, LedgerEntry, ToolStep, build_entries, check_citations, new_run_id
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


def ledger(repos: Repositories, tenant_id: str, alert_id: str, run_id: str) -> FactLedger:
    return FactLedger(tenant_id, alert_id, run_id, repos.evidence_facts, clock=lambda: NOW)


async def observe(run: FactLedger, evidence_id: str, handler: Handler, **declared: Any) -> List[LedgerEntry]:
    tools = fact_tools(handler, **declared)
    result = await tools.call(Ctx(tenant_id=run.tenant_id, alert_id=run.alert_id), TOOL, P, agent="investigation")
    return list(await run.record(tool_step(evidence_id, tools.get(TOOL), result)))


async def test_a_second_tenant_can_neither_read_nor_cite_the_first_tenants_facts(db: Database, repos: Repositories) -> None:
    alert_a, run_a = await make_alert(repos, TENANT_A), new_run_id()
    [fact] = await observe(ledger(repos, TENANT_A, alert_a, run_a), "host", Handler(answer=(host_fact(),)))

    # Tenant B names tenant A's alert and run: it reads nothing, so tenant A's id cites nothing there.
    intruder = FactLedger(TENANT_B, alert_a, run_a, repos.evidence_facts)
    assert await intruder.facts() == ()
    assert check_citations([fact.fact_id], await intruder.facts(), benign_claim=False) == [(fact.fact_id, "unknown_fact")]
    assert await repos.evidence_facts.list_for_run(TENANT_B, alert_a, run_a) == []
    assert await repos.evidence_facts.latest_run(TENANT_B, alert_a) == (0, [])
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
    assert [e.fact_id for e in await ledger(repos, TENANT_A, alert_a, run_a).facts()] == ["host:0"]
    alert_b = await make_alert(repos, TENANT_B)
    [own] = await observe(ledger(repos, TENANT_B, alert_b, new_run_id()), "host", Handler(answer=(host_fact("B-HOST"),)))
    assert own.fact_id == "host:0" and own.content_hash != fact.content_hash
    assert [e.content_hash for e in (await repos.evidence_facts.latest_run(TENANT_A, alert_a)).entries] == [fact.content_hash]


async def test_the_ledger_is_append_only(db: Database, repos: Repositories, app_db: Database, app: Repositories) -> None:
    """No update or delete path: none in the repository, none for the runtime role, and a trigger for everyone."""
    alert_id, run_id = await make_alert(app, TENANT_A), new_run_id()
    [entry] = await observe(ledger(app, TENANT_A, alert_id, run_id), "host", Handler(answer=(host_fact(),)))
    assert {name for name in vars(EvidenceFactsRepo) if not name.startswith("_")} == {"append", "list_for_run", "latest_run"}

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
    # The runtime role cannot take the rows away through their alert either.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with app_db.tenant_tx(TENANT_A) as conn:
            await conn.execute("DELETE FROM alerts WHERE tenant_id = $1 AND id = $2", TENANT_A, alert_id)
    [stored] = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)
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
        # One notion of complete: the row and its fact cannot disagree, whichever way.
        (0, "host:0", "host", digest, "success", False, bound),
        (0, "host:0", "host", digest, "success", True, {**bound, "complete": False}),
        (0, "host:0", "host", digest, "success", True, {k: v for k, v in bound.items() if k != "complete"}),
        (0, "host:0", "host", digest, "success", True, {**bound, "complete": "true"}),
        (0, "host:0", "other", digest, "success", True, None),                     # the id names another evidence id
        (0, "anything", "host", digest, "success", True, None),                    # not an id the ledger mints
        (0, "host:0", "host", "not-a-hash", "success", True, None),
        (0, "host:0", "host", digest, "unknown", True, None),
        (MAX_RUN_ENTRIES, "host:0", "host", digest, "empty", True, None),          # past the end of a run's ledger
        (-1, "host:0", "host", digest, "empty", True, None),
    ]
    for row in broken:
        with pytest.raises(asyncpg.CheckViolationError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(INSERT, TENANT_A, alert_id, *row)
    async with db.tenant_tx(TENANT_A) as conn:  # the same statement with rows that keep the rules
        assert await conn.execute(INSERT, TENANT_A, alert_id, 7, "host:7", "host", digest, "success", True, {**bound, "id": "host:7"}) == "INSERT 0 1"
        silent = {k: v for k, v in bound.items() if k != "complete"}
        assert await conn.execute(INSERT, TENANT_A, alert_id, 8, "host:8", "host", digest, "success", False, {**silent, "id": "host:8"}) == "INSERT 0 1"
        assert await conn.execute(INSERT, TENANT_A, alert_id, MAX_RUN_ENTRIES - 1, "host:9", "host", digest, "empty", True, None) == "INSERT 0 1"

    # An id is minted once in a run: a second entry under it is refused, whoever built it.
    run_id = new_run_id()
    entries = build_entries(ToolStep("host", TOOL, 1, digest, digest, "empty", True), [], NOW)
    assert await repos.evidence_facts.append(TENANT_A, alert_id, run_id, entries) == 1
    with pytest.raises(Conflict):
        await repos.evidence_facts.append(TENANT_A, alert_id, run_id, entries)
    assert [e.fact_id for e in await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)] == ["host:0"]


async def test_a_run_reads_back_what_it_recorded_and_a_retry_mints_nothing(repos: Repositories) -> None:
    alert_id, run_id = await make_alert(repos, TENANT_A), new_run_id()
    run = ledger(repos, TENANT_A, alert_id, run_id)
    calls = [
        ("host", Handler(answer=(host_fact("a"), host_fact("b")))),
        ("fanout", Handler(answer=())),
        ("lineage", Boom()),
    ]
    recorded = [entry for evidence_id, handler in calls for entry in await observe(run, evidence_id, handler)]

    resumed = ledger(repos, TENANT_A, alert_id, run_id)  # a new process picks the run up from the table
    stored = await resumed.facts()
    assert [e.fact_id for e in stored] == ["host:0", "host:1", "fanout:0", "lineage:0"]
    assert [(e.outcome, e.complete, e.reason) for e in stored[2:]] == [("empty", True, None), ("failed", False, "error:RuntimeError")]
    assert [e.model_dump(include=set(LedgerEntry.model_fields)) for e in stored] == [e.model_dump() for e in recorded]
    assert all(e.intact for e in stored) and [e.citable_as_benign_evidence for e in stored] == [True, True, False, False]
    rows = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)
    assert [(row.seq, row.run_id, row.tenant_id) for row in rows] == [(n, run_id, TENANT_A) for n in range(4)]

    # The node runs again after a crash: the same three calls are the entries the run already has.
    retried = [entry for evidence_id, handler in calls for entry in await observe(resumed, evidence_id, handler)]
    assert retried == list(stored)
    assert len(await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)) == 4
    # A new observation continues the numbering.
    [more] = await observe(resumed, "host", Handler(answer=(host_fact("c"),)))
    assert more.fact_id == "host:2"


async def test_two_writers_of_one_run_never_mint_one_id_and_both_see_the_run(repos: Repositories) -> None:
    alert_id, run_id = await make_alert(repos, TENANT_A), new_run_id()
    one, two = ledger(repos, TENANT_A, alert_id, run_id), ledger(repos, TENANT_A, alert_id, run_id)
    assert await one.facts() == await two.facts() == ()
    [a] = await observe(one, "host", Handler(answer=(host_fact("a"),)))
    [b] = await observe(two, "host", Handler(answer=(host_fact("b"),)))  # it reads the run again: no stale copy
    assert (a.fact_id, b.fact_id) == ("host:0", "host:1")
    assert [e.fact_id for e in await one.facts()] == [e.fact_id for e in await two.facts()] == ["host:0", "host:1"]

    # At the same moment: the table lets one in first, the other reads again and takes the next numbers.
    results = await asyncio.gather(*(
        observe(writer, "host", Handler(answer=(host_fact(f"{name}-1"), host_fact(f"{name}-2"))))
        for name, writer in (("one", one), ("two", two), ("three", ledger(repos, TENANT_A, alert_id, run_id)))
    ), return_exceptions=True)
    landed = [r for r in results if not isinstance(r, BaseException)]
    rows = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)
    assert [row.seq for row in rows] == list(range(len(rows))) and len(rows) == 2 + 2 * len(landed) and len(landed) >= 2
    assert sorted(row.fact_id for row in rows) == sorted(f"host:{n}" for n in range(len(rows)))
    assert [e.fact_id for e in await one.facts()] == [row.fact_id for row in rows]
    # A writer that lost twice was refused, not given an id someone else has.
    assert all(isinstance(r, Conflict) for r in results if isinstance(r, BaseException))


async def test_a_fact_with_text_the_database_rewrites_reads_back_intact(repos: Repositories) -> None:
    """A NUL, a negative zero, whole and tiny floats, the longest text: the stored row still matches its hash."""
    alert_id, run_id = await make_alert(repos, TENANT_A), new_run_id()
    long_line = "powershell -enc " + "A" * 4_000
    odd = host_fact("FIN\x00SRV café \U0001f600", confidence=1.0, value={
        "window_start": "2026-11-07T08:45:00Z", "window_end": "2026-11-07T09:30:00Z", "total": 3,
        "events": [{"at": "2026-11-07T09:00:00Z", "user": "CONTOSO\\svc\x00deploy", "command_template": long_line}] * 50,
    })
    scores = [
        host_fact(f"score-{n}", kind="reputation", subject={"type": "ip", "value": "203.0.113.9"},
                  value={"verdict": "benign", "score": score})
        for n, score in enumerate((-0.0, 0.0, 85.0, 1e-7, 0.30000000000000004, 99.99999999999999))
    ]
    run = ledger(repos, TENANT_A, alert_id, run_id)
    recorded = [*await observe(run, "host", Handler(answer=(odd,))),
                *await observe(run, "rep", Handler(answer=tuple(scores)), produces=frozenset({"reputation"}), row_cap=50)]

    stored = await ledger(repos, TENANT_A, alert_id, run_id).facts()
    assert [e.model_dump(include=set(LedgerEntry.model_fields)) for e in stored] == [e.model_dump() for e in recorded]
    assert all(e.intact for e in stored)
    assert check_citations([e.fact_id for e in stored], stored, benign_claim=True) == []
    host = stored[0].fact or {}
    assert host["subject"]["value"] == "FIN�SRV café \U0001f600" and host["confidence"] == 1
    assert host["value"]["events"][49] == {"at": "2026-11-07T09:00:00Z", "groups": [], "user": "CONTOSO\\svc�deploy", "command_template": long_line}
    assert [(e.fact or {})["value"]["score"] for e in stored[1:]] == [0, 0, 85, 1e-7, 0.30000000000000004, 99.99999999999999]


async def test_the_view_reads_the_newest_run_its_first_entries_and_every_call_without_a_fact(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    old, new = new_run_id(), new_run_id()
    await observe(ledger(repos, TENANT_A, alert_id, old), "host", Handler(answer=(host_fact("OLD"),)))
    run = ledger(repos, TENANT_A, alert_id, new)
    await observe(run, "a", Handler(answer=tuple(host_fact(f"a{n}") for n in range(4))), row_cap=50)
    await observe(run, "nothing", Handler(answer=()))
    await observe(run, "b", Handler(answer=tuple(host_fact(f"b{n}") for n in range(3))), row_cap=50)
    await observe(run, "broken", Boom())

    whole = await repos.evidence_facts.latest_run(TENANT_A, alert_id)
    assert (whole.total, {e.run_id for e in whole.entries}, len(whole.entries)) == (9, {new}, 9)
    cut = await repos.evidence_facts.latest_run(TENANT_A, alert_id, limit=2)
    assert cut.total == 9 and [e.fact_id for e in cut.entries] == ["a:0", "a:1", "nothing:0", "broken:0"]
    assert await repos.evidence_facts.latest_run(TENANT_A, "no-such-alert") == (0, [])
    with pytest.raises(ValueError):
        await repos.evidence_facts.latest_run(TENANT_A, alert_id, limit=MAX_RUN_ENTRIES + 1)
