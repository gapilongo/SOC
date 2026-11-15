"""Review probes for PR #438 against Postgres. Each test asserts the SAFE behaviour; a failure is a finding.

The reviewer's file, kept as written except ``i2``: its facts now say ``complete: true``. Under the
review's decision 4 a benign claim that cites a fact which does not say it is complete gets an
``incomplete_fact`` finding, and the probe is about the JSONB round trip, not about completeness.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, List

import asyncpg
import pytest

from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.ledger import LedgerEntry, ToolStep, build_entries, check_citations
from lg_sotf.models.evidence_fact import parse_fact
from tests.integration.db._support import TENANT_A, make_alert, sha256_hex
from tests.unit.agents.investigation._support import TOOL, fact_tools, host_fact
from tests.unit.tools._support import Ctx, Handler, P

pytestmark = pytest.mark.asyncio
NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def ledger(repos: Repositories, tenant_id: str, alert_id: str) -> FactLedger:
    return FactLedger(tenant_id, alert_id, thread_id_for(tenant_id, alert_id), repos.evidence_facts, clock=lambda: NOW)


async def observe(run: FactLedger, evidence_id: str, handler: Handler) -> List[LedgerEntry]:
    tools = fact_tools(handler)
    result = await tools.call(Ctx(tenant_id=run.tenant_id, alert_id=run.alert_id), TOOL, P, agent="investigation")
    return list(await run.record(tool_step(evidence_id, tools.get(TOOL), result)))


async def test_i1_a_nul_in_a_fact_field_does_not_break_the_write(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    try:
        fact = host_fact("FIN\x00SRV")
    except Exception:  # noqa: BLE001 - the reviewer's probe, kept as written
        return  # the schema refuses it
    try:
        await observe(ledger(repos, TENANT_A, alert_id), "host", Handler(answer=(fact, host_fact("clean"))))
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"one attacker-chosen character loses the whole call's facts: {type(exc).__name__}")


async def test_i2_a_stored_fact_stays_intact_after_the_jsonb_round_trip(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    digest = sha256_hex("in")
    facts = tuple(
        parse_fact({
            "id": "x", "kind": "reputation", "subject": {"type": "ip", "value": "203.0.113.9"},
            "observed_at": "2026-11-07T09:30:00Z", "source": {"name": "virustotal"}, "complete": True,
            "value": {"verdict": "benign", "score": score},
        })
        for score in (-0.0, 1e-7, 0.30000000000000004, 85.0)
    )
    step = ToolStep("rep", "platform.example", 1, digest, digest, "success", True, None, facts)
    run_id = thread_id_for(TENANT_A, alert_id)
    await repos.evidence_facts.append(TENANT_A, alert_id, run_id, build_entries(step, [], NOW))
    stored = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)
    problems = check_citations([e.fact_id for e in stored], stored, benign_claim=True)
    assert problems == [], "an untouched row reads back as altered"


async def test_i3_the_table_refuses_lookalike_ids(db: Database, repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    digest = sha256_hex("in")
    sql = (
        "INSERT INTO evidence_facts (tenant_id, alert_id, run_id, seq, fact_id, evidence_id, tool, tool_version, "
        "input_hash, outcome, complete, as_of, content_hash) VALUES ($1, $2, 'r', $3, $4, $5, 't', 1, $6, 'empty', true, now(), $6)"
    )
    for n, (fact_id, evidence_id) in enumerate([("host:0\n", "host"), ("host\n:0", "host\n"), ("host:00", "host"), ("Host:0", "Host"), ("host:0 ", "host")]):
        with pytest.raises(asyncpg.CheckViolationError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(sql, TENANT_A, alert_id, n, fact_id, evidence_id, digest)
    for bad in ("host:0\n", "host:00", "host:0 "):
        with pytest.raises(Exception):  # noqa: B017
            LedgerEntry(fact_id=bad, evidence_id="host", tool="t", tool_version=1, input_hash=digest, outcome="empty",
                        complete=True, as_of=NOW, content_hash=digest)


async def test_i4_two_writers_of_one_run_at_once(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    one, two = ledger(repos, TENANT_A, alert_id), ledger(repos, TENANT_A, alert_id)
    await one.facts(), await two.facts()
    results: List[Any] = await asyncio.gather(
        observe(one, "host", Handler(answer=(host_fact("a"), host_fact("b")))),
        observe(two, "net", Handler(answer=(host_fact("c"),))),
        return_exceptions=True,
    )
    rows = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, one.run_id)
    print("RACE", [type(r).__name__ for r in results], [(r.seq, r.fact_id) for r in rows])
    assert [r.seq for r in rows] == list(range(len(rows)))
    # Whoever was not refused holds a ledger that agrees with the table.
    for run, result in zip((one, two), results, strict=True):
        if not isinstance(result, BaseException):
            assert [e.fact_id for e in await run.facts()] == [r.fact_id for r in rows], "a writer's ledger misses rows of its own run"


async def test_i5_the_runtime_role_cannot_remove_facts_through_their_alert(app_db: Database, app: Repositories) -> None:
    alert_id = await make_alert(app, TENANT_A)
    await observe(ledger(app, TENANT_A, alert_id), "host", Handler(answer=(host_fact(),)))
    with pytest.raises(asyncpg.PostgresError):
        async with app_db.tenant_tx(TENANT_A) as conn:
            await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
            await conn.execute("DELETE FROM alerts WHERE tenant_id = $1 AND id = $2", TENANT_A, alert_id)
    async with app_db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval("SELECT count(*) FROM evidence_facts") == 1


async def test_i6_a_fact_with_a_nul_reads_back_intact(repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    run = ledger(repos, TENANT_A, alert_id)
    (entry,) = await observe(run, "host", Handler(answer=(host_fact("FIN\x00SRV"),)))
    resumed = ledger(repos, TENANT_A, alert_id)
    stored = await resumed.facts()
    print("NUL", repr((stored[0].fact or {})["subject"]["value"]), repr((entry.fact or {})["subject"]["value"]))
    assert check_citations(["host:0"], stored, benign_claim=True) == [], "the stored row no longer matches its hash"
