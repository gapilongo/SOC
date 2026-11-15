"""Review probes for PR #438 (AI-E3.2). Each test asserts the SAFE behaviour; a failure is a finding.

The reviewer's file, kept as written except ``p1`` (see its docstring).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.domain.ledger import MAX_RUN_ENTRIES, LedgerError, check_citations, new_run_id, planner_view
from tests.unit.agents.investigation._support import AT, TOOL, MemoryStore, fact_tools, host_fact
from tests.unit.tools._support import Ctx, Handler, P

pytestmark = pytest.mark.unit


async def observe(ledger: FactLedger, evidence_id: str, handler: Handler, **declared: Any) -> Any:
    tools = fact_tools(handler, **declared)
    result = await tools.call(Ctx(), TOOL, P, agent="investigation")
    return await ledger.record(tool_step(evidence_id, tools.get(TOOL), result))


async def test_p1_a_reprocessed_alert_does_not_inherit_the_previous_investigations_ids(make_settings: Any) -> None:
    """Workflow.run deletes the checkpoint thread on reprocess and starts a fresh thread with the SAME thread id.

    Adapted to the review's decision 1: a ledger is keyed by the investigation run id, minted with each
    run's first state (``initial_state``), and ``for_run`` never falls back to the thread id. The probe
    built both contexts without a run id; each now carries the id of its own run, as the engine gives it.
    """
    store = MemoryStore()
    repos = cast(Any, SimpleNamespace(evidence_facts=store))

    def run_context() -> AgentContext:
        return AgentContext("tenant-a", "alert-1", make_settings(), repos=repos, investigation_run_id=new_run_id())

    with pytest.raises(LedgerError, match="no investigation run id"):
        FactLedger.for_run(AgentContext("tenant-a", "alert-1", make_settings(), repos=repos))
    first = FactLedger.for_run(run_context())
    await observe(first, "host", Handler(answer=(host_fact("OLD-OBSERVATION"),)))

    # The alert is re-queued (reprocess): a new investigation, new context, nothing observed yet.
    second = FactLedger.for_run(run_context())
    assert await second.facts() == (), "the new investigation starts with the old one's facts"
    assert check_citations(["host:0"], await second.facts(), benign_claim=True) == [("host:0", "unknown_fact")]


async def test_p2_a_retried_step_is_not_recorded_twice_and_cannot_fill_the_ledger_for_good() -> None:
    store = MemoryStore()
    run = FactLedger("t1", "a1", "t1:a1", store, clock=lambda: AT)
    tools = fact_tools(Handler(answer=(host_fact(),)))
    result = await tools.call(Ctx(), TOOL, P, agent="investigation")
    step = tool_step("host", tools.get(TOOL), result)
    await run.record(step)
    # The node re-runs after a crash before its checkpoint: a new process, the same call (same hashes).
    resumed = FactLedger("t1", "a1", "t1:a1", store, clock=lambda: AT)
    await resumed.record(step)
    assert [e.fact_id for e in await resumed.facts()] == ["host:0"], "the same call is on the ledger twice"


async def test_p2b_a_full_ledger_is_permanent_for_the_alert() -> None:
    store = MemoryStore()
    run = FactLedger("t1", "a1", "t1:a1", store, clock=lambda: AT)
    tools = fact_tools(Handler(answer=(host_fact(),)))
    result = await tools.call(Ctx(), TOOL, P, agent="investigation")
    step = tool_step("host", tools.get(TOOL), result)
    for _ in range(MAX_RUN_ENTRIES):
        await run.record(step)
    later = FactLedger("t1", "a1", "t1:a1", store, clock=lambda: AT)  # any later run of the alert
    try:
        await later.record(step)
    except LedgerError as exc:
        pytest.fail(f"the alert can never be investigated again: {exc}")


async def test_p3_the_content_hash_binds_the_id_and_what_the_analyst_sees() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    (found,) = await observe(run, "host", Handler(answer=(host_fact(),)))
    (nothing,) = await observe(run, "fanout", Handler(answer=()))
    # The success fact relabelled under the empty call's id (and the reverse): both still "intact".
    swapped_fact = {**(found.fact or {}), "id": "fanout:0"}
    forged = [
        found.model_copy(update={"fact_id": "fanout:0", "evidence_id": "fanout", "fact": swapped_fact}),
        nothing.model_copy(update={"fact_id": "host:0", "evidence_id": "host"}),
    ]
    assert not all(e.intact for e in forged), "an entry whose id was changed still matches its content hash"


async def test_p3b_reason_and_time_are_covered() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    (nothing,) = await observe(run, "fanout", Handler(answer=()))
    changed = nothing.model_copy(update={"reason": "checked: nothing malicious, safe to close"})
    assert planner_view([changed])[0]["reason"] == "checked: nothing malicious, safe to close"
    assert not changed.intact, "the reason shown to the planner is not covered by the hash"


async def test_p4_an_incomplete_result_is_not_benign_evidence() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    capped = await observe(run, "host", Handler(answer=(host_fact("a"), host_fact("b"))), row_cap=2)
    assert [e.complete for e in capped] == [False, False]
    problems = check_citations([e.fact_id for e in capped], await run.facts(), benign_claim=True)
    assert problems, "a benign claim rests on a result the source cut, and check_citations says nothing"


async def test_p4b_a_benign_claim_with_no_citation_is_a_problem() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    await observe(run, "fanout", Handler(answer=()))
    assert check_citations([], await run.facts(), benign_claim=True), "a benign claim citing nothing passes"


async def test_p5_the_planner_view_marks_the_facts_own_completeness() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    # The tool's fact says it is not complete; the registry's row cap was not hit.
    (entry,) = await observe(run, "host", Handler(answer=(host_fact(complete=False),)))
    shown = planner_view([entry])[0]
    assert (entry.fact or {}).get("complete") is False
    assert shown["complete"] is False, f"planner sees complete={shown['complete']} for a fact that says complete=false"


async def test_p6_planner_context_is_bounded() -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    big = host_fact("H" * 1024)
    for _ in range(MAX_RUN_ENTRIES // 50):
        await observe(run, "host", Handler(answer=tuple(big for _ in range(50))), row_cap=500)
    size = len(json.dumps(await run.planner_context()))
    assert size < 100_000, f"planner_context is {size} bytes before the prompt builder"


@pytest.mark.parametrize("cited", ["Host:0", "host:0 ", " host:0", "host:00", "host:０", "host:0#x", "host:0\n", "hоst:0", "HOST:0"])
async def test_p7_lookalike_ids_are_unknown(cited: str) -> None:
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    await observe(run, "host", Handler(answer=(host_fact(),)))
    assert check_citations([cited], await run.facts(), benign_claim=True) == [(cited, "unknown_fact")]


async def test_p8_a_nul_in_attacker_text_is_refused_or_cleaned_before_the_store() -> None:
    try:
        fact = host_fact("FIN\x00SRV")
    except Exception:  # noqa: BLE001 - the reviewer's probe, kept as written
        return  # the schema refuses it: sound
    run = FactLedger("t1", "a1", "t1:a1", None, clock=lambda: AT)
    (entry,) = await observe(run, "host", Handler(answer=(fact,)))
    assert "\x00" not in json.dumps(entry.fact, ensure_ascii=False), "a NUL reaches the JSONB insert (Postgres refuses \\u0000)"
