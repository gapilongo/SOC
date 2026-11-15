"""The investigation executor (AI-E3.3): a fixed plan through the registry, every call on the ledger, budgets,
a breaker, and never an exception for the alert's run."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.agents.investigation.catalog import load_catalog
from lg_sotf.agents.investigation.executor import InvestigationRun, SkillInvestigator, switched_on
from lg_sotf.domain.investigation_budget import Budget, BudgetLimits
from lg_sotf.domain.ledger import FACT_ID_PATTERN
from lg_sotf.models.skill import SkillSpec
from lg_sotf.settings import Settings
from lg_sotf.tools.wazuh.tools import HOST_ACTIVITY, LOGON_FANOUT, PREVALENCE, Evidence
from tests.unit.agents.investigation._executor import (
    AT,
    FILE,
    HOSTILE,
    LOGON,
    RUN_ID,
    SWITCH_ON,
    Answers,
    Clock,
    context,
    host_fact,
    investigator,
    logon_fact,
    wazuh_alert,
)
from tests.unit.agents.investigation._support import MemoryStore
from tests.unit.tools._support import Settings as TenantTools

pytestmark = pytest.mark.unit

Make = Callable[..., Settings]
DOWN = Evidence(error="unreachable")


def outcomes(run: InvestigationRun) -> List[Any]:
    return [(step.evidence_id, step.outcome, step.reason) for step in run.steps]


async def test_the_plan_runs_in_file_order_and_every_call_is_on_the_ledger(make_settings: Make) -> None:
    """Success, empty and failed alike: each call the plan makes is one ledger entry, in the order it was made."""
    answers = Answers({LOGON_FANOUT: lambda p: Evidence() if p.pivot == "target_user" else DOWN})
    store = MemoryStore()
    ctx = context(make_settings(), store=store)

    run = await investigator(answers, make_settings()).investigate(ctx, wazuh_alert())

    assert run is not None and (run.skill_id, run.skill_version, run.run_id) == ("wazuh.default", "1.0.0", RUN_ID)
    assert answers.called == [HOST_ACTIVITY, LOGON_FANOUT, LOGON_FANOUT]
    assert outcomes(run) == [("host", "success", None), ("prevalence", "skipped", "no_binding"),
                             ("logons_user", "empty", None), ("logons_source", "failed", "reported")]
    entries = store.rows[("t1", "a1", RUN_ID)]
    assert [(e.fact_id, e.outcome, e.fact is not None) for e in entries] == [
        ("host:0", "success", True), ("logons_user:0", "empty", False), ("logons_source:0", "failed", False)]
    assert [step.fact_ids for step in run.steps] == [("host:0",), (), ("logons_user:0",), ("logons_source:0",)]
    # The values came from the alert's detector fields and the file, through the tools' own parameter models.
    assert answers.calls[0][1] == {"host": "FIN-SRV-02", "at": AT, "before_min": 60, "after_min": 0}
    assert answers.calls[1][1] | {"pivot": "target_user", "value": "j.doe", "before_min": 1440} == answers.calls[1][1]
    assert answers.calls[2][1]["value"] == "10.20.1.83"
    # It finished with a fact, so the deep model is shown the ledger's view; the trace has one step a call.
    assert (run.stop_reason, run.reason, run.facts) == ("finished", None, 1)
    assert run.context is not None and [o["id"] for o in run.context["observations"]] == [e.fact_id for e in entries]
    assert [(s.agent, s.tool, s.outcome) for s in ctx.trace.steps] == [
        ("investigation", HOST_ACTIVITY, "success"), ("investigation", LOGON_FANOUT, "empty"),
        ("investigation", LOGON_FANOUT, "failed")]
    assert [e.input_hash for e in entries] == [s.input_hash for s in ctx.trace.steps]
    assert run.digest() == {
        "status": "completed", "reason": None, "skill": "wazuh.default", "skill_version": "1.0.0",
        "stop_reason": "finished", "lookups": 3, "facts": 1, "empty": 1, "failed": 1, "skipped": 1,
    }
    assert run.record()["budget"]["steps"] == {"used": 3, "limit": 8} and run.record()["budget"]["usd"]["used"] == 0


@pytest.mark.parametrize(
    "tenant_settings",
    [None, {}, {"tools": {}}, {"tools": {"wazuh_indexer": {}}}, {"tools": {"wazuh_indexer": {"enabled": False}}},
     {"tools": {"wazuh_indexer": {"enabled": "true"}}}, {"tools": {"wazuh_indexer": {"enabled": 1}}},
     {"tools": {"wazuh_indexer": True}}, {"tools": [["wazuh_indexer", {"enabled": True}]]},
     {"tools": {"virustotal": {"enabled": True}}}],
)
async def test_the_harness_is_opt_in_per_tenant(make_settings: Make, tenant_settings: Any) -> None:
    """Only ``tools.wazuh_indexer.enabled: true`` turns it on. Otherwise nothing runs and nothing is recorded."""
    answers, store = Answers(), MemoryStore()
    ctx = context(make_settings(), tenant_settings, store=store)
    assert await investigator(answers, make_settings()).investigate(ctx, wazuh_alert()) is None
    assert answers.calls == [] and store.rows == {} and ctx.trace.steps == []
    assert not switched_on(tenant_settings, ["wazuh_indexer"])
    assert switched_on(SWITCH_ON, ["wazuh_indexer"]) and not switched_on(SWITCH_ON, [])


@pytest.mark.parametrize("alert", [wazuh_alert(normalizer="sentinel"), wazuh_alert(normalizer=None), {"title": "x"}])
async def test_an_alert_without_evidence_tools_keeps_todays_path(make_settings: Make, alert: Dict[str, Any]) -> None:
    answers, store = Answers(), MemoryStore()
    ctx = context(make_settings(), store=store)
    assert await investigator(answers, make_settings()).investigate(ctx, alert) is None
    assert answers.calls == [] and store.rows == {}
    without_repos = context(make_settings())
    without_repos.repos = None
    assert await investigator(answers, make_settings()).investigate(without_repos, wazuh_alert()) is None


async def test_the_step_budget_stops_the_run(make_settings: Make) -> None:
    answers = Answers()
    ctx = context(make_settings(), {**SWITCH_ON, "investigation": {"budget": {"steps": 2}}})
    run = await investigator(answers, make_settings()).investigate(ctx, wazuh_alert())
    assert run is not None and answers.called == [HOST_ACTIVITY, LOGON_FANOUT]
    assert outcomes(run)[-1] == ("logons_source", "skipped", "budget_steps")
    # A spent budget is today's path with the reason: the facts stay on the ledger, the model is not shown them.
    assert (run.stop_reason, run.reason, run.context, run.facts) == ("budget_steps", "budget_steps", None, 2)
    assert run.digest()["status"] == "degraded" and run.budget["steps"] == {"used": 2, "limit": 2}


async def test_the_wall_clock_budget_stops_the_run(make_settings: Make) -> None:
    clock = Clock()

    def slow(params: Any) -> Evidence:
        clock.now += 61.0  # the first call took longer than the whole budget
        return Evidence([host_fact()])

    answers = Answers({HOST_ACTIVITY: slow})
    run = await investigator(answers, make_settings(), clock=clock).investigate(context(make_settings()), wazuh_alert())
    assert run is not None and answers.called == [HOST_ACTIVITY]
    assert outcomes(run)[1:] == [(e, "skipped", "budget_wall") for e in ("prevalence", "logons_user", "logons_source")]
    assert (run.stop_reason, run.reason, run.context) == ("budget_wall", "budget_wall", None)
    assert run.budget["wall_s"] == {"used": 61.0, "limit": 60.0}


async def test_a_call_still_running_when_the_time_is_spent_is_cut_and_recorded_as_failed(make_settings: Make) -> None:
    async def hangs() -> Evidence:
        await asyncio.sleep(30)
        return Evidence([host_fact()])

    answers, store = Answers({HOST_ACTIVITY: lambda p: hangs()}), MemoryStore()
    tenant = {**SWITCH_ON, "investigation": {"budget": {"wall_s": 0.05}}}
    run = await investigator(answers, make_settings()).investigate(context(make_settings(), tenant, store=store), wazuh_alert(FILE))
    assert run is not None and outcomes(run) == [
        ("host", "failed", "budget_wall"), ("prevalence", "skipped", "budget_wall"),
        ("logons_user", "skipped", "budget_wall"), ("logons_source", "skipped", "budget_wall")]
    (entry,) = store.rows[("t1", "a1", RUN_ID)]
    assert (entry.fact_id, entry.outcome, entry.complete, entry.reason, entry.output_hash) == (
        "host:0", "failed", False, "budget_wall", None)
    assert (run.stop_reason, run.reason, run.context) == ("budget_wall", "budget_wall", None)


async def test_the_money_budget_counts_the_price_the_registry_declares(make_settings: Make) -> None:
    """The Wazuh tools are free. A priced tool is paid for before it is called, and never called past the budget."""
    answers = Answers(prices={HOST_ACTIVITY: 0.10, LOGON_FANOUT: 0.10})
    run = await investigator(answers, make_settings()).investigate(context(make_settings()), wazuh_alert())
    assert run is not None and answers.called == [HOST_ACTIVITY, LOGON_FANOUT]  # 0.10 + 0.10, and 0.30 is over 0.25
    assert outcomes(run)[-1] == ("logons_source", "skipped", "budget_usd")
    assert (run.stop_reason, run.reason, run.context) == ("budget_usd", "budget_usd", None)
    assert run.budget["usd"] == {"used": 0.2, "limit": 0.25}
    free = Answers()
    zero = {**SWITCH_ON, "investigation": {"budget": {"usd": 0}}}
    run = await investigator(free, make_settings()).investigate(context(make_settings(), zero), wazuh_alert())
    assert run is not None and run.stop_reason == "finished" and len(free.calls) == 3


async def test_the_token_budget_stops_the_run_once_a_model_call_spent_it(make_settings: Make) -> None:
    """The executor makes no model call while the plan is fixed, so nothing here spends tokens yet. The budget
    is the one the planner will charge: once it is over, no further query starts."""
    answers = Answers()
    engine = investigator(answers, make_settings())
    ctx = context(make_settings())
    budget = Budget(BudgetLimits(steps=8, wall_s=60.0, tokens=1_000, usd=0.25), Clock())
    budget.charge(tokens=1_001)  # what a planner call would have cost
    run = InvestigationRun("wazuh.default", "1.0.0", RUN_ID)
    await engine._run(ctx, wazuh_alert(), engine.catalog[0], run, budget)
    assert answers.calls == [] and (run.stop_reason, run.reason, run.context) == ("budget_tokens", "budget_tokens", None)
    assert {step.reason for step in run.steps} == {"budget_tokens"} and run.budget["tokens"] == {"used": 1_001, "limit": 1_000}


async def test_a_tenants_override_is_cut_to_the_installs_maximum(make_settings: Make) -> None:
    settings = make_settings(investigation={"tenant_max": {"steps": 9, "wall_s": 61.0, "tokens": 20_000, "usd": 0.25}})
    greedy = {**SWITCH_ON, "investigation": {"budget": {"steps": 10_000, "wall_s": 9_999, "usd": 500, "tokens": 10**9}}}
    run = await investigator(Answers(), settings).investigate(context(settings, greedy), wazuh_alert())
    assert run is not None
    assert {kind: used["limit"] for kind, used in run.budget.items()} == {"steps": 9, "wall_s": 61.0, "tokens": 20_000, "usd": 0.25}
    # Never more than a quarter of the analysis node's own time, whatever the install allows.
    short = make_settings(worker={"analysis_timeout_s": 40.0})
    assert investigator(Answers(), short).limits({}).wall_s == 10.0


async def test_the_breaker_opens_after_two_calls_without_an_answer(make_settings: Make) -> None:
    """An unreachable indexer costs two calls, not the plan's worth: the rest are skipped, never retried."""
    answers, store = Answers({HOST_ACTIVITY: DOWN, LOGON_FANOUT: DOWN}), MemoryStore()
    run = await investigator(answers, make_settings()).investigate(context(make_settings(), store=store), wazuh_alert())
    assert run is not None and answers.called == [HOST_ACTIVITY, LOGON_FANOUT]
    assert outcomes(run) == [("host", "failed", "reported"), ("prevalence", "skipped", "no_binding"),
                             ("logons_user", "failed", "reported"), ("logons_source", "skipped", "circuit_open")]
    assert (run.stop_reason, run.reason, run.context, run.facts) == ("circuit_open", "circuit_open", None, 0)
    assert [e.outcome for e in store.rows[("t1", "a1", RUN_ID)]] == ["failed", "failed"]
    # An answer in between closes it again: two failures apart are not an outage.
    apart = Answers({HOST_ACTIVITY: DOWN, LOGON_FANOUT: lambda p: Evidence() if p.pivot == "target_user" else DOWN})
    run = await investigator(apart, make_settings()).investigate(context(make_settings()), wazuh_alert())
    assert run is not None and len(apart.calls) == 3 and run.stop_reason == "finished" and run.reason == "no_facts"
    one = make_settings(investigation={"breaker_failures": 1})
    run = await investigator(Answers({HOST_ACTIVITY: DOWN}), one).investigate(context(one), wazuh_alert())
    assert run is not None and [s.outcome for s in run.steps] == ["failed", "skipped", "skipped", "skipped"]


async def test_a_tool_that_raises_or_is_switched_off_in_the_registry_is_a_failed_fact_not_an_error(make_settings: Make) -> None:
    def explode(params: Any) -> Evidence:
        raise RuntimeError("detail-from-the-indexer")  # the registry names the type only

    run = await investigator(Answers({HOST_ACTIVITY: explode}), make_settings()).investigate(context(make_settings()), wazuh_alert())
    assert run is not None and outcomes(run)[0] == ("host", "failed", "error:RuntimeError") and "detail-from" not in str(run.record())
    off = Answers(tenant_tools=TenantTools({"wazuh_indexer": {"enabled": False}}))  # the registry's own, cached, switch
    run = await investigator(off, make_settings()).investigate(context(make_settings()), wazuh_alert())
    assert run is not None and off.calls == [] and run.stop_reason == "circuit_open"
    assert [s.reason for s in run.steps] == ["disabled", "no_binding", "disabled", "circuit_open"]


async def test_no_executor_error_reaches_the_alerts_run(make_settings: Make) -> None:
    """The ledger's store is down: the investigation says ``error`` and the analysis goes on as it does today."""
    answers, store = Answers(), MemoryStore()
    store.refuse = True
    run = await investigator(answers, make_settings()).investigate(context(make_settings(), store=store), wazuh_alert())
    assert run is not None and (run.stop_reason, run.reason, run.context) == ("error", "error", None)
    assert run.digest()["status"] == "degraded" and len(answers.calls) == 1
    # A run started before investigation run ids existed has no ledger: nothing is called.
    untracked = Answers()
    run = await investigator(untracked, make_settings()).investigate(context(make_settings(), run_id=None), wazuh_alert())
    assert run is not None and (run.reason, run.steps, untracked.calls) == ("no_run_id", [], [])
    # An alert without a usable time binds nothing: every query is skipped, and there is no fact to show.
    for when in ("yesterday", "2026-10-19T07:28:01", None):
        run = await investigator(untracked, make_settings()).investigate(context(make_settings()), wazuh_alert(occurred_at=when))
        assert run is not None and (run.reason, {s.reason for s in run.steps}, untracked.calls) == ("no_facts", {"no_binding"}, [])


async def test_a_retried_or_resumed_run_sends_nothing_twice(make_settings: Make) -> None:
    """The same run again: every call is found on the ledger, a failed one included, and no id is minted."""
    answers, store = Answers({LOGON_FANOUT: lambda p: Evidence([logon_fact()]) if p.pivot == "target_user" else DOWN}), MemoryStore()
    engine = investigator(answers, make_settings())
    first = await engine.investigate(context(make_settings(), store=store), wazuh_alert())
    again = await engine.investigate(context(make_settings(), store=store), wazuh_alert())
    assert first is not None and again is not None and len(answers.calls) == 3
    assert [(s.evidence_id, s.outcome, s.fact_ids) for s in again.steps] == [(s.evidence_id, s.outcome, s.fact_ids) for s in first.steps]
    assert [s.reused for s in first.steps] == [False] * 4 and [s.reused for s in again.steps] == [True, False, True, True]
    assert [e.fact_id for e in store.rows[("t1", "a1", RUN_ID)]] == ["host:0", "logons_user:0", "logons_source:0"]
    assert again.context == first.context and again.budget["steps"]["used"] == 3
    # Another run of the same alert (a reprocess) starts from an empty ledger and asks again.
    other = await engine.investigate(context(make_settings(), store=store, run_id="inv_" + "2" * 32), wazuh_alert())
    assert other is not None and len(answers.calls) == 6 and not any(s.reused for s in other.steps)


async def test_a_value_the_tool_refuses_skips_the_query(make_settings: Make) -> None:
    """The file asks sshd for a pivot sshd does not record: the tool's own parameter model says no, nothing is sent."""
    default = load_catalog()[0]
    doc = default.model_dump(by_alias=True, mode="json")
    doc["evidence"][3]["args"]["pivot"] = {"const": "source_host"}
    catalog = [SkillSpec.model_validate(doc)]
    sshd = {"agent": {"name": "web-01"}, "decoder": {"name": "sshd"}, "data": {"srcip": "198.51.100.7", "dstuser": "root"}}
    answers = Answers()
    run = await investigator(answers, make_settings(), catalog=catalog).investigate(context(make_settings()), wazuh_alert(sshd))
    assert run is not None and outcomes(run)[-1] == ("logons_source", "skipped", "binding_refused")
    assert answers.called == [HOST_ACTIVITY, LOGON_FANOUT] and answers.calls[1][1]["family"] == "sshd"


async def test_attacker_text_in_a_fact_changes_neither_the_plan_nor_the_budget_nor_the_ids(make_settings: Make) -> None:
    """A fact's typed fields can carry strings the attacker chose. The executor reads none of them: the same
    calls with the same values, the same limits, and only ids the ledger minted."""
    clean_answers, hostile_store = Answers({PREVALENCE: Evidence()}), MemoryStore()
    poisoned = Answers({
        HOST_ACTIVITY: Evidence([host_fact(events=[{"at": "2026-10-19T07:00:00Z", "user": HOSTILE, "command_template": HOSTILE}])]),
        LOGON_FANOUT: Evidence([logon_fact(failed_users=[HOSTILE], source_hosts=[HOSTILE])]),
    })
    clean = await investigator(clean_answers, make_settings()).investigate(context(make_settings()), wazuh_alert())
    hostile = await investigator(poisoned, make_settings()).investigate(context(make_settings(), store=hostile_store), wazuh_alert())
    assert clean is not None and hostile is not None
    assert poisoned.calls == clean_answers.calls  # the plan and every value: nothing was added, nothing redirected
    assert PREVALENCE not in poisoned.called and all(params.get("host", "FIN-SRV-02") == "FIN-SRV-02" for _, params in poisoned.calls)
    assert hostile.budget == {**clean.budget, "wall_s": hostile.budget["wall_s"]}
    assert {kind: used["limit"] for kind, used in hostile.budget.items()} == {"steps": 8, "wall_s": 60.0, "tokens": 20_000, "usd": 0.25}
    import re

    ids = [e.fact_id for e in hostile_store.rows[("t1", "a1", RUN_ID)]]
    assert ids == ["host:0", "logons_user:0", "logons_source:0"] and all(re.fullmatch(FACT_ID_PATTERN, i) for i in ids)
    assert hostile.context is not None and [o["id"] for o in hostile.context["observations"]] == ids
    # The text is on the ledger as data, inside typed fields, and nowhere in what the executor decided.
    assert HOSTILE in str(hostile.context) and HOSTILE not in str(hostile.record())


def test_an_invalid_catalogue_stops_the_process(make_settings: Make) -> None:
    from lg_sotf.agents.investigation.catalog import SkillError

    doc = load_catalog()[0].model_dump(by_alias=True, mode="json")
    doc["evidence"][0]["tool"] = "wazuh.host_activity:2"
    with pytest.raises(SkillError, match="is version 1, not 2"):
        SkillInvestigator(Answers().registry, make_settings(), catalog=[SkillSpec.model_validate(doc)])
    assert [skill.id for skill in investigator(Answers(), make_settings()).catalog] == ["wazuh.default"]


def test_limits_default_to_the_install(make_settings: Make) -> None:
    engine = investigator(Answers(), make_settings())
    assert engine.limits(None) == engine.limits({}) == BudgetLimits(steps=8, wall_s=60.0, tokens=20_000, usd=0.25)
