"""Investigation trace (AI-E1.3): every LLM call and tool call of an agent run reaches the trace store, in order."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import httpx
import pytest
from structlog.testing import capture_logs

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.analysis.react import STEP_PROMPT
from lg_sotf.agents.base import AgentContext, persist_trace
from lg_sotf.agents.triage.base import PROMPT as TRIAGE_PROMPT
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.llm.trace import MAX_STEPS, content_hash
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from tests.unit.agents._support import AMBIGUOUS, ASSESSMENT, NOW, ctx, factory, fake_repos, scripted

VT_KEY = "test-only-vt-key-0123456789"
ALERT = {
    "title": "Possible C2 beacon",
    "severity": "high",
    "entities": {"ips": ["185.220.101.44"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"], "users": ["jdoe"]},
}


def _step(action: str, target: str = "", **extra: Any) -> Dict[str, Any]:
    return {
        "thought": f"{action} {target}", "threat_score": 60, "certainty": 50, "verdict": "inconclusive",
        "conclusion": "Beaconing to a known relay.", "recommended_actions": [], "action": action, "target": target,
        **extra,
    }


def _vt(seen: List[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}})

    return httpx.MockTransport(handler)


@pytest.fixture
def vt_settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(tools={"virustotal": {"api_key": VT_KEY, "share_with_tenants": True, "requests_per_minute": 100}})


async def test_every_llm_and_tool_step_of_an_analysis_run_is_stored_in_order(vt_settings: Settings) -> None:
    model = scripted(InvestigationStep=[
        _step("lookup", "i1", threat_score=30), _step("lookup", "i2", threat_score=60),
        _step("finish", threat_score=90, verdict="malicious"),
    ])
    seen: List[httpx.Request] = []
    agent = AnalysisAgent(
        settings=vt_settings, model_factory=factory(model),
        enrichment=EnrichmentService.from_settings(vt_settings, transport=_vt(seen)),
    )
    repos = fake_repos()

    result = await agent.run(ctx(vt_settings, repos=repos), ALERT, triage={}, correlation={})

    rows = repos.investigation_steps.rows
    assert {(t, a, r) for t, a, r, _ in rows} == {("t1", "a1", "t1:a1")}
    steps = repos.investigation_steps.steps
    kinds = [(s.kind, s.tool or s.prompt_name) for s in steps]
    history = [("tool", "history")] * len(result.history)
    react = [("llm", "analysis.react_step"), ("tool", "reputation")] * 2 + [("llm", "analysis.react_step")]
    assert kinds == history + react
    # Every model call and every lookup made is in the trace, nothing else.
    assert sum(k == "llm" for k, _ in kinds) == len(model.calls) == result.llm_calls
    assert sum(t == "reputation" for _, t in kinds) == len(seen) == result.tool_steps
    assert all(s.agent == "analysis" and s.outcome == "success" and s.started_at.tzinfo for s in steps)
    llm = [s for s in steps if s.kind == "llm"]
    assert all(s.prompt_hash == STEP_PROMPT.hash and s.model == "fake-scripted" for s in llm)
    assert all(s.input_tokens > 0 and s.output_tokens > 0 for s in llm)
    lookups = [s for s in steps if s.tool == "reputation"]
    # A tool observation is identified by the hash of its request (record/replay).
    hash_request = {"tool": "reputation", "kind": "hash", "value": "44d88612fea8a8f36de82e1278abb02f",
                    "providers": ["virustotal"]}
    assert lookups[0].input_hash == content_hash(hash_request)
    assert lookups[0].output_hash == content_hash(result.observations[0]["results"])
    assert lookups[0].result_digest == {"value": result.observations[0]["results"]}


async def test_triage_call_is_stored_with_its_prompt_version(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    await TriageAgent(settings=settings, model_factory=factory(scripted(TriageAssessment=[ASSESSMENT]))).run(
        ctx(settings, repos=repos, run_id="shadow-1"), AMBIGUOUS
    )
    [(_, _, run_id, step)] = repos.investigation_steps.rows
    assert run_id == "shadow-1"
    assert (step.agent, step.kind, step.prompt_name, step.prompt_hash) == ("triage", "llm", "triage.assess",
                                                                           TRIAGE_PROMPT.hash)
    assert step.result_digest["value"]["reasoning"] == ASSESSMENT["reasoning"]


async def test_a_failed_trace_write_is_logged_and_never_fails_the_run(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    repos.investigation_steps.error = RuntimeError("database unavailable")
    with capture_logs() as logs:
        result = await TriageAgent(settings=settings, model_factory=factory(scripted(TriageAssessment=[ASSESSMENT]))).run(
            ctx(settings, repos=repos), AMBIGUOUS
        )
    assert result.llm_used
    assert [e["error_type"] for e in logs if e["event"] == "agent.trace_write_failed"] == ["RuntimeError"]
    # The LLM accounting is still written.
    assert repos.alerts.rows[("t1", "a1")].summary["llm_usage"]["calls"] == 1


async def test_a_replay_context_writes_no_trace(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    await TriageAgent(settings=settings, model_factory=factory(scripted(TriageAssessment=[ASSESSMENT]))).run(
        AgentContext("t1", "a1", settings, repos=repos, persist=False), AMBIGUOUS
    )
    assert repos.investigation_steps.rows == []


async def test_steps_beyond_the_cap_are_counted_and_logged(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    context = ctx(settings, repos=repos)
    step = NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash="0" * 64, outcome="success",
                        started_at=NOW)
    for _ in range(MAX_STEPS + 3):
        context.trace.add(step)
    with capture_logs() as logs:
        await persist_trace(context)
    assert len(repos.investigation_steps.rows) == MAX_STEPS
    assert [e["dropped"] for e in logs if e["event"] == "agent.trace_steps_dropped"] == [3]
    assert context.trace.steps == [] and context.trace.dropped == 0
