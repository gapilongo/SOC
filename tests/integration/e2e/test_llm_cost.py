"""LLM cost controls end to end: gated triage, one correlation call, per-alert totals that match billing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable, Dict

import pytest

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.registry import AgentSet
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.llm.fake import ScriptedChatModel
from tests.integration.db._support import TENANT_A
from tests.integration.e2e.conftest import Stack, eventually, running

pytestmark = pytest.mark.integration

ENTITIES = {"ips": ["185.220.101.44"], "hosts": ["ws-042"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"]}
BENIGN = {
    "source_alert_id": "bk-1",
    "title": "Scheduled backup maintenance test job",
    "severity": "low",
    "occurred_at": "2026-09-01T10:00:00Z",
    "entities": {"hosts": ["backup-01"]},
}
FIRST = {
    "source_alert_id": "c2-1",
    "title": "Unusual outbound connection from workstation",
    "severity": "medium",
    "occurred_at": "2026-09-01T10:05:00Z",
    "entities": ENTITIES,
}
SECOND = {**FIRST, "source_alert_id": "c2-2", "title": "Repeated beacon to the same relay"}


async def engine_with(stack: Stack, model: ScriptedChatModel) -> WorkflowEngine:
    def factory(tier: str, settings: Any) -> ScriptedChatModel:
        return model

    s = stack.settings
    agents = AgentSet(
        triage=TriageAgent(settings=s, model_factory=factory),
        correlation=CorrelationAgent(settings=s, model_factory=factory),
        analysis=AnalysisAgent(settings=s, model_factory=factory),
    )
    engine = await WorkflowEngine.create(
        settings=s, db=stack.db, redis=stack.redis, events=stack.events, agents=agents, checkpoint_pool_size=4
    )
    stack.engines.append(engine)
    return engine


async def run_one(stack: Stack, engine: WorkflowEngine, event: Dict[str, Any]) -> str:
    result = await stack.ingest(TENANT_A, "api", [event])
    await stack.dispatch(TENANT_A, result)
    alert_id = result.inserted[0].alert_id
    async with running(stack.worker(engine)):
        await eventually(lambda: stack.all_settled(TENANT_A, [alert_id]), within=60)
        await eventually(stack.stream_empty)
    return alert_id


def calls_by_schema(model: ScriptedChatModel, start: int = 0) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for call in model.calls[start:]:
        out[call.schema] = out.get(call.schema, 0) + 1
    return out


async def test_llm_calls_are_gated_and_totals_are_written_per_alert(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    model = ScriptedChatModel(model_name="fake-cost")
    engine = await engine_with(stack, model)

    benign_id = await run_one(stack, engine, BENIGN)
    benign = await repos.alerts.get(TENANT_A, benign_id)
    assert (benign.status, benign.disposition) == ("closed", "benign")
    assert model.calls == [], "a decisive rule outcome must not cost an LLM call"
    assert benign.summary["triage"]["llm_skipped"] == "rules_decisive"
    assert "llm_usage" not in benign.summary

    first_id = await run_one(stack, engine, FIRST)
    first_calls = calls_by_schema(model)
    # Ambiguous triage (1 call), no related alerts (0 correlation calls), no providers (1 verdict call).
    assert first_calls == {"TriageAssessment": 1, "AnalysisVerdict": 1}
    first = await repos.alerts.get(TENANT_A, first_id)
    assert first.summary["correlation"]["llm_skipped"] == "no_related_alerts"
    usage = first.summary["llm_usage"]
    assert usage["calls"] == 2 and set(usage["by_agent"]) == {"triage", "analysis"}
    assert usage["input_tokens"] > 0 and usage["output_tokens"] > 0

    before = len(model.calls)
    second_id = await run_one(stack, engine, SECOND)
    second_calls = calls_by_schema(model, before)
    assert second_calls.get("CorrelationAssessment") == 1, second_calls
    [correlation_call] = [c for c in model.calls[before:] if c.schema == "CorrelationAssessment"]
    prompt = str(correlation_call.messages[1].content)
    assert "Unusual outbound connection from workstation" in prompt and first_id not in prompt
    second = await repos.alerts.get(TENANT_A, second_id)
    assert second.summary["correlation"]["related_alert_ids"] == [first_id]
    assert second.summary["llm_usage"]["by_agent"]["correlation"]["calls"] == 1
    assert second.summary["llm_usage"]["calls"] == sum(second_calls.values())

    # Per-alert totals reconcile with the billing table the worker flushed on shutdown.
    daily = await repos.llm_usage.day_totals(TENANT_A, datetime.now(UTC).date())
    per_alert = [first.summary["llm_usage"], second.summary["llm_usage"]]
    assert daily.calls == sum(u["calls"] for u in per_alert) == len(model.calls)
    assert daily.input_tokens == sum(u["input_tokens"] for u in per_alert)
    assert daily.output_tokens == sum(u["output_tokens"] for u in per_alert)
