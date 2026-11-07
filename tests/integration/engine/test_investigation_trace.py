"""Investigation trace store (AI-E1.3) against real Postgres: every LLM and tool step of a run is stored and in
the run's evidence pack; the trace follows the tenant's alert retention."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.registry import AgentSet
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.compliance.evidence import build_evidence_pack, render_evidence_html
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.retention import purge_expired
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.settings import RetentionSettings, Settings
from lg_sotf.tools.enrichment import EnrichmentService
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.integration

VT_KEY = "test-only-vt-key-0123456789"
ENTITIES = {"ips": ["185.220.101.44"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"], "users": ["jdoe"]}


def _step(action: str, target: str, threat: int) -> Dict[str, Any]:
    return {
        "thought": f"{action} {target}", "threat_score": threat, "certainty": 40 + threat // 2,
        "verdict": "malicious" if action == "finish" else "inconclusive", "conclusion": "Beacon to a known relay.",
        "recommended_actions": ["Block the relay address"], "action": action, "target": target,
    }


def _vt(seen: List[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}})

    return httpx.MockTransport(handler)


async def test_every_llm_and_tool_step_of_a_run_is_in_the_trace_store_and_the_evidence_pack(
    engine_factory: Callable[..., Any], engine_settings: Settings, repos: Repositories
) -> None:
    vt = {"api_key": VT_KEY, "share_with_tenants": True, "requests_per_minute": 100}
    settings = engine_settings.model_copy(update={"tools": {"virustotal": vt}})
    model = ScriptedChatModel(
        model_name="fake-trace",
        script={"InvestigationStep": [_step("lookup", "i1", 30), _step("lookup", "i2", 60), _step("finish", "", 90)]},
    )
    seen: List[httpx.Request] = []

    def factory(tier: str, s: Settings) -> ScriptedChatModel:
        return model

    agents = AgentSet(
        triage=TriageAgent(settings=settings, model_factory=factory),
        correlation=CorrelationAgent(settings=settings, model_factory=factory),
        analysis=AnalysisAgent(
            settings=settings, model_factory=factory,
            enrichment=EnrichmentService.from_settings(settings, transport=_vt(seen)),
        ),
    )
    engine = await engine_factory(settings=settings, agents=agents)
    alert_id = await make_alert(
        repos, TENANT_A, title="Possible C2 beacon from workstation", severity="high",
        normalized={"entities": ENTITIES}, raw={"vendor": "edr"},
    )

    await engine.run(TENANT_A, alert_id)

    stored = await repos.investigation_steps.list_for_alert(TENANT_A, alert_id)
    assert {s.run_id for s in stored} == {thread_id_for(TENANT_A, alert_id)}
    assert [s.step_index for s in stored] == list(range(len(stored)))
    llm = [s for s in stored if s.kind == "llm"]
    tools = [s for s in stored if s.kind == "tool"]
    # Every model call and every lookup of the run is a step, and nothing else is.
    assert len(llm) == len(model.calls) >= 3
    assert sorted({s.prompt_name for s in llm}) >= ["analysis.react_step"]
    alert = await repos.alerts.get(TENANT_A, alert_id)
    analysis = alert.summary["analysis"]
    assert [s.tool for s in tools].count("reputation") == len(seen) == analysis["tool_steps"] == 2
    assert [s.tool for s in tools].count("history") == len(analysis["history"]) > 0
    assert all(s.outcome == "success" and s.output_hash and s.latency_ms >= 0 for s in stored)
    assert all(s.input_tokens > 0 and s.model == "fake-trace" for s in llm)

    pack = await build_evidence_pack(repos, settings, TENANT_A, alert_id, generated_by={"actor_type": "test"})
    trace = pack["investigation"]
    assert [(s["step_index"], s["kind"], s["input_hash"], s["output_hash"]) for s in trace["steps"]] == [
        (s.step_index, s.kind, s.input_hash, s.output_hash) for s in stored
    ]
    assert trace["totals"]["llm_steps"] == len(llm) and trace["totals"]["tool_steps"] == len(tools)
    assert trace["totals"]["input_tokens"] == sum(s.input_tokens for s in stored)
    section = render_evidence_html(pack).split('<section id="trace">')[1].split("</section>")[0]
    assert all(s.output_hash in section for s in stored if s.output_hash)
    assert section.count("analysis.react_step (version ") == sum(s.prompt_name == "analysis.react_step" for s in llm)
    assert section.count("<td>tool</td>") == len(tools)


async def test_the_trace_follows_the_tenants_alert_retention(repos: Repositories, db: Database) -> None:
    now = datetime.now(UTC)
    await repos.tenants.update_settings(TENANT_B, {"retention": {"alerts_days": 5}})
    step = NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash="a" * 64, outcome="success",
                        started_at=now)
    kept_a = await make_alert(repos, TENANT_A)
    expired_b = await make_alert(repos, TENANT_B)
    for tenant_id, alert_id in ((TENANT_A, kept_a), (TENANT_B, expired_b)):
        assert await repos.investigation_steps.append(tenant_id, alert_id, "run-1", [step, step]) == 2
        assert await repos.investigation_steps.append(tenant_id, alert_id, "run-1", [step]) == 1
        for status in ("queued", "processing"):
            await repos.alerts.update_status(tenant_id, alert_id, status)
        await repos.alerts.update_status(tenant_id, alert_id, "closed", now=now - timedelta(days=10))
    assert [s.step_index for s in await repos.investigation_steps.list_for_alert(TENANT_A, kept_a)] == [0, 1, 2]

    await purge_expired(db, RetentionSettings(), now=now)

    assert await repos.investigation_steps.list_for_alert(TENANT_B, expired_b) == []
    assert len(await repos.investigation_steps.list_for_alert(TENANT_A, kept_a)) == 3
