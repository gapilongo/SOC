"""LLM-W6-01: attacker-chosen process and hash targets are never contained automatically.

An implant named ``lsass.exe`` runs from a Temp folder with a C2 port (the
attacker controls both "rules" observations) and was started by
``explorer.exe``. The response must not terminate a critical OS process, must
never target the parent process or its hash, and scopes host-local actions
to the alert's hosts.
"""

from __future__ import annotations

from typing import Any

import pytest

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.registry import AgentSet
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.llm.fake import ScriptedChatModel
from tests.integration.db._support import TENANT_A
from tests.integration.e2e.conftest import eventually, running

pytestmark = pytest.mark.integration

EXPLORER_SHA256 = "b4a1c3b6c7e2f9a8d5e4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2"
IMPLANT_SHA256 = "e3b1c4d2a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2"


def _model() -> ScriptedChatModel:
    verdict = {
        "threat_score": 95,
        "certainty": 90,
        "verdict": "malicious",
        "conclusion": "beacon",
        "recommended_actions": ["Terminate the process", "Quarantine the file"],
    }
    triage = {
        "threat_likelihood": 95,
        "threat_assessment": "likely_threat",
        "false_positive_indicators": [],
        "true_positive_indicators": ["beacon"],
        "threat_categories": ["malware"],
        "urgency_level": "high",
        "recommended_actions": [],
        "reasoning": "x",
    }
    correlation = {"campaign_likelihood": 50, "attack_campaign_indicators": [], "reasoning": "x"}
    return ScriptedChatModel(
        model_name="fake",
        script={"TriageAssessment": [triage] * 5, "AnalysisVerdict": [verdict] * 5, "CorrelationAssessment": [correlation] * 5},
    )


async def test_masquerading_and_parent_targets_are_not_contained(stack_factory: Any, repos: Any) -> None:
    stack = stack_factory()
    await repos.tenants.update_settings(
        TENANT_A,
        {
            "autonomy": {"low": "auto", "medium": "auto", "high": "approval", "critical": "disabled"},
            "protected_assets": {"hosts": ["dc-*"], "hashes": ["a" * 64], "processes": ["corp-agent.exe"]},
        },
    )
    await repos.sources.create(TENANT_A, "webhook", "Splunk hook", source_id="splunk-hook", config={"format": "splunk"})
    event = {
        "event_id": "n-1",
        "rule_name": "Endpoint - Malware beacon",
        "urgency": "high",
        "_time": "2026-09-01T10:00:00Z",
        "dest": "ws-042",
        "user": "jdoe",
        "process_name": "lsass.exe",
        "parent_process_name": "explorer.exe",
        "process_hash": IMPLANT_SHA256,
        "parent_process_hash": EXPLORER_SHA256,
        "file_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass.exe",
        "destination_port": 4444,
    }
    model = _model()
    s = stack.settings
    agents = AgentSet(
        triage=TriageAgent(settings=s, model_factory=lambda tier, settings: model),
        correlation=CorrelationAgent(settings=s, model_factory=lambda tier, settings: model),
        analysis=AnalysisAgent(settings=s, model_factory=lambda tier, settings: model),
    )
    engine = await WorkflowEngine.create(
        settings=s, db=stack.db, redis=stack.redis, events=stack.events, agents=agents, checkpoint_pool_size=4
    )
    stack.engines.append(engine)
    result = await stack.ingest(TENANT_A, "splunk-hook", [event])
    await stack.dispatch(TENANT_A, result)
    alert_id = result.inserted[0].alert_id
    async with running(stack.worker(engine)):
        await eventually(lambda: stack.all_settled(TENANT_A, [alert_id]), within=60)

    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=100)).items
    by_target = {(a.action_type, a.target.lower()): a for a in actions}
    auto = {(a.action_type, a.target.lower()) for a in actions if a.approved_by == "policy:auto"}
    # Never the parent process or the parent's hash, in any status.
    assert not any(t in (EXPLORER_SHA256, "explorer.exe") for _, t in by_target), sorted(by_target)
    # The masquerading "lsass.exe" is a critical process name: blocked, never terminated.
    lsass = by_target[("terminate_process", "lsass.exe")]
    assert lsass.status == "blocked" and lsass.blocked_reason == "protected_asset"
    assert ("terminate_process", "lsass.exe") not in auto
    # The implant's own hash is what the temp-directory rule is about; it is scoped to the host.
    quarantine = by_target[("quarantine_file", IMPLANT_SHA256)]
    assert quarantine.params.get("scope") == {"hosts": ["ws-042"]}
