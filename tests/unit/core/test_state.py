"""Typed workflow digests (roadmap T3): every key a digest writes is declared by its TypedDict."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Set, get_type_hints

import pytest

from lg_sotf.agents.analysis.base import AnalysisResult
from lg_sotf.agents.analysis.react import Candidate, Observation
from lg_sotf.agents.correlation.base import CorrelationResult
from lg_sotf.agents.investigation.executor import InvestigationRun, StepRecord
from lg_sotf.agents.triage.base import TriageResult
from lg_sotf.core.graph import WorkflowState, build_graph
from lg_sotf.core.nodes import _escalation_summary
from lg_sotf.core.state import (
    AlertSummary,
    AnalysisDigest,
    AnalysisSummary,
    AnalystInput,
    ApprovalInput,
    CitationFinding,
    CorrelationDigest,
    DecisionDigest,
    EscalationSummary,
    GateDigest,
    InvestigationClaimRecord,
    InvestigationRecord,
    InvestigationStepRecord,
    LlmRefusal,
    PhishingDigest,
    PlanDigest,
    ResponseSummary,
    ReviewBand,
    RoutingDigest,
    ToolObservation,
    TriageDigest,
)
from lg_sotf.domain.phishing import PhishingAssessment
from lg_sotf.domain.routing import Decision, RoutingThresholds, routing_digest
from lg_sotf.services.response.planner import PlanResult
from lg_sotf.tools.enrichment import EnrichmentResult

pytestmark = pytest.mark.unit

REFUSAL = {"reason": "model_refused", "category": "policy", "agent": "triage"}


def declared(typed_dict: Any) -> Set[str]:
    return set(typed_dict.__annotations__)


def assert_declared(digest: Mapping[str, Any], typed_dict: Any, *, complete: bool) -> None:
    keys = set(digest)
    assert keys <= declared(typed_dict), sorted(keys - declared(typed_dict))
    if complete:
        # A fully populated result writes every declared key: the TypedDict names no key nobody writes.
        assert keys == declared(typed_dict), sorted(declared(typed_dict) - keys)


def phishing() -> PhishingAssessment:
    return PhishingAssessment(
        tp=["email_dmarc_fail"],
        sender_authenticated=False,
        lookalikes=["examp1e.test"],
        lookalike_hosts=["examp1e.test"],
        impersonation="the display name uses the brand Example",
        suspicious_urls=["http://examp1e.test/login"],
    )


def triage(**overrides: Any) -> TriageResult:
    return TriageResult(confidence=40, rule_confidence=35, priority=3, rule_fp=["a"], rule_tp=["b"], **overrides)


def correlation(**overrides: Any) -> CorrelationResult:
    return CorrelationResult(
        score=20,
        confidence=40,
        related_alert_ids=["r1"],
        related_count=1,
        indicator_count=2,
        indicator_types={"ip": 1},
        burst=False,
        frequency_level="low",
        **overrides,
    )


def analysis(**overrides: Any) -> AnalysisResult:
    return AnalysisResult(
        threat_score=70,
        certainty=60,
        verdict="malicious",
        rule_threat_score=50,
        rule_verdict="inconclusive",
        conclusion="Looks bad.",
        recommended_actions=["isolate host"],
        threat_indicators=["network_communication"],
        llm_used=True,
        tool_steps=1,
        **overrides,
    )


def test_triage_digest_keys_are_declared() -> None:
    assert_declared(triage().digest(), TriageDigest, complete=False)
    full = triage(llm_refusal=dict(REFUSAL), phishing=phishing().digest(), reasoning="r").digest()
    assert_declared(full, TriageDigest, complete=True)


def test_correlation_digest_keys_are_declared() -> None:
    assert_declared(correlation().digest(), CorrelationDigest, complete=False)
    assert_declared(correlation(llm_refusal=dict(REFUSAL)).digest(), CorrelationDigest, complete=True)


def investigated() -> Dict[str, Any]:
    """What the analysis stores of an investigation: the executor's record and the model's checked claims."""
    run = InvestigationRun(
        "wazuh.default", "1.0.0", "inv_" + "0" * 32, steps=[StepRecord("host", "wazuh.host_activity", "success")],
        budget={"steps": {"used": 1, "limit": 8}}, indicators={"high_level_alert_on_host": "false"}, facts=1,
    )
    claim = {"text": "t", "supports": "benign", "cites": ["host:0"], "findings": [{"fact_id": "x:1", "code": "unknown_fact"}]}
    blocking = {"steering": [], "indicators": {}, "citations": ["unknown_fact"]}
    return {**run.record(), "claims": [claim], "evidence_truncated": False, "claims_checked": True,
            "verdict_findings": [], "blocking": blocking, "evidence_backed": False}


def test_analysis_digest_keys_are_declared() -> None:
    assert_declared(analysis().digest(), AnalysisDigest, complete=False)
    full = analysis(llm_refusal=dict(REFUSAL), investigation=investigated())
    assert_declared(full.digest(), AnalysisDigest, complete=True)
    # The investigation record: the digest carries counts and codes, the summary the steps, budgets and claims.
    digest, summary = full.digest()["investigation"], full.summary()["investigation"]
    assert set(digest) | set(summary) == declared(InvestigationRecord)
    assert not {"steps", "claims", "budget", "indicators", "run_id", "steering", "verdict_findings", "evidence_backed"} & set(digest)
    assert digest["blocking"] == summary["blocking"]  # what holds a close: the decision reads the digest
    assert (digest["claim_count"], digest["citation_findings"]) == (1, 1)
    assert set(summary["steps"][0]) == declared(InvestigationStepRecord)
    assert set(summary["claims"][0]) == declared(InvestigationClaimRecord)
    assert set(summary["claims"][0]["findings"][0]) == declared(CitationFinding)
    assert "investigation" not in analysis().digest() and "investigation" not in analysis().summary()


def test_phishing_digest_keys_are_declared() -> None:
    assert_declared(PhishingAssessment().digest(), PhishingDigest, complete=False)
    assert_declared(phishing().digest(), PhishingDigest, complete=True)


def test_decision_and_plan_digest_keys_are_declared() -> None:
    assert_declared(Decision("close", "low threat", "benign", "rule_corroborated_benign").as_dict(), DecisionDigest, complete=True)
    assert_declared(PlanResult(threat_type="generic", auto=["a1"]).as_dict(), PlanDigest, complete=True)


def test_refusal_digest_keys_are_declared() -> None:
    assert set(REFUSAL) == declared(LlmRefusal)


def test_analysis_summary_and_tool_observation_keys_are_declared() -> None:
    observation = Observation(
        Candidate("i1", "ip", "203.0.113.7", ["abuseipdb"]),
        [EnrichmentResult.ok("abuseipdb", "ip", "malicious", {"score": 90})],
    )
    tool = observation.digest()
    assert_declared(tool, ToolObservation, complete=True)
    summary = analysis(llm_refusal=dict(REFUSAL), observations=[dict(tool)], investigation=investigated()).summary()
    assert_declared(summary, AnalysisSummary, complete=True)


def test_escalation_summary_keys_are_declared() -> None:
    state: Dict[str, Any] = {"alert": {"title": "t"}, "severity": "high", "analysis": analysis().digest()}
    summary = _escalation_summary(state, routing_digest("grey_zone", 50.0, RoutingThresholds()))
    assert set(summary) <= declared(EscalationSummary)
    assert set(summary["routing"]) == declared(RoutingDigest)
    assert set(summary["routing"]["band"] or {}) == declared(ReviewBand)


def test_alert_summary_declares_what_the_close_node_writes() -> None:
    """The keys the close node writes (the full set is checked against real runs in the engine tests)."""
    closed = {
        "verdict", "close_reason", "confidence", "threat_score", "decision", "analyst_decision", "escalation_id",
        "actions", "dry_run", "simulated_evidence", "llm_budget_exceeded", "suppressed_by",
    }
    accounting = {"llm_usage", "llm_models", "llm_refusals", "llm_budget_exceeded"}
    # ``related_open``: the decide node's related-alert check of a model-led close (AI-E3.16).
    nodes = {"triage", "correlation", "analysis", "response", "escalation_attached", "detached_from", "related_open"}
    # The blind audit, and the safety net of policy v3 (core.retro_reopen): reopened, or only linked to a threat.
    review = {"blind_audit_review", "reopened", "linked", "linked_alert_ids"}
    assert closed | accounting | nodes | review == declared(AlertSummary)
    assert declared(ResponseSummary) == {"threat_type", "evidence", "auto", "awaiting", "blocked", "done"}


class GateClosesNodes:
    """Stub nodes: the gate suppresses the alert, so the run goes gate -> close -> END."""

    def node(self, name: str) -> Callable[[WorkflowState], Awaitable[Dict[str, Any]]]:
        async def fn(state: WorkflowState) -> Dict[str, Any]:
            if name == "gate":
                return {"gate": {"suppressed": True, "suppressed_by": {"type": "suppression_rule", "rule_id": "r1"}}}
            if name == "close":
                return {"disposition": "benign", "close_reason": "suppression_rule"}
            raise AssertionError(f"unexpected node {name}")

        return fn


def test_workflow_state_schema_resolves_and_the_graph_compiles() -> None:
    """LangGraph reads the schema with get_type_hints: the digest types must resolve at runtime."""
    hints = get_type_hints(WorkflowState, include_extras=True)
    assert hints["gate"] is GateDigest and hints["triage"] is TriageDigest
    assert hints["analyst"] == Optional[AnalystInput] and hints["approval"] == Optional[ApprovalInput]
    compiled = build_graph(GateClosesNodes(), RoutingThresholds()).compile()
    assert set(WorkflowState.__annotations__) <= set(compiled.channels)

    final = asyncio.run(compiled.ainvoke({"tenant_id": "t1", "alert_id": "a1", "severity": "low"}))
    # TypedDicts are erased: the state holds plain dicts, exactly as checkpoints store them.
    assert type(final["gate"]) is dict
    assert final["gate"]["suppressed_by"] == {"type": "suppression_rule", "rule_id": "r1"}
    assert final["disposition"] == "benign"

