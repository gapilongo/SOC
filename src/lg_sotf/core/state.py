"""Typed digests of the workflow state (roadmap T3).

Each graph node writes a small digest of its result into the workflow state
(:class:`lg_sotf.core.graph.WorkflowState`); these ``total=False`` TypedDicts
name the keys and value types of each digest, so mypy checks every reader and
writer against them.

TypedDicts are erased at runtime: the values are plain ``dict`` objects, so
LangGraph checkpoints are unchanged. A digest read back from a checkpoint
written by an older release may lack keys that were added later, which is why
every key is optional and readers keep their defaults.

This module imports only :mod:`typing` and the domain vocabulary, so any layer
may reference it (lower layers under ``TYPE_CHECKING``, ADR-0001).
"""

from typing import Dict, List, Optional, TypedDict

from lg_sotf.models.vocabulary import Decision, Route

__all__ = [
    "AnalysisDigest",
    "AnalystInput",
    "ApprovalInput",
    "CorrelationDigest",
    "DecisionDigest",
    "GateDigest",
    "LlmRefusal",
    "PhishingDigest",
    "PlanDigest",
    "SuppressedBy",
    "TriageDigest",
]


class LlmRefusal(TypedDict, total=False):
    """``llm_refusal`` in an agent digest: the model declined to assess the alert."""

    reason: Optional[str]
    category: Optional[str]
    agent: Optional[str]


class SuppressedBy(TypedDict, total=False):
    """What closed the alert at the gate: a suppression rule or a cached analyst verdict."""

    type: str
    # type "suppression_rule"
    rule_id: str
    name: str
    # type "verdict_cache"
    decision: Optional[str]
    source_alert_id: Optional[str]


class GateDigest(TypedDict, total=False):
    suppressed: bool
    suppressed_by: SuppressedBy


class PhishingDigest(TypedDict, total=False):
    """Email alerts: sender authentication, lookalikes and suspicious links (``lg_sotf.domain.phishing``)."""

    sender_authenticated: bool
    lookalikes: List[str]
    lookalike_hosts: List[str]
    impersonation: str
    suspicious_urls: List[str]


class TriageDigest(TypedDict, total=False):
    confidence: int
    rule_confidence: int
    priority: int
    rule_fp: List[str]
    rule_tp: List[str]
    rule_score: Optional[int]
    trusted_score: Optional[int]
    llm_fp: List[str]
    llm_tp: List[str]
    llm_used: bool
    llm_skipped: Optional[str]
    llm_refusal: LlmRefusal
    threat_assessment: Optional[str]
    threat_categories: List[str]
    reasoning: Optional[str]
    phishing: PhishingDigest


class CorrelationDigest(TypedDict, total=False):
    score: int
    confidence: int
    related_alert_ids: List[str]
    related_count: int
    indicator_count: int
    indicator_types: Dict[str, int]
    burst: bool
    frequency_level: str
    llm_used: bool
    llm_skipped: Optional[str]
    llm_refusal: LlmRefusal
    related_dispositions: Dict[str, int]
    campaign_indicators: List[str]


class AnalysisDigest(TypedDict, total=False):
    threat_score: int
    certainty: int
    verdict: str
    rule_threat_score: int
    rule_verdict: str
    rule_corroborated: bool
    rule_evidence: List[str]
    corroborated_targets: List[List[str]]
    conclusion: str
    recommended_actions: List[str]
    llm_used: bool
    tool_steps: int
    llm_calls: int
    stop_reason: Optional[str]
    simulated_evidence: bool
    llm_refusal: LlmRefusal


class DecisionDigest(TypedDict, total=False):
    """The routing decision after analysis (``lg_sotf.domain.routing.Decision``)."""

    route: Route
    reason: str
    disposition: Optional[str]
    code: str


class PlanDigest(TypedDict, total=False):
    """The response plan: action ids by what happens to them next."""

    threat_type: str
    auto: List[str]
    awaiting: List[str]
    blocked: List[str]
    done: List[str]


class AnalystInput(TypedDict, total=False):
    """The analyst decision a run resumes with (``AnalystDecisionPayload``).

    ``inherited_from`` is set by the workflow when the decision was made on a
    grouped escalation's parent alert; ``approved_actions`` is then empty.
    """

    type: str
    escalation_id: str
    decision: Decision
    approved_actions: List[str]
    decided_by: str
    notes: str
    approver_role: Optional[str]
    inherited_from: Optional[str]


class ApprovalInput(TypedDict, total=False):
    """The approval decision a run resumes with (``ApprovalPayload``)."""

    type: str
    approved_action_ids: List[str]
    rejected_action_ids: List[str]
    decided_by: str
    reject_remaining: bool
