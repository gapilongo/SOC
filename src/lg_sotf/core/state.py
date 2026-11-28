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

from typing import Any, Dict, List, Optional, TypedDict

from lg_sotf.models.vocabulary import Decision, Route

__all__ = [
    "AlertSummary",
    "AnalysisDigest",
    "AnalysisSummary",
    "AnalystInput",
    "ApprovalInput",
    "CorrelationDigest",
    "DecisionDigest",
    "EscalationSummary",
    "GateDigest",
    "InvestigationRecord",
    "LlmRefusal",
    "PhishingDigest",
    "PlanDigest",
    "RelatedOpenDigest",
    "ResponseSummary",
    "ReviewBand",
    "RoutingDigest",
    "SuppressedBy",
    "ToolObservation",
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
    threat_likelihood: Optional[int]
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
    related_threats: int
    related_open_reviews: int
    campaign_indicators: List[str]


class CitationFinding(TypedDict, total=False):
    """What is wrong with one citation of a claim (``lg_sotf.domain.ledger.check_citations``)."""

    fact_id: str
    code: str


class InvestigationClaimRecord(TypedDict, total=False):
    """A claim of the deep model with the ledger ids it cites, as code checked them against the run's ledger."""

    text: str
    supports: str
    cites: List[str]
    findings: List[CitationFinding]


class InvestigationStepRecord(TypedDict, total=False):
    """One query of an investigation's plan: ``outcome`` is ``success``, ``empty``, ``failed`` or ``skipped``."""

    evidence_id: str
    tool: str
    outcome: str
    reason: Optional[str]
    fact_ids: List[str]
    complete: bool
    reused: bool


class InvestigationRecord(TypedDict, total=False):
    """What the investigation executor did for an alert (AI-E3.3). Absent when no investigation applies.

    The analysis digest (graph state, the node's timeline event) carries the counts and codes; the alert's
    summary (``alerts.summary.analysis.investigation``) also the steps, budgets, indicators and claims.
    """

    #: ``completed``: the evidence was shown to the deep model. ``degraded``: the analysis ran without it.
    status: str
    #: Why the analysis ran without the evidence (``lg_sotf.agents.investigation.executor.DEGRADED_REASONS``).
    reason: Optional[str]
    skill: str
    skill_version: str
    stop_reason: str
    lookups: int
    facts: int
    empty: int
    failed: int
    skipped: int
    #: What of the investigation holds a model-led close (``lg_sotf.domain.closure.evidence_holds``):
    #: ``{steering: [fact ids], indicators: {indicator: [fact ids]}, citations: [finding codes]}``.
    blocking: Dict[str, Any]
    # Digest only: how many claims the model made, and how many citation findings code raised on them.
    claim_count: int
    citation_findings: int
    # Summary only.
    run_id: Optional[str]
    steps: List[InvestigationStepRecord]
    #: ``{steps | wall_s | tokens | usd: {used, limit}}``.
    budget: Dict[str, Dict[str, float]]
    #: The skill's malicious indicators over the run's facts: ``true``, ``false`` or ``unknown``. Reported only.
    indicators: Dict[str, str]
    claims: List[InvestigationClaimRecord]
    #: The prompt builder cut the evidence to fit its size limit: the model saw some facts in part.
    evidence_truncated: bool
    #: False when the citation check itself failed (the claims are then left out).
    claims_checked: bool
    #: Ids of the facts in which the injection scan found steering text (the model was shown a marker instead).
    steering: List[str]
    #: Findings about the verdict as a whole: ``no_claims`` (a benign verdict that rests on no claim).
    verdict_findings: List[CitationFinding]
    #: The benign verdict rests on recorded evidence: every benign claim cites a complete fact and has no
    #: finding. False for any other verdict or record: a close is then on the model's word. A label only.
    evidence_backed: bool


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
    investigation: InvestigationRecord


class DecisionDigest(TypedDict, total=False):
    """The routing decision after analysis (``lg_sotf.domain.routing.Decision``)."""

    route: Route
    reason: str
    disposition: Optional[str]
    code: str


class RelatedOpenDigest(TypedDict, total=False):
    """The related alerts on the same host or user, as stored when the alert was decided. ``threats`` and
    ``in_progress`` hold back a close on the models' word: ids of the threats that are high or critical and
    judged by a model, or were confirmed by a person, and of the high or critical alerts in progress on the
    same host. ``model_only``: ids of the other threats a model judged or planned a response for (also one that
    waits for its approval); the alert closes and is linked to their case. ``unchecked``: the check did not complete (``read_failed``,
    ``too_many_candidates``), so nothing closed on the models' word; the lists are then absent."""

    threats: List[str]
    in_progress: List[str]
    model_only: List[str]
    unchecked: str


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


# --------------------------------------------------------------- alerts.summary


class ToolObservation(TypedDict, total=False):
    """One reputation lookup of the analysis agent (``alerts.summary.analysis.tools``)."""

    tool: str
    kind: str
    target: str
    results: List[Dict[str, Any]]
    simulated: bool
    #: ISO 8601: when the platform received the results.
    checked_at: str


class AnalysisSummary(AnalysisDigest, total=False):
    """``alerts.summary.analysis``: the analysis digest plus the evidence behind it."""

    threat_indicators: List[str]
    tools: List[ToolObservation]
    #: Analyst-confirmed history lookups: kind, value, the lookup result and ``checked_at``.
    history: List[Dict[str, Any]]
    reasoning: List[str]


class ResponseSummary(TypedDict, total=False):
    """``alerts.summary.response``: the response plan's playbook, evidence and action counts."""

    threat_type: str
    evidence: str
    auto: int
    awaiting: int
    blocked: int
    done: int


class AlertSummary(TypedDict, total=False):
    """The ``alerts.summary`` document. Writers shallow-merge a subset of these keys (``AlertsRepo.update``).

    Rows written by an older release may lack keys or hold other shapes, so
    readers stay defensive; nothing validates this at runtime.
    """

    # The agents' digests (triage, correlation) and the full analysis.
    triage: TriageDigest
    correlation: CorrelationDigest
    analysis: AnalysisSummary
    # LLM accounting (lg_sotf.agents.base.persist_llm_accounting).
    llm_usage: Dict[str, Any]
    llm_models: Dict[str, Dict[str, str]]
    llm_refusals: List[LlmRefusal]
    llm_budget_exceeded: bool
    # Escalation (escalate and await_analyst nodes).
    escalation_id: Optional[str]
    escalation_attached: bool
    detached_from: str
    # The response plan (plan_response node).
    response: ResponseSummary
    # The outcome (close node).
    verdict: str
    close_reason: str
    # Decision policy v3 safety net (lg_sotf.core.retro_reopen): why a model-closed alert was reopened.
    reopened: Dict[str, Optional[str]]
    # A person flagged the AI's close as wrong (lg_sotf.core.reopen): who and when. Never their words.
    flagged: Dict[str, Optional[str]]
    # The same safety net, for a threat only a model judged: the links of an alert that stays closed (threat
    # alert, case, time) and, on the threat, the alerts it linked.
    linked: List[Dict[str, Optional[str]]]
    linked_alert_ids: List[str]
    # The related-alert check of a model-led close, as the database stood when ``decide`` ran (only at the tier).
    related_open: RelatedOpenDigest
    confidence: Optional[float]
    threat_score: Optional[float]
    decision: Optional[DecisionDigest]
    analyst_decision: Optional[str]
    # A blind-audit escalation a fresh run starts at (lg_sotf.services.blind_audit); cleared when it starts.
    blind_audit_review: Optional[str]
    actions: Dict[str, int]
    dry_run: bool
    simulated_evidence: bool
    suppressed_by: Optional[SuppressedBy]


# ---------------------------------------------------------- escalations.summary


class ReviewBand(TypedDict):
    min: int
    max: int


class RoutingDigest(TypedDict):
    """The routing outcome that created an escalation (``escalations.summary.routing``)."""

    code: str
    confidence: float
    band: Optional[ReviewBand]


class EscalationSummary(TypedDict, total=False):
    """What the workflow writes to ``escalations.summary`` (the database adds ``attached_count``)."""

    title: str
    severity: str
    confidence: float
    threat_score: Optional[int]
    verdict: Optional[str]
    conclusion: str
    simulated_evidence: bool
    recommended_actions: List[str]
    #: Whether ``conclusion`` was written by the model (else by the rules); null without an analysis.
    llm_used: Optional[bool]
    routing: RoutingDigest
    # Added by EscalationService and the escalations repository.
    correlated_alert_ids: List[str]
    attached_count: int
    # A detached escalation (an attached alert that needs its own decision).
    detached_from: str
    parent_alert_id: str
    parent_decision: str
    own_review_reason: str
