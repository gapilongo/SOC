"""The investigation read model: what the investigation view shows about one alert (PRD-2.8a).

One typed shape for the verdict, the claims, the observations and what is not
established. Today it is filled from the stored digests, lookups, timeline and
trace store; the investigation harness (the fact ledger and the evidence
record, ADR-0014 Amendments 1 and 2) later fills the same shape, so the screen
does not change. Fields today's data cannot fill are empty and named in
``pending_harness``.

Two kinds of text, never mixed: a *sentence* is fixed text from
:mod:`lg_sotf.domain.investigation.words`; everything an alert, a model or a
provider wrote (claim texts, targets, excerpt lines, rule names) is *data*,
cut to a stated length, and is never formatted into a sentence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema

from lg_sotf.domain.actions import ACTION_CATALOG
from lg_sotf.models.vocabulary import ACTION_STATUSES, RISK_LEVELS

SCHEMA_VERSION = 1

OutcomeCategory = Literal["ai_closed_evidence", "ai_closed_audit", "needs_decision", "needs_review"]
ClosedByKind = Literal["ai", "suppression_rule", "cached_verdict", "analyst"]
Direction = Literal["malicious", "benign"]
ClaimCheck = Literal["supported", "unsupported", "rejected"]
ObservationOutcome = Literal["success", "empty", "failed"]
StepActor = Literal["code", "model", "check", "policy", "person"]
WrittenBy = Literal["model", "rules"]


def _enum(values: Any) -> Dict[str, Any]:
    """Advertised as an enum, kept ``str`` at runtime (ADR-0009: a value a newer release added still serializes)."""
    return {"type": "string", "enum": list(values)}


ActionTypeName = Annotated[str, WithJsonSchema(_enum(ACTION_CATALOG))]
RiskName = Annotated[str, WithJsonSchema(_enum(RISK_LEVELS))]
ActionStatusName = Annotated[str, WithJsonSchema(_enum(ACTION_STATUSES))]


class _Model(BaseModel):
    # A response always carries every field, so the schema marks fields with a default as required too.
    model_config = ConfigDict(frozen=True, json_schema_serialization_defaults_required=True)


class InvestigationReason(_Model):
    code: str = Field(description="The decide code, blocker or close reason, for filters and tests.")
    sentence: str = Field(description="The same in plain words (fixed text, never built from alert content).")


class InvestigationClosedBy(_Model):
    """Who or what closed the alert, and why."""

    kind: ClosedByKind
    reason: InvestigationReason
    at: Optional[datetime] = None
    rule_id: Optional[str] = Field(default=None, description="suppression_rule: the rule.")
    rule_name: Optional[str] = Field(default=None, description="suppression_rule: its name, as data.")
    source_alert_id: Optional[str] = Field(default=None, description="cached_verdict: the alert the analyst decided.")
    decision: Optional[str] = Field(default=None, description="analyst or cached_verdict: the analyst's decision.")


class InvestigationOutcome(_Model):
    category: Optional[OutcomeCategory] = Field(
        description=(
            "What happens next. ai_closed_evidence: closed by the AI on approved evidence. ai_closed_audit: "
            "closed on the model's word and sampled for audit. needs_decision: with a person, likely malicious. "
            "needs_review: with a person, not proven either way. Null when a suppression rule or a cached "
            "analyst verdict closed the alert before the AI looked at it."
        )
    )
    reason: Optional[InvestigationReason] = Field(description="Why the alert is with a person, or why it was closed.")
    blockers: List[InvestigationReason] = Field(
        default_factory=list, description="Why the AI may not close this alert on its own (needs_* categories)."
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="ai_closed_evidence: the approved benign signals the rules found (codes written by code).",
    )
    closed_by: Optional[InvestigationClosedBy] = Field(default=None, description="Null while the alert is open.")


class InvestigationSummary(_Model):
    text: Optional[str] = Field(description="The conclusion as it was written: data, at most 2000 characters.")
    written_by: Optional[WrittenBy] = Field(
        description=(
            "model: a model wrote the text. rules: the rule-based assessment did. Null without a text, or when "
            "the stored row does not say."
        )
    )


class InvestigationClaim(_Model):
    id: str
    text: str = Field(description="A model claim in the model's words (data), or the fixed sentence of a rule claim.")
    written_by: WrittenBy
    direction: Direction = Field(description="What the claim points to.")
    observation_ids: List[str] = Field(description="The observations the claim rests on.")
    check: ClaimCheck = Field(
        description="Today: supported when a lookup backs the claim, otherwise unsupported; rejected comes with the checker."
    )
    check_reason: Optional[str] = Field(default=None, description="Why the claim is not supported, in plain words.")


class ObservationMark(_Model):
    """A highlighted character range of an excerpt line (``start`` inclusive, ``end`` exclusive)."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)


class ObservationExcerptLine(_Model):
    text: str = Field(description="One line of what the tool returned: data, at most 200 characters.")
    marks: List[ObservationMark] = Field(default_factory=list)


class InvestigationObservation(_Model):
    """One tool call and what it returned."""

    id: str
    tool: str
    title: str = Field(description="What the tool looks up, in plain words.")
    kind: Optional[str] = Field(default=None, description="The kind of value looked up (ip, domain, hash, user, ...).")
    target: Optional[str] = Field(default=None, description="The value looked up: data, redacted, at most 128 characters.")
    sources: List[str] = Field(default_factory=list, description="The providers that answered or failed.")
    at: Optional[datetime] = None
    outcome: ObservationOutcome = Field(
        description="success: a source returned data. empty: the sources answered and found nothing. failed: none answered."
    )
    verdict: Optional[str] = Field(default=None, description="The worst provider verdict of a success (malicious ... unknown).")
    cached: bool = Field(default=False, description="Every result came from the lookup cache.")
    excerpt: List[ObservationExcerptLine] = Field(default_factory=list)
    excerpt_truncated: bool = False
    input_sha256: Optional[str] = Field(default=None, description="From the trace store, when it has the call.")
    output_sha256: Optional[str] = None


class NotCheckedItem(_Model):
    what: str
    why: str


class UnavailableItem(_Model):
    what: str
    why: str
    kind: Literal["no_source", "tool_failed"]
    source: Optional[str] = Field(default=None, description="The provider, as data.")
    observation_id: Optional[str] = None


class NotEstablished(_Model):
    """What the investigation does not establish. Nothing here counts for or against the outcome."""

    empty: List[str] = Field(default_factory=list, description="Observation ids: checked, found nothing.")
    not_checked: List[NotCheckedItem] = Field(default_factory=list)
    unavailable: List[UnavailableItem] = Field(
        default_factory=list, description="Could not be checked for this customer (no source connected, or it failed)."
    )


class PlainStep(_Model):
    """One thing the investigation did, in plain words (no engine node names)."""

    ts: datetime
    actor: StepActor
    text: str
    produced: Optional[str] = Field(
        default=None, description="What the step produced: counts and vocabulary values only, never alert text."
    )


class OutcomeTrackRecord(_Model):
    """How often people confirmed this outcome category for this tenant: the counts, and a rate only with enough of them."""

    category: OutcomeCategory
    basis: Literal["analyst_decisions", "blind_audit_labels"] = Field(
        description=(
            "analyst_decisions (needs_*): total is the alerts of the category analysts decided, confirmed those "
            "decided true_positive. blind_audit_labels (ai_closed_*): total is the closes of the category an "
            "analyst labelled blind, confirmed those whose label agrees with the AI."
        )
    )
    window_days: int
    total: int
    confirmed: int
    min_samples: int
    rate: Optional[float] = Field(description="confirmed / total; null when total is below min_samples.")


class ProposedActionGuardrail(_Model):
    verdict: Literal["passed", "blocked"]
    code: Optional[str] = None
    reason: Optional[str] = None


class ProposedAction(_Model):
    action_id: Optional[UUID] = Field(default=None, description="plan: the action on the ledger.")
    action_type: ActionTypeName
    target: str = Field(description="The exact target: data, at most 512 characters.")
    description: Optional[str] = None
    risk: RiskName
    reversible: Optional[bool] = None
    inverse_action: Optional[str] = None
    irreversible_note: Optional[str] = None
    status: Optional[ActionStatusName] = Field(default=None, description="plan: the action's status; null in a preview.")
    guardrail: Optional[ProposedActionGuardrail] = None
    without_preapproval: Optional[Literal["automatic", "awaiting_approval", "blocked"]] = Field(
        default=None, description="preview: what happens to it when nothing is pre-approved."
    )
    can_preapprove: Optional[bool] = Field(default=None, description="preview: your role may pre-approve it.")
    role_lock: Optional[Literal["admin", "disabled"]] = None
    approval_entry: Optional[str] = Field(default=None, description="preview: its approved_actions entry.")


class ProposedResponse(_Model):
    source: Literal["plan", "preview", "none"] = Field(
        description=(
            "plan: the actions the workflow recorded for this alert. preview: what a true_positive decision would "
            "propose now (nothing is written). none: no response is proposed."
        )
    )
    actions: List[ProposedAction] = Field(default_factory=list)


class PendingHarnessField(_Model):
    field: str = Field(description="The path of a field that stays empty until the investigation harness fills it.")
    why: str
    issue: int = Field(description="The GitHub issue of the story that fills it.")


class Investigation(_Model):
    schema_version: int = SCHEMA_VERSION
    alert_id: str
    tenant_id: str
    generated_at: datetime
    hidden_for_blind_audit: bool = Field(
        default=False,
        description="The alert waits for its blind-audit label: the AI's side is withheld and every list is empty.",
    )
    outcome: Optional[InvestigationOutcome] = Field(description="Null while the alert is still being processed.")
    summary: InvestigationSummary
    claims: List[InvestigationClaim]
    observations: List[InvestigationObservation]
    not_established: NotEstablished
    steps: List[PlainStep]
    track_record: Optional[OutcomeTrackRecord]
    response: ProposedResponse
    pending_harness: List[PendingHarnessField]


__all__ = [
    "SCHEMA_VERSION",
    "ClaimCheck",
    "ClosedByKind",
    "Direction",
    "Investigation",
    "InvestigationClaim",
    "InvestigationClosedBy",
    "InvestigationObservation",
    "InvestigationOutcome",
    "InvestigationReason",
    "InvestigationSummary",
    "NotCheckedItem",
    "NotEstablished",
    "ObservationExcerptLine",
    "ObservationMark",
    "ObservationOutcome",
    "OutcomeCategory",
    "OutcomeTrackRecord",
    "PendingHarnessField",
    "PlainStep",
    "ProposedAction",
    "ProposedActionGuardrail",
    "ProposedResponse",
    "StepActor",
    "WrittenBy",
]
