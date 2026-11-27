"""The case read model: what the case page shows about one case (PRD-2.9).

A case is today's escalation with its alerts: the alert it was opened for
and the alerts attached to it since (grouped with it, linked to it by the
safety net, or reopened into it). One typed shape says, for every alert,
its state and who or what closed it and why.

The two kinds of text of the investigation read model are kept apart here
too: a *sentence* is fixed text (:mod:`lg_sotf.domain.case.words`, and the
investigation's tables for decide codes and close reasons); what an alert,
an analyst or a provider wrote (titles, entity values, rule names, decision
notes, action targets) is *data*, cut to a stated length, and is never
formatted into a sentence.

What the stored data cannot say yet is listed in ``not_available`` with the
reason, and its fields are null. Nothing is estimated in its place.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema

from lg_sotf.domain.closure import AUTONOMY_TIERS
from lg_sotf.domain.investigation.model import (
    ClosedByKind,
    InvestigationReason,
    OutcomeCategory,
    ProposedAction,
    StepActor,
)
from lg_sotf.models.vocabulary import (
    ALERT_STATUSES,
    AUDIT_LABELS,
    DECISIONS,
    DISPOSITIONS,
    ESCALATION_STATUSES,
    SEVERITIES,
)

SCHEMA_VERSION = 1

AlertRole = Literal["primary", "attached", "linked", "reopened", "withheld"]
AlertState = Literal["open", "processing", "closed"]
AuditState = Literal["not_sampled", "pending", "labelled"]
ReopenMode = Literal["folded", "requeued"]
ConfirmedBy = Literal["person", "workflow"]


def _enum(values: Any) -> Dict[str, Any]:
    """Advertised as an enum, kept ``str`` at runtime (ADR-0009: a value a newer release added still serializes)."""
    return {"type": "string", "enum": list(values)}


SeverityName = Annotated[str, WithJsonSchema(_enum(SEVERITIES))]
AlertStatusName = Annotated[str, WithJsonSchema(_enum(ALERT_STATUSES))]
DispositionName = Annotated[str, WithJsonSchema(_enum(DISPOSITIONS))]
CaseStatusName = Annotated[str, WithJsonSchema(_enum(ESCALATION_STATUSES))]
DecisionName = Annotated[str, WithJsonSchema(_enum(DECISIONS))]
AutonomyTierName = Annotated[str, WithJsonSchema(_enum(AUTONOMY_TIERS))]
AuditLabelName = Annotated[str, WithJsonSchema(_enum(AUDIT_LABELS))]


class _Model(BaseModel):
    # A response always carries every field, so the schema marks fields with a default as required too.
    model_config = ConfigDict(frozen=True, json_schema_serialization_defaults_required=True)


class CasePerson(_Model):
    """A user of the tenant. ``email`` is null for an account that no longer exists."""

    user_id: str
    email: Optional[str] = None


class CaseOwner(_Model):
    user_id: str
    email: Optional[str] = None
    since: Optional[datetime] = Field(default=None, description="When the owner claimed the case.")


class CaseDecision(_Model):
    """The decision an analyst recorded on the case."""

    decision: DecisionName
    notes: Optional[str] = Field(default=None, description="What the analyst wrote: data, at most 4000 characters.")
    decided_by: Optional[CasePerson] = Field(
        default=None, description="Null when an MSSP analyst decided under a grant (the audit log names them)."
    )
    decided_at: Optional[datetime] = None


class CaseClosedBy(_Model):
    """Who or what closed an alert, and why."""

    kind: ClosedByKind
    reason: InvestigationReason = Field(description="The close reason: its code and the same in plain words.")
    at: Optional[datetime] = None
    decision: Optional[str] = Field(default=None, description="analyst or cached_verdict: the analyst's decision.")
    analyst: Optional[CasePerson] = Field(default=None, description="analyst: who decided.")
    notes: Optional[str] = Field(
        default=None,
        description="analyst: what they wrote, when the decision was recorded on this case (data). Null otherwise.",
    )
    decided_in_case_id: Optional[str] = Field(
        default=None, description="analyst: the case the decision was recorded on (this one, or another)."
    )
    policy: Optional[InvestigationReason] = Field(
        default=None, description="ai: the rule of the decision policy that closed it (the decide code and its sentence)."
    )
    tier: Optional[AutonomyTierName] = Field(
        default=None,
        description="ai: the tenant's model-led closure tier as the decide step recorded it. Null when it did not.",
    )
    rule_id: Optional[str] = Field(default=None, description="suppression_rule: the rule.")
    rule_name: Optional[str] = Field(default=None, description="suppression_rule: its name, as data.")
    source_alert_id: Optional[str] = Field(default=None, description="cached_verdict: the alert the analyst decided.")


class CaseBlindAudit(_Model):
    """The blind audit of an alert the AI closed."""

    state: AuditState = Field(
        description=(
            "not_sampled: no blind audit drew this alert. pending: it waits for its label, so the AI's side is "
            "withheld. labelled: an analyst labelled it without seeing the AI's verdict."
        )
    )
    label: Optional[AuditLabelName] = None
    agrees: Optional[bool] = Field(
        default=None, description="labelled: whether the label agrees with the AI. Null for unsure."
    )
    labelled_at: Optional[datetime] = None


class CaseLink(_Model):
    """The safety net linked this alert to the case: it stays closed."""

    reason: InvestigationReason
    threat_alert_id: Optional[str] = Field(default=None, description="The alert a model judged a threat.")
    at: Optional[datetime] = None


class CaseReopened(_Model):
    """This alert, which the AI had closed on the model's word, was reopened: by the safety net, or by a person."""

    reason: InvestigationReason = Field(
        description=(
            "related_threat: the safety net reopened it. analyst_reopen: a person reopened it. analyst_flag: a "
            "person flagged the AI's close as wrong, which reopened it."
        )
    )
    note: Optional[str] = Field(
        default=None,
        description="analyst_reopen, analyst_flag: the reason the person gave. Data, at most 1000 characters.",
    )
    threat_alert_id: Optional[str] = Field(default=None, description="The alert whose threat was confirmed.")
    mode: Optional[ReopenMode] = Field(
        default=None,
        description="folded: it joined the open case and that case's decision settles it. requeued: a new run reviews it.",
    )
    confirmed_by: Optional[ConfirmedBy] = Field(
        default=None,
        description=(
            "person: a person's confirmation was recorded directly (a true positive, an approved response action "
            "or a blind-audit label). workflow: the run reopened it, after an analyst's true positive it resumed "
            "from or a response action it carried out. Null when the timeline no longer has the event."
        ),
    )
    by: Optional[CasePerson] = Field(default=None, description="person: who confirmed, reopened or flagged.")
    at: Optional[datetime] = None


class CaseFlagged(_Model):
    """A person flagged the AI's close of this alert as wrong."""

    by: Optional[CasePerson] = None
    at: Optional[datetime] = None
    note: Optional[str] = Field(
        default=None,
        description="The reason the person gave. Data, at most 1000 characters. Null when the timeline no longer has it.",
    )


class CaseEntityRef(_Model):
    kind: str = Field(description="host, user, ip, domain, url, hash, process, command_line or email.")
    value: str = Field(description="Data, at most 128 characters.")


class CaseAlert(_Model):
    id: str
    title: str = Field(description="As the source sent it: data, at most 300 characters.")
    severity: SeverityName
    status: AlertStatusName
    state: AlertState = Field(
        description="open: with a person. processing: the workflow has not decided yet. closed: closed."
    )
    role: AlertRole = Field(
        description=(
            "primary: the alert the case was opened for. attached: grouped with it, so the decision on the case "
            "applies to it. linked: closed by the AI and linked by the safety net; it stays closed. reopened: "
            "closed by the AI and reopened, by the safety net or by a person. withheld: the alert waits for its blind-audit "
            "label, so how it joined is withheld with the AI's side."
        )
    )
    occurred_at: datetime
    closed_at: Optional[datetime] = None
    disposition: Optional[DispositionName] = None
    entities: List[CaseEntityRef] = Field(default_factory=list, description="The first value of each entity kind.")
    hidden_for_blind_audit: bool = Field(
        default=False, description="The alert waits for its blind-audit label: nothing of the AI's side is given."
    )
    category: Optional[OutcomeCategory] = Field(
        default=None, description="The alert's outcome category, as on the investigation view."
    )
    why: Optional[InvestigationReason] = Field(
        default=None, description="Why the alert is with a person. Null when it is closed (see closed_by) or processed."
    )
    closed_by: Optional[CaseClosedBy] = Field(default=None, description="Null while the alert is open.")
    blind_audit: CaseBlindAudit
    link: Optional[CaseLink] = Field(default=None, description="role linked: why it was linked, and when.")
    reopened: Optional[CaseReopened] = Field(default=None, description="role reopened: what reopened it.")
    flagged: Optional[CaseFlagged] = Field(default=None, description="A person flagged the AI's close as wrong.")
    can_reopen: bool = Field(
        default=False,
        description=(
            "The AI closed it on the model's word and the close stands: an analyst may reopen it or flag the close "
            "(POST /alerts/{id}/reopen, POST /alerts/{id}/flag)."
        ),
    )


class CaseAction(ProposedAction):
    """A response action on the ledger for one of the case's alerts."""

    alert_id: str
    created_at: datetime


class CaseTimelineEntry(_Model):
    """One thing that happened in the case, in plain words."""

    ts: datetime
    kind: str = Field(description="What the entry is about, for filters and tests (case.opened, alert.closed, ...).")
    actor: StepActor
    text: str = Field(description="Fixed text.")
    produced: Optional[str] = Field(default=None, description="Counts and vocabulary values only, never alert text.")
    alert_id: Optional[str] = Field(default=None, description="The alert it happened to; null for the case itself.")
    by: Optional[CasePerson] = Field(default=None, description="The person, when a person acted.")


class CaseEntity(_Model):
    """A value the case's alerts name."""

    kind: str
    value: str = Field(description="Data, at most 128 characters.")
    alerts: int = Field(description="How many of the case's alerts name it.")


class CaseClosedByCounts(_Model):
    """The case's closed alerts by who or what closed them."""

    ai_evidence: int = 0
    ai_audit: int = 0
    suppression_rule: int = 0
    cached_verdict: int = 0
    analyst: int = 0


class CaseCounts(_Model):
    alerts: int = Field(description="Every alert of the case, also those a truncated list leaves out.")
    open: int = 0
    processing: int = 0
    closed: int = 0
    linked: int = 0
    reopened: int = 0
    flagged: int = Field(default=0, description="Alerts whose AI close a person flagged as wrong.")
    withheld: int = Field(default=0, description="Alerts that wait for their blind-audit label.")
    closed_by: CaseClosedByCounts = CaseClosedByCounts()
    actions_awaiting_approval: int = 0


class NotAvailable(_Model):
    """Something the case page shows in the design that the stored data cannot say yet."""

    field: str = Field(description="The path of the field that is null or absent.")
    reason: str
    issue: Optional[int] = Field(default=None, description="The GitHub issue of the story that fills it, when there is one.")


class Case(_Model):
    schema_version: int = SCHEMA_VERSION
    id: str = Field(description="The case key: the id of the escalation.")
    tenant_id: str
    generated_at: datetime
    alert_id: str = Field(description="The alert the case was opened for.")
    title: str = Field(description="That alert's title: data, at most 300 characters.")
    status: CaseStatusName
    active: bool = Field(description="The case still waits for its decision (open, claimed or expired).")
    severity: SeverityName = Field(description="The highest severity among the case's alerts.")
    category: Optional[OutcomeCategory] = Field(
        description="needs_decision (likely malicious) or needs_review (not proven either way), from the primary alert."
    )
    reason: Optional[InvestigationReason] = Field(description="Why the case is with a person.")
    opened_at: datetime
    sla_deadline: Optional[datetime] = None
    owner: Optional[CaseOwner] = None
    version: int = Field(description="The version a claim or a decision is recorded against.")
    decision: Optional[CaseDecision] = None
    counts: CaseCounts
    alerts: List[CaseAlert] = Field(description="Oldest first.")
    alerts_truncated: bool = Field(default=False, description="The case has more alerts than one response lists.")
    entities: List[CaseEntity] = Field(description="What the case touches: most shared first.")
    actions: List[CaseAction] = Field(description="The response actions of the case's alerts, oldest first.")
    timeline: List[CaseTimelineEntry] = Field(description="Oldest first.")
    timeline_truncated: bool = Field(default=False, description="Older entries were left out.")
    not_available: List[NotAvailable]


__all__ = [
    "SCHEMA_VERSION",
    "AlertRole",
    "AlertState",
    "AuditState",
    "Case",
    "CaseAction",
    "CaseAlert",
    "CaseBlindAudit",
    "CaseClosedBy",
    "CaseClosedByCounts",
    "CaseCounts",
    "CaseDecision",
    "CaseEntity",
    "CaseEntityRef",
    "CaseFlagged",
    "CaseLink",
    "CaseOwner",
    "CasePerson",
    "CaseReopened",
    "CaseTimelineEntry",
    "ConfirmedBy",
    "NotAvailable",
    "ReopenMode",
]
