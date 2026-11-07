"""Request and response bodies of the escalation triage endpoints (grouping, bulk actions, response preview)."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from lg_sotf.api.schemas import AutonomyModeStr, EscalationOut, In, RiskLevelStr, SuppressionOut
from lg_sotf.services.triage import MAX_BULK

# ----------------------------------------------------------------- grouping


class EscalationGroupOut(BaseModel):
    """Active escalations whose alerts share a detection rule (and source)."""

    source_id: str
    source_name: Optional[str] = None
    rule: str = Field(description="The detection rule name, else the alert title; filter with GET /escalations?rule=.")
    size: int
    unassigned: int
    overdue: int
    earliest_sla_deadline: Optional[datetime] = None
    min_confidence: Optional[float] = None
    max_confidence: Optional[float] = None
    by_severity: Dict[str, int]
    escalation_ids: List[str] = Field(description="Up to 10 of the group's escalations, soonest deadline first.")


class EscalationGroupsOut(BaseModel):
    items: List[EscalationGroupOut]
    truncated: bool = Field(description="More groups matched than ``limit``.")
    generated_at: datetime


# --------------------------------------------------------------------- bulk


def _unique(values: List[str]) -> List[str]:
    if len(set(values)) != len(values):
        raise ValueError("each escalation may appear only once")
    return values


class BulkItemIn(In):
    escalation_id: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=0, description="The version you read; a stale one fails this item with 409.")


class BulkClaimIn(In):
    items: List[BulkItemIn] = Field(min_length=1, max_length=MAX_BULK)

    @field_validator("items")
    @classmethod
    def _distinct(cls, items: List[BulkItemIn]) -> List[BulkItemIn]:
        _unique([i.escalation_id for i in items])
        return items


class BulkCloseIn(BulkClaimIn):
    decision: Literal["false_positive", "benign_positive"] = "false_positive"
    notes: str = Field(min_length=1, max_length=4_000, description="Recorded on every escalation.")
    propose_suppression: bool = Field(
        default=False,
        description="Also propose one disabled suppression rule from the escalations that closed "
        "(instead of one suggestion per escalation).",
    )

    @field_validator("notes")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("notes must not be blank")
        return value


class BulkProposeSuppressionIn(In):
    escalation_ids: List[str] = Field(min_length=1, max_length=MAX_BULK)
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)

    @field_validator("escalation_ids")
    @classmethod
    def _distinct(cls, values: List[str]) -> List[str]:
        for value in values:
            if not 1 <= len(value) <= 128:
                raise ValueError("escalation ids are 1-128 characters")
        return _unique(values)


class BulkErrorOut(BaseModel):
    """What the single-item endpoint would have answered for this item."""

    status: int
    code: str
    message: str


class BulkItemOut(BaseModel):
    escalation_id: str
    ok: bool
    escalation: Optional[EscalationOut] = None
    error: Optional[BulkErrorOut] = None
    resumes_enqueued: int = 0
    resumes_failed: int = 0


class BulkOut(BaseModel):
    """Per-item results, in request order. Items that succeeded are committed whatever the others did."""

    results: List[BulkItemOut]
    succeeded: int
    failed: int
    suppression: Optional[SuppressionOut] = None
    suppression_created: Optional[bool] = None


class SuppressionProposalOut(BaseModel):
    suppression: SuppressionOut
    created: bool
    escalation_ids: List[str]


# ------------------------------------------------------------------ preview


class PreviewGuardrailOut(BaseModel):
    verdict: Literal["passed", "blocked"]
    code: Optional[str] = None
    reason: Optional[str] = None


class PreviewConnectorOut(BaseModel):
    name: str = Field(description="microsoft, ticketing, webhook or dry_run.")
    source: str = Field(description="Why this connector: kill_switch, tenant_dry_run, sample, explicit, ticketing, ...")
    live: Optional[bool] = Field(default=None, description="Microsoft: the capability changes the tenant for real.")
    ready: bool = Field(description="False when the route has a configuration problem (the action would fail).")


class PreviewActionOut(BaseModel):
    action_type: str
    target: str
    description: str
    risk: RiskLevelStr
    reversible: bool
    inverse_action: Optional[str] = None
    irreversible_note: Optional[str] = None
    connector: PreviewConnectorOut
    guardrail: PreviewGuardrailOut
    autonomy: AutonomyModeStr = Field(description="The tenant's autonomy mode for this risk.")
    without_preapproval: Literal["automatic", "awaiting_approval", "blocked"]
    can_preapprove: bool = Field(description="Your role may pre-approve it with a true_positive decision.")
    role_lock: Optional[Literal["admin", "disabled"]] = Field(
        default=None, description="admin: high and critical risk need an admin; disabled: nobody may approve it."
    )
    approval_entry: str = Field(description="The approved_actions entry naming exactly this action.")


class ResponsePreviewOut(BaseModel):
    escalation_id: str
    alert_id: str
    generated_at: datetime
    threat_type: str
    evidence: str = Field(description="Always analyst: the preview assumes a true_positive decision.")
    dry_run_forced: bool
    actions: List[PreviewActionOut]
