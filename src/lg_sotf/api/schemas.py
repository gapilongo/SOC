"""Request and response bodies (the OpenAPI schema is generated from these)."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")

Role = Literal["viewer", "analyst", "admin"]
Scope = Literal["ingest", "read", "write"]
Decision = Literal["true_positive", "false_positive", "benign_positive", "needs_more_info"]
SourceType = Literal["splunk", "qradar", "sentinel", "wazuh", "crowdstrike", "guardduty", "webhook", "file"]


class Out(BaseModel):
    """Response model built from repository records; unknown (and secret) fields are dropped."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PageOut(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None


# ------------------------------------------------------------------- auth


class LoginIn(In):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    tenant: Optional[str] = Field(default=None, max_length=63)


class UserOut(Out):
    id: UUID
    tenant_id: str
    email: str
    role: str
    is_platform_admin: bool
    is_active: bool
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int
    user: UserOut


class MeOut(BaseModel):
    kind: Literal["user", "api_key"]
    tenant_id: str
    home_tenant_id: str
    auth_method: str
    role: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    user_id: Optional[UUID] = None
    api_key_id: Optional[UUID] = None
    email: Optional[str] = None
    is_platform_admin: bool = False
    expires_at: Optional[datetime] = None


# ----------------------------------------------------------------- ingest


class IngestItemOut(BaseModel):
    index: int
    status: Literal["inserted", "duplicate", "rejected"]
    alert_id: Optional[str] = None
    reason: Optional[str] = None


class IngestOut(BaseModel):
    source_id: str
    received: int
    inserted: int
    duplicates: int
    rejected: int
    enqueued: int
    items: List[IngestItemOut]


# ----------------------------------------------------------------- alerts


class AlertOut(Out):
    id: str
    tenant_id: str
    source_id: str
    source_alert_id: str
    fingerprint: str
    title: str
    severity: str
    category: Optional[str] = None
    status: str
    disposition: Optional[str] = None
    confidence: Optional[float] = None
    threat_score: Optional[float] = None
    priority: Optional[int] = None
    assigned_to: Optional[UUID] = None
    occurred_at: datetime
    ingested_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    case_key: Optional[str] = None


class AlertDetailOut(AlertOut):
    raw: Dict[str, Any] = Field(default_factory=dict)
    normalized: Dict[str, Any] = Field(default_factory=dict)


class AlertEventOut(Out):
    id: int
    alert_id: str
    ts: datetime
    node: Optional[str] = None
    event_type: str
    actor_type: str
    actor_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class NoteIn(In):
    text: str = Field(min_length=1, max_length=4_000)

    @field_validator("text")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("text must not be blank")
        return value


class ReprocessOut(BaseModel):
    alert_id: str
    status: str
    entry_id: str


# ------------------------------------------------------------ escalations


class EscalationOut(Out):
    id: str
    tenant_id: str
    alert_id: str
    level: str
    status: str
    reason: str
    priority: int
    summary: Dict[str, Any] = Field(default_factory=dict)
    related_alert_ids: List[str] = Field(default_factory=list)
    assigned_to: Optional[UUID] = None
    sla_deadline: Optional[datetime] = None
    decision: Optional[str] = None
    decision_notes: Optional[str] = None
    approved_actions: List[str] = Field(default_factory=list)
    decided_by: Optional[UUID] = None
    decided_at: Optional[datetime] = None
    claimed_at: Optional[datetime] = None
    version: int
    created_at: datetime
    updated_at: datetime


class ClaimIn(In):
    version: int = Field(ge=0)


class FeedbackIn(In):
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    triage_correct: Optional[bool] = None
    correlation_helpful: Optional[bool] = None
    analysis_accurate: Optional[bool] = None


class DecisionIn(In):
    decision: Decision
    version: int = Field(ge=0)
    notes: Optional[str] = Field(default=None, max_length=4_000)
    approved_actions: List[str] = Field(default_factory=list, max_length=50)
    feedback: Optional[FeedbackIn] = None
    suggest_suppression: Optional[bool] = None


class DecisionOut(BaseModel):
    escalation: EscalationOut
    approved_actions: List[str]
    resumed_alert_ids: List[str]
    own_review_alert_ids: List[str]
    feedback_id: Optional[str] = None
    suppression_suggestion_id: Optional[str] = None
    resumes_enqueued: int
    resumes_failed: int


# ---------------------------------------------------------------- actions


class ActionOut(Out):
    id: UUID
    tenant_id: str
    alert_id: str
    action_type: str
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    status: str
    blocked_reason: Optional[str] = None
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    connector: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    rollback_of: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


class ApprovalIn(In):
    reject_remaining: bool = False


class ApprovalOut(BaseModel):
    action: ActionOut
    resumed_alert_ids: List[str]
    resumes_enqueued: int
    resumes_failed: int


# ---------------------------------------------------------------- sources

SOURCE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class SourceCreateIn(In):
    id: Optional[str] = Field(default=None, pattern=SOURCE_ID_PATTERN)
    type: SourceType
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: Optional[Dict[str, Any]] = Field(
        default=None, description="Credentials; write-only (encrypted at rest, never returned)."
    )
    poll_interval_s: int = Field(default=60, ge=10, le=86_400)


class SourceUpdateIn(In):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    secret: Optional[Dict[str, Any]] = Field(
        default=None, description="Replaces the credentials; null removes them. Write-only."
    )
    poll_interval_s: Optional[int] = Field(default=None, ge=10, le=86_400)


class SourceOut(Out):
    id: str
    tenant_id: str
    type: str
    name: str
    enabled: bool
    config: Dict[str, Any] = Field(default_factory=dict)
    has_secret: bool = False
    poll_interval_s: int
    cursor_watermark: Optional[datetime] = None
    last_polled_at: Optional[datetime] = None
    next_poll_at: Optional[datetime] = None
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    health: str
    created_at: datetime
    updated_at: datetime


class SourceTestOut(BaseModel):
    ok: bool
    detail: str


# ----------------------------------------------------------- suppressions


class SuppressionCreateIn(In):
    name: str = Field(min_length=1, max_length=200)
    match: Dict[str, Any]
    expires_at: Optional[datetime] = None
    enabled: bool = True


class SuppressionUpdateIn(In):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    match: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    enabled: Optional[bool] = None


class SuppressionOut(Out):
    id: str
    tenant_id: str
    name: str
    match: Dict[str, Any]
    disposition: str
    created_by: Optional[UUID] = None
    source_feedback_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    hit_count: int
    last_hit_at: Optional[datetime] = None
    enabled: bool
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------------------ users


class UserCreateIn(In):
    email: str = Field(min_length=3, max_length=320)
    role: Role
    password: Optional[str] = Field(
        default=None, max_length=1_024, description="Omit for SSO-only accounts. Write-only."
    )
    is_active: bool = True
    is_platform_admin: bool = False


class UserUpdateIn(In):
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, max_length=1_024, description="Write-only.")
    is_platform_admin: Optional[bool] = None


# --------------------------------------------------------------- api keys


class ApiKeyCreateIn(In):
    name: str = Field(min_length=1, max_length=200)
    scopes: List[Scope] = Field(min_length=1, max_length=3)


class ApiKeyOut(Out):
    id: UUID
    tenant_id: str
    name: str
    prefix: str
    scopes: List[str]
    created_by: Optional[UUID] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyCreatedOut(ApiKeyOut):
    key: str = Field(description="The API key. Shown only in this response; store it now.")


# ----------------------------------------------------------------- tenant


class TenantSettingsOut(BaseModel):
    tenant_id: str
    name: str
    status: str
    settings: Dict[str, Any]
    updated_at: datetime


# -------------------------------------------------------------- dashboard


class DashboardOut(BaseModel):
    window_hours: int
    since: datetime
    generated_at: datetime
    alerts_total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_disposition: Dict[str, int]
    mtta_s: Optional[float] = None
    mttr_s: Optional[float] = None
    acknowledged: int
    resolved: int
    open_escalations: int
    runs_by_status: Dict[str, int]
    queue_depth: int
    llm_cost_usd: float
    llm_tokens: int


class UsageDayOut(Out):
    day: date
    model: str
    agent: str
    calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: Decimal
    refusals: int
    errors: int


class UsageOut(BaseModel):
    start: date
    end: date
    days: List[UsageDayOut]
    total_calls: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: Decimal


class VerdictCacheClearedOut(BaseModel):
    removed: int


class LLMTierCheckOut(BaseModel):
    tier: Literal["fast", "deep"]
    model: str
    ok: bool
    latency_ms: int
    structured_output: Optional[str] = None
    error_code: Optional[str] = None
    error: Optional[str] = None


class LLMTestOut(BaseModel):
    provider: str
    enabled: bool
    ok: bool
    tiers: List[LLMTierCheckOut]
