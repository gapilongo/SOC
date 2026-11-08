"""Request and response bodies (the OpenAPI schema is generated from these)."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Dict, Generic, Iterable, List, Literal, Optional, TypeVar, get_args
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema, field_validator

from lg_sotf.api.summary_schema import AlertSummaryJson
from lg_sotf.db.repos.alert_events import EVENT_ACTOR_TYPES
from lg_sotf.db.repos.audit import AUDIT_ACTOR_TYPES
from lg_sotf.db.repos.integrations import INTEGRATION_KINDS, TICKETING_KINDS
from lg_sotf.db.repos.outbox import OUTBOX_OPERATIONS, OUTBOX_STATUSES
from lg_sotf.db.repos.sources import SOURCE_HEALTH
from lg_sotf.db.repos.tenants import TENANT_STATUSES
from lg_sotf.domain.actions import ACTION_CATALOG, TargetKind
from lg_sotf.integrations.events import EVENT_TYPES as INTEGRATION_EVENT_TYPES
from lg_sotf.models.vocabulary import (
    ACTION_STATUSES,
    ALERT_STATUSES,
    AUTONOMY_MODES,
    DECISIONS,
    DISPOSITIONS,
    ESCALATION_LEVELS,
    ESCALATION_STATUSES,
    EXECUTION_OWNERS,
    RISK_LEVELS,
    ROLES,
    SCOPES,
    SEVERITIES,
    SOURCE_TYPES,
    VERIFICATION_STATES,
    Decision,
    Role,
    Scope,
    SourceType,
)

T = TypeVar("T")


# ------------------------------------------------------------- vocabulary
# Response fields drawn from a vocabulary (ADR-0009, tolerant reader). The OpenAPI schema advertises
# the values as an enum, but the field stays ``str`` at runtime: a value that a newer release added
# still serializes during a rolling deploy, and clients must tolerate values they do not know.
# Request models use the vocabulary ``Literal`` itself and validate strictly.


def vocabulary_schema(values: Iterable[str]) -> Dict[str, Any]:
    """The JSON schema of a response field drawn from ``values`` (canonical order kept)."""
    return {"type": "string", "enum": list(values)}


RoleStr = Annotated[str, WithJsonSchema(vocabulary_schema(ROLES))]
ScopeStr = Annotated[str, WithJsonSchema(vocabulary_schema(SCOPES))]
SeverityStr = Annotated[str, WithJsonSchema(vocabulary_schema(SEVERITIES))]
AlertStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(ALERT_STATUSES))]
DispositionStr = Annotated[str, WithJsonSchema(vocabulary_schema(DISPOSITIONS))]
DecisionStr = Annotated[str, WithJsonSchema(vocabulary_schema(DECISIONS))]
EscalationStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(ESCALATION_STATUSES))]
EscalationLevelStr = Annotated[str, WithJsonSchema(vocabulary_schema(ESCALATION_LEVELS))]
ActionStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(ACTION_STATUSES))]
RiskLevelStr = Annotated[str, WithJsonSchema(vocabulary_schema(RISK_LEVELS))]
AutonomyModeStr = Annotated[str, WithJsonSchema(vocabulary_schema(AUTONOMY_MODES))]
VerificationStateStr = Annotated[str, WithJsonSchema(vocabulary_schema(VERIFICATION_STATES))]
ExecutionOwnerStr = Annotated[str, WithJsonSchema(vocabulary_schema(EXECUTION_OWNERS))]
SourceTypeStr = Annotated[str, WithJsonSchema(vocabulary_schema(SOURCE_TYPES))]
# The response action catalog (domain/actions.py): its action types and their target kinds.
ActionTypeStr = Annotated[str, WithJsonSchema(vocabulary_schema(ACTION_CATALOG))]
TargetKindStr = Annotated[str, WithJsonSchema(vocabulary_schema(get_args(TargetKind)))]
# Value sets owned by one repository or adapter (each checked against its database CHECK constraint).
SourceHealthStr = Annotated[str, WithJsonSchema(vocabulary_schema(SOURCE_HEALTH))]
TenantStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(TENANT_STATUSES))]
AuditActorTypeStr = Annotated[str, WithJsonSchema(vocabulary_schema(AUDIT_ACTOR_TYPES))]
EventActorTypeStr = Annotated[str, WithJsonSchema(vocabulary_schema(EVENT_ACTOR_TYPES))]
IntegrationKindStr = Annotated[str, WithJsonSchema(vocabulary_schema(INTEGRATION_KINDS))]
TicketingKindStr = Annotated[str, WithJsonSchema(vocabulary_schema(TICKETING_KINDS))]
IntegrationEventStr = Annotated[str, WithJsonSchema(vocabulary_schema(INTEGRATION_EVENT_TYPES))]
DeliveryStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(OUTBOX_STATUSES))]
DeliveryOperationStr = Annotated[str, WithJsonSchema(vocabulary_schema(OUTBOX_OPERATIONS))]



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
    role: RoleStr
    is_platform_admin: bool
    is_active: bool
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    mfa_enabled: bool = False
    #: Created by OIDC just-in-time provisioning (role follows the identity provider).
    oidc_provisioned: bool = False


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int
    user: UserOut
    mfa_required: Literal[False] = False
    #: Set when this sign-in used a recovery code: how many are left.
    recovery_codes_remaining: Optional[int] = None


class MfaChallengeOut(BaseModel):
    """The password was right; finish with ``POST /auth/mfa/verify`` (or enroll when ``enrollment_required``)."""

    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int
    enrollment_required: bool
    methods: List[Literal["totp", "recovery_code"]]


class MfaVerifyIn(In):
    mfa_token: str = Field(min_length=1, max_length=4_096)
    code: str = Field(min_length=1, max_length=32, description="A 6-digit TOTP code or a recovery code.")


class MfaEnrollIn(In):
    mfa_token: Optional[str] = Field(
        default=None, max_length=4_096, description="The enrollment challenge from login; omit with a session."
    )


class MfaEnrollOut(BaseModel):
    secret: str = Field(description="Base32 TOTP secret for manual entry. Shown once.")
    otpauth_uri: str
    qr: Optional[List[str]] = Field(
        default=None, description="QR code of otpauth_uri as rows of '1' (dark) and '0' (light), no quiet zone."
    )
    expires_in: int


class MfaConfirmIn(In):
    code: str = Field(min_length=1, max_length=32)
    mfa_token: Optional[str] = Field(default=None, max_length=4_096)


class MfaConfirmOut(BaseModel):
    recovery_codes: List[str] = Field(description="Single-use recovery codes. Shown once.")
    #: The new session when enrollment completed a sign-in (``mfa_token`` was given).
    session: Optional[TokenOut] = None


class MfaCodeIn(In):
    code: str = Field(min_length=1, max_length=32)


class MfaDisableIn(In):
    password: str = Field(min_length=1, max_length=1_024)
    code: str = Field(min_length=1, max_length=32)


class RecoveryCodesOut(BaseModel):
    recovery_codes: List[str]


class MfaStatusOut(BaseModel):
    available: bool = Field(description="MFA applies to this account (local password sign-in).")
    enabled: bool
    enabled_at: Optional[datetime] = None
    pending: bool = False
    recovery_codes_remaining: int = 0
    required: bool = Field(description="Policy (tenant or platform-admin rule) requires MFA for this account.")


class MeOut(BaseModel):
    kind: Literal["user", "api_key"]
    tenant_id: str
    #: Display name of ``tenant_id`` (the tenant the request acts on).
    tenant_name: Optional[str] = None
    home_tenant_id: str
    auth_method: str
    role: Optional[RoleStr] = None
    scopes: List[ScopeStr] = Field(default_factory=list)
    user_id: Optional[UUID] = None
    api_key_id: Optional[UUID] = None
    email: Optional[str] = None
    is_platform_admin: bool = False
    expires_at: Optional[datetime] = None
    #: Set while acting in ``tenant_id`` under an MSSP organisation's grant (``role`` is the grant's).
    grant_id: Optional[UUID] = None


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


class EntityRefOut(BaseModel):
    kind: Literal["user", "host", "ip", "email", "domain", "url", "process", "hash"]
    value: str


class EntitiesPreviewOut(BaseModel):
    """The first value of up to 3 entity kinds (users, hosts, IPs, e-mails, domains, URLs, processes,
    hashes, in that order) and how many values each kind present has."""

    items: List[EntityRefOut]
    counts: Dict[str, int]


class FindingOut(BaseModel):
    """One evidence lookup of the analysis agent: a provider's result for one indicator."""

    origin: Literal["threat_intel", "history"]
    kind: str
    target: str
    source: str = Field(description="The provider (e.g. abuseipdb, virustotal, history).")
    status: str
    verdict: str
    checked_at: Optional[datetime] = Field(
        default=None, description="When the platform received the result; null for older analyses."
    )
    cached: bool = False
    data: Dict[str, Any] = Field(default_factory=dict)


class AlertCountsOut(BaseModel):
    """Alert counts for the list views: every status but ``closed`` all-time, ``closed`` in the window."""

    by_status: Dict[str, int]
    closed_from: datetime
    closed_to: Optional[datetime] = Field(default=None, description="End of the closed window; null: open-ended.")
    generated_at: datetime


class AlertOut(Out):
    id: str
    tenant_id: str
    source_id: str
    source_alert_id: str
    fingerprint: str
    title: str
    severity: SeverityStr
    category: Optional[str] = None
    status: AlertStatusStr
    disposition: Optional[DispositionStr] = None
    confidence: Optional[float] = None
    threat_score: Optional[float] = None
    priority: Optional[int] = None
    assigned_to: Optional[UUID] = None
    occurred_at: datetime
    ingested_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    summary: AlertSummaryJson = Field(default_factory=dict)
    case_key: Optional[str] = None
    source_name: Optional[str] = Field(default=None, description="The source's name; null once it is deleted.")
    entities_preview: Optional[EntitiesPreviewOut] = None
    hidden_for_blind_audit: bool = Field(
        default=False,
        description="True while the alert waits for its blind-audit label: disposition, confidence, scores, "
        "priority, summary and findings are withheld (null or the marker) for everyone in the tenant.",
    )


class AlertDetailOut(AlertOut):
    raw: Dict[str, Any] = Field(default_factory=dict)
    normalized: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingOut] = Field(default_factory=list)


class AlertEventOut(Out):
    id: int
    alert_id: str
    ts: datetime
    node: Optional[str] = None
    event_type: str
    actor_type: EventActorTypeStr
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
    status: AlertStatusStr
    entry_id: str


# ------------------------------------------------------------ escalations


class ReviewBandOut(BaseModel):
    min: int
    max: int


class RoutingOut(BaseModel):
    """The routing outcome that created the escalation (null on escalations created before it was recorded)."""

    code: str = Field(description="grey_zone, false_positive_review, inconclusive, high_risk, model_refused, ...")
    confidence: Optional[float] = None
    band: Optional[ReviewBandOut] = Field(
        default=None, description="The confidence band that sent the alert to an analyst (grey_zone only)."
    )


class EscalationOut(Out):
    id: str
    tenant_id: str
    alert_id: str
    level: EscalationLevelStr
    status: EscalationStatusStr
    reason: str
    priority: int
    summary: Dict[str, Any] = Field(default_factory=dict)
    related_alert_ids: List[str] = Field(default_factory=list)
    assigned_to: Optional[UUID] = None
    sla_deadline: Optional[datetime] = None
    decision: Optional[DecisionStr] = None
    decision_notes: Optional[str] = None
    approved_actions: List[str] = Field(default_factory=list)
    decided_by: Optional[UUID] = None
    decided_at: Optional[datetime] = None
    claimed_at: Optional[datetime] = None
    version: int
    created_at: datetime
    updated_at: datetime
    assigned_to_email: Optional[str] = None
    decided_by_email: Optional[str] = None
    alert_severity: Optional[SeverityStr] = None
    rule: Optional[str] = Field(default=None, description="The alert's detection rule name, else its title.")
    source_id: Optional[str] = None
    source_name: Optional[str] = None
    entities_preview: Optional[EntitiesPreviewOut] = None
    ai_reason: Optional[str] = Field(default=None, description="First sentence of the analysis conclusion.")
    ai_reason_source: Optional[Literal["model", "rules"]] = Field(
        default=None, description="Who wrote the conclusion; null for older escalations."
    )
    routing: Optional[RoutingOut] = None


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


class RollbackEligibilityOut(BaseModel):
    """Whether the action can be rolled back now, with the inverse type and its risk; ``reason`` when not."""

    available: bool = False
    action_type: Optional[ActionTypeStr] = None
    risk: Optional[RiskLevelStr] = None
    until: Optional[datetime] = None
    reason: Optional[str] = None


class GuardrailOut(BaseModel):
    """Guardrail verdict: checked now for an action awaiting approval, as recorded for a blocked one."""

    verdict: Literal["passed", "blocked"]
    evaluated: Literal["now", "recorded"]
    code: Optional[str] = None
    reason: Optional[str] = None
    approval_reason: Optional[str] = Field(default=None, description="Why a human must approve (planner code).")


class BlastRadiusOut(BaseModel):
    """What the action changes; the hourly limits are given for actions awaiting approval only."""

    target_kind: Optional[TargetKindStr] = None
    scope_hosts: List[str] = Field(default_factory=list)
    hourly_limit: Optional[int] = Field(default=None, description="Per-type executions allowed per hour.")
    executed_last_hour: Optional[int] = None
    tenant_hourly_cap: Optional[int] = None
    tenant_executed_last_hour: Optional[int] = None


class ActionOut(Out):
    id: UUID
    tenant_id: str
    alert_id: str
    action_type: ActionTypeStr
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevelStr
    status: ActionStatusStr
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
    execution_owner: ExecutionOwnerStr = "workflow"
    integration_id: Optional[UUID] = None
    external_ref: Optional[Dict[str, Any]] = None
    attempts: int = 0
    verification: Optional[VerificationStateStr] = None
    verification_detail: Optional[Dict[str, Any]] = None
    verify_deadline: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    rollback: RollbackEligibilityOut = Field(default_factory=RollbackEligibilityOut)
    rolled_back_by: Optional[UUID] = Field(default=None, description="The live rollback of this action, if any.")
    guardrail: Optional[GuardrailOut] = None
    blast_radius: Optional[BlastRadiusOut] = None
    reversible: Optional[bool] = Field(default=None, description="The action type has an inverse (rollback).")
    irreversible_note: Optional[str] = None


class ApprovalIn(In):
    reject_remaining: bool = False


class RollbackIn(In):
    reason: str = Field(min_length=1, max_length=500)
    approve: bool = Field(
        default=True, description="Approve the rollback yourself when your role may approve its risk."
    )


class RollbackOut(BaseModel):
    rollback: ActionOut
    original: ActionOut
    created: bool


class RetryIn(In):
    reason: str = Field(min_length=1, max_length=500)


class VerifyIn(In):
    pass


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
    type: SourceTypeStr
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
    health: SourceHealthStr
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
    disposition: DispositionStr
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
    scopes: List[ScopeStr]
    created_by: Optional[UUID] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyCreatedOut(ApiKeyOut):
    key: str = Field(description="The API key. Shown only in this response; store it now.")


# ----------------------------------------------------------------- tenant


class RetentionLimitsOut(BaseModel):
    """Install-level bounds and defaults for the tenant ``retention`` settings (days)."""

    min_days: int
    max_days: int
    alerts_days: int
    indicators_days: int


class TenantSettingsOut(BaseModel):
    tenant_id: str
    name: str
    status: TenantStatusStr
    settings: Dict[str, Any]
    updated_at: datetime
    retention_limits: Optional[RetentionLimitsOut] = None


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
    # Value tiles (definitions: lg_sotf.services.reporting, docs/reporting.md).
    handled_without_human: int = 0
    needed_human: int = 0
    handled_without_human_rate: Optional[float] = None
    analyst_hours_saved: float = 0.0
    minutes_per_alert: int = 15
    # Escalation queue (active escalations, as of generated_at).
    open_escalations_by_severity: Dict[str, int] = Field(default_factory=dict)
    overdue_escalations: int = 0
    unassigned_escalations: int = 0
    unassigned_breaching: int = 0
    next_sla_deadline: Optional[datetime] = None
    # Approval queue: all pending actions, and those the caller may approve.
    pending_approvals_total: int = 0
    pending_approvals_by_risk: Dict[str, int] = Field(default_factory=dict)
    pending_approvals: int = 0
    my_claimed: int = 0
    llm_model: Optional[str] = None


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
