# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/platform`` (platform admins only): operations across tenants, the MSSP console.

* ``POST /platform/tenants`` provisions a tenant, optionally with its first
  admin user and with settings seeded from a ``profile`` or copied from
  another tenant (``copy_settings_from``; policy only, never secrets or the
  source customer's destinations and assets, see
  :mod:`lg_sotf.services.tenancy`). The runtime database role cannot insert
  tenants itself; the row is created through the ``lgsotf_create_tenant``
  SECURITY DEFINER function (migration 0002). The creation is audited in the
  new tenant and in the platform admin's home tenant.
* ``GET /platform/tenants``: every tenant with its status, quotas and
  activity figures (``lgsotf_platform_tenant_stats``, migration 0004).
* ``PATCH /platform/tenants/{id}``: name, status (``active``/``suspended``)
  and quotas. Suspension refuses the tenant's users, SSO identities and API
  keys (``403 tenant_suspended``, ingest included), stops its pull sources
  and leaves its queued work queued and its escalations' SLA clocks frozen
  (the SLA sweep skips it); reactivation hands the queued runs back to the
  workers and restarts the open escalations' SLA clocks. Other API processes see a status change within their
  tenant cache TTL (15 s).
* ``GET /platform/escalations``: open and claimed escalations of every
  tenant, soonest SLA deadline first.
* ``GET /platform/usage``: invoicing figures per tenant for a month (JSON or
  CSV).

Every cross-tenant read is audited in the platform admin's home tenant;
changes to a tenant are audited in that tenant and in the home tenant.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from lg_sotf.api.auth.deps import PLATFORM_ADMIN, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.routers.identity import check_password
from lg_sotf.api.schemas import In, Out, PageOut, UserOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.repos import Tenant, TenantStats
from lg_sotf.db.repos._base import Connection
from lg_sotf.db.repos.escalations import ESCALATION_LEVELS
from lg_sotf.db.repos.users import normalize_email
from lg_sotf.db.tenancy import TENANT_ID_PATTERN
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.hashing import ahash_password
from lg_sotf.services.escalation import resolve_review_policy
from lg_sotf.services.tenancy import Profile, copyable_settings, profile_settings, quotas_of

log = get_logger(__name__)

router = APIRouter(prefix="/platform", tags=["platform"])

MAX_ALERTS_PER_DAY = 1_000_000_000
MAX_COUNT_QUOTA = 1_000_000
REQUEUE_LIMIT = 10_000
REQUEUE_CHUNK = 500
_MONTH = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
_CSV_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


class TenantCreateIn(In):
    id: str = Field(pattern=TENANT_ID_PATTERN, description="2-63 characters: a-z, 0-9, '-', '_'.")
    name: str = Field(min_length=1, max_length=200)
    admin_email: Optional[str] = Field(default=None, min_length=3, max_length=320)
    admin_password: Optional[str] = Field(
        default=None, max_length=1_024, description="Omit for an SSO-only admin. Write-only."
    )
    profile: Optional[Profile] = Field(
        default=None, description="Seed autonomy, response and review settings from a template."
    )
    copy_settings_from: Optional[str] = Field(
        default=None,
        pattern=TENANT_ID_PATTERN,
        description="Copy another tenant's policy settings (never its secrets, destinations or assets).",
    )


class TenantCreatedOut(Out):
    id: str
    name: str
    status: str
    created_at: datetime
    admin: Optional[UserOut] = None
    settings_keys: List[str] = Field(default_factory=list)


class QuotasIn(In):
    max_alerts_per_day: Optional[int] = Field(default=None, ge=0, le=MAX_ALERTS_PER_DAY)
    max_sources: Optional[int] = Field(default=None, ge=0, le=MAX_COUNT_QUOTA)
    max_users: Optional[int] = Field(default=None, ge=0, le=MAX_COUNT_QUOTA)


class TenantUpdateIn(In):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    status: Optional[Literal["active", "suspended"]] = None
    quotas: Optional[QuotasIn] = Field(
        default=None, description="Only the quotas present change; null means unlimited."
    )


class QuotaUsageOut(BaseModel):
    used: int
    limit: Optional[int] = None


class TenantStatsOut(BaseModel):
    alerts_24h: int = 0
    alerts_today: int = 0
    last_ingest_at: Optional[datetime] = None
    open_escalations: int = 0
    overdue_escalations: int = 0
    sla_breaches_24h: int = 0
    llm_cost_mtd_usd: Decimal = Decimal(0)
    llm_tokens_mtd: int = 0
    users: int = 0
    sources: int = 0


class TenantSummaryOut(BaseModel):
    id: str
    name: str
    status: str
    created_at: datetime
    updated_at: datetime
    quotas: Dict[str, Optional[int]]
    quota_usage: Dict[str, QuotaUsageOut]
    stats: TenantStatsOut


class PlatformEscalationOut(Out):
    id: str
    tenant_id: str
    tenant_name: str
    tenant_status: str
    alert_id: str
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = None
    level: str
    status: str
    priority: int
    reason: str
    assigned_to: Optional[UUID] = None
    sla_deadline: Optional[datetime] = None
    overdue: bool = False
    created_at: datetime


class TenantUsageOut(Out):
    tenant_id: str
    tenant_name: str
    tenant_status: str
    alerts_ingested: int
    alerts_processed: int
    alerts_rejected_quota: int
    llm_calls: int
    llm_input_tokens: int
    llm_output_tokens: int
    llm_cost_usd: Decimal
    active_users: int
    users: int
    sources: int


class UsageReportOut(BaseModel):
    month: str
    start: date
    end: date
    generated_at: datetime
    tenants: List[TenantUsageOut]
    totals: Dict[str, Any]


USAGE_CSV_COLUMNS = (
    "tenant_id",
    "tenant_name",
    "tenant_status",
    "alerts_ingested",
    "alerts_processed",
    "alerts_rejected_quota",
    "llm_calls",
    "llm_input_tokens",
    "llm_output_tokens",
    "llm_cost_usd",
    "active_users",
    "users",
    "sources",
)


async def _audit_home(ctx: ApiContext, principal: Principal, action: str, resource_id: Optional[str], **details: Any) -> None:
    await AuditLogger(ctx.repos).record_event(
        principal.home_tenant_id,
        action,
        "tenant",
        resource_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={"home_tenant_id": principal.home_tenant_id, **details},
    )


# ------------------------------------------------------------------ tenants


@router.post("/tenants", status_code=201, response_model=TenantCreatedOut, summary="Provision a tenant")
async def create_tenant(
    body: TenantCreateIn, request: Request, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> TenantCreatedOut:
    ctx = get_ctx(request)
    name = body.name.strip()
    if not name:
        raise ApiError(422, "validation_error", "name must not be blank")
    if body.admin_password is not None and body.admin_email is None:
        raise ApiError(422, "validation_error", "admin_password needs admin_email")
    if body.profile is not None and body.copy_settings_from is not None:
        raise ApiError(422, "validation_error", "use either profile or copy_settings_from, not both")
    email: Optional[str] = None
    password_hash: Optional[str] = None
    if body.admin_email is not None:
        try:
            email = normalize_email(body.admin_email)
        except ValueError as exc:
            raise ApiError(422, "validation_error", "admin_email is not a valid address") from exc
        if body.admin_password is not None:
            check_password(ctx, body.admin_password)
            password_hash = await ahash_password(body.admin_password)
    seed: Dict[str, Any] = {}
    template: Dict[str, Any] = {}
    if body.profile is not None:
        seed = profile_settings(body.profile)
        template = {"profile": body.profile}
    elif body.copy_settings_from is not None:
        try:
            source = await ctx.repos.tenants.get(body.copy_settings_from)
        except NotFound as exc:
            raise ApiError(422, "validation_error", "copy_settings_from names no existing tenant") from exc
        seed = copyable_settings(source.settings)
        template = {"copied_from": source.id}
    try:
        tenant = await ctx.repos.tenants.provision(body.id, name)
    except Conflict as exc:
        raise ApiError(409, "conflict", f"tenant {body.id!r} already exists") from exc
    if seed:
        tenant = await ctx.repos.tenants.update_settings(tenant.id, seed)
    ctx.tenants.invalidate(tenant.id)
    audit = AuditLogger(ctx.repos)
    details = {
        "name": tenant.name,
        "home_tenant_id": principal.home_tenant_id,
        "with_admin": email is not None,
        **template,
        "settings_keys": sorted(seed),
    }
    for tenant_id, action in ((tenant.id, "tenant.created"), (principal.home_tenant_id, "platform.tenant_created")):
        await audit.record(
            tenant_id,
            action,
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details=details,
        )
    if body.copy_settings_from is not None:
        # Reading another tenant's configuration is cross-tenant access: that tenant's log shows it.
        await audit.record(
            body.copy_settings_from,
            "platform.settings_copied",
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"home_tenant_id": principal.home_tenant_id, "to_tenant": tenant.id, "keys": sorted(seed)},
        )
    admin: Optional[UserOut] = None
    if email is not None:
        user = await ctx.repos.users.create(tenant.id, email, "admin", password_hash=password_hash)
        await audit.record(
            tenant.id,
            "user.created",
            "user",
            str(user.id),
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"role": user.role, "sso_only": password_hash is None, "home_tenant_id": principal.home_tenant_id},
        )
        admin = UserOut.model_validate(user)
    return TenantCreatedOut(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        created_at=tenant.created_at,
        admin=admin,
        settings_keys=sorted(seed),
    )


def _summary(tenant: Tenant, stats: Optional[TenantStats]) -> TenantSummaryOut:
    figures = (
        TenantStatsOut(
            alerts_24h=stats.alerts_24h,
            alerts_today=stats.alerts_today,
            last_ingest_at=stats.last_ingest_at,
            open_escalations=stats.open_escalations,
            overdue_escalations=stats.overdue_escalations,
            sla_breaches_24h=stats.sla_breaches_24h,
            llm_cost_mtd_usd=stats.llm_cost_mtd,
            llm_tokens_mtd=stats.llm_tokens_mtd,
            users=stats.users,
            sources=stats.sources,
        )
        if stats is not None
        else TenantStatsOut()
    )
    quotas = quotas_of(tenant)
    return TenantSummaryOut(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
        quotas=quotas,
        quota_usage={
            "max_alerts_per_day": QuotaUsageOut(used=figures.alerts_today, limit=quotas["max_alerts_per_day"]),
            "max_sources": QuotaUsageOut(used=figures.sources, limit=quotas["max_sources"]),
            "max_users": QuotaUsageOut(used=figures.users, limit=quotas["max_users"]),
        },
        stats=figures,
    )


@router.get("/tenants", response_model=List[TenantSummaryOut], summary="Every tenant with status, quotas and activity")
async def list_tenants(
    request: Request,
    status: Optional[Literal["active", "suspended"]] = Query(default=None),
    principal: Principal = Depends(require(PLATFORM_ADMIN)),
) -> List[TenantSummaryOut]:
    ctx = get_ctx(request)
    tenants = await ctx.repos.tenants.list_all_tenants(status=status)
    stats = {s.tenant_id: s for s in await ctx.repos.platform.tenant_stats()}
    await _audit_home(ctx, principal, "platform.tenants_listed", None, count=len(tenants), status=status)
    return [_summary(t, stats.get(t.id)) for t in tenants]


async def _requeue_queued_runs(ctx: ApiContext, tenant_id: str) -> int:
    """Hand a reactivated tenant's queued runs back to the workers (the orphan sweep covers any beyond the cap)."""
    queued = await ctx.repos.runs.list_queued(tenant_id, limit=REQUEUE_LIMIT)
    for start in range(0, len(queued), REQUEUE_CHUNK):
        await ctx.queue.enqueue_process_many(tenant_id, queued[start : start + REQUEUE_CHUNK])
    return len(queued)


async def _reset_sla_deadlines(ctx: ApiContext, tenant: Tenant, conn: Connection) -> int:
    """Restart the SLA clock of a reactivated tenant's open escalations (now + the level's SLA).

    The sweep skips suspended tenants, so without this every escalation whose
    deadline passed during the suspension would jump a level on the next
    sweep. Deadlines are only ever pushed out, never shortened.
    """
    policy = resolve_review_policy(tenant.settings, ctx.settings)
    now = datetime.now(UTC)
    deadlines = {level: now + timedelta(minutes=policy.sla_minutes[level]) for level in ESCALATION_LEVELS}
    return await ctx.repos.escalations.extend_sla_deadlines(tenant.id, deadlines, conn=conn)


@router.patch("/tenants/{tenant_id}", response_model=TenantSummaryOut, summary="Rename, suspend/reactivate or set quotas")
async def update_tenant(
    tenant_id: str, body: TenantUpdateIn, request: Request, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> TenantSummaryOut:
    ctx = get_ctx(request)
    fields = body.model_fields_set
    for name in ("name", "status", "quotas"):
        if name in fields and getattr(body, name) is None:
            raise ApiError(422, "validation_error", f"{name} cannot be null")
    if not re.fullmatch(TENANT_ID_PATTERN, tenant_id):
        raise NotFound("tenant", tenant_id)
    if body.status == "suspended" and tenant_id == principal.home_tenant_id:
        raise ApiError(409, "conflict", "you cannot suspend your own home tenant")
    changes: Dict[str, Any] = {}
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise ApiError(422, "validation_error", "name must not be blank")
        changes["name"] = name
    if body.status is not None:
        changes["status"] = body.status
    if body.quotas is not None:
        for quota in body.quotas.model_fields_set:
            changes[quota] = getattr(body.quotas, quota)
    async with ctx.db.tenant_tx(tenant_id) as conn:
        before = await ctx.repos.tenants.get(tenant_id, for_update=True, conn=conn)
        updated = await ctx.repos.tenants.update_admin(tenant_id, **changes, conn=conn)
        diff = {k: {"from": getattr(before, k), "to": v} for k, v in changes.items() if getattr(before, k) != v}
        status_changed = before.status != updated.status
        action = (
            ("tenant.suspended" if updated.status == "suspended" else "tenant.reactivated")
            if status_changed
            else "tenant.updated"
        )
        extra: Dict[str, Any] = {}
        if status_changed and updated.is_active:
            extra["sla_deadlines_reset"] = await _reset_sla_deadlines(ctx, updated, conn)
        await AuditLogger(ctx.repos).record(
            tenant_id,
            action,
            "tenant",
            tenant_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"home_tenant_id": principal.home_tenant_id, "changes": diff, **extra},
            conn=conn,
        )
    ctx.tenants.invalidate(tenant_id)
    await _audit_home(ctx, principal, "platform.tenant_updated", tenant_id, tenant_action=action, changes=diff)
    if status_changed and updated.is_active:
        requeued = await _requeue_queued_runs(ctx, tenant_id)
        log.info("platform.tenant_reactivated", tenant_id=tenant_id, requeued=requeued)
    elif status_changed:
        log.warning("platform.tenant_suspended", tenant_id=tenant_id)
    stats = {s.tenant_id: s for s in await ctx.repos.platform.tenant_stats()}
    return _summary(updated, stats.get(tenant_id))


# -------------------------------------------------------------- escalations


@router.get(
    "/escalations",
    response_model=PageOut[PlatformEscalationOut],
    summary="Open and claimed escalations of every tenant, soonest SLA first",
)
async def list_escalations(
    request: Request,
    tenant_id: Optional[str] = Query(default=None, pattern=TENANT_ID_PATTERN),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None, max_length=512),
    principal: Principal = Depends(require(PLATFORM_ADMIN)),
) -> PageOut[PlatformEscalationOut]:
    ctx = get_ctx(request)
    page = await ctx.repos.platform.open_escalations(limit=limit, cursor=cursor, tenant_id=tenant_id)
    now = datetime.now(UTC)
    await _audit_home(ctx, principal, "platform.escalations_listed", tenant_id, count=len(page.items))
    return PageOut[PlatformEscalationOut](
        items=[
            PlatformEscalationOut.model_validate(
                {**e.model_dump(), "overdue": e.sla_deadline is not None and e.sla_deadline < now}
            )
            for e in page.items
        ],
        next_cursor=page.next_cursor,
    )


# -------------------------------------------------------------------- usage


def month_bounds(month: str) -> tuple[date, date]:
    if not _MONTH.fullmatch(month):
        raise ApiError(422, "validation_error", "month must be YYYY-MM")
    start = date(int(month[:4]), int(month[5:7]), 1)
    following = date(start.year + (start.month == 12), start.month % 12 + 1, 1)
    return start, following - timedelta(days=1)


def csv_cell(value: Any) -> str:
    """Text for one CSV cell; text that a spreadsheet would run as a formula is prefixed with ``'``."""
    if value is None:
        return ""
    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        return str(value)
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIX) or text.lstrip().startswith(_CSV_FORMULA_PREFIX):
        text = "'" + text
    return text


def usage_csv(rows: List[TenantUsageOut]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(USAGE_CSV_COLUMNS)
    for row in rows:
        writer.writerow([csv_cell(getattr(row, column)) for column in USAGE_CSV_COLUMNS])
    return out.getvalue()


@router.get(
    "/usage",
    response_model=UsageReportOut,
    summary="Invoicing figures per tenant for a month (JSON or CSV)",
    responses={200: {"content": {"text/csv": {}}}},
)
async def usage_report(
    request: Request,
    month: Optional[str] = Query(default=None, description="YYYY-MM (UTC); default: the current month"),
    format: Literal["json", "csv"] = Query(default="json"),  # noqa: A002 - the public query parameter name
    principal: Principal = Depends(require(PLATFORM_ADMIN)),
) -> Any:
    ctx = get_ctx(request)
    now = datetime.now(UTC)
    month = month or now.strftime("%Y-%m")
    start, end = month_bounds(month)
    rows = [TenantUsageOut.model_validate(r) for r in await ctx.repos.platform.usage(start, end)]
    await _audit_home(ctx, principal, "platform.usage_exported", None, month=month, format=format, tenants=len(rows))
    if format == "csv":
        return Response(
            content=usage_csv(rows),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="lg-sotf-usage-{month}.csv"'},
        )
    totals: Dict[str, Any] = {
        column: sum((getattr(r, column) for r in rows), Decimal(0) if column == "llm_cost_usd" else 0)
        for column in USAGE_CSV_COLUMNS[3:]
    }
    return UsageReportOut(month=month, start=start, end=end, generated_at=now, tenants=rows, totals=totals)
