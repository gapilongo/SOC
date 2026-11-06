# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""Compliance endpoints: case evidence packs, NIS2 report drafts, tenant data export and erasure.

* ``GET /alerts/{id}/evidence?format=json|html`` (viewer): the sealed
  evidence pack (see :mod:`lg_sotf.compliance.evidence`). Every export is
  audited (``alert.evidence_exported`` with the bundle digest).
* ``POST /alerts/{id}/incident-report`` (analyst): a NIS2 Article 23 draft
  for one stage, stored as an ``incident_report_draft`` timeline event and
  audited. It is a draft for a person to complete and submit; LG-SOTF never
  submits anything to a CSIRT.
* ``GET /platform/tenants/{id}/erasure``, ``POST /platform/tenants/{id}/export``
  and ``DELETE /platform/tenants/{id}`` (platform admins): erasure readiness,
  a streamed ZIP export and the erasure itself. Export and erasure are
  audited in the target tenant's chain and in the admin's home tenant.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from lg_sotf.api.auth.deps import ANALYST, PLATFORM_ADMIN, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import In
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.compliance import nis2
from lg_sotf.compliance.evidence import build_evidence_pack, render_evidence_html
from lg_sotf.compliance.tenant_data import (
    ErasureRefused,
    erase_tenant,
    erased_at,
    erasure_blockers,
    export_filename,
    export_tenant_zip,
)
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import LLMUsageDelta, Tenant
from lg_sotf.db.tenancy import TENANT_ID_PATTERN
from lg_sotf.domain.events import publish_event
from lg_sotf.llm import USE_DEFAULT, BudgetLimit, LLMUsageRow, TokenBudget, get_usage_recorder
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

alerts = APIRouter(prefix="/alerts", tags=["compliance"])
platform = APIRouter(prefix="/platform", tags=["platform"])

MAX_EVENT_VALUE_CHARS = 4_000
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _filename(stem: str, alert_id: str, ext: str) -> str:
    return f"{stem}-{_FILENAME_UNSAFE.sub('_', alert_id)[:100]}.{ext}"


def _actor(principal: Principal) -> Dict[str, Any]:
    out: Dict[str, Any] = {"actor_type": principal.actor_type, "actor_id": principal.actor_id}
    if principal.overridden:
        out["home_tenant_id"] = principal.home_tenant_id
    return out


# ------------------------------------------------------------------ evidence


@alerts.get(
    "/{alert_id}/evidence",
    summary="Case evidence pack (JSON bundle or printable HTML)",
    responses={200: {"content": {"application/json": {}, "text/html": {}}}},
)
async def evidence_pack(
    alert_id: str,
    request: Request,
    format: Literal["json", "html"] = Query(default="json"),  # noqa: A002 - public query parameter name
    principal: Principal = Depends(require(VIEWER)),
) -> Response:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    pack = await build_evidence_pack(ctx.repos, ctx.settings, tenant_id, alert_id, generated_by=_actor(principal))
    digest = pack["integrity"]["bundle_sha256"]
    signature = pack["integrity"]["signature"]
    entry = await AuditLogger(ctx.repos).record_event(
        tenant_id,
        "alert.evidence_exported",
        "alert",
        alert_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={
            "format": format,
            "bundle_sha256": digest,
            "signed": signature is not None,
            **({"home_tenant_id": principal.home_tenant_id} if principal.overridden else {}),
        },
    )
    headers = {"X-Evidence-Bundle-SHA256": digest}
    if entry is not None:
        headers["X-Audit-Entry-Id"] = str(entry.id)
    if format == "html":
        headers["Content-Disposition"] = f'attachment; filename="{_filename("evidence", alert_id, "html")}"'
        return Response(render_evidence_html(pack), media_type="text/html; charset=utf-8", headers=headers)
    headers["Content-Disposition"] = f'attachment; filename="{_filename("evidence", alert_id, "json")}"'
    return JSONResponse(pack, headers=headers)


# ------------------------------------------------------------------ NIS2


class IncidentReportIn(In):
    stage: Literal["early_warning", "notification", "final"]
    include_ai_narrative: bool = True


class DraftFieldOut(BaseModel):
    key: str
    label: str
    value: Optional[str] = None
    source: Literal["case_data", "requires_human", "ai_drafted"]
    required: bool
    help: Optional[str] = None


class AiNarrativeOut(BaseModel):
    text: str
    label: str
    provider: str
    model: str


class IncidentReportOut(BaseModel):
    alert_id: str
    stage: str
    event_id: int
    generated_at: datetime
    disclaimer: str
    deadline_hint: str
    fields: List[DraftFieldOut]
    ai_narrative: Optional[AiNarrativeOut] = None
    ai_narrative_error: Optional[str] = None
    html: str


async def _budget_limit(ctx: Any, tenant_id: str) -> BudgetLimit:
    try:
        tenant = await ctx.repos.tenants.get(tenant_id)
    except NotFound:
        return USE_DEFAULT
    limit = tenant.settings.get("llm_daily_token_budget")
    return limit if isinstance(limit, int) and not isinstance(limit, bool) else USE_DEFAULT


async def _flush_llm_usage(ctx: Any) -> None:
    """Write buffered LLM usage (this call's included) to ``llm_usage_daily``; best effort.

    The API process has no periodic flusher like the worker's, so the
    narrative's tokens and cost would otherwise never reach the usage report.
    """

    async def sink(rows: List[LLMUsageRow]) -> None:
        await ctx.repos.llm_usage.upsert_daily([LLMUsageDelta(**row) for row in rows])

    try:
        await get_usage_recorder().flush(sink)
    except Exception as exc:  # noqa: BLE001 - kept in the buffer for the next flush
        log.warning("api.llm_usage_flush_failed", error_type=type(exc).__name__)


def _clip(value: Optional[str]) -> Optional[str]:
    if value is None or len(value) <= MAX_EVENT_VALUE_CHARS:
        return value
    return value[:MAX_EVENT_VALUE_CHARS]


@alerts.post(
    "/{alert_id}/incident-report",
    status_code=201,
    response_model=IncidentReportOut,
    summary="Draft a NIS2 incident report (early warning, notification or final) for a person to complete",
)
async def incident_report(
    alert_id: str, body: IncidentReportIn, request: Request, principal: Principal = Depends(require(ANALYST))
) -> IncidentReportOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    case = await nis2.load_case(ctx.repos, tenant_id, alert_id)
    fields = [f.as_dict() for f in nis2.build_draft_fields(case, body.stage)]
    narrative: Optional[Dict[str, Any]] = None
    narrative_error: Optional[str] = None
    if body.include_ai_narrative:
        budget = TokenBudget(ctx.redis, ctx.settings, usage_seed=ctx.repos.llm_usage.day_tokens)
        result = await nis2.draft_narrative(
            ctx.settings,
            tenant_id,
            case,
            body.stage,
            budget=budget,
            budget_limit=await _budget_limit(ctx, tenant_id),
        )
        narrative, narrative_error = result.narrative, result.error
        await _flush_llm_usage(ctx)
    generated_at = datetime.now(UTC)
    draft = {"stage": body.stage, "fields": fields, "ai_narrative": narrative}
    draft_sha256 = hashlib.sha256(
        json.dumps(draft, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    async with ctx.db.tenant_tx(tenant_id) as conn:
        event = await ctx.repos.alert_events.append(
            tenant_id,
            alert_id,
            "incident_report_draft",
            actor_type="user" if principal.is_user else "system",
            actor_id=principal.actor_id,
            data={
                "stage": body.stage,
                "framework": "NIS2 Art. 23",
                "status": "draft_not_submitted",
                "author": principal.email or principal.actor_id,
                "draft_sha256": draft_sha256,
                "fields": [
                    {"key": f["key"], "source": f["source"], "value": _clip(f["value"])} for f in fields
                ],
                "ai_narrative": {**narrative, "text": _clip(narrative["text"])} if narrative else None,
            },
            conn=conn,
        )
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "alert.incident_report_drafted",
            "alert",
            alert_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={
                "stage": body.stage,
                "event_id": event.id,
                "draft_sha256": draft_sha256,
                "ai_narrative": narrative is not None,
            },
            conn=conn,
        )
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"incident_report_draft": body.stage})
    html = nis2.render_draft_html(
        alert_id=alert_id,
        stage=body.stage,
        fields=fields,
        generated_at=generated_at.isoformat(),
        ai_narrative=narrative,
    )
    return IncidentReportOut(
        alert_id=alert_id,
        stage=body.stage,
        event_id=event.id,
        generated_at=generated_at,
        disclaimer=nis2.DISCLAIMER,
        deadline_hint=nis2.DEADLINES[body.stage],
        fields=[DraftFieldOut(**f) for f in fields],
        ai_narrative=AiNarrativeOut(**narrative) if narrative else None,
        ai_narrative_error=narrative_error,
        html=html,
    )


# ------------------------------------------------------------------ platform: tenant data

TenantIdPath = Path(pattern=TENANT_ID_PATTERN, description="Tenant id.")


class ErasureStatusOut(BaseModel):
    tenant_id: str
    name: str
    status: str
    erasable: bool
    blockers: List[str]
    erased_at: Optional[str] = None


class TenantEraseIn(In):
    confirm: str = Field(max_length=63, description="Must equal the tenant id.")


class TenantErasedOut(BaseModel):
    tenant_id: str
    erased_at: datetime
    deleted: Dict[str, int]
    redis_keys: int
    queue_entries: int
    audit_entries_retained: int


async def _tenant(ctx: Any, tenant_id: str) -> Tenant:
    try:
        tenant: Tenant = await ctx.repos.tenants.get(tenant_id)
    except NotFound as exc:
        raise ApiError(404, "not_found", "tenant not found") from exc
    return tenant


@platform.get(
    "/tenants/{tenant_id}/erasure", response_model=ErasureStatusOut, summary="Whether a tenant can be erased now"
)
async def erasure_status(
    request: Request, tenant_id: str = TenantIdPath, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> ErasureStatusOut:
    ctx = get_ctx(request)
    tenant = await _tenant(ctx, tenant_id)
    blockers = await erasure_blockers(ctx.db, tenant, home_tenant_id=principal.home_tenant_id)
    return ErasureStatusOut(
        tenant_id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        erasable=not blockers,
        blockers=blockers,
        erased_at=erased_at(tenant),
    )


@platform.post(
    "/tenants/{tenant_id}/export",
    summary="Export a tenant's data (streamed ZIP of JSONL files; secrets removed)",
    responses={200: {"content": {"application/zip": {}}}},
)
async def export_tenant(
    request: Request, tenant_id: str = TenantIdPath, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> StreamingResponse:
    ctx = get_ctx(request)
    tenant = await _tenant(ctx, tenant_id)
    now = datetime.now(UTC)
    filename = export_filename(tenant.id, now)
    audit = AuditLogger(ctx.repos)
    details = {"home_tenant_id": principal.home_tenant_id, "filename": filename, "tenant_status": tenant.status}
    for target, action in ((tenant.id, "tenant.data_exported"), (principal.home_tenant_id, "platform.tenant_exported")):
        await audit.record_event(
            target,
            action,
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details=details,
        )
    stream = export_tenant_zip(ctx.db, tenant, exported_by={**_actor(principal), "home_tenant_id": principal.home_tenant_id}, now=now)
    return StreamingResponse(
        stream,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@platform.delete(
    "/tenants/{tenant_id}",
    response_model=TenantErasedOut,
    summary="Erase a suspended tenant's data (the audit log is retained)",
)
async def erase(
    body: TenantEraseIn,
    request: Request,
    tenant_id: str = TenantIdPath,
    principal: Principal = Depends(require(PLATFORM_ADMIN)),
) -> TenantErasedOut:
    ctx = get_ctx(request)
    if body.confirm != tenant_id:
        raise ApiError(422, "confirmation_mismatch", "'confirm' must equal the id of the tenant to erase")
    tenant = await _tenant(ctx, tenant_id)
    blockers = await erasure_blockers(ctx.db, tenant, home_tenant_id=principal.home_tenant_id)
    if blockers:
        code = "tenant_not_suspended" if tenant.status != "suspended" else "erasure_blocked"
        raise ApiError(409, code, "; ".join(blockers))
    audit = AuditLogger(ctx.repos)
    # Erasure deletes in many streamed batches, one transaction each, so it has no single transaction to
    # audit in: the start is recorded before the first batch and the result after the last one.
    await audit.record_event(
        principal.home_tenant_id,
        "platform.tenant_erasure_started",
        "tenant",
        tenant.id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={"tenant_name": tenant.name},
    )
    try:
        report = await erase_tenant(ctx.db, ctx.redis, ctx.prefix, tenant.id)
    except ErasureRefused as exc:
        raise ApiError(409 if exc.code != "not_found" else 404, exc.code, str(exc)) from exc
    ctx.tenants.invalidate(tenant.id)
    details = {
        "home_tenant_id": principal.home_tenant_id,
        "rows_deleted": report.total_rows,
        "deleted": report.deleted,
        "redis_keys": report.redis_keys,
        "queue_entries": report.queue_entries,
        "audit_entries_retained": report.audit_entries_retained,
    }
    for target, action in ((tenant.id, "tenant.erased"), (principal.home_tenant_id, "platform.tenant_erased")):
        await audit.record_event(
            target,
            action,
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details=details,
        )
    log.info("platform.tenant_erased", erased_tenant=tenant.id, rows=report.total_rows)
    return TenantErasedOut.model_validate(report.as_dict())
