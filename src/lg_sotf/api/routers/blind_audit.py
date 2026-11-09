# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/blind-audit``: blind audit of auto-closed alerts (PRD-10.2), and ``GET /reports/blind-audit``.

* ``GET /blind-audit/items`` and ``GET /blind-audit/items/{item_id}``
  (analysts and admins, user accounts): the queue. An unlabelled item shows
  the alert as its source sent it (title, severity, source, times, entities,
  raw and normalized event) and **never** the AI's verdict, confidence,
  scores, routing or reasoning; ``reveal`` is ``null`` until the item is
  labelled.
* ``POST /blind-audit/items/{item_id}/label``: the label (``malicious``,
  ``benign``, ``unsure``), once; the response reveals the AI's side and the
  agreement. ``malicious`` opens a normal escalation for the alert.
* ``GET /blind-audit/runs`` (viewers) and ``POST /blind-audit/runs``
  (the tenant's own admins, not under an MSSP grant): sampling runs with
  their seed, frame and counts; a run on demand (server seed, contiguous with
  the last run), or a dry run that records nothing (the only place for a
  caller's seed).
* ``GET /reports/blind-audit`` (viewers): the production false-negative
  estimate over the runs of a window, with its interval and ``n``.

All beta (:func:`lg_sotf.api.app.api_routers`).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, Literal, Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.api.auth.deps import ADMIN_NOT_UNDER_GRANT, REVIEWER, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import aware, forget_cached_figures, invalidate_verdicts
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import EntitiesPreviewOut, In, Out, PageOut, SeverityStr
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos.blind_audit import BlindAuditItem, BlindAuditRunSummary, Reveal
from lg_sotf.domain.blind_audit import MAX_SAMPLE_PER_RUN, MAX_SEED
from lg_sotf.domain.digests import entities_preview
from lg_sotf.domain.events import publish_event
from lg_sotf.models.vocabulary import AuditLabel, Disposition
from lg_sotf.services.blind_audit import (
    MAX_MIN_PER_WEEK,
    MAX_NOTES_CHARS,
    BlindAuditDraw,
    BlindAuditReport,
    BlindAuditService,
    SampleRequest,
    SamplingError,
)
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.reporting import ReportWindowError, resolve_window

router = APIRouter(prefix="/blind-audit", tags=["blind-audit"])
report = APIRouter(prefix="/reports", tags=["reports"])

MAX_CONCLUSION_CHARS = 2_000


class BlindAlertOut(BaseModel):
    """The alert as its source sent it: nothing the AI concluded, and not its id (the item id is the
    handle; the alert's own routes withhold its AI side until the label exists anyway)."""

    title: str
    severity: SeverityStr
    source_id: str
    source_name: Optional[str] = None
    category: Optional[str] = None
    occurred_at: datetime
    ingested_at: datetime
    entities_preview: Optional[EntitiesPreviewOut] = None
    raw: Optional[Dict[str, Any]] = Field(default=None, description="The source event (item detail only).")
    normalized: Optional[Dict[str, Any]] = Field(default=None, description="The normalized event (item detail only).")


class BlindAuditRevealOut(Out):
    """The AI's side, shown once the item is labelled: its class when sampled, and the alert's verdict now."""

    ai_class: Disposition
    agreement: Optional[bool] = Field(description="The label equals the AI class; null for an unsure label.")
    disposition: Optional[Disposition] = None
    confidence: Optional[float] = None
    threat_score: Optional[float] = None
    close_reason: Optional[str] = None
    routing_code: Optional[str] = None
    conclusion: Optional[str] = None


class BlindAuditItemOut(BaseModel):
    id: UUID
    run_id: UUID
    sample_rank: int
    label: Optional[AuditLabel] = None
    notes: Optional[str] = None
    labelled_at: Optional[datetime] = None
    labelled_by: Optional[UUID] = None
    escalation_id: Optional[str] = None
    created_at: datetime
    alert: BlindAlertOut
    reveal: Optional[BlindAuditRevealOut] = Field(default=None, description="Null until the item is labelled.")


class BlindAuditLabelIn(In):
    label: AuditLabel
    notes: Optional[str] = Field(default=None, max_length=MAX_NOTES_CHARS)


class BlindAuditLabelOut(BaseModel):
    item: BlindAuditItemOut
    escalation_id: Optional[str] = None
    escalation_created: bool = False


class BlindAuditSampleIn(In):
    """A run on demand: alerts closed from where the last run ended (the tenant's first run: ``from``, default
    7 days back) to ``to`` (default and at most: 5 minutes before now). ``dry_run`` draws without recording
    anything and is the only way to pass a ``seed`` (with it, ``from`` may be any time)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    start: Optional[datetime] = Field(default=None, alias="from")
    end: Optional[datetime] = Field(default=None, alias="to")
    dry_run: bool = Field(default=False, description="Draw and return the sample without recording a run.")
    seed: Optional[int] = Field(
        default=None, ge=0, le=MAX_SEED, description="Dry runs only (a recorded run's seed is the server's)."
    )
    sample_rate: Optional[float] = Field(default=None, gt=0, le=1, description="Default: the tenant setting.")
    min_per_week: Optional[int] = Field(default=None, ge=0, le=MAX_MIN_PER_WEEK)
    size: Optional[int] = Field(
        default=None, ge=1, le=MAX_SAMPLE_PER_RUN, description="Draw exactly this many (replaces rate and minimum)."
    )


def service(ctx: ApiContext) -> BlindAuditService:
    return BlindAuditService(ctx.repos, EscalationService(ctx.repos, ctx.events, ctx.settings))


def item_out(item: BlindAuditItem, reveal: Optional[Reveal] = None) -> BlindAuditItemOut:
    preview = entities_preview(item.entities)
    alert = BlindAlertOut(
        title=item.title,
        severity=item.severity,
        source_id=item.source_id,
        source_name=item.source_name,
        category=item.category,
        occurred_at=item.occurred_at,
        ingested_at=item.ingested_at,
        entities_preview=EntitiesPreviewOut.model_validate(preview) if preview else None,
        raw=item.raw,
        normalized=item.normalized,
    )
    shown = None
    if reveal is not None and item.label is not None:
        shown = BlindAuditRevealOut.model_validate(reveal).model_copy(
            update={"conclusion": (reveal.conclusion or "")[:MAX_CONCLUSION_CHARS] or None}
        )
    return BlindAuditItemOut(
        id=item.id,
        run_id=item.run_id,
        sample_rank=item.sample_rank,
        label=item.label,
        notes=item.notes,
        labelled_at=item.labelled_at,
        labelled_by=item.labelled_by,
        escalation_id=item.escalation_id,
        created_at=item.created_at,
        alert=alert,
        reveal=shown,
    )


@router.get("/items", response_model=PageOut[BlindAuditItemOut], summary="The blind audit queue (no AI verdict)")
async def list_items(
    request: Request,
    status: Literal["pending", "labelled"] = Query(default="pending"),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(REVIEWER)),
) -> PageOut[BlindAuditItemOut]:
    page = await service(get_ctx(request)).queue(
        principal.tenant_id, labelled=status == "labelled", limit=limit, cursor=cursor
    )
    # Listed items carry no reveal: a labelled item's reveal is on its own read.
    return PageOut[BlindAuditItemOut](items=[item_out(i) for i in page.items], next_cursor=page.next_cursor)


@router.get("/items/{item_id}", response_model=BlindAuditItemOut, summary="One sampled alert; the AI side once labelled")
async def get_item(
    item_id: UUID, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> BlindAuditItemOut:
    item, reveal = await service(get_ctx(request)).item(principal.tenant_id, item_id)
    return item_out(item, reveal)


@router.post(
    "/items/{item_id}/label", response_model=BlindAuditLabelOut, summary="Label a sampled alert, then see the AI's verdict"
)
async def label_item(
    item_id: UUID, body: BlindAuditLabelIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> BlindAuditLabelOut:
    ctx = get_ctx(request)
    result = await service(ctx).label(
        principal.tenant_id, item_id, body.label, notes=body.notes, actor=principal.actor,
        user_id=principal.local_user_id, organisation=principal.home_tenant_id if principal.delegated else None,
    )
    if body.label == "malicious":
        await invalidate_verdicts(ctx, principal.tenant_id, [result.item.alert_id], principal.actor)
    # The alert counts again in the dashboard and report figures (pending samples are left out of them).
    await forget_cached_figures(ctx, principal.tenant_id)
    await publish_event(ctx.events, "alert.updated", principal.tenant_id, result.item.alert_id, {"blind_audit": "labelled"})
    return BlindAuditLabelOut(
        item=item_out(result.item, result.reveal),
        escalation_id=result.escalation.id if result.escalation else None,
        escalation_created=result.escalation_created,
    )


@router.get(
    "/runs", response_model=PageOut[BlindAuditRunSummary], summary="Sampling runs: window, seed, frame and label counts"
)
async def list_runs(
    request: Request,
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[BlindAuditRunSummary]:
    page = await service(get_ctx(request)).runs(principal.tenant_id, limit=limit, cursor=cursor)
    return PageOut[BlindAuditRunSummary](items=page.items, next_cursor=page.next_cursor)


@router.post(
    "/runs",
    response_model=Union[BlindAuditRunSummary, BlindAuditDraw],
    status_code=201,
    summary="Sample auto-closed alerts now (or draw without recording: dry_run)",
)
async def create_run(
    body: BlindAuditSampleIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(require(ADMIN_NOT_UNDER_GRANT)),
) -> Union[BlindAuditRunSummary, BlindAuditDraw]:
    sample = SampleRequest(
        since=aware(body.start), until=aware(body.end), seed=body.seed, sample_rate=body.sample_rate,
        min_per_week=body.min_per_week, size=body.size,
    )
    svc = service(get_ctx(request))
    try:
        if body.dry_run:
            response.status_code = 200
            return await svc.dry_run(principal.tenant_id, sample)
        run = await svc.sample(principal.tenant_id, sample, trigger="api", actor=principal.actor)
    except SamplingError as exc:
        status = 409 if exc.code in ("window_already_sampled", "window_not_contiguous") else 400
        raise ApiError(status, exc.code, str(exc)) from exc
    # The drawn samples leave the dashboard and report figures until they are labelled.
    await forget_cached_figures(get_ctx(request), principal.tenant_id)
    # A new run: every sample is waiting for its label.
    return BlindAuditRunSummary.model_validate({**run.model_dump(), "sampled": run.sample_size})


@report.get(
    "/blind-audit",
    response_model=BlindAuditReport,
    summary="Production false-negative estimate from blind audits of auto-closed alerts, with its interval",
)
async def blind_audit_report(
    request: Request,
    start: Optional[date] = Query(default=None, alias="from"),
    end: Optional[date] = Query(default=None, alias="to"),
    principal: Principal = Depends(require(VIEWER)),
) -> BlindAuditReport:
    try:
        window = resolve_window(start, end)
    except ReportWindowError as exc:
        raise ApiError(400, "invalid_window", str(exc)) from exc
    return await service(get_ctx(request)).report(principal.tenant_id, window)
