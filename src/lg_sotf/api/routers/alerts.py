# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/alerts``: listing, detail, timeline, notes and reprocessing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request

from lg_sotf.api.auth.deps import ADMIN, ANALYST, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import AlertDetailOut, AlertEventOut, AlertOut, NoteIn, PageOut, ReprocessOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import publish_event
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.repos.alerts import DEFAULT_SEARCH_WINDOW, MAX_SEARCH_WINDOW
from lg_sotf.models.vocabulary import AlertStatus, Disposition, Severity
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

MAX_LIMIT = 200


def aware(value: Optional[datetime]) -> Optional[datetime]:
    """Query timestamps without an offset are taken as UTC."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


@router.get("", response_model=PageOut[AlertOut], summary="List alerts (newest first, keyset pagination)")
async def list_alerts(
    request: Request,
    status: Optional[List[AlertStatus]] = Query(default=None),
    severity: Optional[List[Severity]] = Query(default=None),
    disposition: Optional[List[Disposition]] = Query(default=None),
    source_id: Optional[str] = Query(default=None, max_length=128),
    q: Optional[str] = Query(
        default=None, max_length=200, description="Title search; needs a window of at most 93 days"
    ),
    since: Optional[datetime] = Query(default=None, alias="from"),
    until: Optional[datetime] = Query(default=None, alias="to"),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[AlertOut]:
    ctx = get_ctx(request)
    since, until = aware(since), aware(until)
    if since is not None and until is not None and until <= since:
        raise ApiError(400, "invalid_window", "'to' must be after 'from'")
    if q is not None and q.strip():
        end = until or datetime.now(UTC)
        start = since or end - DEFAULT_SEARCH_WINDOW
        if end - start > MAX_SEARCH_WINDOW:
            raise ApiError(
                400, "search_window_too_large", f"a text search may span at most {MAX_SEARCH_WINDOW.days} days"
            )
        since = start
    page = await ctx.repos.alerts.list(
        principal.tenant_id,
        status=status,
        severity=severity,
        disposition=disposition,
        source_id=source_id,
        q=q,
        since=since,
        until=until,
        limit=limit,
        cursor=cursor,
    )
    return PageOut[AlertOut](items=[AlertOut.model_validate(a) for a in page.items], next_cursor=page.next_cursor)


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Alert detail")
async def get_alert(alert_id: str, request: Request, principal: Principal = Depends(require(VIEWER))) -> AlertDetailOut:
    alert = await get_ctx(request).repos.alerts.get(principal.tenant_id, alert_id)
    return AlertDetailOut.model_validate(alert)


@router.get("/{alert_id}/events", response_model=PageOut[AlertEventOut], summary="Alert timeline (oldest first)")
async def alert_events(
    alert_id: str,
    request: Request,
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[AlertEventOut]:
    ctx = get_ctx(request)
    async with ctx.db.tenant_tx(principal.tenant_id, readonly=True) as conn:
        await ctx.repos.alerts.get(principal.tenant_id, alert_id, conn=conn)
        page = await ctx.repos.alert_events.list_for_alert(
            principal.tenant_id, alert_id, limit=limit, cursor=cursor, conn=conn
        )
    return PageOut[AlertEventOut](
        items=[AlertEventOut.model_validate(e) for e in page.items], next_cursor=page.next_cursor
    )


@router.post("/{alert_id}/notes", status_code=201, response_model=AlertEventOut, summary="Add an analyst note")
async def add_note(
    alert_id: str, body: NoteIn, request: Request, principal: Principal = Depends(require(ANALYST))
) -> AlertEventOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    async with ctx.db.tenant_tx(tenant_id) as conn:
        await ctx.repos.alerts.get(tenant_id, alert_id, conn=conn)
        event = await ctx.repos.alert_events.append(
            tenant_id,
            alert_id,
            "note",
            actor_type="user" if principal.is_user else "system",
            actor_id=principal.actor_id,
            data={"text": body.text, "author": principal.email or principal.actor_id},
            conn=conn,
        )
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "alert.note_added",
            "alert",
            alert_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"event_id": event.id},
            conn=conn,
        )
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"note_added": True})
    return AlertEventOut.model_validate(event)


@router.post("/{alert_id}/reprocess", status_code=202, response_model=ReprocessOut, summary="Run the workflow again")
async def reprocess(alert_id: str, request: Request, principal: Principal = Depends(require(ADMIN))) -> ReprocessOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    async with ctx.db.tenant_tx(tenant_id) as conn:
        alert = await ctx.repos.alerts.get(tenant_id, alert_id, conn=conn)
        previous = alert.status
        run = await ctx.repos.runs.upsert_queued(tenant_id, alert_id, requeue_terminal=True, conn=conn)
        if run.status != "queued":
            raise ApiError(409, "run_active", f"the alert's run is {run.status}; it cannot be reprocessed now")
        try:
            alert = await ctx.repos.alerts.update_status(tenant_id, alert_id, "queued", conn=conn)
        except InvalidTransition:
            log.info("api.reprocess_status_kept", status=previous)
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "alert.reprocess_requested",
            "alert",
            alert_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"previous_status": previous},
            conn=conn,
        )
    entry_id = await ctx.queue.enqueue_process(tenant_id, alert_id, alert.severity)
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"status": "queued", "reprocess": True})
    return ReprocessOut(alert_id=alert_id, status="queued", entry_id=entry_id)
