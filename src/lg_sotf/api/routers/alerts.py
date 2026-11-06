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
from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.repos.alerts import DEFAULT_SEARCH_WINDOW, MAX_SEARCH_WINDOW
from lg_sotf.domain.events import publish_event
from lg_sotf.models.vocabulary import AlertStatus, Disposition, Severity
from lg_sotf.services import alerts as alert_changes

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
    page = await alert_changes.timeline(
        get_ctx(request).repos, principal.tenant_id, alert_id, limit=limit, cursor=cursor
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
    event = await alert_changes.add_note(
        ctx.repos,
        AuditLogger(ctx.repos),
        tenant_id,
        principal.actor,
        alert_id,
        text=body.text,
        author=principal.email or principal.actor_id,
        timeline_actor=Actor("user" if principal.is_user else "system", principal.actor_id),
    )
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"note_added": True})
    return AlertEventOut.model_validate(event)


@router.post("/{alert_id}/reprocess", status_code=202, response_model=ReprocessOut, summary="Run the workflow again")
async def reprocess(alert_id: str, request: Request, principal: Principal = Depends(require(ADMIN))) -> ReprocessOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    try:
        alert = await alert_changes.request_reprocess(
            ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, alert_id
        )
    except InvalidTransition as exc:
        raise ApiError(409, "run_active", f"the alert's run is {exc.current}; it cannot be reprocessed now") from exc
    entry_id = await ctx.queue.enqueue_process(tenant_id, alert_id, alert.severity)
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"status": "queued", "reprocess": True})
    return ReprocessOut(alert_id=alert_id, status="queued", entry_id=entry_id)
