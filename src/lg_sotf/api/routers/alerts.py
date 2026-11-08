# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/alerts``: listing, view counts, detail, timeline, notes and reprocessing.

``GET /alerts/counts`` is cached for :data:`COUNTS_CACHE_TTL_S` seconds per
tenant and window in Redis (Redis being down only disables the cache).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from redis.exceptions import RedisError

from lg_sotf.api.auth.deps import ADMIN, ANALYST, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import alert_detail_out, alert_out, aware, hidden_alert_ids
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import AlertCountsOut, AlertDetailOut, AlertEventOut, AlertOut, NoteIn, PageOut, ReprocessOut
from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos.alerts import DEFAULT_SEARCH_WINDOW, MAX_SEARCH_WINDOW
from lg_sotf.domain.blind_audit import hidden_event_data
from lg_sotf.domain.events import publish_event
from lg_sotf.models.vocabulary import AlertStatus, Disposition, Severity
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.services import alerts as alert_changes

log = get_logger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

COUNTS_CACHE_TTL_S = 15



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
    closed_from: Optional[datetime] = Query(default=None, description="Closed at or after (closed alerts only)"),
    closed_to: Optional[datetime] = Query(default=None, description="Closed before (closed alerts only)"),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[AlertOut]:
    ctx = get_ctx(request)
    since, until = aware(since), aware(until)
    closed_from, closed_to = aware(closed_from), aware(closed_to)
    if since is not None and until is not None and until <= since:
        raise ApiError(400, "invalid_window", "'to' must be after 'from'")
    if closed_from is not None and closed_to is not None and closed_to <= closed_from:
        raise ApiError(400, "invalid_window", "'closed_to' must be after 'closed_from'")
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
        closed_from=closed_from,
        closed_to=closed_to,
        limit=limit,
        cursor=cursor,
    )
    hidden = await hidden_alert_ids(ctx, principal.tenant_id, [a.id for a in page.items])
    return PageOut[AlertOut](items=[alert_out(a, hidden=a.id in hidden) for a in page.items], next_cursor=page.next_cursor)


def counts_cache_key(ctx: ApiContext, tenant_id: str, closed_from: datetime, closed_to: Optional[datetime]) -> str:
    end = int(closed_to.timestamp()) if closed_to is not None else "open"
    return f"{ctx.prefix}:t:{tenant_id}:cache:alert-counts:{int(closed_from.timestamp())}:{end}"


@router.get("/counts", response_model=AlertCountsOut, summary="Alert counts by status for the list views (cached 15 s)")
async def alert_counts(
    request: Request,
    closed_from: Optional[datetime] = Query(
        default=None, description="Count closed alerts closed at or after this time (default: today 00:00 UTC)"
    ),
    closed_to: Optional[datetime] = Query(default=None, description="... and before this time (default: no end)"),
    principal: Principal = Depends(require(VIEWER)),
) -> AlertCountsOut:
    """Every status but ``closed`` is counted over all alerts; ``closed`` only inside the closed window."""
    ctx = get_ctx(request)
    now = datetime.now(UTC)
    start = aware(closed_from) or now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = aware(closed_to)
    if end is not None and end <= start:
        raise ApiError(400, "invalid_window", "'closed_to' must be after 'closed_from'")
    key = counts_cache_key(ctx, principal.tenant_id, start, end)
    try:
        cached = await ctx.redis.get(key)
        if cached is not None:
            return AlertCountsOut.model_validate_json(cached)
    except (RedisError, OSError, TimeoutError, ValueError) as exc:
        log_failure(log, "alerts.counts_cache_unavailable", exc, level="warning", error_type=type(exc).__name__)
    counts = await ctx.repos.views.alert_view_counts(principal.tenant_id, start, end)
    result = AlertCountsOut(by_status=counts, closed_from=start, closed_to=end, generated_at=now)
    try:
        await ctx.redis.set(key, result.model_dump_json().encode(), ex=COUNTS_CACHE_TTL_S)
    except (RedisError, OSError, TimeoutError) as exc:
        log_failure(log, "alerts.counts_cache_unavailable", exc, level="warning", error_type=type(exc).__name__)
    return result


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Alert detail")
async def get_alert(alert_id: str, request: Request, principal: Principal = Depends(require(VIEWER))) -> AlertDetailOut:
    ctx = get_ctx(request)
    alert = await ctx.repos.alerts.get(principal.tenant_id, alert_id)
    return alert_detail_out(alert, hidden=bool(await hidden_alert_ids(ctx, principal.tenant_id, [alert_id])))


@router.get("/{alert_id}/events", response_model=PageOut[AlertEventOut], summary="Alert timeline (oldest first)")
async def alert_events(
    alert_id: str,
    request: Request,
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=100, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[AlertEventOut]:
    ctx = get_ctx(request)
    page = await alert_changes.timeline(ctx.repos, principal.tenant_id, alert_id, limit=limit, cursor=cursor)
    items = [AlertEventOut.model_validate(e) for e in page.items]
    if await hidden_alert_ids(ctx, principal.tenant_id, [alert_id]):
        items = [e.model_copy(update={"data": hidden_event_data(e.event_type, e.data)}) for e in items]
    return PageOut[AlertEventOut](items=items, next_cursor=page.next_cursor)


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
