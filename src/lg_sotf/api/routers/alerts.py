# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/alerts``: listing, view counts, detail, timeline, the investigation view, notes, reprocessing, and a
person's reopening or flag of an alert the AI closed (:mod:`lg_sotf.core.reopen`).

``GET /alerts/counts`` is cached for :data:`COUNTS_CACHE_TTL_S` seconds per
tenant and window in Redis (Redis being down only disables the cache).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from redis.exceptions import RedisError

from lg_sotf.api.auth.deps import ADMIN, ANALYST, REVIEWER, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import (
    alert_detail_out,
    alert_out,
    aware,
    blind_view,
    enqueue_reopened,
    hidden_alert_ids,
    reopen_confirmed,
)
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import (
    AlertCountsOut,
    AlertDetailOut,
    AlertEventOut,
    AlertOut,
    AlertStatusStr,
    In,
    NoteIn,
    PageOut,
    ReprocessOut,
)
from lg_sotf.api.stability import route_contract
from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.reopen import MAX_REASON_CHARS, NotReopenable, reopen
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos.alerts import DEFAULT_SEARCH_WINDOW, MAX_SEARCH_WINDOW
from lg_sotf.domain.blind_audit import shown_while_hidden
from lg_sotf.domain.events import publish_event
from lg_sotf.domain.investigation import Investigation
from lg_sotf.models.vocabulary import AlertStatus, Disposition, Severity
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.services import alerts as alert_changes
from lg_sotf.services.investigation import investigation

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
    view = await blind_view(ctx, principal.tenant_id, page.items)
    return PageOut[AlertOut](items=[alert_out(a, view=view) for a in page.items], next_cursor=page.next_cursor)


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
    return alert_detail_out(alert, view=await blind_view(ctx, principal.tenant_id, [alert]))


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
        # Only ingestion and notes: the workflow's events would reveal its path (gate straight to close).
        items = [e for e in items if shown_while_hidden(e.event_type)]
    return PageOut[AlertEventOut](items=items, next_cursor=page.next_cursor)


@router.get(
    "/{alert_id}/investigation",
    response_model=Investigation,
    summary="What the AI concluded about the alert and why (the investigation view)",
    **route_contract(stability="beta"),
)
async def get_investigation(
    alert_id: str, request: Request, principal: Principal = Depends(require(VIEWER))
) -> Investigation:
    """One read model for the investigation view: the outcome and its reason in plain words, the summary, the
    claims and the observations they rest on, what is not established, the steps, the track record of the
    outcome category and the proposed response. Built from stored data: no model is called, nothing is written.

    ``pending_harness`` names the fields that stay empty until the investigation harness fills them. While the
    alert waits for its blind-audit label, the AI's side is withheld (``hidden_for_blind_audit``).
    """
    ctx = get_ctx(request)
    return await investigation(
        ctx.repos, ctx.review.responses, ctx.settings, principal.tenant_id, alert_id, role=principal.role
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
    if await hidden_alert_ids(ctx, tenant_id, [alert_id]):
        raise ApiError(
            409, "hidden_for_blind_audit",
            "the alert waits for its blind-audit label; label it first (a new run would reveal the verdict)",
        )
    try:
        alert = await alert_changes.request_reprocess(
            ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, alert_id
        )
    except InvalidTransition as exc:
        raise ApiError(409, "run_active", f"the alert's run is {exc.current}; it cannot be reprocessed now") from exc
    entry_id = await ctx.queue.enqueue_process(tenant_id, alert_id, alert.severity)
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"status": "queued", "reprocess": True})
    return ReprocessOut(alert_id=alert_id, status="queued", entry_id=entry_id)


class ReopenIn(In):
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARS, description="Why, in the person's words: data.")
    case_id: Optional[str] = Field(
        default=None, max_length=128,
        description="The case the alert returns to (it must hold the alert). Default: the open case it is attached to.",
    )

    @field_validator("reason")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason must not be blank")
        return value


class ReopenOut(BaseModel):
    alert_id: str
    status: AlertStatusStr
    mode: Literal["folded", "requeued"] = Field(
        description="folded: it waits for a person in case_id. requeued: no open case holds it, a new run reviews it."
    )
    case_id: Optional[str] = None
    flagged: bool


async def _reopen(ctx: ApiContext, principal: Principal, alert_id: str, body: ReopenIn, *, flag: bool) -> ReopenOut:
    tenant_id = principal.tenant_id
    try:
        done = await reopen(
            ctx.repos, tenant_id, alert_id, actor=principal.actor, reason=body.reason, flag=flag, case_id=body.case_id
        )
    except NotReopenable as exc:
        raise ApiError(409, exc.code, str(exc)) from exc
    except InvalidTransition as exc:
        raise ApiError(409, "run_active", f"the alert's run is {exc.current}; it cannot be reopened now") from exc
    await enqueue_reopened(ctx, tenant_id, alert_id)  # a requeued alert's new run; a folded one has none
    status = "waiting_human" if done.case_id else "queued"
    await publish_event(ctx.events, "alert.updated", tenant_id, alert_id, {"status": status, "reopened": True})
    if flag:
        # A person stands behind the flag: for the safety net it confirms the threat of the case the alert
        # returned to (as a true positive on that case would), else the flagged alert itself.
        threat = await ctx.repos.alerts.get(tenant_id, done.case_alert_id or alert_id)
        await reopen_confirmed(ctx, tenant_id, threat, principal.actor, escalation_id=done.case_id, path="flag")
    return ReopenOut(alert_id=alert_id, status=status, mode=done.mode, case_id=done.case_id, flagged=flag)


@router.post(
    "/{alert_id}/reopen",
    response_model=ReopenOut,
    summary="Reopen an alert the AI closed, with a reason: it waits for a person",
    **route_contract(stability="beta"),
)
async def reopen_alert(
    alert_id: str, body: ReopenIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> ReopenOut:
    """Put an alert the AI closed on the model's word back in front of a person. While its case is open it joins
    that case as open and the decision on the case settles it; otherwise a new run reviews it. Either way the AI
    never closes it on the model's word again. Audited ``alert.reopened`` with the person and the reason.

    409 ``not_ai_closed`` for any other alert, ``hidden_for_blind_audit`` while it waits for its blind-audit
    label, ``already_with_a_person``, ``not_in_case`` when ``case_id`` does not hold it.
    """
    return await _reopen(get_ctx(request), principal, alert_id, body, flag=False)


@router.post(
    "/{alert_id}/flag",
    response_model=ReopenOut,
    summary="Flag an AI close as wrong, with a reason: recorded as a disagreement, and the alert is reopened",
    **route_contract(stability="beta"),
)
async def flag_alert(
    alert_id: str, body: ReopenIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> ReopenOut:
    """Say the AI was wrong to close the alert. The disagreement is audited ``alert.flagged`` and counted by the
    blind-audit and accuracy reports; the alert is reopened as by ``/reopen``; and, because a person stands
    behind it, the safety net treats it as a confirmation: the other alerts the AI closed on the same host or
    user are reopened too. Same refusals as ``/reopen``.
    """
    return await _reopen(get_ctx(request), principal, alert_id, body, flag=True)
