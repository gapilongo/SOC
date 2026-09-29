# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/escalations`` and ``/actions``: human review through :class:`~lg_sotf.services.review.ReviewService`.

Decisions and approvals commit first; the resume messages the service
returns are enqueued afterwards (one per waiting alert). A resume that
cannot be enqueued is reported in the response (``resumes_failed``) and
logged; the decision itself stands.
"""

from __future__ import annotations

from typing import List, Literal, Optional, Sequence, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from lg_sotf.api.auth.deps import REVIEWER, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import (
    ActionOut,
    ApprovalIn,
    ApprovalOut,
    ClaimIn,
    DecisionIn,
    DecisionOut,
    EscalationOut,
    PageOut,
)
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.review import ResumeRequest

log = get_logger(__name__)

escalations = APIRouter(prefix="/escalations", tags=["escalations"])
actions = APIRouter(prefix="/actions", tags=["actions"])

EscalationStatus = Literal["open", "claimed", "decided", "expired", "cancelled"]
Level = Literal["L1", "L2", "L3"]
ActionStatus = Literal[
    "proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "dry_run", "blocked"
]
Risk = Literal["low", "medium", "high", "critical"]
MAX_LIMIT = 200


async def enqueue_resumes(ctx: ApiContext, tenant_id: str, requests: Sequence[ResumeRequest]) -> Tuple[int, int]:
    ok = failed = 0
    for request in requests:
        try:
            await ctx.queue.enqueue_resume(tenant_id, request.alert_id, request.payload)
            ok += 1
        except Exception as exc:  # noqa: BLE001 - the decision is committed; report instead of failing it
            failed += 1
            log.error("api.resume_enqueue_failed", alert_id=request.alert_id, error_type=type(exc).__name__)
    return ok, failed


def _assignee(principal: Principal, value: Optional[str]) -> Optional[UUID]:
    if value is None:
        return None
    if value == "me":
        if principal.local_user_id is None:
            raise ApiError(400, "invalid_request", "'me' needs a user account in this tenant")
        return principal.local_user_id
    try:
        return UUID(value)
    except ValueError as exc:
        raise ApiError(400, "invalid_request", "assigned_to must be a user id or 'me'") from exc


@escalations.get("", response_model=PageOut[EscalationOut], summary="List escalations (newest first)")
async def list_escalations(
    request: Request,
    status: Optional[List[EscalationStatus]] = Query(default=None),
    level: Optional[List[Level]] = Query(default=None),
    assigned_to: Optional[str] = Query(default=None, description="A user id or 'me'"),
    alert_id: Optional[str] = Query(default=None, max_length=256),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[EscalationOut]:
    page = await get_ctx(request).repos.escalations.list(
        principal.tenant_id,
        status=status,
        level=level,
        assigned_to=_assignee(principal, assigned_to),
        alert_id=alert_id,
        limit=limit,
        cursor=cursor,
    )
    return PageOut[EscalationOut](
        items=[EscalationOut.model_validate(e) for e in page.items], next_cursor=page.next_cursor
    )


@escalations.get("/{escalation_id}", response_model=EscalationOut, summary="Escalation detail")
async def get_escalation(
    escalation_id: str, request: Request, principal: Principal = Depends(require(VIEWER))
) -> EscalationOut:
    return EscalationOut.model_validate(
        await get_ctx(request).repos.escalations.get(principal.tenant_id, escalation_id)
    )


@escalations.post("/{escalation_id}/claim", response_model=EscalationOut, summary="Claim (assign to yourself)")
async def claim(
    escalation_id: str, body: ClaimIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> EscalationOut:
    assert principal.user_id is not None and principal.role is not None
    claimed = await get_ctx(request).review.claim(
        principal.tenant_id, escalation_id, principal.user_id, body.version, role=principal.role
    )
    return EscalationOut.model_validate(claimed)


@escalations.post(
    "/{escalation_id}/decision", response_model=DecisionOut, summary="Record the analyst decision and resume the run(s)"
)
async def decide(
    escalation_id: str, body: DecisionIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> DecisionOut:
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    result = await ctx.review.decide(
        principal.tenant_id,
        escalation_id,
        principal.user_id,
        principal.role,
        body.decision,
        body.notes,
        body.approved_actions,
        body.version,
        feedback=body.feedback.model_dump(exclude_none=True) if body.feedback else None,
        suggest_suppression=body.suggest_suppression,
    )
    ok, failed = await enqueue_resumes(ctx, principal.tenant_id, result)
    return DecisionOut(
        escalation=EscalationOut.model_validate(result.escalation),
        approved_actions=result.approved_actions,
        resumed_alert_ids=[r.alert_id for r in result],
        own_review_alert_ids=result.own_review_alert_ids,
        feedback_id=result.feedback_id,
        suppression_suggestion_id=result.suppression_suggestion_id,
        resumes_enqueued=ok,
        resumes_failed=failed,
    )


@actions.get("", response_model=PageOut[ActionOut], summary="Response action ledger (newest first)")
async def list_actions(
    request: Request,
    status: Optional[List[ActionStatus]] = Query(default=None),
    risk_level: Optional[List[Risk]] = Query(default=None),
    alert_id: Optional[str] = Query(default=None, max_length=256),
    action_type: Optional[str] = Query(default=None, max_length=64),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[ActionOut]:
    page = await get_ctx(request).repos.actions.list(
        principal.tenant_id,
        status=status,
        risk_level=risk_level,
        alert_id=alert_id,
        action_type=action_type,
        limit=limit,
        cursor=cursor,
    )
    return PageOut[ActionOut](items=[ActionOut.model_validate(a) for a in page.items], next_cursor=page.next_cursor)


@actions.get("/{action_id}", response_model=ActionOut, summary="Response action detail")
async def get_action(action_id: UUID, request: Request, principal: Principal = Depends(require(VIEWER))) -> ActionOut:
    return ActionOut.model_validate(await get_ctx(request).repos.actions.get(principal.tenant_id, action_id))


async def _review_action(
    request: Request, principal: Principal, action_id: UUID, body: ApprovalIn, *, approve: bool
) -> ApprovalOut:
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    review = ctx.review.approve_actions if approve else ctx.review.reject_actions
    requests = await review(
        principal.tenant_id, [action_id], principal.user_id, principal.role, reject_remaining=body.reject_remaining
    )
    ok, failed = await enqueue_resumes(ctx, principal.tenant_id, requests)
    action = await ctx.repos.actions.get(principal.tenant_id, action_id)
    return ApprovalOut(
        action=ActionOut.model_validate(action),
        resumed_alert_ids=[r.alert_id for r in requests],
        resumes_enqueued=ok,
        resumes_failed=failed,
    )


@actions.post("/{action_id}/approve", response_model=ApprovalOut, summary="Approve one pending action")
async def approve(
    action_id: UUID,
    request: Request,
    body: Optional[ApprovalIn] = None,
    principal: Principal = Depends(require(REVIEWER)),
) -> ApprovalOut:
    return await _review_action(request, principal, action_id, body or ApprovalIn(), approve=True)


@actions.post("/{action_id}/reject", response_model=ApprovalOut, summary="Reject one pending action")
async def reject(
    action_id: UUID,
    request: Request,
    body: Optional[ApprovalIn] = None,
    principal: Principal = Depends(require(REVIEWER)),
) -> ApprovalOut:
    return await _review_action(request, principal, action_id, body or ApprovalIn(), approve=False)
