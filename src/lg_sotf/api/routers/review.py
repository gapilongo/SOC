# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/escalations`` and ``/actions``: human review through :class:`~lg_sotf.services.review.ReviewService`.

Decisions and approvals commit first; the resume messages the service
returns are enqueued afterwards (one per waiting alert). A resume that
cannot be enqueued is reported in the response (``resumes_failed``) and
logged; the decision itself stands.

Escalations carry their owners' addresses and a digest of their alert
(:mod:`lg_sotf.services.escalation_views`). Every action carries its
guardrail verdict, blast radius and reversibility
(:mod:`lg_sotf.services.action_views`), its rollback eligibility
(``rollback``) and its live rollback (``rolled_back_by``). ``POST /actions/{id}/rollback`` requests a
rollback (:mod:`lg_sotf.services.rollback`), ``POST /actions/{id}/retry``
runs a failed Microsoft action again, and ``POST /actions/{id}/verify``
re-checks a finished verification (:mod:`lg_sotf.services.verification`).
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Dict, List, Literal, Optional, Sequence, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from lg_sotf.api.auth.deps import REVIEWER, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import escalations_out, one_escalation_out
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import (
    ActionOut,
    ApprovalIn,
    ApprovalOut,
    BlastRadiusOut,
    ClaimIn,
    DecisionIn,
    DecisionOut,
    EscalationOut,
    GuardrailOut,
    PageOut,
    RetryIn,
    RollbackEligibilityOut,
    RollbackIn,
    RollbackOut,
    VerifyIn,
)
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos import ResponseAction
from lg_sotf.models.vocabulary import ActionStatus, EscalationStatus
from lg_sotf.models.vocabulary import EscalationLevel as Level
from lg_sotf.models.vocabulary import RiskLevel as Risk
from lg_sotf.models.vocabulary import VerificationState as Verification
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.action_views import ActionView, action_views
from lg_sotf.services.response import ActionRequestError
from lg_sotf.services.review import ResumeRequest
from lg_sotf.services.rollback import RollbackService
from lg_sotf.services.verification import VerificationService

log = get_logger(__name__)

escalations = APIRouter(prefix="/escalations", tags=["escalations"])
actions = APIRouter(prefix="/actions", tags=["actions"])



def _rollbacks(ctx: ApiContext) -> RollbackService:
    return RollbackService(ctx.review.responses)


def action_out(
    rollbacks: RollbackService,
    action: ResponseAction,
    live: Optional[ResponseAction],
    *,
    now: datetime,
    view: Optional[ActionView] = None,
) -> ActionOut:
    """An action with its rollback eligibility and live rollback, and its guardrail and blast-radius view."""
    eligibility = rollbacks.eligibility(action, live, now=now)
    update: Dict[str, object] = {
        "rollback": RollbackEligibilityOut(**eligibility.as_dict()),
        "rolled_back_by": live.id if live is not None else None,
    }
    if view is not None:
        update.update(
            guardrail=GuardrailOut(**asdict(view.guardrail)) if view.guardrail else None,
            blast_radius=BlastRadiusOut(**asdict(view.blast_radius)),
            reversible=view.reversible,
            irreversible_note=view.irreversible_note,
        )
    return ActionOut.model_validate(action).model_copy(update=update)


async def actions_out(ctx: ApiContext, tenant_id: str, actions: Sequence[ResponseAction]) -> List[ActionOut]:
    """Many actions with their rollback state (live rollbacks read in one query) and their views."""
    live: Dict[UUID, ResponseAction] = await ctx.repos.actions.live_rollbacks(tenant_id, [a.id for a in actions])
    views = await action_views(ctx.repos, ctx.settings, tenant_id, actions)
    rollbacks = _rollbacks(ctx)
    now = datetime.now(UTC)
    return [action_out(rollbacks, a, live.get(a.id), now=now, view=views.get(a.id)) for a in actions]


async def one_action_out(ctx: ApiContext, tenant_id: str, action: ResponseAction) -> ActionOut:
    return (await actions_out(ctx, tenant_id, [action]))[0]


def action_error(exc: ActionRequestError) -> ApiError:
    return ApiError(exc.status, exc.code, str(exc), details=[{"reason": exc.reason}] if exc.reason else None)


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


async def invalidate_verdicts(ctx: ApiContext, tenant_id: str, alert_ids: Sequence[str]) -> None:
    """Drop cached benign verdicts of these alerts' fingerprints (an analyst confirmed a threat)."""
    cache = VerdictCache(ctx.redis, ctx.prefix)
    for alert_id in alert_ids:
        try:
            alert = await ctx.repos.alerts.get(tenant_id, alert_id)
            if alert.fingerprint:
                await cache.invalidate(tenant_id, alert.fingerprint)
        except Exception as exc:  # noqa: BLE001 - the workflow invalidates again when it plans the response
            log.warning("api.verdict_invalidate_failed", alert_id=alert_id, error_type=type(exc).__name__)


def _user_ref(principal: Principal, value: Optional[str], name: str) -> Optional[UUID]:
    if value is None:
        return None
    if value == "me":
        if principal.local_user_id is None:
            raise ApiError(400, "invalid_request", "'me' needs a user account in this tenant")
        return principal.local_user_id
    try:
        return UUID(value)
    except ValueError as exc:
        raise ApiError(400, "invalid_request", f"{name} must be a user id or 'me'") from exc


@escalations.get("", response_model=PageOut[EscalationOut], summary="List escalations (newest first, or by SLA)")
async def list_escalations(
    request: Request,
    status: Optional[List[EscalationStatus]] = Query(default=None),
    level: Optional[List[Level]] = Query(default=None),
    assigned_to: Optional[str] = Query(default=None, description="A user id, 'me', or 'none' (unassigned)"),
    decided_by: Optional[str] = Query(default=None, description="A user id or 'me'"),
    overdue: bool = Query(default=False, description="Only active escalations past their SLA deadline"),
    alert_id: Optional[str] = Query(default=None, max_length=256),
    order: Literal["created_at", "sla_deadline"] = Query(
        default="created_at",
        description="created_at: newest first. sla_deadline: soonest deadline first, so overdue escalations "
        "come first and those without a deadline last.",
    ),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[EscalationOut]:
    ctx = get_ctx(request)
    unassigned = assigned_to == "none"
    page = await ctx.repos.escalations.list(
        principal.tenant_id,
        status=status,
        level=level,
        assigned_to=None if unassigned else _user_ref(principal, assigned_to, "assigned_to"),
        unassigned=unassigned,
        decided_by=_user_ref(principal, decided_by, "decided_by"),
        overdue_at=datetime.now(UTC) if overdue else None,
        alert_id=alert_id,
        order=order,
        limit=limit,
        cursor=cursor,
    )
    items = await escalations_out(ctx, principal.tenant_id, page.items)
    return PageOut[EscalationOut](items=items, next_cursor=page.next_cursor)


@escalations.get("/{escalation_id}", response_model=EscalationOut, summary="Escalation detail")
async def get_escalation(
    escalation_id: str, request: Request, principal: Principal = Depends(require(VIEWER))
) -> EscalationOut:
    ctx = get_ctx(request)
    return await one_escalation_out(
        ctx, principal.tenant_id, await ctx.repos.escalations.get(principal.tenant_id, escalation_id)
    )


@escalations.post("/{escalation_id}/claim", response_model=EscalationOut, summary="Claim (assign to yourself)")
async def claim(
    escalation_id: str, body: ClaimIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> EscalationOut:
    assert principal.user_id is not None and principal.role is not None
    ctx = get_ctx(request)
    claimed = await ctx.review.claim(
        principal.tenant_id, escalation_id, principal.user_id, body.version, role=principal.role
    )
    return await one_escalation_out(ctx, principal.tenant_id, claimed)


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
    if body.decision == "true_positive":
        await invalidate_verdicts(ctx, principal.tenant_id, [result.escalation.alert_id])
    ok, failed = await enqueue_resumes(ctx, principal.tenant_id, result)
    return DecisionOut(
        escalation=await one_escalation_out(ctx, principal.tenant_id, result.escalation),
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
    verification: Optional[List[Verification]] = Query(default=None),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[ActionOut]:
    ctx = get_ctx(request)
    page = await ctx.repos.actions.list(
        principal.tenant_id,
        status=status,
        risk_level=risk_level,
        alert_id=alert_id,
        action_type=action_type,
        verification=verification,
        limit=limit,
        cursor=cursor,
    )
    items = await actions_out(ctx, principal.tenant_id, page.items)
    return PageOut[ActionOut](items=items, next_cursor=page.next_cursor)


@actions.get("/{action_id}", response_model=ActionOut, summary="Response action detail")
async def get_action(action_id: UUID, request: Request, principal: Principal = Depends(require(VIEWER))) -> ActionOut:
    ctx = get_ctx(request)
    return await one_action_out(ctx, principal.tenant_id, await ctx.repos.actions.get(principal.tenant_id, action_id))


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
        action=await one_action_out(ctx, principal.tenant_id, action),
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


@actions.post(
    "/{action_id}/rollback",
    status_code=201,
    response_model=RollbackOut,
    summary="Roll back an executed action (a new action of the inverse type)",
)
async def rollback(
    action_id: UUID, body: RollbackIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> RollbackOut:
    """Proposes the inverse action; approved at once when ``approve`` and your role may approve its risk.

    An existing live rollback is returned with ``created: false``. 409
    ``rollback_unavailable`` (``details[0].reason``) when the action cannot be
    rolled back.
    """
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    try:
        rolled, original, created = await _rollbacks(ctx).request(
            principal.tenant_id, action_id, user=principal.user_id, role=principal.role, reason=body.reason,
            approve=body.approve,
        )
    except ActionRequestError as exc:
        raise action_error(exc) from None
    rolled_out, original_out = await actions_out(ctx, principal.tenant_id, [rolled, original])
    return RollbackOut(rollback=rolled_out, original=original_out, created=created)


@actions.post("/{action_id}/retry", response_model=ActionOut, summary="Run a failed Microsoft action again")
async def retry(
    action_id: UUID, body: RetryIn, request: Request, principal: Principal = Depends(require(REVIEWER))
) -> ActionOut:
    """Allowed for a retryable (or partial) failure of a Microsoft action whose risk your role may approve.

    Guardrails and caps are checked again: 409 ``guardrail_blocked`` or
    ``cap_reached`` leave the action unchanged; 409 ``retry_unavailable``
    when it is not retryable. The scheduler executes it.
    """
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    try:
        updated = await ctx.review.responses.retry(
            principal.tenant_id, action_id, user=principal.user_id, role=principal.role, reason=body.reason
        )
    except ActionRequestError as exc:
        raise action_error(exc) from None
    return await one_action_out(ctx, principal.tenant_id, updated)


@actions.post("/{action_id}/verify", response_model=ActionOut, summary="Verify an executed Microsoft action again")
async def verify(
    action_id: UUID,
    request: Request,
    body: Optional[VerifyIn] = None,
    principal: Principal = Depends(require(REVIEWER)),
) -> ActionOut:
    """Re-opens a finished verification for an hour of checks. 409 when not applicable; 429 within 5 minutes."""
    ctx = get_ctx(request)
    assert principal.user_id is not None
    try:
        updated = await VerificationService(ctx.review.responses).recheck(
            principal.tenant_id, action_id, user=principal.user_id
        )
    except ActionRequestError as exc:
        raise action_error(exc) from None
    return await one_action_out(ctx, principal.tenant_id, updated)
