# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""Escalation triage: grouping by detection rule, bulk claim / close / suppression proposal, response preview.

Registered before the ``/escalations`` router so ``/escalations/groups`` and
``/escalations/bulk/...`` are not taken for an escalation id.

Bulk claim and close answer per-item results (200 whatever the items did;
see :mod:`lg_sotf.services.triage`); each item is the single-item call,
audited the same way. Proposing a suppression is all-or-nothing.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, Response

from lg_sotf.api.auth.deps import ANALYST, REVIEWER, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import escalations_out, user_ref
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError, describe_error
from lg_sotf.api.schemas import SuppressionOut
from lg_sotf.api.triage_schemas import (
    BulkClaimIn,
    BulkCloseIn,
    BulkErrorOut,
    BulkItemOut,
    BulkOut,
    BulkProposeSuppressionIn,
    EscalationGroupOut,
    EscalationGroupsOut,
    PreviewActionOut,
    PreviewConnectorOut,
    PreviewGuardrailOut,
    ResponsePreviewOut,
    SuppressionProposalOut,
)
from lg_sotf.domain.suppression import InvalidRule
from lg_sotf.observability.logging import get_logger
from lg_sotf.services import triage
from lg_sotf.services.response_preview import PreviewAction, response_preview
from lg_sotf.services.review import enqueue_resumes

log = get_logger(__name__)

router = APIRouter(prefix="/escalations", tags=["escalations"])

MAX_GROUPS = 100


@router.get("/groups", response_model=EscalationGroupsOut, summary="Active escalations grouped by detection rule")
async def groups(
    request: Request,
    assigned_to: Optional[str] = Query(default=None, description="A user id, 'me', or 'none' (unassigned)"),
    min_size: int = Query(default=2, ge=1, le=1_000, description="Smallest group returned"),
    limit: int = Query(default=50, ge=1, le=MAX_GROUPS),
    principal: Principal = Depends(require(VIEWER)),
) -> EscalationGroupsOut:
    """Open and claimed escalations grouped by their alert's source and rule (largest group first).

    List a group's escalations with ``GET /escalations?source_id=&rule=``.
    """
    ctx = get_ctx(request)
    now = datetime.now(UTC)
    unassigned = assigned_to == "none"
    found, truncated = await ctx.repos.views.escalation_groups(
        principal.tenant_id,
        now=now,
        assigned_to=None if unassigned else user_ref(principal, assigned_to, "assigned_to"),
        unassigned=unassigned,
        min_size=min_size,
        limit=limit,
    )
    return EscalationGroupsOut(
        items=[EscalationGroupOut.model_validate(g.model_dump()) for g in found],
        truncated=truncated,
        generated_at=now,
    )


def _items(outcomes: List[triage.ItemOutcome]) -> List[BulkItemOut]:
    results: List[BulkItemOut] = []
    for outcome in outcomes:
        if outcome.error is not None:
            described = describe_error(outcome.error)
            assert described is not None  # ITEM_ERRORS all have a registered handler
            status, code, message = described
            results.append(
                BulkItemOut(
                    escalation_id=outcome.escalation_id,
                    ok=False,
                    error=BulkErrorOut(status=status, code=code, message=message),
                )
            )
        else:
            results.append(BulkItemOut(escalation_id=outcome.escalation_id, ok=True))
    return results


async def _bulk_out(ctx: ApiContext, tenant_id: str, outcomes: List[triage.ItemOutcome]) -> BulkOut:
    results = _items(outcomes)
    # Resumes first: the decisions are committed, whatever happens to the read below.
    for item, outcome in zip(results, outcomes, strict=True):
        if outcome.decision is not None:
            item.resumes_enqueued, item.resumes_failed = await enqueue_resumes(ctx.queue, tenant_id, outcome.decision)
    done = [o.escalation for o in outcomes if o.escalation is not None]
    rows = {e.id: e for e in await escalations_out(ctx, tenant_id, done)}
    for item, outcome in zip(results, outcomes, strict=True):
        if outcome.escalation is not None:
            item.escalation = rows.get(outcome.escalation.id)
    succeeded = sum(1 for r in results if r.ok)
    return BulkOut(results=results, succeeded=succeeded, failed=len(results) - succeeded)


@router.post("/bulk/claim", response_model=BulkOut, summary="Claim several escalations (per-item results)")
async def bulk_claim(body: BulkClaimIn, request: Request, principal: Principal = Depends(require(REVIEWER))) -> BulkOut:
    """Each item is ``POST /escalations/{id}/claim`` with its ``version``; failures are reported per item."""
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    outcomes = await triage.bulk_claim(
        ctx.review,
        principal.tenant_id,
        [(i.escalation_id, i.version) for i in body.items],
        user=principal.user_id,
        role=principal.role,
    )
    return await _bulk_out(ctx, principal.tenant_id, outcomes)


@router.post(
    "/bulk/close", response_model=BulkOut, summary="Close several escalations as benign with one note (per-item results)"
)
async def bulk_close(body: BulkCloseIn, request: Request, principal: Principal = Depends(require(REVIEWER))) -> BulkOut:
    """Each item is ``POST /escalations/{id}/decision`` with ``decision`` and ``notes``; failures are reported
    per item. With ``propose_suppression`` one disabled rule is proposed from the escalations that closed
    (and no per-escalation suggestion is made)."""
    ctx = get_ctx(request)
    assert principal.user_id is not None and principal.role is not None
    outcomes = await triage.bulk_close(
        ctx.review,
        principal.tenant_id,
        [(i.escalation_id, i.version) for i in body.items],
        user=principal.user_id,
        role=principal.role,
        decision=body.decision,
        notes=body.notes,
        suggest_suppression=False if body.propose_suppression else None,
    )
    out = await _bulk_out(ctx, principal.tenant_id, outcomes)
    closed = [o.escalation_id for o in outcomes if o.error is None]
    if body.propose_suppression and closed:
        try:
            proposal = await triage.propose_suppression(
                ctx.repos,
                ctx.review,
                principal.tenant_id,
                closed,
                actor_type=principal.actor_type,
                actor_id=principal.actor_id,
                created_by=principal.local_user_id,
            )
        except InvalidRule:
            log.warning("triage.bulk_close_proposal_invalid")
        else:
            if proposal.rule is not None:
                out.suppression = SuppressionOut.model_validate(proposal.rule)
                out.suppression_created = proposal.created
    return out


@router.post(
    "/bulk/propose-suppression",
    response_model=SuppressionProposalOut,
    status_code=201,
    summary="Propose one (disabled) suppression rule from escalations decided benign; an admin enables it",
)
async def bulk_propose_suppression(
    body: BulkProposeSuppressionIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(require(ANALYST)),
) -> SuppressionProposalOut:
    """All-or-nothing: 404 when an escalation is not found, 422 ``not_confirmed_benign`` (``details`` lists
    them) when one has no false_positive/benign_positive decision. 200 with the existing rule when an
    unexpired rule already has the same match."""
    ctx = get_ctx(request)
    proposal = await triage.propose_suppression(
        ctx.repos,
        ctx.review,
        principal.tenant_id,
        body.escalation_ids,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        created_by=principal.local_user_id,
        name=body.name,
    )
    if proposal.rule is None:
        raise ApiError(
            422,
            "not_confirmed_benign",
            "every escalation needs an analyst's false_positive or benign_positive decision",
            details=[{"escalation_id": i} for i in proposal.unconfirmed],
        )
    if not proposal.created:
        response.status_code = 200
    return SuppressionProposalOut(
        suppression=SuppressionOut.model_validate(proposal.rule),
        created=proposal.created,
        escalation_ids=proposal.escalation_ids,
    )


def _preview_action(action: PreviewAction) -> PreviewActionOut:
    data = asdict(action)
    return PreviewActionOut(
        **{k: v for k, v in data.items() if not k.startswith(("connector", "guardrail_"))},
        connector=PreviewConnectorOut(
            name=action.connector, source=action.connector_source, live=action.connector_live, ready=action.connector_ready
        ),
        guardrail=PreviewGuardrailOut(
            verdict=action.guardrail_verdict, code=action.guardrail_code, reason=action.guardrail_reason
        ),
    )


@router.get(
    "/{escalation_id}/response-preview",
    response_model=ResponsePreviewOut,
    summary="Dry run of the response plan a true_positive decision would produce",
)
async def preview(
    escalation_id: str, request: Request, principal: Principal = Depends(require(VIEWER))
) -> ResponsePreviewOut:
    """Nothing is written and no connector is called; ``can_preapprove`` and ``role_lock`` are for your role."""
    ctx = get_ctx(request)
    result = await response_preview(
        ctx.repos, ctx.review.responses, principal.tenant_id, escalation_id, role=principal.role
    )
    return ResponsePreviewOut(
        escalation_id=result.escalation_id,
        alert_id=result.alert_id,
        generated_at=result.generated_at,
        threat_type=result.threat_type,
        evidence=result.evidence,
        dry_run_forced=result.dry_run_forced,
        actions=[_preview_action(a) for a in result.actions],
    )

