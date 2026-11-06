"""Helpers shared by several routers (routers never import each other): response builders, resume enqueueing."""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple
from uuid import UUID

from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import AlertDetailOut, AlertOut, EntitiesPreviewOut, EscalationOut, FindingOut, RoutingOut
from lg_sotf.db.repos import Alert, AlertListItem, Escalation
from lg_sotf.domain.digests import entities_preview, findings
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.escalation_views import EscalationView, escalation_views
from lg_sotf.services.review import ResumeRequest

log = get_logger(__name__)


def user_ref(principal: Principal, value: Optional[str], name: str) -> Optional[UUID]:
    """A user filter: a user id, or ``me`` (the caller's account in this tenant)."""
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


async def enqueue_resumes(ctx: ApiContext, tenant_id: str, requests: Sequence[ResumeRequest]) -> Tuple[int, int]:
    """Enqueue a committed decision's resume messages: ``(enqueued, failed)``. A failure is logged and
    counted, never raised: the decision stands."""
    ok = failed = 0
    for request in requests:
        try:
            await ctx.queue.enqueue_resume(tenant_id, request.alert_id, request.payload)
            ok += 1
        except Exception as exc:  # noqa: BLE001 - the decision is committed; report instead of failing it
            failed += 1
            log.error("api.resume_enqueue_failed", alert_id=request.alert_id, error_type=type(exc).__name__)
    return ok, failed


def alert_out(alert: AlertListItem) -> AlertOut:
    preview = entities_preview(alert.entities)
    return AlertOut.model_validate(alert).model_copy(
        update={"entities_preview": EntitiesPreviewOut.model_validate(preview) if preview else None}
    )


def alert_detail_out(alert: Alert) -> AlertDetailOut:
    preview = entities_preview(alert.entities)
    return AlertDetailOut.model_validate(alert).model_copy(
        update={
            "entities_preview": EntitiesPreviewOut.model_validate(preview) if preview else None,
            "findings": [FindingOut.model_validate(f) for f in findings(alert.summary)],
        }
    )


def escalation_out(escalation: Escalation, view: Optional[EscalationView]) -> EscalationOut:
    out = EscalationOut.model_validate(escalation)
    if view is None:
        return out
    return out.model_copy(
        update={
            "assigned_to_email": view.assigned_to_email,
            "decided_by_email": view.decided_by_email,
            "alert_severity": view.alert_severity,
            "rule": view.rule,
            "source_id": view.source_id,
            "source_name": view.source_name,
            "entities_preview": EntitiesPreviewOut.model_validate(view.entities_preview) if view.entities_preview else None,
            "ai_reason": view.ai_reason,
            "ai_reason_source": view.ai_reason_source,
            "routing": RoutingOut.model_validate(view.routing) if view.routing else None,
        }
    )


async def escalations_out(ctx: ApiContext, tenant_id: str, escalations: Sequence[Escalation]) -> List[EscalationOut]:
    """Escalations with their owners' addresses and their alerts' digests (two lookups per call)."""
    views = await escalation_views(ctx.repos, tenant_id, escalations)
    return [escalation_out(e, views.get(e.id)) for e in escalations]


async def one_escalation_out(ctx: ApiContext, tenant_id: str, escalation: Escalation) -> EscalationOut:
    return (await escalations_out(ctx, tenant_id, [escalation]))[0]
