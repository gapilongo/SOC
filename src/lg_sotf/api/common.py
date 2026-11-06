"""Response builders shared by several routers (routers never import each other)."""

from __future__ import annotations

from typing import List, Optional, Sequence

from lg_sotf.api.context import ApiContext
from lg_sotf.api.schemas import AlertDetailOut, AlertOut, EntitiesPreviewOut, EscalationOut, FindingOut, RoutingOut
from lg_sotf.db.repos import Alert, AlertListItem, Escalation
from lg_sotf.domain.digests import entities_preview, findings
from lg_sotf.services.escalation_views import EscalationView, escalation_views


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
