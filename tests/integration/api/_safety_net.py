"""Helpers of the safety net API tests (decision policy v3, AI-E3.15): model-closed alerts, a threat with an
alert linked to it, and the audited alerts of an action."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict, List, Optional

from lg_sotf.audit.logger import Actor
from lg_sotf.core.retro_reopen import link_related_model_closes
from lg_sotf.db.repos import Escalation
from lg_sotf.domain import closure
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

LONG_AGO = datetime.now(UTC) - timedelta(days=3)  # outside the safety net's 24-hour window


async def model_closed(api: ApiHarness, entities: Dict[str, List[str]], closed_at: Optional[datetime] = None) -> str:
    alert_id = await make_alert(api.repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(TENANT_A, alert_id, status, now=closed_at)
    await api.repos.alerts.update(TENANT_A, alert_id, disposition="benign",
                                  summary={"close_reason": closure.MODEL_CLOSE_REASON})
    return alert_id


async def threat_with_linked(api: ApiHarness, host: str, *, case: bool = True) -> tuple[str, str, Optional[Escalation]]:
    """A threat a model judged three days ago, its open case (if any) and the model close linked to it then."""
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": [host]}})
    linked = await model_closed(api, {"hosts": [host]}, closed_at=LONG_AGO)
    escalation = None
    if case:
        escalation, _ = await api.repos.escalations.create_or_attach(
            TENANT_A, threat, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
        )
    assert await link_related_model_closes(
        api.repos, TENANT_A, await api.repos.alerts.get(TENANT_A, threat), actor=Actor("agent", "workflow"),
        escalation_id=escalation.id if escalation else None, now=LONG_AGO + timedelta(hours=1),
    ) == [linked]
    return threat, linked, await api.repos.escalations.get(TENANT_A, escalation.id) if escalation else None


async def audited(api: ApiHarness, action: str) -> List[str]:
    return [e.resource_id for e in (await api.repos.audit.list(TENANT_A, action=action)).items]
