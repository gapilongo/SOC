"""One alert's timeline and the audited analyst changes on it: notes and reprocess requests.

Each change runs with its audit entry in one ``db.tenant_tx``, so an audit
failure rolls the change back. Publishing the change and enqueueing work
happen after the commit, in the caller (``api.routers.alerts``).
"""

from __future__ import annotations

from typing import Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.pagination import Page
from lg_sotf.db.repos import Alert, AlertEvent, Repositories
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)


async def timeline(
    repos: Repositories, tenant_id: str, alert_id: str, *, limit: int, cursor: Optional[str]
) -> Page[AlertEvent]:
    """The alert's events, oldest first (``NotFound`` when the alert is not the tenant's)."""
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        await repos.alerts.get(tenant_id, alert_id, conn=conn)
        return await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=limit, cursor=cursor, conn=conn)


async def add_note(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    alert_id: str,
    *,
    text: str,
    author: str,
    timeline_actor: Actor,
) -> AlertEvent:
    """Append a ``note`` event to the timeline as ``timeline_actor``; audited ``alert.note_added``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        await repos.alerts.get(tenant_id, alert_id, conn=conn)
        event = await repos.alert_events.append(
            tenant_id,
            alert_id,
            "note",
            actor_type=timeline_actor.type,
            actor_id=timeline_actor.id,
            data={"text": text, "author": author},
            conn=conn,
        )
        await audit.record(
            tenant_id,
            "alert.note_added",
            "alert",
            alert_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"event_id": event.id},
            conn=conn,
        )
    return event


async def request_reprocess(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, alert_id: str
) -> Alert:
    """Queue the alert's run again and the alert with it; audited ``alert.reprocess_requested``.

    A finished run is reset to ``queued``. A run that is claimed or running
    cannot be: ``InvalidTransition`` (``current`` is the run's status) and
    nothing changes. An alert whose status cannot move to ``queued`` keeps it.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        previous = alert.status
        run = await repos.runs.upsert_queued(tenant_id, alert_id, requeue_terminal=True, conn=conn)
        if run.status != "queued":
            raise InvalidTransition("workflow run", alert_id, run.status, "queued")
        try:
            alert = await repos.alerts.update_status(tenant_id, alert_id, "queued", conn=conn)
        except InvalidTransition:
            log.info("api.reprocess_status_kept", status=previous)
        await audit.record(
            tenant_id,
            "alert.reprocess_requested",
            "alert",
            alert_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"previous_status": previous},
            conn=conn,
        )
    return alert
