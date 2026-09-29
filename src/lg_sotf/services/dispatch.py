"""Hand newly ingested alerts to the workers."""

from __future__ import annotations

from typing import List, Optional, Protocol, Sequence, Tuple

from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.repos import Repositories
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.producer import WorkQueue

log = get_logger(__name__)


class DispatchableAlert(Protocol):
    """Structural type of ``lg_sotf.models.alert.IngestedAlert``."""

    @property
    def alert_id(self) -> str: ...

    @property
    def severity(self) -> str: ...


async def dispatch_new_alerts(
    repos: Repositories,
    queue: WorkQueue,
    tenant_id: str,
    alerts: Sequence[DispatchableAlert],
    *,
    events: Optional[EventPublisher] = None,
) -> int:
    """Create queued runs, mark the alerts ``queued`` and enqueue ``process`` messages.

    Idempotent: an alert whose run already left ``queued`` (running, waiting,
    finished) is not enqueued again, and repeating a dispatch for a still
    queued run only adds a duplicate message, which the worker drops. The
    database changes commit before anything is enqueued, so a worker never
    sees a message for a run that does not exist. Returns the number of
    messages enqueued.

    With ``events``, an ``alert.created`` event (best effort) is published
    for every alert enqueued, so live UIs see new alerts before a worker
    picks them up.
    """
    if not alerts:
        return 0
    to_enqueue: List[Tuple[str, str]] = []
    async with repos.db.tenant_tx(tenant_id) as conn:
        for alert in alerts:
            run = await repos.runs.upsert_queued(tenant_id, alert.alert_id, conn=conn)
            if run.status != "queued":
                continue
            try:
                await repos.alerts.update_status(tenant_id, alert.alert_id, "queued", conn=conn)
            except InvalidTransition as exc:
                # The run is queued (e.g. recovered after a crash) but the alert moved on; the run decides.
                log.info("dispatch.alert_status_kept", alert_id=alert.alert_id, status=exc.current)
            to_enqueue.append((alert.alert_id, alert.severity))
    for alert_id, severity in to_enqueue:
        await queue.enqueue_process(tenant_id, alert_id, severity)
        await publish_event(events, "alert.created", tenant_id, alert_id, {"status": "queued", "severity": severity})
    if to_enqueue:
        log.info("dispatch.enqueued", tenant_id=tenant_id, count=len(to_enqueue), skipped=len(alerts) - len(to_enqueue))
    return len(to_enqueue)
