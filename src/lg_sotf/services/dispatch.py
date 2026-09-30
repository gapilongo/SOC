"""Hand newly ingested alerts to the workers."""

from __future__ import annotations

from typing import List, Optional, Protocol, Sequence, Tuple

from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.db.repos import Repositories
from lg_sotf.integrations.outbox import enqueue_critical_alerts
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
    severity = {a.alert_id: a.severity for a in alerts}
    # One transaction with a fixed number of statements for the whole batch (PERF-3); an alert
    # whose run left 'queued' is not enqueued, one whose alert row moved on keeps its status.
    critical = {a for a, s in severity.items() if s == "critical"}
    if critical:
        # Critical alerts also notify subscribed integrations, in the same transaction (outbox).
        async with repos.db.tenant_tx(tenant_id) as conn:
            queued = await repos.runs.queue_alerts(tenant_id, list(severity), conn=conn)
            await enqueue_critical_alerts(conn, tenant_id, [a for a in queued if a in critical])
    else:
        queued = await repos.runs.queue_alerts(tenant_id, list(severity))
    to_enqueue: List[Tuple[str, str]] = [(a, severity[a]) for a in queued]
    await queue.enqueue_process_many(tenant_id, to_enqueue)
    for alert_id, sev in to_enqueue:
        await publish_event(events, "alert.created", tenant_id, alert_id, {"status": "queued", "severity": sev})
    if to_enqueue:
        log.info("dispatch.enqueued", tenant_id=tenant_id, count=len(to_enqueue), skipped=len(alerts) - len(to_enqueue))
    return len(to_enqueue)
