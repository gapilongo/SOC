"""Recovery of workflow runs that have no queue message.

A run can be left ``queued`` or ``failed`` with nothing in Redis to drive it:
Redis lost data (failover without persistence), a process died between a
committed database change and its ``XADD``, or a pending entry was deleted.
Contract section 1 makes Redis entries re-derivable from ``workflow_runs``;
:func:`claim_orphaned_runs` is that derivation. Re-enqueueing a run that
still has a message is harmless: the claim rules let exactly one of the
duplicates execute and the retry budget lives on ``workflow_runs.attempt``.
Suspended tenants are skipped: the worker leaves their work queued, and
these sweeps hand it back to the workers once the tenant is reactivated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from lg_sotf.db.pool import Database
from lg_sotf.db.repos.alerts import AlertsRepo
from lg_sotf.db.repos.runs import RunsRepo
from lg_sotf.queue.streams import CONSUMER_GROUP, QueueStreams
from lg_sotf.settings import Settings


@dataclass(frozen=True)
class OrphanedRun:
    tenant_id: str
    alert_id: str
    status: str
    attempt: int
    severity: str


def orphan_thresholds(settings: Settings) -> Tuple[float, float]:
    """Seconds without a change after which a ``queued`` / ``failed`` run counts as orphaned.

    A queued run's message is normally read within one visibility timeout; a
    failed run's pending entry is reclaimed once per visibility timeout until
    ``max_deliveries`` is used up.
    """
    visibility = float(settings.worker.visibility_timeout_s)
    return 2 * visibility, visibility * max(settings.worker.max_deliveries, 1)


async def claim_orphaned_runs(
    db: Database, *, queued_older_than_s: Optional[float], failed_older_than_s: float, limit: int
) -> List[OrphanedRun]:
    """Pick orphaned runs across tenants, oldest first, and touch ``updated_at`` so each is returned once per threshold.

    ``queued_older_than_s=None`` skips queued runs. Needs the owner role (``system_tx``).
    """
    rows = await RunsRepo(db).claim_orphaned_all_tenants(
        queued_older_than_s=queued_older_than_s, failed_older_than_s=failed_older_than_s, limit=limit
    )
    return [
        OrphanedRun(tenant_id=r.tenant_id, alert_id=r.alert_id, status=r.status, attempt=r.attempt, severity=r.severity)
        for r in rows
    ]


# An alert stays 'new' only between its insert and the dispatch right after it.
STRANDED_NEW_AFTER_S = 300.0


@dataclass(frozen=True)
class StrandedAlert:
    tenant_id: str
    alert_id: str
    severity: str


async def find_stranded_new_alerts(db: Database, *, older_than_s: float, limit: int) -> List[StrandedAlert]:
    """Alerts stored but never dispatched (no run): a crash or cancel between insert and dispatch."""
    rows = await AlertsRepo(db).find_stranded_new_all_tenants(older_than_s=older_than_s, limit=limit)
    return [StrandedAlert(r.tenant_id, r.alert_id, r.severity) for r in rows]


def _text(value: object) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


async def oldest_undelivered_age_s(
    redis: Redis, streams: QueueStreams, *, clock: Callable[[], float] = time.time
) -> float:
    """Age of the oldest work entry not yet delivered to the ``workers`` group (0 when caught up).

    A queued run older than this may simply be waiting its turn in the backlog. ``clock`` is
    the wall clock (stream ids are epoch milliseconds).
    """
    now_ms = clock() * 1000
    oldest = 0.0
    for stream in streams.work:
        try:
            groups = await redis.xinfo_groups(stream)
        except ResponseError as exc:
            if "no such key" in str(exc).lower():
                continue
            raise
        last_delivered = "0-0"
        for group in groups:
            if _text(group.get("name")) == CONSUMER_GROUP:
                last_delivered = _text(group.get("last-delivered-id") or "0-0")
        entries = await redis.xrange(stream, min=f"({last_delivered}", max="+", count=1)
        if entries:
            entry_ms = int(_text(entries[0][0]).split("-", 1)[0])
            oldest = max(oldest, (now_ms - entry_ms) / 1000.0)
    return oldest
