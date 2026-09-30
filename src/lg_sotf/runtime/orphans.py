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
from typing import List, Optional, Tuple

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from lg_sotf.db.pool import Database
from lg_sotf.queue.streams import CONSUMER_GROUP, QueueStreams
from lg_sotf.settings import Settings

_CLAIM_ORPHANS_SQL = """
WITH picked AS (
    SELECT tenant_id, alert_id FROM workflow_runs
    WHERE (($1::float8 IS NOT NULL AND status = 'queued' AND updated_at < now() - make_interval(secs => $1))
           OR (status = 'failed' AND updated_at < now() - make_interval(secs => $2)))
      AND tenant_id IN (SELECT id FROM tenants WHERE status = 'active')
    ORDER BY updated_at
    LIMIT $3
    FOR UPDATE SKIP LOCKED
)
UPDATE workflow_runs r SET updated_at = now()
FROM picked p, alerts a
WHERE r.tenant_id = p.tenant_id AND r.alert_id = p.alert_id
  AND a.tenant_id = r.tenant_id AND a.id = r.alert_id
RETURNING r.tenant_id, r.alert_id, r.status, r.attempt, a.severity
"""


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
    if limit < 1:
        raise ValueError("limit must be >= 1")
    async with db.system_tx() as conn:
        rows = await conn.fetch(
            _CLAIM_ORPHANS_SQL,
            None if queued_older_than_s is None else float(queued_older_than_s),
            float(failed_older_than_s),
            limit,
        )
    return [
        OrphanedRun(
            tenant_id=r["tenant_id"],
            alert_id=r["alert_id"],
            status=r["status"],
            attempt=r["attempt"],
            severity=r["severity"],
        )
        for r in rows
    ]


_STRANDED_NEW_SQL = """
SELECT a.tenant_id, a.id AS alert_id, a.severity
FROM alerts a
WHERE a.status = 'new' AND a.ingested_at < now() - make_interval(secs => $1)
  AND a.tenant_id IN (SELECT id FROM tenants WHERE status = 'active')
  AND NOT EXISTS (SELECT 1 FROM workflow_runs r WHERE r.tenant_id = a.tenant_id AND r.alert_id = a.id)
ORDER BY a.ingested_at
LIMIT $2
"""
# An alert stays 'new' only between its insert and the dispatch right after it.
STRANDED_NEW_AFTER_S = 300.0


@dataclass(frozen=True)
class StrandedAlert:
    tenant_id: str
    alert_id: str
    severity: str


async def find_stranded_new_alerts(db: Database, *, older_than_s: float, limit: int) -> List[StrandedAlert]:
    """Alerts stored but never dispatched (no run): a crash or cancel between insert and dispatch."""
    async with db.system_tx(readonly=True) as conn:
        rows = await conn.fetch(_STRANDED_NEW_SQL, float(older_than_s), limit)
    return [StrandedAlert(r["tenant_id"], r["alert_id"], r["severity"]) for r in rows]


def _text(value: object) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


async def oldest_undelivered_age_s(redis: Redis, streams: QueueStreams) -> float:
    """Age of the oldest work entry not yet delivered to the ``workers`` group (0 when caught up).

    A queued run older than this may simply be waiting its turn in the backlog.
    """
    now_ms = time.time() * 1000
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
