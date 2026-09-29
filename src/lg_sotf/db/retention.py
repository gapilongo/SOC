"""Data retention (scheduler maintenance job, system scope).

Deletes run in bounded batches, each in its own short transaction, so the job
never holds long locks or bloats a single transaction. Tenants may override
``alerts_days`` and ``indicators_days`` via ``settings.retention`` in their
tenant settings; partitioned tables (``alert_events``, ``audit_log``) follow
the global setting because they are dropped a whole month at a time.

Alerts expire when they ended (``closed`` since ``closed_at``, or ``failed``,
e.g. dead-lettered, since their last change) more than ``alerts_days`` ago.
An alert's LangGraph checkpoints (its full workflow state) are deleted in
the same transaction as the alert, so a tenant ``alerts_days`` shorter than
``checkpoints_days`` never leaves unreachable checkpoints behind; checkpoint
threads without a run (whatever the cause) are removed once they are older
than ``checkpoints_days``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog

from lg_sotf.db.partitions import (
    DEFAULT_LOCK_TIMEOUT_MS,
    default_partition_name,
    drop_expired_partitions,
    expired_partitions,
)
from lg_sotf.db.pool import Database
from lg_sotf.settings import RetentionSettings, get_settings

log = structlog.get_logger(__name__)

REFRESH_TOKEN_GRACE = timedelta(days=1)
_OVERRIDE_PATTERN = "^[1-9][0-9]{0,4}$"
_OVERRIDE_KEYS = ("alerts_days", "indicators_days")


@dataclass
class RetentionReport:
    alerts: int = 0
    indicator_sightings: int = 0
    llm_usage_rows: int = 0
    refresh_tokens: int = 0
    checkpoint_threads: int = 0
    default_partition_rows: int = 0
    dropped_partitions: List[str] = field(default_factory=list)
    busy_partitions: List[str] = field(default_factory=list)
    """Expired partitions not dropped because their locks were busy (lock_timeout)."""
    complete: bool = True
    """False when a step stopped at ``max_batches`` or a partition was busy; the next run continues."""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "alerts": self.alerts,
            "indicator_sightings": self.indicator_sightings,
            "llm_usage_rows": self.llm_usage_rows,
            "refresh_tokens": self.refresh_tokens,
            "checkpoint_threads": self.checkpoint_threads,
            "default_partition_rows": self.default_partition_rows,
            "dropped_partitions": list(self.dropped_partitions),
            "busy_partitions": list(self.busy_partitions),
            "complete": self.complete,
        }


def _override_days(key: str) -> str:
    if key not in _OVERRIDE_KEYS:
        raise ValueError(key)
    return (
        f"CASE WHEN t.settings->'retention'->>'{key}' ~ '{_OVERRIDE_PATTERN}' "
        f"THEN (t.settings->'retention'->>'{key}')::int END"
    )


async def _min_days(db: Database, key: str, default_days: int) -> int:
    async with db.system_tx(readonly=True) as c:
        override = await c.fetchval(f"SELECT min({_override_days(key)}) FROM tenants t")  # noqa: S608
    return default_days if override is None else min(default_days, int(override))


async def _batched(
    db: Database, sql: str, args: Tuple[Any, ...], batch_size: int, max_batches: int
) -> Tuple[int, bool]:
    """Run a DELETE that takes ``LIMIT`` as its last parameter until it removes fewer rows than a batch."""
    total = 0
    for _ in range(max_batches):
        async with db.system_tx() as c:
            status = await c.execute(sql, *args, batch_size)
        deleted = int(status.split()[-1])
        total += deleted
        if deleted < batch_size:
            return total, True
    return total, False


async def purge_expired(
    db: Database,
    retention: Optional[RetentionSettings] = None,
    *,
    now: Optional[datetime] = None,
    batch_size: int = 5_000,
    max_batches: int = 200,
    lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
) -> RetentionReport:
    """Delete data past its retention period and return what was removed.

    Runs as the schema owner (scheduler). Partition drops wait at most
    ``lock_timeout_ms`` for their locks so they never stall writers.
    """
    if batch_size < 1 or max_batches < 1:
        raise ValueError("batch_size and max_batches must be >= 1")
    retention = retention or get_settings().retention
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    report = RetentionReport()

    report.checkpoint_threads, done = await _purge_checkpoints(db, retention, now, batch_size, max_batches)
    report.complete &= done

    has_checkpoints = await _checkpoint_tables_present(db)
    # Checkpoint rows of the doomed alerts go in the same statement (thread id = tenant:alert).
    checkpoint_ctes = (
        "".join(
            f""", gone_{table} AS (
            DELETE FROM {table} c USING doomed d WHERE c.thread_id = d.tenant_id || ':' || d.id
        )"""  # noqa: S608 - fixed table names
            for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints")
        )
        if has_checkpoints
        else ""
    )
    min_alert_days = await _min_days(db, "alerts_days", retention.alerts_days)
    ended = "CASE WHEN a.status = 'closed' THEN a.closed_at ELSE a.updated_at END"
    report.alerts, done = await _batched(
        db,
        f"""
        WITH doomed AS (
            SELECT a.tenant_id, a.id
            FROM alerts a JOIN tenants t ON t.id = a.tenant_id
            WHERE a.status IN ('closed', 'failed')
              AND {ended} < $1::timestamptz - make_interval(days => $2)
              AND {ended} < $1::timestamptz
                  - make_interval(days => COALESCE({_override_days("alerts_days")}, $3))
            LIMIT $4
        ){checkpoint_ctes}
        DELETE FROM alerts a USING doomed d WHERE a.tenant_id = d.tenant_id AND a.id = d.id
        """,  # noqa: S608
        (now, min_alert_days, retention.alerts_days),
        batch_size,
        max_batches,
    )
    report.complete &= done

    min_indicator_days = await _min_days(db, "indicators_days", retention.indicators_days)
    report.indicator_sightings, done = await _batched(
        db,
        f"""
        WITH doomed AS (
            SELECT s.tenant_id, s.alert_id, s.indicator_type, s.value_hash
            FROM indicator_sightings s JOIN tenants t ON t.id = s.tenant_id
            WHERE s.seen_at < $1::timestamptz - make_interval(days => $2)
              AND s.seen_at < $1::timestamptz
                  - make_interval(days => COALESCE({_override_days("indicators_days")}, $3))
            LIMIT $4
        )
        DELETE FROM indicator_sightings s USING doomed d
        WHERE s.tenant_id = d.tenant_id AND s.alert_id = d.alert_id
          AND s.indicator_type = d.indicator_type AND s.value_hash = d.value_hash
        """,  # noqa: S608
        (now, min_indicator_days, retention.indicators_days),
        batch_size,
        max_batches,
    )
    report.complete &= done

    report.llm_usage_rows, done = await _batched(
        db,
        """
        DELETE FROM llm_usage_daily u USING (
            SELECT tenant_id, day, model, agent FROM llm_usage_daily WHERE day < $1 LIMIT $2
        ) d
        WHERE u.tenant_id = d.tenant_id AND u.day = d.day AND u.model = d.model AND u.agent = d.agent
        """,
        ((now - timedelta(days=retention.llm_usage_days)).date(),),
        batch_size,
        max_batches,
    )
    report.complete &= done

    report.refresh_tokens, done = await _batched(
        db,
        """
        DELETE FROM refresh_tokens WHERE id IN (
            SELECT id FROM refresh_tokens WHERE expires_at < $1 LIMIT $2
        )
        """,
        (now - REFRESH_TOKEN_GRACE,),
        batch_size,
        max_batches,
    )
    report.complete &= done

    for table, days in (("alert_events", retention.events_days), ("audit_log", retention.audit_days)):
        cutoff = now - timedelta(days=days)
        async with db.system_tx() as c:
            report.dropped_partitions += await drop_expired_partitions(
                c, table, days, now=now, lock_timeout_ms=lock_timeout_ms
            )
            busy = await expired_partitions(c, table, days, now=now)
        if busy:
            report.busy_partitions += busy
            report.complete = False
        default = default_partition_name(table)
        removed, done = await _batched(
            db,
            f"""
            DELETE FROM {default} WHERE ctid = ANY(ARRAY(
                SELECT ctid FROM {default} WHERE ts < $1 LIMIT $2
            ))
            """,  # noqa: S608
            (cutoff,),
            batch_size,
            max_batches,
        )
        report.default_partition_rows += removed
        report.complete &= done

    log.info("db.retention.purged", **report.as_dict())
    return report


async def _checkpoint_tables_present(db: Database) -> bool:
    async with db.system_tx(readonly=True) as c:
        return bool(
            await c.fetchval(
                "SELECT to_regclass('public.checkpoints') IS NOT NULL "
                "AND to_regclass('public.checkpoint_blobs') IS NOT NULL "
                "AND to_regclass('public.checkpoint_writes') IS NOT NULL"
            )
        )


async def _purge_checkpoints(
    db: Database, retention: RetentionSettings, now: datetime, batch_size: int, max_batches: int
) -> Tuple[int, bool]:
    """Delete LangGraph checkpoints of runs that finished before the checkpoint cutoff,
    and threads that have no run at all (their alert and run are gone) once that old."""
    if not await _checkpoint_tables_present(db):
        return 0, True
    cutoff = now - timedelta(days=retention.checkpoints_days)
    total = 0
    for _ in range(max_batches):
        async with db.system_tx() as c:
            threads = await c.fetch(
                """
                (SELECT r.thread_id FROM workflow_runs r
                 WHERE r.status IN ('completed', 'dead_lettered') AND r.completed_at < $1
                   AND EXISTS (SELECT 1 FROM checkpoints cp WHERE cp.thread_id = r.thread_id)
                 LIMIT $2)
                UNION
                (SELECT DISTINCT cp.thread_id FROM checkpoints cp
                 WHERE NOT EXISTS (SELECT 1 FROM workflow_runs r WHERE r.thread_id = cp.thread_id)
                   AND (cp.checkpoint ->> 'ts') < to_char($1 AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
                 LIMIT $2)
                """,
                cutoff,
                batch_size,
            )
            ids = [r["thread_id"] for r in threads]
            if ids:
                for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                    await c.execute(f"DELETE FROM {table} WHERE thread_id = ANY($1::text[])", ids)  # noqa: S608
        total += len(ids)
        if len(ids) < batch_size:
            return total, True
    return total, False


__all__ = ["RetentionReport", "purge_expired"]
