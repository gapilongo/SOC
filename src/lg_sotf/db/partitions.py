"""Monthly range partitions for ``alert_events`` and ``audit_log``.

Partitions are named ``<table>_pYYYY_MM`` and cover ``[first of month,
first of next month)`` in UTC. Each parent also has a ``<table>_default``
partition so writes never fail when maintenance lags; :func:`ensure_partitions`
moves any rows that landed in the default partition into the new monthly
partition before attaching it.

The DDL here is shared by migration ``0001`` and the scheduler's maintenance
job, so changes must stay compatible with partitions that already exist.

Creating, attaching or dropping a partition takes an ACCESS EXCLUSIVE lock on
the parent and the default partition. Maintenance therefore waits at most
``lock_timeout_ms`` for each lock and skips (and logs) a partition it could
not lock; the next run retries it. Without the bound, a DDL statement queued
behind one long reader would stall every audit append and event insert.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta
from typing import List, Optional, Tuple

import asyncpg
import structlog

from lg_sotf.db import locks

log = structlog.get_logger(__name__)

PARTITIONED_TABLES: Tuple[str, ...] = ("alert_events", "audit_log")
_PARTITION_RE = re.compile(r"^(alert_events|audit_log)_p(\d{4})_(\d{2})$")
DEFAULT_LOCK_TIMEOUT_MS = 2_000

# The InitPlan form ``(SELECT f())`` evaluates the bypass check once per query, not per row.
TENANT_POLICY_PREDICATE = "tenant_id = current_setting('app.tenant_id', true) OR (SELECT lgsotf_rls_bypass())"


def _check_table(table: str) -> str:
    if table not in PARTITIONED_TABLES:
        raise ValueError(f"not a partitioned table: {table!r}")
    return table


def month_start(value: date) -> date:
    if isinstance(value, datetime):
        value = value.astimezone(UTC).date() if value.tzinfo else value.date()
    return value.replace(day=1)


def add_months(month: date, n: int) -> date:
    index = month.year * 12 + (month.month - 1) + n
    return date(index // 12, index % 12 + 1, 1)


def partition_name(table: str, month: date) -> str:
    return f"{_check_table(table)}_p{month.year:04d}_{month.month:02d}"


def default_partition_name(table: str) -> str:
    return f"{_check_table(table)}_default"


def partition_bounds(month: date) -> Tuple[datetime, datetime]:
    lo = datetime(month.year, month.month, 1, tzinfo=UTC)
    nxt = add_months(month, 1)
    hi = datetime(nxt.year, nxt.month, 1, tzinfo=UTC)
    return lo, hi


def parse_partition_name(name: str) -> Optional[Tuple[str, date]]:
    m = _PARTITION_RE.fullmatch(name)
    if not m:
        return None
    return m.group(1), date(int(m.group(2)), int(m.group(3)), 1)


def _bound_literal(ts: datetime) -> str:
    return ts.strftime("'%Y-%m-%d %H:%M:%S+00'")


def partition_security_sql(table: str, partition: str) -> List[str]:
    """RLS for direct access to a partition (queries via the parent use the parent's policy)."""
    stmts = [
        f"ALTER TABLE {partition} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {partition} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY tenant_isolation ON {partition} "
        f"USING ({TENANT_POLICY_PREDICATE}) WITH CHECK ({TENANT_POLICY_PREDICATE})",
    ]
    if table == "audit_log":
        # Statement-level TRUNCATE triggers are not inherited by partitions.
        stmts.append(
            f"CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON {partition} "
            "FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation()"
        )
    return stmts


def create_partition_sql(table: str, month: date) -> List[str]:
    name = partition_name(table, month)
    lo, hi = partition_bounds(month)
    return [
        f"CREATE TABLE {name} PARTITION OF {table} FOR VALUES FROM ({_bound_literal(lo)}) TO ({_bound_literal(hi)})",
        *partition_security_sql(table, name),
    ]


def create_default_partition_sql(table: str) -> List[str]:
    name = default_partition_name(table)
    return [
        f"CREATE TABLE {name} PARTITION OF {table} DEFAULT",
        *partition_security_sql(table, name),
    ]


async def _require_bypass(conn: asyncpg.Connection) -> None:
    if not conn.is_in_transaction() or not await conn.fetchval("SELECT lgsotf_rls_bypass()"):
        raise RuntimeError("partition maintenance must run inside db.system_tx() as the schema owner")


async def _set_lock_timeout(conn: asyncpg.Connection, lock_timeout_ms: int) -> str:
    if lock_timeout_ms < 1:
        raise ValueError("lock_timeout_ms must be >= 1")
    previous = await conn.fetchval("SELECT current_setting('lock_timeout')")
    await conn.execute("SELECT set_config('lock_timeout', $1, true)", f"{int(lock_timeout_ms)}ms")
    return previous


async def _restore_lock_timeout(conn: asyncpg.Connection, previous: str) -> None:
    await conn.execute("SELECT set_config('lock_timeout', $1, true)", previous)


async def _create_partition(conn: asyncpg.Connection, table: str, month: date) -> None:
    name = partition_name(table, month)
    default = default_partition_name(table)
    lo, hi = partition_bounds(month)
    probe = f"SELECT EXISTS (SELECT 1 FROM {default} WHERE ts >= $1 AND ts < $2)"  # noqa: S608
    stranded = await conn.fetchval(probe, lo, hi)
    if not stranded:
        for stmt in create_partition_sql(table, month):
            await conn.execute(stmt)
        return
    await conn.execute(f"CREATE TABLE {name} (LIKE {table} INCLUDING DEFAULTS INCLUDING CONSTRAINTS)")
    await conn.execute(
        f"WITH moved AS (DELETE FROM {default} WHERE ts >= $1 AND ts < $2 RETURNING *) "  # noqa: S608
        f"INSERT INTO {name} SELECT * FROM moved",
        lo,
        hi,
    )
    await conn.execute(
        f"ALTER TABLE {table} ATTACH PARTITION {name} FOR VALUES FROM ({_bound_literal(lo)}) TO ({_bound_literal(hi)})"
    )
    for stmt in partition_security_sql(table, name):
        await conn.execute(stmt)


async def ensure_partitions(
    conn: asyncpg.Connection,
    months_ahead: int = 2,
    *,
    today: Optional[date] = None,
    tables: Tuple[str, ...] = PARTITIONED_TABLES,
    lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
) -> List[str]:
    """Create the current month's partition and ``months_ahead`` more.

    Must be called inside ``db.system_tx()``. Returns the names of partitions
    created. A partition whose locks are not granted within
    ``lock_timeout_ms`` is skipped and logged (``db.partitions.busy``); the
    next run creates it. Safe to run concurrently with itself (advisory lock).
    """
    if months_ahead < 0:
        raise ValueError("months_ahead must be >= 0")
    await _require_bypass(conn)
    await conn.execute("SELECT pg_advisory_xact_lock($1, 0)", locks.PARTITION_MAINTENANCE)
    previous = await _set_lock_timeout(conn, lock_timeout_ms)
    first = month_start(today or datetime.now(UTC).date())
    created: List[str] = []
    busy: List[str] = []
    for table in tables:
        _check_table(table)
        for i in range(months_ahead + 1):
            month = add_months(first, i)
            name = partition_name(table, month)
            if await conn.fetchval("SELECT to_regclass($1)", f"public.{name}") is not None:
                continue
            try:
                async with conn.transaction():
                    await _create_partition(conn, table, month)
            except asyncpg.LockNotAvailableError:
                busy.append(name)
                continue
            created.append(name)
    await _restore_lock_timeout(conn, previous)
    if busy:
        log.warning("db.partitions.busy", operation="create", partitions=busy, lock_timeout_ms=lock_timeout_ms)
    return created


async def list_partitions(conn: asyncpg.Connection, table: str) -> List[str]:
    rows = await conn.fetch(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
        "WHERE i.inhparent = to_regclass($1) ORDER BY c.relname",
        f"public.{_check_table(table)}",
    )
    return [r["relname"] for r in rows]


async def expired_partitions(
    conn: asyncpg.Connection,
    table: str,
    older_than_days: int,
    *,
    now: Optional[datetime] = None,
) -> List[str]:
    """Monthly partitions of ``table`` whose whole range is older than the cutoff."""
    _check_table(table)
    if older_than_days < 1:
        raise ValueError("older_than_days must be >= 1")
    cutoff = (now or datetime.now(UTC)) - timedelta(days=older_than_days)
    expired: List[str] = []
    for name in await list_partitions(conn, table):
        parsed = parse_partition_name(name)
        if parsed is None or parsed[0] != table:
            continue
        if partition_bounds(parsed[1])[1] <= cutoff:
            expired.append(name)
    return expired


async def drop_expired_partitions(
    conn: asyncpg.Connection,
    table: str,
    older_than_days: int,
    *,
    now: Optional[datetime] = None,
    lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
) -> List[str]:
    """Drop monthly partitions whose whole range is older than the cutoff.

    Must be called inside ``db.system_tx()``. The default partition is never
    dropped. Returns the names of dropped partitions; a partition whose locks
    are not granted within ``lock_timeout_ms`` is skipped and logged
    (``db.partitions.busy``) and dropped by a later run.
    """
    _check_table(table)
    if older_than_days < 1:
        raise ValueError("older_than_days must be >= 1")
    await _require_bypass(conn)
    await conn.execute("SELECT pg_advisory_xact_lock($1, 0)", locks.PARTITION_MAINTENANCE)
    previous = await _set_lock_timeout(conn, lock_timeout_ms)
    dropped: List[str] = []
    busy: List[str] = []
    for name in await expired_partitions(conn, table, older_than_days, now=now):
        try:
            async with conn.transaction():
                await conn.execute(f"DROP TABLE {name}")
        except asyncpg.LockNotAvailableError:
            busy.append(name)
            continue
        dropped.append(name)
    await _restore_lock_timeout(conn, previous)
    if busy:
        log.warning("db.partitions.busy", operation="drop", partitions=busy, lock_timeout_ms=lock_timeout_ms)
    return dropped
