"""Partition maintenance and the retention job."""

from __future__ import annotations

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import AsyncIterator, List

import asyncpg
import pytest
import pytest_asyncio

from lg_sotf.db.migrate import drop_expired_partitions, ensure_partitions, setup_checkpointer
from lg_sotf.db.partitions import add_months, list_partitions, month_start, partition_name
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, Repositories
from lg_sotf.db.retention import purge_expired
from lg_sotf.settings import RetentionSettings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

NOW = datetime.now(UTC)
THIS_MONTH = month_start(NOW.date())
OLD_MONTH = date(2024, 1, 1)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest_asyncio.fixture
async def cleanup_partitions(db: Database) -> AsyncIterator[List[str]]:
    """Partitions a test creates outside the standard window; dropped afterwards."""
    created: List[str] = []
    yield created
    async with db.system_tx() as conn:
        for name in created:
            await conn.execute(f"DROP TABLE IF EXISTS {name}")
        await ensure_partitions(conn)


async def _insert_event(db: Database, tenant_id: str, alert_id: str, ts: datetime) -> str:
    async with db.tenant_tx(tenant_id) as conn:
        return await conn.fetchval(
            "INSERT INTO alert_events (tenant_id, alert_id, ts, event_type) VALUES ($1, $2, $3, 'x') "
            "RETURNING tableoid::regclass::text",
            tenant_id,
            alert_id,
            ts,
        )


async def _insert_audit(db: Database, tenant_id: str, ts: datetime) -> str:
    async with db.system_tx() as conn:
        return await conn.fetchval(
            """
            WITH e AS (SELECT nextval(pg_get_serial_sequence('audit_log', 'id')) AS id)
            INSERT INTO audit_log (tenant_id, id, ts, actor_type, action, resource_type, details, hash)
            SELECT $1, e.id, $2, 'system', 'old', 'test', '{}'::jsonb,
                   audit_entry_hash($1, e.id, $2, 'system', NULL, 'old', 'test', NULL, '{}'::jsonb, NULL)
            FROM e
            RETURNING tableoid::regclass::text
            """,
            tenant_id,
            ts,
        )


@asynccontextmanager
async def long_reader(db: Database, table: str) -> AsyncIterator[None]:
    """A tenant transaction that keeps an ACCESS SHARE lock on ``table`` until the block exits."""
    holding = asyncio.Event()
    release = asyncio.Event()

    async def read() -> None:
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.fetchval(f"SELECT count(*) FROM {table}")  # noqa: S608
            holding.set()
            await release.wait()

    task = asyncio.create_task(read())
    await asyncio.wait_for(holding.wait(), timeout=5)
    try:
        yield
    finally:
        release.set()
        await task


async def wait_for_lock_request(db: Database, timeout_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        async with db.connection() as conn:
            if await conn.fetchval("SELECT count(*) FROM pg_locks WHERE NOT granted AND mode = 'AccessExclusiveLock'"):
                return
        await asyncio.sleep(0.02)
    raise AssertionError("maintenance never queued for its lock")


class TestPartitions:
    async def test_current_window_exists_and_ensure_is_idempotent(self, db: Database) -> None:
        async with db.system_tx() as conn:
            assert await ensure_partitions(conn) == []
            names = await list_partitions(conn, "alert_events")
        for i in range(3):
            assert partition_name("alert_events", add_months(THIS_MONTH, i)) in names

    async def test_creates_future_partitions(self, db: Database, cleanup_partitions: List[str]) -> None:
        future = add_months(THIS_MONTH, 12)
        async with db.system_tx() as conn:
            created = await ensure_partitions(conn, months_ahead=1, today=future)
            cleanup_partitions.extend(created)
            again = await ensure_partitions(conn, months_ahead=1, today=future)
        assert sorted(created) == sorted(
            partition_name(t, add_months(future, i)) for t in ("alert_events", "audit_log") for i in range(2)
        )
        assert again == []

    async def test_rows_stranded_in_default_move_to_new_partition(
        self, db: Database, repos: Repositories, cleanup_partitions: List[str]
    ) -> None:
        future = add_months(THIS_MONTH, 24)
        ts = datetime(future.year, future.month, 15, tzinfo=UTC)
        alert_id = await make_alert(repos, TENANT_A)
        assert await _insert_event(db, TENANT_A, alert_id, ts) == "alert_events_default"
        assert await _insert_audit(db, TENANT_A, ts) == "audit_log_default"

        async with db.system_tx() as conn:
            created = await ensure_partitions(conn, months_ahead=0, today=future)
            cleanup_partitions.extend(created)
        assert set(created) == {partition_name("alert_events", future), partition_name("audit_log", future)}

        async with db.tenant_tx(TENANT_A) as conn:
            where = await conn.fetchval("SELECT tableoid::regclass::text FROM alert_events WHERE ts = $1", ts)
            assert where == partition_name("alert_events", future)
            assert await conn.fetchval("SELECT count(*) FROM alert_events_default") == 0
        future_events = partition_name("alert_events", future)
        async with db.tenant_tx(TENANT_B) as conn:
            assert await conn.fetchval(f"SELECT count(*) FROM {future_events}") == 0  # noqa: S608
        audit_part = partition_name("audit_log", future)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(f"TRUNCATE {audit_part}")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(f"DELETE FROM {audit_part}")  # noqa: S608
        assert (await repos.audit.verify_chain(TENANT_A)).ok

    async def test_maintenance_requires_system_scope(self, db: Database) -> None:
        with pytest.raises(RuntimeError):
            async with db.tenant_tx(TENANT_A) as conn:
                await ensure_partitions(conn)
        async with db.connection() as conn:
            with pytest.raises(RuntimeError):
                await drop_expired_partitions(conn, "audit_log", 30)

    async def test_drop_expired_partitions(self, db: Database, cleanup_partitions: List[str]) -> None:
        async with db.system_tx() as conn:
            cleanup_partitions.extend(await ensure_partitions(conn, months_ahead=0, today=OLD_MONTH))
            dropped = await drop_expired_partitions(conn, "alert_events", 90)
            remaining = await list_partitions(conn, "alert_events")
            with pytest.raises(ValueError):
                await drop_expired_partitions(conn, "alerts", 90)
            with pytest.raises(ValueError):
                await drop_expired_partitions(conn, "audit_log", 0)
        assert partition_name("alert_events", OLD_MONTH) in dropped
        assert "alert_events_default" in remaining
        assert partition_name("alert_events", THIS_MONTH) in remaining


class TestMaintenanceLocks:
    """Partition DDL must give up on busy locks instead of queueing writers behind a long reader."""

    async def test_drop_gives_up_instead_of_blocking_writers(
        self, db: Database, repos: Repositories, cleanup_partitions: List[str]
    ) -> None:
        async with db.system_tx() as conn:
            cleanup_partitions.extend(await ensure_partitions(conn, months_ahead=0, today=OLD_MONTH))
        old = partition_name("audit_log", OLD_MONTH)

        async def maintenance() -> List[str]:
            async with db.system_tx() as conn:
                return await drop_expired_partitions(conn, "audit_log", 365, lock_timeout_ms=1_000)

        async with long_reader(db, "audit_log"):
            dropping = asyncio.create_task(maintenance())
            await wait_for_lock_request(db)
            started = time.perf_counter()
            entry = await asyncio.wait_for(repos.audit.append(TENANT_A, "user", "u1", "during", "test"), timeout=10)
            writer_wait = time.perf_counter() - started
            assert await asyncio.wait_for(dropping, timeout=10) == []
        assert entry.action == "during" and writer_wait < 5
        async with db.system_tx() as conn:
            assert old in await list_partitions(conn, "audit_log")
            assert old in await drop_expired_partitions(conn, "audit_log", 365)
        assert (await repos.audit.verify_chain(TENANT_A)).ok

    async def test_create_gives_up_and_succeeds_on_the_next_run(
        self, db: Database, repos: Repositories, cleanup_partitions: List[str]
    ) -> None:
        future = add_months(THIS_MONTH, 30)
        name = partition_name("alert_events", future)
        alert_id = await make_alert(repos, TENANT_A)

        async def maintenance() -> List[str]:
            async with db.system_tx() as conn:
                return await ensure_partitions(
                    conn, months_ahead=0, today=future, tables=("alert_events",), lock_timeout_ms=1_000
                )

        async with long_reader(db, "alert_events"):
            creating = asyncio.create_task(maintenance())
            await wait_for_lock_request(db)
            await asyncio.wait_for(repos.alert_events.append(TENANT_A, alert_id, "during"), timeout=10)
            assert await asyncio.wait_for(creating, timeout=10) == []
        async with db.system_tx() as conn:
            created = await ensure_partitions(conn, months_ahead=0, today=future, tables=("alert_events",))
            cleanup_partitions.extend(created)
        assert created == [name]

    async def test_retention_reports_busy_partitions(self, db: Database, cleanup_partitions: List[str]) -> None:
        async with db.system_tx() as conn:
            cleanup_partitions.extend(await ensure_partitions(conn, months_ahead=0, today=OLD_MONTH))
        async with long_reader(db, "audit_log"):
            report = await asyncio.wait_for(
                purge_expired(db, RetentionSettings(), now=NOW, lock_timeout_ms=200), timeout=20
            )
        assert partition_name("audit_log", OLD_MONTH) in report.busy_partitions
        assert partition_name("alert_events", OLD_MONTH) in report.dropped_partitions
        assert not report.complete
        again = await purge_expired(db, RetentionSettings(), now=NOW)
        assert again.complete and partition_name("audit_log", OLD_MONTH) in again.dropped_partitions

    async def test_lock_timeout_is_restored(self, db: Database) -> None:
        async with db.system_tx() as conn:
            before = await conn.fetchval("SHOW lock_timeout")
            await ensure_partitions(conn, lock_timeout_ms=1_234)
            await drop_expired_partitions(conn, "audit_log", 36_500, lock_timeout_ms=1_234)
            assert await conn.fetchval("SHOW lock_timeout") == before
            with pytest.raises(ValueError):
                await ensure_partitions(conn, lock_timeout_ms=0)


class TestRetention:
    async def test_purge_expired(self, db: Database, repos: Repositories, cleanup_partitions: List[str]) -> None:
        old_closed = await make_alert(repos, TENANT_A, source_alert_id="old-closed")
        recent_closed = await make_alert(repos, TENANT_A, source_alert_id="recent-closed")
        old_open = await make_alert(repos, TENANT_A, source_alert_id="old-open", ingested_at=NOW - timedelta(days=400))
        for alert_id, closed_at in (
            (old_closed, NOW - timedelta(days=100)),
            (recent_closed, NOW - timedelta(days=10)),
        ):
            for status in ("queued", "processing"):
                await repos.alerts.update_status(TENANT_A, alert_id, status)
            await repos.alerts.update_status(TENANT_A, alert_id, "closed", now=closed_at)
        await repos.alert_events.append(TENANT_A, old_closed, "closed")

        await repos.indicators.add_sightings(
            TENANT_A,
            old_open,
            [("ip", sha("1"), None, NOW - timedelta(days=40)), ("ip", sha("2"), None, NOW)],
        )
        await repos.llm_usage.upsert_daily(
            [
                LLMUsageDelta(
                    tenant_id=TENANT_A, day=(NOW - timedelta(days=500)).date(), model="m", agent="a", calls=1
                ),
                LLMUsageDelta(tenant_id=TENANT_A, day=NOW.date(), model="m", agent="a", calls=1, cost_usd=Decimal("0")),
            ]
        )
        user = await repos.users.create(TENANT_A, "r@x.io", "viewer")
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("stale"), NOW - timedelta(days=2))
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("live"), NOW + timedelta(days=2))
        assert await _insert_event(db, TENANT_A, old_open, datetime(2020, 1, 1, tzinfo=UTC)) == ("alert_events_default")
        async with db.system_tx() as conn:
            cleanup_partitions.extend(await ensure_partitions(conn, months_ahead=0, today=OLD_MONTH))
        assert await _insert_audit(db, TENANT_A, datetime(2024, 1, 10, tzinfo=UTC)) == (
            partition_name("audit_log", OLD_MONTH)
        )

        report = await purge_expired(db, RetentionSettings(), now=NOW)

        assert report.complete
        assert report.alerts == 1
        assert report.indicator_sightings == 1
        assert report.llm_usage_rows == 1
        assert report.refresh_tokens == 1
        assert report.default_partition_rows == 1
        assert {partition_name("alert_events", OLD_MONTH), partition_name("audit_log", OLD_MONTH)} <= set(
            report.dropped_partitions
        )
        remaining = {a.id for a in (await repos.alerts.list(TENANT_A)).items}
        assert remaining == {recent_closed, old_open}
        assert (await repos.alert_events.list_for_alert(TENANT_A, old_closed)).items == []
        assert len(await repos.indicators.sightings_for_alert(TENANT_A, old_open)) == 1
        assert await repos.refresh_tokens.get_by_hash(TENANT_A, sha("live")) is not None

        second = await purge_expired(db, RetentionSettings(), now=NOW)
        assert (second.alerts, second.indicator_sightings, second.dropped_partitions) == (0, 0, [])

    async def test_tenant_override_and_batching(self, repos: Repositories, db: Database) -> None:
        await repos.tenants.update_settings(TENANT_B, {"retention": {"alerts_days": 5}})
        for tenant_id in (TENANT_A, TENANT_B):
            for _ in range(3):
                alert_id = await make_alert(repos, tenant_id)
                for status in ("queued", "processing"):
                    await repos.alerts.update_status(tenant_id, alert_id, status)
                await repos.alerts.update_status(tenant_id, alert_id, "closed", now=NOW - timedelta(days=10))

        partial = await purge_expired(db, RetentionSettings(), now=NOW, batch_size=1, max_batches=2)
        assert partial.alerts == 2 and not partial.complete
        rest = await purge_expired(db, RetentionSettings(), now=NOW, batch_size=1)
        assert rest.alerts == 1 and rest.complete
        assert (await repos.alerts.list(TENANT_B)).items == []
        assert len((await repos.alerts.list(TENANT_A)).items) == 3

    async def test_checkpoints_of_finished_runs_are_purged(
        self, db: Database, repos: Repositories, migrated_database_url: str
    ) -> None:
        await setup_checkpointer(migrated_database_url)
        old = await make_alert(repos, TENANT_A)
        recent = await make_alert(repos, TENANT_A)
        running = await make_alert(repos, TENANT_A)
        for alert_id, finished in ((old, NOW - timedelta(days=45)), (recent, NOW - timedelta(days=1))):
            await repos.runs.start(TENANT_A, alert_id, "w", lease_s=60)
            await repos.runs.complete(TENANT_A, alert_id, now=finished)
        await repos.runs.start(TENANT_A, running, "w", lease_s=60)
        threads = [f"{TENANT_A}:{a}" for a in (old, recent, running)]
        async with db.system_tx() as conn:
            for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                await conn.execute(f"DELETE FROM {table}")  # noqa: S608
            for thread in threads:
                await conn.execute(
                    "INSERT INTO checkpoints (thread_id, checkpoint_id, checkpoint) VALUES ($1, 'c1', '{}'::jsonb)",
                    thread,
                )
                await conn.execute(
                    "INSERT INTO checkpoint_blobs (thread_id, channel, version, type) VALUES ($1, 'ch', '1', 'empty')",
                    thread,
                )
                await conn.execute(
                    "INSERT INTO checkpoint_writes (thread_id, checkpoint_id, task_id, idx, channel, blob) "
                    "VALUES ($1, 'c1', 't', 0, 'ch', '\\x00'::bytea)",
                    thread,
                )

        report = await purge_expired(db, RetentionSettings(checkpoints_days=30), now=NOW)

        assert report.checkpoint_threads == 1
        async with db.system_tx() as conn:
            for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes"):
                left = {r["thread_id"] for r in await conn.fetch(f"SELECT thread_id FROM {table}")}  # noqa: S608
                assert left == set(threads[1:]), table
            for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                await conn.execute(f"DELETE FROM {table}")  # noqa: S608
