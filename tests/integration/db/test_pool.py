"""Database pool behaviour: scoping, codecs, timeouts and exhaustion."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import asyncpg
import pytest

from lg_sotf.db.errors import DatabaseUnavailable, InvalidTenantId, PoolExhausted
from lg_sotf.db.pool import Database
from lg_sotf.db.types import Connection
from lg_sotf.observability.metrics import REGISTRY
from tests.integration.db._support import TENANT_A, db_settings

pytestmark = pytest.mark.asyncio


async def test_ping_and_stats(db: Database) -> None:
    latency = await db.ping()
    assert latency is not None and latency >= 0
    stats = db.stats()
    assert stats.max_size == 8 and stats.size >= 1


async def test_ping_reports_busy_not_down_when_pool_is_saturated(migrated_database_url: str) -> None:
    """Load must not fail readiness on every replica at once while the database is healthy."""
    db = Database(db_settings(migrated_database_url, pool_min=1, pool_max=2), acquire_timeout_s=5.0)
    await db.open()
    try:
        async with db.connection(), db.connection():
            started = asyncio.get_running_loop().time()
            assert await db.ping(acquire_timeout_s=0.2) is None
            assert asyncio.get_running_loop().time() - started < 2
        assert (await db.ping()) is not None
    finally:
        await db.close()


async def test_ping_unreachable_database_raises() -> None:
    db = Database(
        db_settings("postgresql://soc:wrong@127.0.0.1:1/none", pool_min=0, command_timeout_s=1.0),
        acquire_timeout_s=1.0,
    )
    await db.open()
    try:
        with pytest.raises(DatabaseUnavailable):
            await db.ping()
    finally:
        await db.close()


async def test_system_scope_is_verified_once(db: Database) -> None:
    async with db.system_tx() as conn:
        assert await conn.fetchval("SELECT lgsotf_rls_bypass()") is True
    async with db.system_tx(readonly=True) as conn:
        assert await conn.fetchval("SELECT count(*) FROM tenants") >= 0


async def test_server_settings_applied(db: Database) -> None:
    async with db.connection() as conn:
        assert await conn.fetchval("SHOW statement_timeout") == "30s"
        assert await conn.fetchval("SHOW application_name") == "lg-sotf-tests"


async def test_tenant_scope_is_transaction_local(db: Database) -> None:
    async with db.tenant_tx("tenant-a") as conn:
        assert await conn.fetchval("SELECT current_setting('app.tenant_id', true)") == "tenant-a"
        assert await conn.fetchval("SELECT current_setting('app.bypass_rls', true)") in (None, "")
    async with db.system_tx() as conn:
        assert await conn.fetchval("SELECT current_setting('app.bypass_rls', true)") == "on"
        assert await conn.fetchval("SELECT current_setting('app.tenant_id', true)") in (None, "")
    for _ in range(3):
        async with db.connection() as conn:
            assert await conn.fetchval("SELECT current_setting('app.tenant_id', true)") in (None, "")
            assert await conn.fetchval("SELECT current_setting('app.bypass_rls', true)") in (None, "")


async def test_tenant_scope_rolls_back_on_error(db: Database) -> None:
    with pytest.raises(RuntimeError):
        async with db.system_tx() as conn:
            await conn.execute("INSERT INTO tenants (id, name) VALUES ('rollback-t', 'x')")
            raise RuntimeError("boom")
    async with db.system_tx() as conn:
        assert await conn.fetchval("SELECT count(*) FROM tenants WHERE id = 'rollback-t'") == 0


@pytest.mark.parametrize("bad", ["", "A", "UPPER", "has space", "x", "-lead", "a" * 64, "t;drop"])
async def test_invalid_tenant_ids_are_rejected(db: Database, bad: str) -> None:
    with pytest.raises(InvalidTenantId):
        async with db.tenant_tx(bad):
            pass


async def test_jsonb_codec_round_trip(db: Database) -> None:
    value = {"a": [1, 2.5, None, True], "nested": {"k": "v", "u": "é"}}
    async with db.connection() as conn:
        assert await conn.fetchval("SELECT $1::jsonb", value) == value
        assert await conn.fetchval("SELECT $1::json", value) == value
        assert await conn.fetchval("SELECT '{\"x\": 1}'::jsonb") == {"x": 1}
        stored = await conn.fetchval("SELECT $1::jsonb", {"n\x00": "a\x00b", "s": "\ud83d", "keep": "\\u0000"})
        assert stored == {"n\ufffd": "a\ufffdb", "s": "?", "keep": "\\u0000"}


async def test_extra_server_settings(migrated_database_url: str) -> None:
    db = Database(db_settings(migrated_database_url), server_settings={"lock_timeout": "1234"})
    await db.open()
    try:
        async with db.connection() as conn:
            assert await conn.fetchval("SHOW lock_timeout") == "1234ms"
            assert await conn.fetchval("SHOW statement_timeout") == "30s"
    finally:
        await db.close()


async def test_pool_exhaustion_raises_instead_of_hanging(migrated_database_url: str) -> None:
    db = Database(db_settings(migrated_database_url, pool_min=1, pool_max=1), acquire_timeout_s=0.2)
    await db.open()
    try:
        async with db.connection():
            with pytest.raises(PoolExhausted):
                async with db.connection():
                    pass
    finally:
        await db.close()


async def test_statement_timeout_cancels_long_queries(migrated_database_url: str) -> None:
    db = Database(db_settings(migrated_database_url, statement_timeout_ms=100))
    await db.open()
    try:
        async with db.connection() as conn:
            with pytest.raises(asyncpg.QueryCanceledError):
                await conn.execute("SELECT pg_sleep(2)")
    finally:
        await db.close()


async def test_closed_pool_raises_unavailable(migrated_database_url: str) -> None:
    db = Database(db_settings(migrated_database_url))
    with pytest.raises(DatabaseUnavailable):
        async with db.connection():
            pass
    await db.open()
    await db.close()
    await db.close()
    assert not db.is_open


async def test_unreachable_database_raises_unavailable() -> None:
    db = Database(
        db_settings("postgresql://soc:wrong@127.0.0.1:1/none", command_timeout_s=1.0),
        acquire_timeout_s=1.0,
    )
    with pytest.raises(DatabaseUnavailable) as info:
        await asyncio.wait_for(db.open(), timeout=10)
    assert "wrong" not in str(info.value)


def _stale_retries() -> float:
    return REGISTRY.get_sample_value("lgsotf_db_stale_statement_retries_total") or 0.0


async def test_run_tenant_tx_runs_a_transaction_a_migration_made_stale_again(
    db: Database, migrated_database_url: str
) -> None:
    """ARCH-E1.6: a migration makes a cached statement stale mid-transaction; the whole transaction runs again.

    The failed attempt is rolled back, and the retry is scoped to the same tenant as the first attempt.
    """
    one_conn = Database(db_settings(migrated_database_url, pool_min=1, pool_max=1))
    tenants_seen: List[str] = []

    async def work(conn: Connection) -> Dict[str, Any]:
        tenants_seen.append(await conn.fetchval("SELECT current_setting('app.tenant_id')"))
        await conn.execute("INSERT INTO arch_e1_6_stale_probe (id) VALUES ($1)", len(tenants_seen) + 1)
        return dict(await conn.fetchrow("SELECT * FROM arch_e1_6_stale_probe WHERE id = $1", 1))

    async with db.connection() as ddl:
        await ddl.execute("CREATE TABLE arch_e1_6_stale_probe (id int PRIMARY KEY)")
        await ddl.execute("INSERT INTO arch_e1_6_stale_probe VALUES (1)")
        try:
            await one_conn.open()
            assert await one_conn.run_tenant_tx(TENANT_A, work) == {"id": 1}  # caches the statements

            await ddl.execute("ALTER TABLE arch_e1_6_stale_probe ADD COLUMN note text")
            before = _stale_retries()
            assert await one_conn.run_tenant_tx(TENANT_A, work) == {"id": 1, "note": None}
            assert _stale_retries() == before + 1
            assert tenants_seen == [TENANT_A] * 3
            assert await ddl.fetchval("SELECT array_agg(id ORDER BY id) FROM arch_e1_6_stale_probe") == [1, 2, 4]

            # Without the retry the same change fails the transaction.
            await ddl.execute("ALTER TABLE arch_e1_6_stale_probe ADD COLUMN extra text")
            with pytest.raises(asyncpg.InvalidCachedStatementError):
                async with one_conn.tenant_tx(TENANT_A) as conn:
                    await work(conn)
        finally:
            await one_conn.close()
            await ddl.execute("DROP TABLE arch_e1_6_stale_probe")
