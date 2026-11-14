"""Shadow mode (AI-E1.5a), second review round: gaps each found by a mutation that no other test caught."""

from __future__ import annotations

from typing import Any

import pytest
from asyncpg.exceptions import ActiveSQLTransactionError

from lg_sotf.db.errors import SystemScopeDenied
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.queue.redis import create_redis
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from tests.integration.db._support import TENANT_A

pytestmark = pytest.mark.integration


async def test_gap_bare_connection_cannot_turn_read_write(db: Database, repos: Repositories) -> None:
    """``SET LOCAL`` passes the statement guard; only the first ``SELECT 1`` keeps the transaction read only."""
    with shadow_scope(ShadowRun("shadow/gap-setlocal")):
        async with db.connection() as conn:
            with pytest.raises((ActiveSQLTransactionError, ShadowEgressRefused)):
                await conn.execute("SET LOCAL transaction_read_only = off")
                await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
                await conn.execute("UPDATE tenants SET name = 'pwned-setlocal' WHERE id = 'tenant-a'")
    assert (await repos.tenants.get(TENANT_A)).name != "pwned-setlocal"


@pytest.mark.parametrize("sql", ["COMMIT", "/* x */ COMMIT"])
async def test_gap_system_tx_refuses_transaction_control(db: Database, sql: str) -> None:
    """The shadow role cannot bypass isolation, so a shadow ``system_tx`` is refused before any statement."""
    with shadow_scope(ShadowRun("shadow/gap-system")):
        with pytest.raises(SystemScopeDenied):
            async with db.system_tx() as conn:
                await conn.execute(sql)


@pytest.mark.parametrize("method", ["executemany", "prepare", "cursor"])
async def test_gap_every_wrapped_method_is_checked(db: Database, method: str) -> None:
    with shadow_scope(ShadowRun("shadow/gap-methods")):
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ShadowEgressRefused):
                if method == "executemany":
                    await conn.executemany("SELECT pg_notify('gap', $1)", [("x",)])
                elif method == "prepare":
                    await conn.prepare("SELECT pg_notify('gap', 'x')")
                else:
                    conn.cursor("SELECT pg_notify('gap', 'x')")


async def test_gap_production_redis_clients_refuse_writes_in_shadow(make_settings: Any, redis_url: str) -> None:
    """Every runtime client comes from create_redis; it must refuse writes in a shadow run, not only the runner's."""
    client = create_redis(make_settings(redis={"url": redis_url}))
    try:
        with shadow_scope(ShadowRun("shadow/gap-redis")):
            with pytest.raises(ShadowEgressRefused):
                await client.set("gap:k", "1")
        assert await client.get("gap:k") is None
    finally:
        await client.aclose()
