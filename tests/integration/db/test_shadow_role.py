"""The SELECT-only shadow role (AI-E1.5c): the database, not the statement guard, stops a shadow run's writes.

The ``db`` fixture opens the shadow runs' pool as ``lgsotf_shadow`` (created by
``scripts/ci/create_test_role.sql``, granted by :func:`grant_shadow_privileges`).
The bypasses the shadow-mode re-review proved against the guard of
:mod:`lg_sotf.db.shadow_connection` are replayed here with that guard removed:
each one fails at the database, for lack of privilege or because the session
is read only.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import pytest
from asyncpg.exceptions import InsufficientPrivilegeError, ReadOnlySQLTransactionError

from lg_sotf.db.errors import DatabaseUnavailable, ShadowRoleRequired
from lg_sotf.db.migrate import SHADOW_EXCLUDED_TABLES, SHADOW_TABLES, grant_runtime_privileges, grant_shadow_privileges
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.shadow_connection import ShadowConnection
from lg_sotf.db.shadow_role import UNSAFE_ROLE_SQL, unsafe_role_reasons
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from lg_sotf.settings import DatabaseSettings
from tests.integration.db._support import SHADOW_ROLE, TENANT_A, db_settings, shadow_url

pytestmark = pytest.mark.asyncio

DATABASE_REFUSALS = (InsufficientPrivilegeError, ReadOnlySQLTransactionError)
ESCAPE = "UPDATE tenants SET name = 'pwned' WHERE id = 'tenant-a'"
SCOPE = "SELECT set_config('app.tenant_id', 'tenant-a', false); "


PROVEN_BYPASSES: dict[str, Callable[[Any], Awaitable[Any]]] = {
    # A COMMIT after a comment marker inside a literal: the guard strips the rest of the statement unseen.
    "commit behind '--'": lambda c: c.execute(f"SELECT '--'; COMMIT; {SCOPE}{ESCAPE}"),
    "commit behind '/*'": lambda c: c.execute(f"SELECT '/*'; COMMIT; {SCOPE}{ESCAPE}; SELECT '*/'"),
    "commit behind $$--$$": lambda c: c.execute(f"SELECT $$--$$; COMMIT; {SCOPE}{ESCAPE}"),
    # A COMMIT through fetchmany, then the write in autocommit.
    "commit via fetchmany": lambda c: _then(c.fetchmany("COMMIT", [()]), c.execute(SCOPE + ESCAPE)),
    # A COMMIT behind '--', then the session default set to read write. The default applies from the next
    # transaction, so the write is still refused as read only; "begin read write" below is the case where
    # only the missing privilege is left.
    "commit, then read write": lambda c: c.execute(
        f"SELECT '--'; COMMIT; SET default_transaction_read_only = off; {SCOPE}{ESCAPE}"
    ),
    "begin read write": lambda c: c.execute(f"SELECT '--'; COMMIT; BEGIN READ WRITE; {SCOPE}{ESCAPE}"),
    # COPY into a table: the driver methods the guard refuses by name.
    "copy into a table": lambda c: c.copy_records_to_table("alert_events", records=[(1,)], columns=["id"]),
    "nextval": lambda c: c.fetchval("SELECT nextval(pg_get_serial_sequence('audit_log', 'id'))"),
}


async def _then(first: Awaitable[Any], second: Awaitable[Any]) -> Any:
    await first
    return await second


@pytest.fixture
def no_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the statement guard: shadow transactions hand out the driver connection itself."""
    monkeypatch.setattr("lg_sotf.db.pool.shadow_connection", lambda conn: conn)


@pytest.mark.parametrize("bypass", list(PROVEN_BYPASSES))
async def test_shadow_role_refuses_each_proven_guard_bypass_at_the_database(
    db: Database, repos: Repositories, no_guard: None, bypass: str
) -> None:
    with shadow_scope(ShadowRun("shadow/e15c")):
        async with db.tenant_tx(TENANT_A) as conn:
            assert not isinstance(conn, ShadowConnection)
            assert await conn.fetchval("SELECT current_user") == SHADOW_ROLE
            with pytest.raises(DATABASE_REFUSALS):
                await PROVEN_BYPASSES[bypass](conn)
    assert (await repos.tenants.get(TENANT_A)).name == "Tenant A"


async def test_shadow_role_refuses_the_bypasses_on_a_bare_connection_too(
    db: Database, repos: Repositories, no_guard: None
) -> None:
    with shadow_scope(ShadowRun("shadow/e15c-bare")):
        async with db.connection() as conn:
            with pytest.raises(DATABASE_REFUSALS):
                await conn.execute(f"SELECT '--'; COMMIT; SET default_transaction_read_only = off; {SCOPE}{ESCAPE}")
    assert (await repos.tenants.get(TENANT_A)).name == "Tenant A"


async def test_shadow_sessions_are_read_only_select_only_and_never_the_runtime_role(
    db: Database, repos: Repositories
) -> None:
    with shadow_scope(ShadowRun("shadow/e15c-session")):
        async with db.tenant_tx(TENANT_A) as conn:
            assert await conn.fetchval("SELECT current_setting('default_transaction_read_only')") == "on"
            assert await conn.fetchval("SELECT session_user") == SHADOW_ROLE
            assert unsafe_role_reasons(tuple(await conn.fetchrow(UNSAFE_ROLE_SQL.format(role="current_user"))), "") == []
            assert (await conn.fetchval("SELECT name FROM tenants")) == "Tenant A"  # reads work, under RLS
    async with db.connection() as conn:
        rows = await conn.fetch(
            "SELECT t, has_table_privilege($1, 'public.' || t, 'SELECT') AS can_read FROM unnest($2::text[]) AS t",
            SHADOW_ROLE,
            [*SHADOW_TABLES, *SHADOW_EXCLUDED_TABLES],
        )
    assert {r["t"] for r in rows if r["can_read"]} == set(SHADOW_TABLES)
    assert not SHADOW_EXCLUDED_TABLES & set(SHADOW_TABLES) and "users" in SHADOW_EXCLUDED_TABLES


async def test_without_the_shadow_role_a_shadow_transaction_is_refused_not_run_on_the_runtime_role(
    migrated_database_url: str, repos: Repositories
) -> None:
    runtime_only = Database(db_settings(migrated_database_url, pool_min=0, pool_max=2), application_name="no-shadow")
    await runtime_only.open()
    try:
        with pytest.raises(ShadowRoleRequired, match="database.shadow_url"):
            await runtime_only.open_shadow()
        with shadow_scope(ShadowRun("shadow/e15c-none")) as run:
            for scope in (runtime_only.tenant_tx(TENANT_A), runtime_only.connection(), runtime_only.system_tx()):
                with pytest.raises(ShadowEgressRefused, match="without the shadow role"):
                    async with scope:
                        pass
        assert {e.outcome for e in run.sink.effects} == {"refused"}
        async with runtime_only.tenant_tx(TENANT_A) as conn:  # live use is unchanged
            assert await conn.fetchval("SELECT count(*) FROM tenants") == 1
    finally:
        await runtime_only.close()


async def test_a_shadow_url_that_logs_in_as_a_role_that_can_write_is_refused(migrated_database_url: str) -> None:
    owner_as_shadow = Database(
        db_settings(migrated_database_url, pool_min=0, pool_max=1, shadow_url=migrated_database_url),
        application_name="owner-as-shadow",
    )
    await owner_as_shadow.open()
    try:
        with pytest.raises(ShadowRoleRequired, match="member of the schema owner.*may write to"):
            await owner_as_shadow.open_shadow()
        with shadow_scope(ShadowRun("shadow/e15c-owner")):
            with pytest.raises(ShadowEgressRefused):
                async with owner_as_shadow.tenant_tx(TENANT_A):
                    pass
    finally:
        await owner_as_shadow.close()


async def test_grant_shadow_privileges_refuses_a_role_that_could_write(
    db: Database, repos: Repositories, migrated_database_url: str
) -> None:
    async with db.connection() as conn:
        owner = await conn.fetchval("SELECT current_user")
    with pytest.raises(ValueError, match="must be SELECT-only"):
        await asyncio.to_thread(grant_shadow_privileges, owner, migrated_database_url, DatabaseSettings())
    with pytest.raises(ValueError, match="role 'no_such_role_xyz' does not exist"):
        await asyncio.to_thread(grant_shadow_privileges, "no_such_role_xyz", migrated_database_url, DatabaseSettings())
    async with db.tenant_tx(TENANT_A) as conn:  # the refused grant was rolled back: the owner still writes
        assert await conn.execute("UPDATE tenants SET name = name WHERE id = $1", TENANT_A) == "UPDATE 1"


async def test_a_shadow_url_that_cannot_log_in_opens_no_pool(migrated_database_url: str) -> None:
    wrong = shadow_url(migrated_database_url).replace(f"{SHADOW_ROLE}:", f"{SHADOW_ROLE}:wrong-")
    database = Database(db_settings(migrated_database_url, pool_min=0, pool_max=1, shadow_url=wrong))
    await database.open()
    try:
        with pytest.raises(DatabaseUnavailable, match="cannot connect as the shadow role"):
            await database.open_shadow()
        with shadow_scope(ShadowRun("shadow/e15c-login")):
            with pytest.raises(ShadowEgressRefused):
                async with database.connection():
                    pass
    finally:
        await database.close()


async def test_pointing_the_shadow_role_at_the_runtime_role_changes_nothing(
    db: Database, migrated_database_url: str
) -> None:
    """``database.shadow_role`` set to the runtime role is refused before its privileges are revoked."""
    runtime = "pg_database_owner"  # stands in for the runtime role, as in test_runtime_role.py
    await asyncio.to_thread(grant_runtime_privileges, runtime, migrated_database_url, DatabaseSettings())
    with pytest.raises(ValueError, match="must be SELECT-only, but it may write to"):
        await asyncio.to_thread(grant_shadow_privileges, runtime, migrated_database_url, DatabaseSettings())
    async with db.connection() as conn:
        assert await conn.fetchval("SELECT has_table_privilege($1, 'public.alerts', 'INSERT')", runtime)
