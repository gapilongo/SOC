"""The API/worker runtime role: least privilege, no RLS bypass, append-only audit log.

The test database is owned by the ``soc`` login role, which is therefore an
implicit member of ``pg_database_owner``. Sessions started with
``role=pg_database_owner`` act as a role that owns no tables and is not a
member of the schema owner, which is exactly the production runtime role.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import AsyncIterator

import asyncpg
import psycopg
import pytest
import pytest_asyncio

from lg_sotf.db.errors import Conflict, NotFound, SystemScopeDenied
from lg_sotf.db.migrate import (
    grant_runtime_privileges,
    schema_is_current,
    setup_checkpointer,
)
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, Repositories
from lg_sotf.db.retention import purge_expired
from lg_sotf.db.tenancy import switch_tenant
from lg_sotf.db.urls import to_libpq_url
from tests.integration.db._support import TENANT_A, TENANT_B, db_settings, make_alert
from tests.integration.db.test_rls import TENANT_TABLES, seed_everything

pytestmark = pytest.mark.asyncio

RUNTIME_ROLE = "pg_database_owner"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest_asyncio.fixture
async def app_db(db: Database, repos: Repositories, migrated_database_url: str) -> AsyncIterator[Database]:
    await setup_checkpointer(migrated_database_url)
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url)
    runtime = Database(
        db_settings(migrated_database_url, pool_min=0, pool_max=4),
        application_name="lg-sotf-tests-runtime",
        server_settings={"role": RUNTIME_ROLE},
    )
    await runtime.open()
    try:
        async with runtime.connection() as conn:
            assert await conn.fetchval("SELECT current_user") == RUNTIME_ROLE
        yield runtime
    finally:
        await runtime.close()


@pytest.fixture
def app(app_db: Database) -> Repositories:
    return Repositories.create(app_db)


async def test_runtime_role_can_run_the_application(app: Repositories, repos: Repositories) -> None:
    now = datetime.now(UTC)
    alert_id = await seed_everything(app, TENANT_A)
    await seed_everything(app, TENANT_B)
    assert await schema_is_current(app.db)

    [user] = await app.users.find_by_email_all_tenants(f"analyst@{TENANT_A}.test")
    assert user.tenant_id == TENANT_A
    token = await app.refresh_tokens.get_by_hash_all_tenants(_sha(f"rt-{TENANT_B}"))
    assert token is not None and token.tenant_id == TENANT_B
    rotated = await app.refresh_tokens.rotate(TENANT_B, _sha(f"rt-{TENANT_B}"), _sha("rt-b2"), now + timedelta(days=1))
    assert rotated.tenant_id == TENANT_B
    [key] = await app.api_keys.list(TENANT_A)
    assert (await app.api_keys.get_by_id_all_tenants(key.id)).tenant_id == TENANT_A
    assert await app.api_keys.touch_last_used(TENANT_A, key.id)
    await app.users.record_login_failure(TENANT_A, user.id, max_attempts=5, lockout_minutes=5)
    await app.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})

    await app.alerts.update_status(TENANT_A, alert_id, "queued")
    run = await app.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
    await app.alerts.update_status(TENANT_A, alert_id, "processing")
    assert await app.runs.heartbeat(TENANT_A, alert_id, "w1", lease_s=60)
    esc = await app.escalations.get_active_for_alert(TENANT_A, alert_id)
    claimed = await app.escalations.claim(TENANT_A, esc.id, user.id, esc.version)
    await app.escalations.decide(
        TENANT_A, esc.id, decision="true_positive", decided_by=user.id, expected_version=claimed.version
    )
    [action] = (await app.actions.list(TENANT_A)).items
    await app.actions.transition(TENANT_A, action.id, "approved", approved_by=str(user.id))
    await app.actions.transition(TENANT_A, action.id, "executing")
    await app.runs.complete(TENANT_A, alert_id, worker_id=run.worker_id)
    [rule] = await app.suppressions.list_active(TENANT_A)
    await app.suppressions.record_hit(TENANT_A, rule.id)
    await app.llm_usage.upsert_daily(
        [
            LLMUsageDelta(tenant_id=t, day=date.today(), model="m", agent="a", calls=1, cost_usd=Decimal("0.1"))
            for t in (TENANT_A, TENANT_B)
        ]
    )
    await app.audit.append(TENANT_A, "user", str(user.id), "action.approved", "response_action", str(action.id))
    assert await app.audit.verify_chain(TENANT_A) == (True, None)
    await app.sources.delete(TENANT_A, (await app.sources.list(TENANT_A))[0].id)

    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "processing"
    assert (await repos.runs.get(TENANT_A, alert_id)).status == "completed"


async def test_setting_the_bypass_guc_does_not_bypass_isolation(app_db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_A)
    await seed_everything(repos, TENANT_B)
    async with app_db.tenant_tx(TENANT_A) as conn:
        await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
        assert await conn.fetchval("SELECT lgsotf_rls_bypass()") is False
        for table in TENANT_TABLES:
            tenants = {r[0] for r in await conn.fetch(f"SELECT DISTINCT tenant_id FROM {table}")}  # noqa: S608
            assert tenants == {TENANT_A}, table
        assert await conn.execute("UPDATE alerts SET title = 'x' WHERE tenant_id = $1", TENANT_B) == "UPDATE 0"
    async with app_db.connection() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
            assert await conn.fetchval("SELECT count(*) FROM alerts") == 0
            assert await conn.fetchval("SELECT count(*) FROM tenants") == 0


async def test_system_scope_is_refused_for_the_runtime_role(app_db: Database, app: Repositories) -> None:
    with pytest.raises(SystemScopeDenied):
        async with app_db.system_tx():
            pass
    with pytest.raises(SystemScopeDenied):
        await app.runs.requeue_stale_all_tenants()
    with pytest.raises(SystemScopeDenied):
        await purge_expired(app_db)


async def test_credential_lookups_restore_the_bypass_setting(app_db: Database, app: Repositories) -> None:
    await seed_everything(app, TENANT_A)
    async with app_db.tenant_tx(TENANT_B) as conn:
        rows = await conn.fetch("SELECT tenant_id FROM lgsotf_auth_users_by_email($1)", f"analyst@{TENANT_A}.test")
        assert [r[0] for r in rows] == [TENANT_A]
        assert (await conn.fetchval("SELECT current_setting('app.bypass_rls', true)")) in ("", None)
        assert await conn.fetchval("SELECT count(*) FROM users") == 0


async def test_audit_log_is_append_only_for_the_runtime_role(app_db: Database, app: Repositories) -> None:
    entry = await app.audit.append(TENANT_A, "system", None, "seed", "test")
    statements = (
        "UPDATE audit_log SET action = 'forged'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        "SELECT count(*) FROM audit_log_default",
        "UPDATE audit_log_default SET action = 'forged'",
    )
    for sql in statements:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with app_db.tenant_tx(TENANT_A) as conn:
                await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
                await conn.execute(sql)
    assert (await app.audit.verify_chain(TENANT_A)) == (True, None)
    assert [e.id for e in (await app.audit.list(TENANT_A)).items] == [entry.id]


@pytest.mark.parametrize(
    "sql",
    [
        "ALTER TABLE audit_log DISABLE TRIGGER audit_log_immutable",
        "ALTER TABLE alerts DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE alerts NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON alerts",
        "CREATE OR REPLACE FUNCTION lgsotf_rls_bypass() RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "DROP TABLE audit_log_default",
        "DELETE FROM alerts",
        "DELETE FROM alert_events",
    ],
)
async def test_runtime_role_cannot_weaken_the_schema(app_db: Database, app: Repositories, sql: str) -> None:
    await make_alert(app, TENANT_A)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with app_db.tenant_tx(TENANT_A) as conn:
            await conn.execute(sql)


def _schema_owner(url: str) -> str:
    with psycopg.connect(to_libpq_url(url), autocommit=True) as conn:
        row = conn.execute(
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.tenants'::regclass"
        ).fetchone()
    assert row is not None
    return str(row[0])


async def test_grants_are_least_privilege(app_db: Database, migrated_database_url: str) -> None:
    async with app_db.connection() as conn:

        async def can(obj: str, privilege: str) -> bool:
            return await conn.fetchval("SELECT has_table_privilege($1, $2)", obj, privilege)

        assert await can("audit_log", "INSERT") and await can("audit_log", "SELECT")
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            assert not await can("audit_log", privilege)
        assert not await can("alerts", "DELETE") and await can("alerts", "UPDATE")
        assert not await can("tenants", "INSERT") and not await can("tenants", "DELETE")
        assert await can("checkpoints", "INSERT") and await can("checkpoint_writes", "DELETE")
        assert not await can("alembic_version", "UPDATE")
    owner = await asyncio.to_thread(_schema_owner, migrated_database_url)
    with pytest.raises(ValueError):
        await asyncio.to_thread(grant_runtime_privileges, owner, migrated_database_url)
    with pytest.raises(ValueError):
        await asyncio.to_thread(grant_runtime_privileges, "no_such_role_xyz", migrated_database_url)


async def _provision_in_one_transaction(app: Repositories, tenant_id: str, *, fail: bool = False) -> None:
    """Tenant row, settings, first admin and both audit entries in one runtime-role transaction."""
    async with app.db.tenant_tx(tenant_id) as conn:
        await app.tenants.provision(tenant_id, "New Co", conn=conn)
        await app.tenants.update_settings(tenant_id, {"autonomy": {"low": "auto"}}, conn=conn)
        user = await app.users.create(tenant_id, f"root@{tenant_id}.example.com", "admin", conn=conn)
        await app.audit.append(tenant_id, "system", "test", "tenant.created", "tenant", tenant_id, conn=conn)
        await app.audit.append(tenant_id, "system", "test", "user.created", "user", str(user.id), conn=conn)
        if fail:
            raise RuntimeError("provisioning interrupted")
        await switch_tenant(conn, TENANT_A)
        await app.audit.append(TENANT_A, "system", "test", "platform.tenant_created", "tenant", tenant_id, conn=conn)


async def test_runtime_role_provisions_a_tenant_in_one_transaction(app: Repositories, repos: Repositories) -> None:
    with pytest.raises(RuntimeError):
        await _provision_in_one_transaction(app, "new-co", fail=True)
    with pytest.raises(NotFound):
        await repos.tenants.get("new-co")
    assert await repos.users.list("new-co") == []
    assert (await repos.audit.list("new-co")).items == []

    await _provision_in_one_transaction(app, "new-co")
    tenant = await repos.tenants.get("new-co")
    assert (tenant.name, tenant.settings) == ("New Co", {"autonomy": {"low": "auto"}})
    assert [u.email for u in await repos.users.list("new-co")] == ["root@new-co.example.com"]
    assert [e.action for e in (await repos.audit.list("new-co")).items] == ["user.created", "tenant.created"]
    assert [e.action for e in (await repos.audit.list(TENANT_A)).items] == ["platform.tenant_created"]
    for tenant_id in ("new-co", TENANT_A):
        assert (await repos.audit.verify_chain(tenant_id)).ok
    # The bypass the SECURITY DEFINER function turned on did not outlive its insert.
    async with app.db.tenant_tx("other-co") as conn:
        await app.tenants.provision("other-co", "Other", conn=conn)
        assert await conn.fetchval("SELECT current_setting('app.bypass_rls', true)") in (None, "")
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 0
    with pytest.raises(Conflict):
        async with app.db.tenant_tx("new-co") as conn:
            await app.tenants.provision("new-co", "Again", conn=conn)
