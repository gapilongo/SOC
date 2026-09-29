"""Migration round trip, schema invariants and checkpointer setup."""

from __future__ import annotations

from datetime import UTC, datetime

import psycopg
import pytest

from lg_sotf.db.migrate import (
    current_revision,
    downgrade_base,
    head_revision,
    schema_is_current,
    setup_checkpointer,
    upgrade_head,
)
from lg_sotf.db.partitions import add_months, month_start, partition_name
from lg_sotf.db.pool import Database
from lg_sotf.db.urls import to_libpq_url

pytestmark = pytest.mark.asyncio

TENANT_OWNED = (
    "users",
    "refresh_tokens",
    "api_keys",
    "sources",
    "alerts",
    "alert_events",
    "workflow_runs",
    "escalations",
    "analyst_feedback",
    "response_actions",
    "suppression_rules",
    "indicator_sightings",
    "llm_usage_daily",
    "audit_log",
)


def _query(url: str, sql: str) -> list:
    with psycopg.connect(to_libpq_url(url)) as conn:
        return conn.execute(sql).fetchall()


async def test_upgrade_downgrade_upgrade_round_trip(migrated_database_url: str) -> None:
    url = migrated_database_url
    assert current_revision(url) == head_revision()

    downgrade_base(url)
    assert current_revision(url) is None
    leftovers = _query(
        url,
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
        "AND tablename NOT IN ('alembic_version') AND tablename NOT LIKE 'checkpoint%'",
    )
    assert leftovers == []

    upgrade_head(url)
    assert current_revision(url) == head_revision()
    with psycopg.connect(to_libpq_url(url)) as conn:
        conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        assert conn.execute("SELECT id, status FROM tenants").fetchall() == [("default", "active")]


async def test_every_tenant_table_has_forced_rls_and_policy(migrated_database_url: str) -> None:
    rows = _query(
        migrated_database_url,
        """
        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
               EXISTS (SELECT 1 FROM pg_policies p WHERE p.tablename = c.relname AND p.policyname = 'tenant_isolation')
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          AND c.relname <> 'alembic_version' AND c.relname NOT LIKE 'checkpoint%'
        """,
    )
    by_name = {r[0]: r[1:] for r in rows}
    for table in (*TENANT_OWNED, "tenants"):
        assert by_name[table] == (True, True, True), table
    partitions = [name for name in by_name if "_p2" in name or name.endswith("_default")]
    assert partitions
    for name in partitions:
        assert by_name[name] == (True, True, True), name


async def test_initial_partitions_cover_current_and_next_two_months(migrated_database_url: str) -> None:
    first = month_start(datetime.now(UTC).date())
    names = {r[0] for r in _query(migrated_database_url, "SELECT tablename FROM pg_tables WHERE schemaname='public'")}
    for table in ("alert_events", "audit_log"):
        assert f"{table}_default" in names
        for i in range(3):
            assert partition_name(table, add_months(first, i)) in names


async def test_check_constraints_reject_unknown_enum_values(migrated_database_url: str) -> None:
    with psycopg.connect(to_libpq_url(migrated_database_url)) as conn:
        conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        conn.execute("INSERT INTO tenants (id, name) VALUES ('check-t', 'x') ON CONFLICT DO NOTHING")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO alerts (tenant_id, source_id, source_alert_id, fingerprint, title, severity, occurred_at) "
                "VALUES ('check-t', 's', '1', 'f', 't', 'urgent', now())"
            )
        conn.rollback()
        conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("INSERT INTO tenants (id, name) VALUES ('Bad Tenant', 'x')")
        conn.rollback()


async def test_schema_hardening_invariants(migrated_database_url: str) -> None:
    url = migrated_database_url
    gin = _query(url, "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexdef ILIKE '%USING gin%'")
    assert gin == [], "trigram/GIN indexes cannot serve ILIKE under FORCE RLS; none are expected"
    sources_pk = _query(
        url,
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'sources'::regclass AND contype = 'p'",
    )
    assert sources_pk == [("PRIMARY KEY (tenant_id, id)",)]
    for fn in (
        "lgsotf_auth_refresh_token(text)",
        "lgsotf_auth_api_key(uuid)",
        "lgsotf_auth_users_by_email(text)",
        "lgsotf_create_tenant(text, text)",
    ):
        [(definer, public_exec)] = _query(
            url,
            f"SELECT p.prosecdef, has_function_privilege('pg_monitor', '{fn}', 'EXECUTE') "  # noqa: S608
            f"FROM pg_proc p WHERE p.oid = '{fn}'::regprocedure",
        )
        assert definer is True and public_exec is False, fn
    policies = _query(url, "SELECT DISTINCT qual FROM pg_policies WHERE schemaname = 'public'")
    assert policies and all("lgsotf_rls_bypass()" in q for (q,) in policies)
    assert all("app.bypass_rls" not in q for (q,) in policies)


async def test_schema_is_current(migrated_database_url: str) -> None:
    db = Database(dsn=migrated_database_url, min_size=0, max_size=1)
    await db.open()
    try:
        assert await schema_is_current(db) is True
    finally:
        await db.close()


async def test_setup_checkpointer_is_idempotent(migrated_database_url: str) -> None:
    await setup_checkpointer(migrated_database_url)
    await setup_checkpointer(migrated_database_url)
    names = {r[0] for r in _query(migrated_database_url, "SELECT tablename FROM pg_tables WHERE schemaname='public'")}
    assert {"checkpoints", "checkpoint_blobs", "checkpoint_writes", "checkpoint_migrations"} <= names
