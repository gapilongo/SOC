"""Migration round trip, schema invariants and checkpointer setup."""

from __future__ import annotations

import io
import re
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from alembic import command
from psycopg.types.json import Jsonb

from lg_sotf.db.migrate import (
    alembic_config,
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
    "user_mfa",
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
    "usage_daily",
    "audit_log",
    "integrations",
    "notification_outbox",
    "external_tickets",
)


def _query(url: str, sql: str) -> list:
    with psycopg.connect(to_libpq_url(url)) as conn:
        return conn.execute(sql).fetchall()


async def test_upgrade_downgrade_upgrade_round_trip(migrated_database_url: str) -> None:
    url = migrated_database_url
    assert current_revision(url) == head_revision()
    # Microsoft integrations block the 0009 downgrade on purpose; tests that ran earlier may have left some.
    with _owner(url) as conn:
        conn.execute("DELETE FROM integrations WHERE kind = 'microsoft'")
        conn.commit()

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
        "lgsotf_platform_tenants()",
        "lgsotf_platform_tenant_stats(timestamptz)",
        "lgsotf_platform_escalations(integer, timestamptz, text, text)",
        "lgsotf_platform_usage(date, date)",
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


async def test_query_indexes_exist(migrated_database_url: str) -> None:
    """PERF-6/PERF-7: composite and partial indexes for list filters and the dashboard."""
    names = {
        row[0]
        for row in _query(
            migrated_database_url, "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
        )
    }
    assert {
        "ix_alerts_status_severity",
        "ix_alerts_disposition",
        "ix_alerts_tenant_closed",
        "ix_escalations_claimed",
        "ix_workflow_runs_active",
    } <= names


# ------------------------------------------------------------------ 0009: direct response and verification


def _owner(url: str) -> psycopg.Connection:
    conn = psycopg.connect(to_libpq_url(url))
    conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
    return conn


def _action_row(conn: psycopg.Connection, tenant: str, alert: str, **values: object) -> str:
    base: dict = {
        "tenant_id": tenant, "alert_id": alert, "action_type": "isolate_host", "target": f"ws-{uuid.uuid4().hex[:6]}",
        "risk_level": "high", "idempotency_key": uuid.uuid4().hex, "status": "approved",
    }
    base.update(values)
    columns = ", ".join(base)
    placeholders = ", ".join(["%s"] * len(base))
    row = conn.execute(
        f"INSERT INTO response_actions ({columns}) VALUES ({placeholders}) RETURNING id",  # noqa: S608
        [Jsonb(v) if isinstance(v, (dict, list)) else v for v in base.values()],
    ).fetchone()
    assert row is not None
    return str(row[0])


def _seed(conn: psycopg.Connection, tenant: str) -> str:
    conn.execute("INSERT INTO tenants (id, name) VALUES (%s, 'x') ON CONFLICT DO NOTHING", (tenant,))
    alert = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO alerts (tenant_id, id, source_id, source_alert_id, fingerprint, title, severity, occurred_at) "
        "VALUES (%s, %s, 's', %s, 'f', 't', 'high', now())",
        (tenant, alert, alert),
    )
    return alert


async def test_0009_ledger_constraints(migrated_database_url: str) -> None:
    tenant = f"m9-{uuid.uuid4().hex[:8]}"
    violations = [
        {"status": "approved", "verification": "verified"},
        {"status": "succeeded", "verification": "pending"},
        {"execution_owner": "robot"},
        {"external_ref": ["not", "an", "object"]},
        {"verification_detail": {"x": "y" * 20_000}},
        {"attempts": -1},
    ]
    for values in violations:
        with _owner(migrated_database_url) as conn:
            alert = _seed(conn, tenant)
            with pytest.raises(psycopg.errors.CheckViolation):
                _action_row(conn, tenant, alert, **values)
    with _owner(migrated_database_url) as conn:
        alert = _seed(conn, tenant)
        original = _action_row(conn, tenant, alert, status="succeeded")
        assert _action_row(conn, tenant, alert, status="succeeded", verification="pending",
                           verify_after=datetime.now(UTC), verify_deadline=datetime.now(UTC))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE response_actions SET rollback_of = id WHERE id = %s", (original,))
    with _owner(migrated_database_url) as conn:
        alert = _seed(conn, tenant)
        original = _action_row(conn, tenant, alert, status="succeeded")
        with pytest.raises(psycopg.errors.CheckViolation):
            _action_row(conn, tenant, alert, action_type="release_host", rollback_of=original, execution_owner="workflow")
    with _owner(migrated_database_url) as conn:
        alert = _seed(conn, tenant)
        original = _action_row(conn, tenant, alert, status="succeeded")
        _action_row(conn, tenant, alert, action_type="release_host", rollback_of=original, execution_owner="scheduler",
                    status="rejected")
        _action_row(conn, tenant, alert, action_type="release_host", rollback_of=original, execution_owner="scheduler",
                    status="awaiting_approval")
        with pytest.raises(psycopg.errors.UniqueViolation):  # one live rollback per original
            _action_row(conn, tenant, alert, action_type="release_host", rollback_of=original,
                        execution_owner="scheduler", status="approved")


async def test_0009_one_microsoft_integration_and_set_null_pin(migrated_database_url: str) -> None:
    tenant = f"m9-{uuid.uuid4().hex[:8]}"
    with _owner(migrated_database_url) as conn:
        alert = _seed(conn, tenant)
        row = conn.execute(
            "INSERT INTO integrations (tenant_id, kind, name) VALUES (%s, 'microsoft', 'ms') RETURNING id", (tenant,)
        ).fetchone()
        assert row is not None
        integration_id = row[0]
        action = _action_row(conn, tenant, alert, status="succeeded", connector="microsoft", integration_id=integration_id)
        conn.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                "INSERT INTO integrations (tenant_id, kind, name, enabled) VALUES (%s, 'microsoft', 'ms2', false)",
                (tenant,),
            )
        conn.rollback()
        conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        conn.execute("DELETE FROM integrations WHERE id = %s", (integration_id,))
        pinned = conn.execute("SELECT integration_id, connector FROM response_actions WHERE id = %s", (action,)).fetchone()
        assert pinned == (None, "microsoft")
        conn.commit()


async def test_0009_downgrade_refuses_while_microsoft_integrations_exist(migrated_database_url: str) -> None:
    url = migrated_database_url
    cfg = alembic_config(url)
    tenant = f"m9-{uuid.uuid4().hex[:8]}"
    with _owner(url) as conn:
        _seed(conn, tenant)
        conn.execute("INSERT INTO integrations (tenant_id, kind, name) VALUES (%s, 'microsoft', 'ms')", (tenant,))
        conn.commit()
    try:
        with pytest.raises(Exception, match="Microsoft integrations exist"):
            command.downgrade(cfg, "0008")
        assert current_revision(url) == head_revision()
        with _owner(url) as conn:
            conn.execute("DELETE FROM integrations WHERE kind = 'microsoft'")
            conn.commit()
        command.downgrade(cfg, "0008")
        assert current_revision(url) == "0008"
        columns = {
            r[0] for r in _query(url, "SELECT column_name FROM information_schema.columns WHERE table_name = 'response_actions'")
        }
        assert not {"execution_owner", "verification", "external_ref", "integration_id", "lease_until"} & columns
        [(kind_check,)] = _query(
            url, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'integrations_kind_check'"
        )
        assert "microsoft" not in kind_check
    finally:
        command.upgrade(cfg, "head")
    assert current_revision(url) == head_revision()


async def test_legacy_idempotency_keys_are_byte_identical() -> None:
    import hashlib
    import json

    from lg_sotf.db.repos.actions import action_idempotency_key

    legacy = hashlib.sha256(
        json.dumps(["t", "a", "block_ip", "1.2.3.4"], separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert action_idempotency_key("t", "a", "block_ip", "1.2.3.4") == legacy
    assert action_idempotency_key("t", "a", "block_ip", "1.2.3.4", "rollback:x:0") != legacy


async def test_0009_indexes_exist(migrated_database_url: str) -> None:
    names = {r[0] for r in _query(migrated_database_url, "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")}
    assert {
        "ux_integrations_microsoft",
        "ix_response_actions_verify_due",
        "ix_response_actions_background",
        "ix_response_actions_approved_workflow",
        "ix_response_actions_rollback_of",
        "ux_response_actions_live_rollback",
    } <= names


def _render(url: str, revisions: str, *, downgrade: bool = False) -> str:
    """The SQL alembic runs for ``revisions`` (offline rendering: nothing is executed)."""
    cfg = alembic_config(url)
    cfg.output_buffer = io.StringIO()
    (command.downgrade if downgrade else command.upgrade)(cfg, revisions, sql=True)
    return str(cfg.output_buffer.getvalue())


async def test_0009_scans_response_actions_only_after_its_catalog_change_committed(migrated_database_url: str) -> None:
    """The ACCESS EXCLUSIVE transaction adds columns and NOT VALID constraints only; scans run afterwards."""
    script = _render(migrated_database_url, "0008:0009")
    locked, _, after = script.partition("COMMIT;")
    assert "VALIDATE CONSTRAINT" not in locked and "UPDATE response_actions" not in locked
    assert not re.search(r"CREATE (UNIQUE )?INDEX \w+ ON response_actions", locked)
    added = re.findall(r"ADD CONSTRAINT (response_actions_\w+)(.*?)(?=,\n\s+ADD CONSTRAINT|;)", locked, re.S)
    assert len(added) == 11 and all(body.rstrip().endswith("NOT VALID") for _, body in added)
    columns = re.search(r"ALTER TABLE response_actions\s+ADD COLUMN.*?;", locked, re.S)
    assert columns is not None and "CHECK" not in columns.group(0)  # no inline CHECK: nothing to scan for
    for name, _ in added:
        assert f"VALIDATE CONSTRAINT {name};" in after
    assert after.index("UPDATE response_actions") < after.index("VALIDATE CONSTRAINT response_actions_rollback_owner")
    assert len(re.findall(r"CREATE (?:UNIQUE )?INDEX CONCURRENTLY IF NOT EXISTS \w+ ON response_actions", after)) == 5
    down = _render(migrated_database_url, "0009:0008", downgrade=True)
    assert down.index("DROP INDEX CONCURRENTLY IF EXISTS ux_response_actions_live_rollback") < down.index("DROP COLUMN")


async def test_0009_constraints_and_indexes_are_valid_after_upgrade(migrated_database_url: str) -> None:
    constraints = dict(_query(
        migrated_database_url,
        "SELECT conname, convalidated FROM pg_constraint WHERE conrelid = 'response_actions'::regclass "
        "AND conname IN ('response_actions_execution_owner_check', 'response_actions_external_ref_check', "
        "'response_actions_attempts_check', 'response_actions_verification_check', "
        "'response_actions_verification_detail_check', 'response_actions_verify_attempts_check', "
        "'response_actions_integration_fk', 'response_actions_verification_on_success', "
        "'response_actions_verification_schedule', 'response_actions_rollback_not_self', "
        "'response_actions_rollback_owner')",
    ))
    assert len(constraints) == 11 and all(constraints.values())
    invalid = _query(
        migrated_database_url,
        "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "WHERE i.indrelid = 'response_actions'::regclass AND NOT i.indisvalid",
    )
    assert invalid == []


async def test_0009_moves_existing_rollbacks_to_the_scheduler(migrated_database_url: str) -> None:
    url = migrated_database_url
    cfg = alembic_config(url)
    with _owner(url) as conn:
        conn.execute("DELETE FROM integrations WHERE kind = 'microsoft'")
        conn.commit()
    tenant = f"m9-{uuid.uuid4().hex[:8]}"
    try:
        command.downgrade(cfg, "0008")
        with _owner(url) as conn:
            alert = _seed(conn, tenant)
            original = _action_row(conn, tenant, alert, status="succeeded")
            rollback = _action_row(conn, tenant, alert, action_type="release_host", rollback_of=original)
            conn.commit()
    finally:
        command.upgrade(cfg, "head")
    with _owner(url) as conn:
        owners = dict(conn.execute(
            "SELECT id::text, execution_owner FROM response_actions WHERE tenant_id = %s", (tenant,)
        ).fetchall())
    assert owners == {original: "workflow", rollback: "scheduler"}
