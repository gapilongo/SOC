"""Schema migrations, LangGraph checkpointer setup, runtime grants and partition maintenance.

Alembic runs synchronously (psycopg driver); call :func:`upgrade_head` via
``asyncio.to_thread`` from async code.

Roles: the schema owner runs migrations and the scheduler (it may bypass RLS
and owns the partitions it creates and drops). The API and worker should use
a separate login role that has only the privileges
:func:`grant_runtime_privileges` gives it; that role cannot bypass tenant
isolation, alter tables, or modify the audit log. ``lg-sotf migrate`` runs
:func:`upgrade_head`, :func:`setup_checkpointer`, then
:func:`grant_runtime_privileges`, and :func:`grant_shadow_privileges` for
the SELECT-only role shadow runs connect as (:mod:`lg_sotf.db.shadow_role`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psycopg
import structlog
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from psycopg import sql
from sqlalchemy import create_engine, pool, text

from lg_sotf.db import locks
from lg_sotf.db.partitions import drop_expired_partitions, ensure_partitions
from lg_sotf.db.pool import Database
from lg_sotf.db.shadow_role import UNSAFE_ROLE_SQL, unsafe_role_reasons
from lg_sotf.db.urls import redact_url, to_libpq_url, to_sqlalchemy_url, with_query_params
from lg_sotf.security.shadow import REFUSE, egress
from lg_sotf.settings import DatabaseSettings

__all__ = [
    "ERASURE_FUNCTIONS",
    "MIGRATIONS_DIR",
    "MIGRATION_LOCK_TIMEOUT",
    "PLATFORM_FUNCTIONS",
    "PROVISIONING_FUNCTIONS",
    "RUNTIME_TABLE_PRIVILEGES",
    "SHADOW_TABLES",
    "alembic_config",
    "current_revision",
    "downgrade_base",
    "drop_expired_partitions",
    "ensure_partitions",
    "grant_runtime_privileges",
    "grant_shadow_privileges",
    "head_revision",
    "libpq_url",
    "migration_transaction_setup",
    "runtime_grant_statements",
    "schema_is_current",
    "setup_checkpointer",
    "sqlalchemy_url",
    "upgrade_head",
]

# Least privilege for the API/worker role. Deletes of alerts, events, tokens
# and audit rows are retention's job (schema owner); audit_log is append-only.
RUNTIME_TABLE_PRIVILEGES: Dict[str, Tuple[str, ...]] = {
    "alembic_version": ("SELECT",),
    "tenants": ("SELECT", "UPDATE"),
    "users": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "user_mfa": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "refresh_tokens": ("SELECT", "INSERT", "UPDATE"),
    "api_keys": ("SELECT", "INSERT", "UPDATE"),
    "sources": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "alerts": ("SELECT", "INSERT", "UPDATE"),
    "alert_events": ("SELECT", "INSERT"),
    "workflow_runs": ("SELECT", "INSERT", "UPDATE"),
    "escalations": ("SELECT", "INSERT", "UPDATE"),
    "analyst_feedback": ("SELECT", "INSERT"),
    "response_actions": ("SELECT", "INSERT", "UPDATE"),
    "suppression_rules": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "indicator_sightings": ("SELECT", "INSERT"),
    "llm_usage_daily": ("SELECT", "INSERT", "UPDATE"),
    "usage_daily": ("SELECT", "INSERT", "UPDATE"),
    "audit_log": ("SELECT", "INSERT"),
    "integrations": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "notification_outbox": ("SELECT", "INSERT", "UPDATE"),
    "external_tickets": ("SELECT", "INSERT", "UPDATE"),
    "investigation_steps": ("SELECT", "INSERT"),
    "shadow_effects": ("SELECT", "INSERT"),
    "shadow_verdicts": ("SELECT", "INSERT"),
    # Written through lgsotf_save_organisation (platform admins) only.
    "organisations": ("SELECT",),
    "organisation_members": ("SELECT", "INSERT", "DELETE"),
    # Revoked grants stay (revoked_at): the customer's record of who could act in it.
    "tenant_grants": ("SELECT", "INSERT", "UPDATE (revoked_at, revoked_by)"),
    # Blind audit (migration 0014): runs are a record; an item is labelled once (a trigger refuses other updates).
    "blind_audit_runs": (
        "SELECT",
        "INSERT (tenant_id, window_start, window_end, seed, sample_rate, min_sample, fixed_size, frame_size, "
        "sample_size, trigger, created_by)",
    ),
    "blind_audit_items": (
        "SELECT",
        "INSERT (tenant_id, run_id, alert_id, sample_rank, ai_class)",
        "UPDATE (label, notes, agreement, labelled_by, labelled_by_actor, labelled_by_org, labelled_at, escalation_id)",
    ),
    # Proof-of-value runs (migration 0019): the API creates and cancels; the scheduler (owner) writes the backtest.
    "pov_runs": (
        "SELECT",
        "INSERT (tenant_id, name, backtest_start, backtest_end, shadow_start, shadow_end, created_by)",
        "UPDATE (cancelled_at, cancelled_by)",
    ),
}
# The shadow role (AI-E1.5c) reads what a run reads: every runtime table but the credentials, and writes nothing.
SHADOW_EXCLUDED_TABLES = frozenset({"users", "user_mfa", "refresh_tokens", "api_keys"})
SHADOW_TABLES: Tuple[str, ...] = tuple(t for t in RUNTIME_TABLE_PRIVILEGES if t not in SHADOW_EXCLUDED_TABLES)
CHECKPOINT_TABLE_PRIVILEGES: Dict[str, Tuple[str, ...]] = {
    "checkpoints": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "checkpoint_blobs": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "checkpoint_writes": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "checkpoint_migrations": ("SELECT",),
}
SERIAL_SEQUENCES: Tuple[Tuple[str, str], ...] = (("alert_events", "id"), ("audit_log", "id"))
AUTH_LOOKUP_FUNCTIONS: Tuple[str, ...] = (
    "lgsotf_auth_refresh_token(text)",
    "lgsotf_auth_api_key(uuid)",
    "lgsotf_auth_users_by_email(text)",
)
PROVISIONING_FUNCTIONS: Tuple[str, ...] = ("lgsotf_create_tenant(text, text)",)
# Cross-tenant aggregates behind the platform-admin endpoints (migration 0004).
PLATFORM_FUNCTIONS: Tuple[str, ...] = (
    "lgsotf_platform_tenants()",
    "lgsotf_platform_tenant_stats(timestamptz)",
    "lgsotf_platform_escalations(integer, timestamptz, text, text)",
    "lgsotf_platform_usage(date, date)",
)
# Tenant erasure (platform admins, migration 0006): bounded batches of one suspended tenant's rows.
ERASURE_FUNCTIONS: Tuple[str, ...] = ("lgsotf_erase_tenant_batch(text, integer)",)
# MSSP organisations (platform admins, migration 0012).
ORGANISATION_FUNCTIONS: Tuple[str, ...] = ("lgsotf_save_organisation(text, text)",)

log = structlog.get_logger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
MIGRATION_LOCK_TIMEOUT = "60s"


def migration_transaction_setup() -> Tuple[str, ...]:
    """The statements that open every migration transaction (env.py).

    A revision whose autocommit block committed that transaction runs them
    again in the one alembic opens afterwards (0009).
    """
    return (
        f"SET LOCAL lock_timeout = '{MIGRATION_LOCK_TIMEOUT}'",
        "SET LOCAL statement_timeout = 0",
        "SELECT set_config('app.bypass_rls', 'on', true)",
        f"SELECT pg_advisory_xact_lock({locks.MIGRATIONS}, 0)",
    )


def _ssl_params(database: DatabaseSettings) -> dict[str, Optional[str]]:
    return {"sslmode": database.ssl_mode, "sslrootcert": database.ssl_root_cert}


def libpq_url(database_url: str, database: DatabaseSettings) -> str:
    """``database_url`` as ``postgresql://`` with the SSL settings of ``database`` applied.

    Configured ``ssl_mode``/``ssl_root_cert`` override the URL's own
    ``sslmode``/``sslrootcert`` so psycopg (migrations, checkpointer) uses the
    same TLS policy as the asyncpg pool.
    """
    return with_query_params(to_libpq_url(database_url), _ssl_params(database), override=True)


def sqlalchemy_url(database_url: str, database: DatabaseSettings) -> str:
    return to_sqlalchemy_url(libpq_url(database_url, database))


def _script_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("path_separator", "os")
    return cfg


def alembic_config(database_url: str, database: DatabaseSettings) -> Config:
    """Alembic configuration built in code; no ini file required."""
    cfg = _script_config()
    cfg.attributes["sqlalchemy_url"] = sqlalchemy_url(database_url, database)
    return cfg


def upgrade_head(database_url: str, database: DatabaseSettings) -> None:
    cfg = alembic_config(database_url, database)
    log.info("db.migrate.upgrade", target="head", url=redact_url(cfg.attributes["sqlalchemy_url"]))
    command.upgrade(cfg, "head")


def downgrade_base(database_url: str, database: DatabaseSettings) -> None:
    """Drop the whole application schema. Intended for tests and teardown."""
    cfg = alembic_config(database_url, database)
    log.warning("db.migrate.downgrade", target="base", url=redact_url(cfg.attributes["sqlalchemy_url"]))
    command.downgrade(cfg, "base")


def head_revision() -> str:
    script = ScriptDirectory.from_config(_script_config())
    head = script.get_current_head()
    if head is None:
        raise RuntimeError("no migration revisions found")
    return head


def current_revision(database_url: str, database: DatabaseSettings) -> Optional[str]:
    engine = create_engine(sqlalchemy_url(database_url, database), poolclass=pool.NullPool)
    try:
        with engine.connect() as conn:
            exists = conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar()
            if exists is None:
                return None
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    finally:
        engine.dispose()


async def schema_is_current(db: Database) -> bool:
    """True when the database is migrated to this code's head revision."""
    async with db.connection() as conn:
        if await conn.fetchval("SELECT to_regclass('public.alembic_version')") is None:
            return False
        version: Optional[str] = await conn.fetchval("SELECT version_num FROM alembic_version")
    return version == head_revision()


def runtime_grant_statements(role: str, *, sequences: List[str], checkpoint_tables: List[str]) -> List[sql.Composed]:
    """Statements that reset ``role`` to exactly the runtime privileges.

    ``sequences`` are schema-qualified sequence names; ``checkpoint_tables``
    are the LangGraph tables that exist.
    """
    who = sql.Identifier(role)
    stmts: List[sql.Composed] = [
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(who),
        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}").format(who),
        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(who),
    ]
    tables = dict(RUNTIME_TABLE_PRIVILEGES)
    tables.update({t: CHECKPOINT_TABLE_PRIVILEGES[t] for t in checkpoint_tables})
    for table, privileges in tables.items():
        stmts.append(
            sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                sql.SQL(", ").join(sql.SQL(p) for p in privileges), sql.Identifier("public", table), who
            )
        )
    for seq in sequences:
        stmts.append(sql.SQL("GRANT USAGE ON SEQUENCE {} TO {}").format(sql.Identifier(*seq.split(".", 1)), who))
    for fn in (
        *AUTH_LOOKUP_FUNCTIONS, *PROVISIONING_FUNCTIONS, *PLATFORM_FUNCTIONS, *ERASURE_FUNCTIONS, *ORGANISATION_FUNCTIONS
    ):
        stmts.append(sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(sql.SQL(fn), who))
    return stmts


@egress("database_connection", REFUSE)
def grant_runtime_privileges(role: str, database_url: str, database: DatabaseSettings) -> None:
    """Give the API/worker login role exactly the privileges it needs (idempotent).

    Run after :func:`upgrade_head` and :func:`setup_checkpointer`, as the
    schema owner. Refuses a role that could bypass RLS (superuser,
    BYPASSRLS, or a member of the owner role), because granting it would
    defeat the separation.
    """
    with psycopg.connect(libpq_url(database_url, database)) as conn:
        found = conn.execute(
            """
            SELECT r.rolsuper, r.rolbypassrls,
                   pg_has_role(r.rolname, (SELECT relowner FROM pg_class WHERE oid = 'public.tenants'::regclass),
                               'MEMBER')
            FROM pg_roles r WHERE r.rolname = %s
            """,
            (role,),
        ).fetchone()
        if found is None:
            raise ValueError(f"database role does not exist: {role!r}")
        if any(found):
            raise ValueError(
                f"runtime role {role!r} must not be a superuser, have BYPASSRLS or be a member of the schema owner"
            )
        sequences: List[str] = [
            r[0]
            for r in conn.execute(
                "SELECT pg_get_serial_sequence(t, c) FROM unnest(%s::text[], %s::text[]) AS x(t, c)",
                ([f"public.{t}" for t, _ in SERIAL_SEQUENCES], [c for _, c in SERIAL_SEQUENCES]),
            ).fetchall()
            if r[0] is not None
        ]
        checkpoint_tables: List[str] = [
            r[0]
            for r in conn.execute(
                "SELECT t FROM unnest(%s::text[]) AS t WHERE to_regclass('public.' || t) IS NOT NULL",
                (list(CHECKPOINT_TABLE_PRIVILEGES),),
            ).fetchall()
        ]
        for stmt in runtime_grant_statements(role, sequences=sequences, checkpoint_tables=checkpoint_tables):
            conn.execute(stmt)
    log.info("db.migrate.runtime_grants", role=role, checkpoint_tables=len(checkpoint_tables))


def shadow_grant_statements(role: str) -> List[sql.Composed]:
    """Statements that reset ``role`` to exactly the shadow runs' privileges: ``SELECT`` on :data:`SHADOW_TABLES`."""
    who = sql.Identifier(role)
    stmts: List[sql.Composed] = [
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(who),
        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}").format(who),
        sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM {}").format(who),
        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(who),
    ]
    stmts += [sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(sql.Identifier("public", t), who) for t in SHADOW_TABLES]
    return stmts


@egress("database_connection", REFUSE)
def grant_shadow_privileges(role: str, database_url: str, database: DatabaseSettings) -> None:
    """Give the shadow runs' login role ``SELECT`` on :data:`SHADOW_TABLES` and nothing else (idempotent).

    Run as the schema owner, after :func:`grant_runtime_privileges`. Refuses,
    changing nothing, a role that may write or bypass isolation, before or
    after the grants (superuser, BYPASSRLS, the owner, a member of a role that
    may write, one allowed a ``SECURITY DEFINER`` function): pointing
    ``database.shadow_role`` at the runtime role must not strip its privileges.
    """
    with psycopg.connect(libpq_url(database_url, database)) as conn:

        def refuse_unsafe() -> None:
            reasons = unsafe_role_reasons(conn.execute(UNSAFE_ROLE_SQL.format(role="%s"), (role,)).fetchone(), role)
            if reasons:
                conn.rollback()
                raise ValueError(f"shadow role {role!r} must be SELECT-only, but it " + "; ".join(reasons))

        refuse_unsafe()
        for stmt in shadow_grant_statements(role):
            conn.execute(stmt)
        refuse_unsafe()
    log.info("db.migrate.shadow_grants", role=role, tables=len(SHADOW_TABLES))


@egress("database_connection", REFUSE)
async def setup_checkpointer(database_url: str, database: DatabaseSettings) -> None:
    """Create or upgrade LangGraph's checkpoint tables and put them under tenant RLS (idempotent).

    The tables hold every alert's workflow state, so they get the same
    ``FORCE ROW LEVEL SECURITY`` policy as the other tenant-owned tables
    (keyed on the ``{tenant}:{alert}`` thread id prefix). It is re-applied on
    every ``lg-sotf migrate``, also when LangGraph recreated a table.
    """
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from psycopg import AsyncConnection
    from psycopg.rows import dict_row

    from lg_sotf.db.checkpointer import secure_checkpoint_tables

    url = libpq_url(database_url, database)
    async with await AsyncConnection.connect(url, autocommit=True, prepare_threshold=0, row_factory=dict_row) as conn:
        await AsyncPostgresSaver(conn).setup()
        async with conn.transaction():
            await secure_checkpoint_tables(conn)
    log.info("db.migrate.checkpointer_ready")
