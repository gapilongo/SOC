"""Alembic environment for LG-SOTF.

The database URL comes from (in order) ``config.attributes["sqlalchemy_url"]``
(set by :mod:`lg_sotf.db.migrate`), ``sqlalchemy.url`` in the ini file, or
``get_settings().database``. Migrations run on a synchronous psycopg engine in
a single transaction, with RLS bypassed so data migrations see every tenant.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection

from lg_sotf.db import locks

config = context.config

if config.config_file_name is not None and config.file_config.has_section("loggers"):
    fileConfig(config.config_file_name)

target_metadata = None

MIGRATION_LOCK_TIMEOUT = "60s"


def _database_url() -> str:
    url = config.attributes.get("sqlalchemy_url") or config.get_main_option("sqlalchemy.url")
    if url:
        return url
    from lg_sotf.db.migrate import sqlalchemy_url

    return sqlalchemy_url()


def _prepare_transaction() -> None:
    context.execute(f"SET LOCAL lock_timeout = '{MIGRATION_LOCK_TIMEOUT}'")
    context.execute("SET LOCAL statement_timeout = 0")
    context.execute("SELECT set_config('app.bypass_rls', 'on', true)")
    context.execute(f"SELECT pg_advisory_xact_lock({locks.MIGRATIONS}, 0)")


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        _prepare_transaction()
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        _prepare_transaction()
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    try:
        with engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
