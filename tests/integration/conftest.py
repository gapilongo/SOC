"""Fixtures shared by every integration test package.

The database named by ``LG_SOTF_TEST_DATABASE_URL`` is reset (public schema
dropped and recreated) and migrated once per session, then truncated before
each test. The Redis database named by ``LG_SOTF_TEST_REDIS_URL`` is flushed
before and after each test that uses it. Tests skip when a variable is unset.
"""

from __future__ import annotations

import os
from typing import AsyncIterator, Iterator, Optional

import psycopg
import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from lg_sotf.db.migrate import upgrade_head
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.urls import database_name, to_libpq_url
from tests.integration.db._support import TENANT_A, TENANT_B, db_settings

ALL_TABLES = (
    "audit_log",
    "usage_daily",
    "llm_usage_daily",
    "indicator_sightings",
    "suppression_rules",
    "response_actions",
    "analyst_feedback",
    "escalations",
    "workflow_runs",
    "alert_events",
    "alerts",
    "sources",
    "api_keys",
    "refresh_tokens",
    "user_mfa",
    "users",
    "tenants",
)

# Created by AsyncPostgresSaver.setup(); truncated only when present.
CHECKPOINT_TABLES = ("checkpoint_writes", "checkpoint_blobs", "checkpoints")


def _test_database_url() -> Optional[str]:
    return os.environ.get("LG_SOTF_TEST_DATABASE_URL") or None


def _test_redis_url() -> Optional[str]:
    return os.environ.get("LG_SOTF_TEST_REDIS_URL") or None


def reset_schema(url: str) -> None:
    name = database_name(url)
    if "test" not in name:
        pytest.fail(f"refusing to reset database {name!r}: its name must contain 'test'")
    with psycopg.connect(to_libpq_url(url), autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _test_database_url()
    if not url:
        pytest.skip("LG_SOTF_TEST_DATABASE_URL is not set")
    return url


def assert_rls_applies(url: str) -> None:
    """Row-level security tests are meaningless for a role that bypasses RLS."""
    with psycopg.connect(to_libpq_url(url), autocommit=True) as conn:
        row = conn.execute(
            "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
    assert row is not None
    name, is_super, bypass = row
    if is_super or bypass:
        pytest.fail(
            f"LG_SOTF_TEST_DATABASE_URL connects as {name!r}, which is a superuser or has BYPASSRLS; "
            "row-level security would not apply. Use a plain role (NOSUPERUSER NOBYPASSRLS CREATEDB) "
            "that owns the test database."
        )


@pytest.fixture(scope="session")
def migrated_database_url(database_url: str) -> Iterator[str]:
    assert_rls_applies(database_url)
    reset_schema(database_url)
    upgrade_head(database_url)
    yield database_url


async def truncate_all(db: Database) -> None:
    async with db.system_tx() as conn:
        await conn.execute(f"TRUNCATE {', '.join(ALL_TABLES)} RESTART IDENTITY CASCADE")
        present = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1::text[])",
            list(CHECKPOINT_TABLES),
        )
        if present:
            await conn.execute(f"TRUNCATE {', '.join(r['tablename'] for r in present)}")


@pytest_asyncio.fixture
async def db(migrated_database_url: str) -> AsyncIterator[Database]:
    database = Database(db_settings(migrated_database_url), application_name="lg-sotf-tests")
    await database.open()
    await truncate_all(database)
    try:
        yield database
    finally:
        await database.close()


@pytest_asyncio.fixture
async def repos(db: Database) -> Repositories:
    r = Repositories.create(db)
    await r.tenants.create(TENANT_A, "Tenant A")
    await r.tenants.create(TENANT_B, "Tenant B")
    return r


@pytest.fixture(scope="session")
def redis_url() -> str:
    url = _test_redis_url()
    if not url:
        pytest.skip("LG_SOTF_TEST_REDIS_URL is not set")
    return url


@pytest_asyncio.fixture
async def redis_client(redis_url: str) -> AsyncIterator[aioredis.Redis]:
    client = aioredis.Redis.from_url(redis_url, decode_responses=False)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()
