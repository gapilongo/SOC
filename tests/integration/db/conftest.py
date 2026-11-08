"""Database test fixtures: a connection pool and repositories acting as the production runtime role.

The test database is owned by the ``soc`` login role, which is therefore an
implicit member of ``pg_database_owner``. Sessions started with
``role=pg_database_owner`` act as a role that owns no tables and is not a
member of the schema owner, which is exactly the production runtime role.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

import pytest
import pytest_asyncio

from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.settings import DatabaseSettings
from tests.integration.db._support import RUNTIME_ROLE, db_settings


@pytest_asyncio.fixture
async def app_db(db: Database, repos: Repositories, migrated_database_url: str) -> AsyncIterator[Database]:
    await setup_checkpointer(migrated_database_url, DatabaseSettings())
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url, DatabaseSettings())
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
