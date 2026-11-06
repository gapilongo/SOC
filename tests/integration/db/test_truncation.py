"""Every table a test can write is truncated between tests (``truncate_all``)."""

from __future__ import annotations

import asyncpg
import pytest

from tests.integration.db._support import ALL_TABLES, CHECKPOINT_TABLES

pytestmark = pytest.mark.integration

# Migration bookkeeping, written only by `lg-sotf migrate` (alembic) and the checkpointer's setup().
BOOKKEEPING = {"alembic_version", "checkpoint_migrations"}


async def test_every_table_is_truncated_between_tests(checkpointed_database_url: str) -> None:
    conn = await asyncpg.connect(checkpointed_database_url)
    try:
        rows = await conn.fetch(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
        )
    finally:
        await conn.close()
    tables = {r["relname"] for r in rows} - BOOKKEEPING
    assert tables, "the migrated test database has no tables"
    assert sorted(tables - set(ALL_TABLES) - set(CHECKPOINT_TABLES)) == [], "add these to ALL_TABLES"
    assert sorted(set(ALL_TABLES) - tables) == [], "ALL_TABLES names tables that no longer exist"
