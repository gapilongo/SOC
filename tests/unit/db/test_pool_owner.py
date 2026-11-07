"""The one schema-owner DSN helper (``database.migration_url``, falling back to ``database.url``)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.compliance import ops as compliance_ops
from lg_sotf.db import pool
from lg_sotf.db.pool import Database, owner_database, owner_dsn
from lg_sotf.runtime import leader, ops, scheduler
from lg_sotf.settings import DatabaseSettings, Settings

pytestmark = pytest.mark.unit


def test_owner_dsn_prefers_migration_url(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(database={"url": "postgresql://rt:x@h/db", "migration_url": "postgresql+psycopg://own:y@h/db"})
    assert owner_dsn(s) == "postgresql://own:y@h/db"
    assert owner_dsn(make_settings(database={"url": "postgres://rt:x@h/db"})) == "postgresql://rt:x@h/db"


def test_owner_database_is_a_small_owner_pool(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(database={"url": "postgresql://rt:x@h/db", "migration_url": "postgresql://own:y@h/db"})
    db = owner_database(s, "lg-sotf-cli")
    assert db._dsn == "postgresql://own:y@h/db"
    assert (db._application_name, db._min_size, db._max_size) == ("lg-sotf-cli", 0, 2)


def test_every_owner_connection_uses_the_one_helper() -> None:
    # The CLI operations, compliance operations and the leader lease share db.pool's helpers.
    assert ops.owner_database is compliance_ops.owner_database is pool.owner_database
    assert ops.owner_dsn is leader.owner_dsn is scheduler.owner_dsn is pool.owner_dsn


async def test_scheduler_and_migrate_connect_as_the_owner(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    s = make_settings(database={"url": "postgresql://rt:x@h/db", "migration_url": "postgres://own:y@h/db"})
    seen: List[Dict[str, Any]] = []

    class Stop(Exception):
        pass

    async def refuse_open(self: Database) -> None:
        seen.append({"dsn": self._dsn, "app": self._application_name})
        raise Stop

    monkeypatch.setattr(Database, "open", refuse_open)
    monkeypatch.setattr("lg_sotf.queue.redis.create_redis", lambda settings: _NoRedis())
    with pytest.raises(Stop):
        await scheduler.run_scheduler(s, metrics_host="127.0.0.1", metrics_port=0)

    urls: List[str] = []
    monkeypatch.setattr(ops, "upgrade_head", lambda url, database: urls.append(url))

    async def checkpointer(url: str, database: DatabaseSettings) -> None:
        assert database is s.database
        urls.append(url)
        raise Stop

    monkeypatch.setattr(ops, "setup_checkpointer", checkpointer)
    with pytest.raises(Stop):
        await ops.migrate(s)

    assert seen == [{"dsn": "postgresql://own:y@h/db", "app": "lg-sotf-scheduler"}]
    assert urls == ["postgresql://own:y@h/db", "postgresql://own:y@h/db"]


class _NoRedis:
    async def aclose(self) -> None:
        return None
