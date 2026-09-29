"""Engine fixtures: real Postgres (checkpointer included), real Redis, fake LLM."""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Dict, List

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.migrate import setup_checkpointer
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.settings import Settings


class RecordingEvents:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        assert event["tenant_id"] == tenant_id
        self.events.append(event)

    def of_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == event_type]


@pytest.fixture(scope="session")
def checkpoint_tables(migrated_database_url: str) -> str:
    import asyncio

    asyncio.run(setup_checkpointer(migrated_database_url))
    return migrated_database_url


@pytest.fixture
def engine_settings(
    checkpoint_tables: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Settings:
    return make_settings(
        database={"url": checkpoint_tables, "pool_min": 1, "pool_max": 4},
        redis={"url": redis_url, "key_prefix": unique_prefix},
        worker={"node_timeout_s": 60.0, "analysis_timeout_s": 120.0, "concurrency": 2},
    )


@pytest.fixture
def events() -> RecordingEvents:
    return RecordingEvents()


@pytest_asyncio.fixture
async def engine_factory(
    engine_settings: Settings, db: Database, repos: Repositories, redis_client: aioredis.Redis, events: RecordingEvents
) -> AsyncIterator[Callable[..., Any]]:
    engines: List[WorkflowEngine] = []

    async def build(**kwargs: Any) -> WorkflowEngine:
        engine = await WorkflowEngine.create(
            settings=kwargs.pop("settings", engine_settings), db=db, redis=redis_client, events=events, **kwargs
        )
        engines.append(engine)
        return engine

    try:
        yield build
    finally:
        for engine in engines:
            await engine.close()


@pytest_asyncio.fixture
async def engine(engine_factory: Callable[..., Any]) -> WorkflowEngine:
    return await engine_factory()
