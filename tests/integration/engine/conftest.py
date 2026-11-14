"""Engine fixtures: real Postgres (checkpointer included), real Redis, fake LLM."""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, List

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.settings import Settings
from tests.integration.db._support import shadow_url
from tests.integration.engine._support import RecordingEvents


@pytest.fixture
def engine_settings(
    checkpointed_database_url: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Settings:
    return make_settings(
        database={
            "url": checkpointed_database_url, "pool_min": 1, "pool_max": 4,
            "shadow_url": shadow_url(checkpointed_database_url),  # the SELECT-only shadow role (AI-E1.5c)
        },
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
