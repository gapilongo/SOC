"""End-to-end fixtures: the real ingestion service, dispatcher, queue, worker and workflow engine.

Everything runs against the shared Postgres/Redis test services with the fake
LLM. Each test gets its own Redis key prefix; the database is truncated by the
shared ``db`` fixture. Helpers (``Stack``, ``running``, ``eventually``) are in ``_support.py``.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import pytest
import pytest_asyncio

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.settings import Settings
from tests.integration.e2e._support import Stack, TappedBus


@pytest.fixture
def e2e_settings(
    checkpointed_database_url: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Callable[..., Settings]:
    def build(*, scheduler: Optional[Dict[str, Any]] = None, **worker: Any) -> Settings:
        return make_settings(
            database={"url": checkpointed_database_url, "pool_min": 1, "pool_max": 8},
            redis={"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            worker={
                "concurrency": 4,
                "per_tenant_concurrency": 4,
                "visibility_timeout_s": 2,
                "block_ms": 100,
                "max_deliveries": 3,
                "node_timeout_s": 20.0,
                "analysis_timeout_s": 20.0,
                "run_timeout_s": 60.0,
                "drain_timeout_s": 5.0,
                **worker,
            },
            scheduler={"tick_s": 0.1, **(scheduler or {})},
        )

    return build


@pytest_asyncio.fixture
async def stack_factory(
    e2e_settings: Callable[..., Settings], db: Database, repos: Repositories, redis_client: Any
) -> AsyncIterator[Callable[..., Stack]]:
    stacks: List[Stack] = []
    buses: List[EventBus] = []

    def build(**worker: Any) -> Stack:
        settings = e2e_settings(**worker)
        bus = EventBus(redis_client, settings)
        buses.append(bus)
        stack = Stack(
            settings=settings,
            db=db,
            redis=redis_client,
            repos=repos,
            queue=WorkQueue(redis_client, settings),
            events=TappedBus(bus),
            ingestion=IngestionService(db, settings),
        )
        stacks.append(stack)
        return stack

    try:
        yield build
    finally:
        for stack in stacks:
            for engine in stack.engines:
                await engine.close()
            await stack.ingestion.close()
        for bus in buses:
            await bus.aclose()
