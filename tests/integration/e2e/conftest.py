"""End-to-end fixtures: the real ingestion service, dispatcher, queue, worker and workflow engine.

Everything runs against the shared Postgres/Redis test services with the fake
LLM. Each test gets its own Redis key prefix; the database is truncated by the
shared ``db`` fixture.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Sequence

import pytest
import pytest_asyncio

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import NotFound
from lg_sotf.db.migrate import setup_checkpointer
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService, IngestResult
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.worker import Worker
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings

WAITING_OR_DONE = ("waiting_human", "waiting_approval", "completed", "dead_lettered")


@pytest.fixture(scope="session")
def e2e_database_url(migrated_database_url: str) -> str:
    """The migrated test database with LangGraph's checkpoint tables (``lg-sotf migrate`` does both)."""
    asyncio.run(setup_checkpointer(migrated_database_url))
    return migrated_database_url


@pytest.fixture
def e2e_settings(
    e2e_database_url: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Callable[..., Settings]:
    def build(**worker: Any) -> Settings:
        return make_settings(
            database={"url": e2e_database_url, "pool_min": 1, "pool_max": 8},
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
            scheduler={"tick_s": 0.1},
        )

    return build


class TappedBus:
    """The real :class:`EventBus`, plus a record of every event published through it."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self.published: List[Dict[str, Any]] = []

    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        assert event["tenant_id"] == tenant_id
        self.published.append(event)
        await self.bus.publish(tenant_id, event)

    def of(self, alert_id: str, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        return [
            e for e in self.published if e["alert_id"] == alert_id and (event_type is None or e["type"] == event_type)
        ]


@dataclass
class Stack:
    """One platform instance: shared services plus factories for engines and workers."""

    settings: Settings
    db: Database
    redis: Any
    repos: Repositories
    queue: WorkQueue
    events: TappedBus
    ingestion: IngestionService
    engines: List[WorkflowEngine] = field(default_factory=list)

    async def ingest(self, tenant_id: str, source_id: str, events: Sequence[Dict[str, Any]]) -> IngestResult:
        return await self.ingestion.ingest(tenant_id, source_id, events)

    async def dispatch(self, tenant_id: str, result: IngestResult) -> int:
        return await dispatch_new_alerts(self.repos, self.queue, tenant_id, result.inserted, events=self.events)

    async def engine(self) -> WorkflowEngine:
        engine = await WorkflowEngine.create(
            settings=self.settings, db=self.db, redis=self.redis, events=self.events, checkpoint_pool_size=4
        )
        self.engines.append(engine)
        return engine

    def worker(self, engine: WorkflowEngine, name: str = "w1", **kwargs: Any) -> Worker:
        consumer = StreamConsumer(self.redis, self.settings, name)
        kwargs.setdefault("lease_s", 1.5)
        return Worker(self.settings, self.db, self.redis, engine, consumer, self.events, worker_id=name, **kwargs)

    async def run_status(self, tenant_id: str, alert_id: str) -> str:
        """The run's status, or ``missing`` while the alert is stored but not yet dispatched."""
        try:
            return (await self.repos.runs.get(tenant_id, alert_id)).status
        except NotFound:
            return "missing"

    async def all_settled(self, tenant_id: str, alert_ids: Sequence[str]) -> bool:
        for alert_id in alert_ids:
            if await self.run_status(tenant_id, alert_id) not in WAITING_OR_DONE:
                return False
        return True

    async def stream_empty(self) -> bool:
        s = self.queue.streams
        return await self.redis.xlen(s.high) + await self.redis.xlen(s.normal) == 0


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


@asynccontextmanager
async def running(worker: Worker, stop_within_s: float = 20.0) -> AsyncIterator[asyncio.Task[None]]:
    """Run a worker for the duration of the block, then stop it and wait for a clean drain."""
    task = asyncio.create_task(worker.run(), name=f"worker:{worker.worker_id}")
    try:
        yield task
    finally:
        worker.request_stop()
        await asyncio.wait_for(task, timeout=stop_within_s)


async def eventually(predicate: Callable[[], Awaitable[bool]], within: float = 20.0, interval: float = 0.05) -> None:
    deadline = time.monotonic() + within
    while True:
        if await predicate():
            return
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(interval)


def count_calls(monkeypatch: pytest.MonkeyPatch, obj: Any, name: str) -> List[int]:
    calls: List[int] = []
    original = getattr(obj, name)

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return await original(*args, **kwargs)

    monkeypatch.setattr(obj, name, spy)
    return calls
