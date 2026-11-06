"""Helpers shared by the runtime tests: a scripted engine, worker builders and polling."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.worker import Worker
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings
from tests.integration.db._support import make_alert


async def eventually(predicate: Callable[[], Awaitable[bool]], within: float = 8.0, interval: float = 0.05) -> None:
    deadline = time.monotonic() + within
    while True:
        if await predicate():
            return
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(interval)


@dataclass
class Outcome:
    status: str
    alert_status: str = "closed"
    interrupt: Optional[dict] = None


Behaviour = Callable[[str, str, str, Optional[dict]], Awaitable[Outcome]]


@dataclass
class FakeEngine:
    """Stands in for WorkflowEngine: records calls and runs a scripted behaviour."""

    behaviour: Behaviour
    calls: List[tuple] = field(default_factory=list)
    active: Dict[str, int] = field(default_factory=dict)
    max_active: Dict[str, int] = field(default_factory=dict)
    closed: bool = False

    async def _call(self, kind: str, tenant_id: str, alert_id: str, payload: Optional[dict]) -> Outcome:
        self.calls.append((kind, tenant_id, alert_id, payload))
        self.active[tenant_id] = self.active.get(tenant_id, 0) + 1
        self.max_active[tenant_id] = max(self.max_active.get(tenant_id, 0), self.active[tenant_id])
        try:
            return await self.behaviour(kind, tenant_id, alert_id, payload)
        finally:
            self.active[tenant_id] -= 1

    async def run(self, tenant_id: str, alert_id: str) -> Outcome:
        return await self._call("process", tenant_id, alert_id, None)

    async def resume(self, tenant_id: str, alert_id: str, payload: dict) -> Outcome:
        return await self._call("resume", tenant_id, alert_id, payload)

    async def close(self) -> None:
        self.closed = True


def returns(status: str, delay: float = 0.0) -> Behaviour:
    async def behaviour(kind: str, tenant_id: str, alert_id: str, payload: Optional[dict]) -> Outcome:
        if delay:
            await asyncio.sleep(delay)
        return Outcome(status)

    return behaviour


@dataclass
class RecordingEvents:
    events: List[tuple] = field(default_factory=list)

    async def publish(self, tenant_id: str, event: dict) -> None:
        self.events.append((tenant_id, event))


class Ingested:
    def __init__(self, alert_id: str, severity: str) -> None:
        self.alert_id = alert_id
        self.severity = severity


def make_worker(
    settings: Settings,
    db: Database,
    redis_client: Any,
    engine: FakeEngine,
    events: Optional[RecordingEvents] = None,
    **kwargs: Any,
) -> Worker:
    consumer = StreamConsumer(redis_client, settings, kwargs.pop("name", "w1"))
    return Worker(settings, db, redis_client, engine, consumer, events or RecordingEvents(), **kwargs)


@asynccontextmanager
async def running(worker: Worker) -> AsyncIterator[asyncio.Task[None]]:
    task = asyncio.create_task(worker.run())
    try:
        yield task
    finally:
        worker.request_stop()
        await asyncio.wait_for(task, timeout=15)


async def dispatch_alert(
    repos: Repositories, settings: Settings, redis_client: Any, tenant: str, severity: str = "high"
) -> str:
    alert_id = await make_alert(repos, tenant, severity=severity)
    await dispatch_new_alerts(repos, WorkQueue(redis_client, settings), tenant, [Ingested(alert_id, severity)])
    return alert_id


async def run_status(repos: Repositories, tenant: str, alert_id: str) -> str:
    return (await repos.runs.get(tenant, alert_id)).status


async def stream_empty(redis_client: Any, settings: Settings) -> bool:
    q = WorkQueue(redis_client, settings).streams
    return await redis_client.xlen(q.high) + await redis_client.xlen(q.normal) == 0


class ManualClock:
    """A clock that moves only when told to; inject it as a worker's or scheduler's ``clock``/``wall_clock``."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
