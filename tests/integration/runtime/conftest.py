"""Runtime tests use the shared Postgres/Redis fixtures from tests/integration/conftest.py."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

import pytest

from lg_sotf.settings import Settings


@pytest.fixture
def runtime_settings(
    make_settings: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> Callable[..., Settings]:
    def build(worker: Optional[Dict[str, Any]] = None, scheduler: Optional[Dict[str, Any]] = None) -> Settings:
        return make_settings(
            database={"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            redis={"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            worker={
                "concurrency": 4,
                "per_tenant_concurrency": 4,
                "visibility_timeout_s": 60,
                "block_ms": 100,
                "max_deliveries": 3,
                "run_timeout_s": 10.0,
                "drain_timeout_s": 5.0,
                **(worker or {}),
            },
            scheduler={"tick_s": 0.1, **(scheduler or {})},
        )

    return build


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
