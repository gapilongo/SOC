"""Helpers shared by the end-to-end tests: one platform instance (``Stack``), worker runs, polling, events."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Sequence
from uuid import UUID

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.batch import IngestResult
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.worker import Worker
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings

WAITING_OR_DONE = ("waiting_human", "waiting_approval", "completed", "dead_lettered")

BENIGN_EVENT: Dict[str, Any] = {
    "source_alert_id": "bk-001",
    "title": "Scheduled backup maintenance test job",
    "rule_name": "scheduled-backup-maintenance-test",
    "severity": "low",
    "occurred_at": "2024-03-05T10:00:00Z",
    "entities": {"hosts": ["backup-01"]},
}
SUSPICIOUS_EVENT: Dict[str, Any] = {
    "source_alert_id": "c2-001",
    "title": "Possible C2 beacon from workstation",
    "severity": "medium",
    "occurred_at": "2024-03-05T10:05:00Z",
    "entities": {
        "ips": ["185.220.101.44", "10.0.0.5"],
        "hosts": ["ws-042"],
        "users": ["jdoe"],
        "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        "processes": ["powershell.exe"],
    },
}


def related_event(n: int) -> Dict[str, Any]:
    return {
        "source_alert_id": f"c2-related-{n}",
        "title": "Possible C2 beacon from workstation",
        "severity": "medium",
        "occurred_at": "2024-03-05T10:05:00Z",
        "entities": {
            "ips": ["185.220.101.44", "10.0.0.5"],
            "hosts": ["ws-042"],
            "users": ["jdoe"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "processes": ["powershell.exe"],
        },
    }


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


async def analyst_decides(
    stack: Stack, tenant_id: str, alert_id: str, decision: str, user_id: str, **extra: Any
) -> str:
    """What ``POST /escalations/{id}/decision`` does: record the decision, then enqueue the resume."""
    esc = await stack.repos.escalations.get_active_for_alert(tenant_id, alert_id)
    assert esc is not None
    await stack.repos.escalations.decide(
        tenant_id, esc.id, decision=decision, decided_by=UUID(user_id), expected_version=esc.version
    )
    payload: Dict[str, Any] = {
        "type": "analyst_decision",
        "escalation_id": esc.id,
        "decision": decision,
        "approved_actions": [],
        "decided_by": user_id,
        "notes": "confirmed on the host",
        "approver_role": "analyst",
    }
    payload.update(extra)
    await stack.queue.enqueue_resume(tenant_id, alert_id, payload)
    return esc.id
