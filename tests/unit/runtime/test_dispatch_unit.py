from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Tuple

import pytest

from lg_sotf.db.errors import InvalidTransition
from lg_sotf.services.dispatch import dispatch_new_alerts


@dataclass(frozen=True)
class Ingested:
    alert_id: str
    severity: str


@dataclass
class Run:
    status: str


class FakeRuns:
    def __init__(self, statuses: Dict[str, str]) -> None:
        self.statuses = statuses

    async def upsert_queued(self, tenant_id: str, alert_id: str, *, conn: Any = None, **_: Any) -> Run:
        assert conn is not None
        return Run(self.statuses.setdefault(alert_id, "queued"))


class FakeAlerts:
    def __init__(self, statuses: Dict[str, str]) -> None:
        self.statuses = statuses

    async def update_status(self, tenant_id: str, alert_id: str, to: str, *, conn: Any = None) -> None:
        current = self.statuses.get(alert_id, "new")
        if current not in ("new", "queued", "failed"):
            raise InvalidTransition("alert", alert_id, current, to)
        self.statuses[alert_id] = to


class FakeDb:
    def __init__(self) -> None:
        self.committed = False
        self.events: List[str] = []

    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str) -> AsyncIterator[object]:
        self.events.append("begin")
        yield object()
        self.events.append("commit")


@dataclass
class FakeRepos:
    db: FakeDb
    runs: FakeRuns
    alerts: FakeAlerts


@dataclass
class FakeQueue:
    db: FakeDb
    sent: List[Tuple[str, str, str]] = field(default_factory=list)

    async def enqueue_process(self, tenant_id: str, alert_id: str, severity: str) -> str:
        self.db.events.append("enqueue")
        self.sent.append((tenant_id, alert_id, severity))
        return f"{len(self.sent)}-0"


def _setup(run_statuses: Dict[str, str], alert_statuses: Dict[str, str]) -> Tuple[FakeRepos, FakeQueue]:
    db = FakeDb()
    return FakeRepos(db, FakeRuns(run_statuses), FakeAlerts(alert_statuses)), FakeQueue(db)


async def test_dispatch_marks_queued_and_enqueues_after_commit() -> None:
    repos, queue = _setup({}, {})
    n = await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high"), Ingested("a2", "low")])  # type: ignore[arg-type]
    assert n == 2
    assert queue.sent == [("tenant-a", "a1", "high"), ("tenant-a", "a2", "low")]
    assert repos.alerts.statuses == {"a1": "queued", "a2": "queued"}
    assert repos.db.events == ["begin", "commit", "enqueue", "enqueue"]


async def test_dispatch_skips_runs_that_left_queued() -> None:
    repos, queue = _setup({"a1": "running", "a2": "completed"}, {"a1": "processing", "a2": "closed"})
    n = await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high"), Ingested("a2", "low")])  # type: ignore[arg-type]
    assert n == 0
    assert queue.sent == []
    assert repos.alerts.statuses == {"a1": "processing", "a2": "closed"}


async def test_dispatch_enqueues_queued_run_even_if_alert_moved_on() -> None:
    repos, queue = _setup({"a1": "queued"}, {"a1": "processing"})
    assert await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "medium")]) == 1  # type: ignore[arg-type]
    assert repos.alerts.statuses["a1"] == "processing"


async def test_dispatch_nothing_is_a_noop() -> None:
    repos, queue = _setup({}, {})
    assert await dispatch_new_alerts(repos, queue, "tenant-a", []) == 0  # type: ignore[arg-type]
    assert repos.db.events == []


async def test_enqueue_failure_propagates_after_commit() -> None:
    repos, queue = _setup({}, {})

    async def boom(*_: Any) -> str:
        raise ConnectionError("redis down")

    queue.enqueue_process = boom  # type: ignore[method-assign]
    with pytest.raises(ConnectionError):
        await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high")])  # type: ignore[arg-type]
    assert repos.alerts.statuses == {"a1": "queued"}
