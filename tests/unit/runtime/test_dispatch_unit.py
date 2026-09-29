from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

import pytest

from lg_sotf.services.dispatch import dispatch_new_alerts


@dataclass(frozen=True)
class Ingested:
    alert_id: str
    severity: str


class FakeRuns:
    """Mirrors ``RunsRepo.queue_alerts``: create missing runs, step 'new'/'failed'/'closed' alerts to queued."""

    def __init__(self, runs: Dict[str, str], alerts: Dict[str, str], events: List[str]) -> None:
        self.runs = runs
        self.alerts = alerts
        self.events = events
        self.calls = 0

    async def queue_alerts(self, tenant_id: str, alert_ids: Sequence[str], *, conn: Any = None) -> List[str]:
        self.calls += 1
        self.events.append("commit")
        queued = []
        for alert_id in alert_ids:
            if self.runs.setdefault(alert_id, "queued") == "queued":
                queued.append(alert_id)
                if self.alerts.get(alert_id, "new") in ("new", "failed", "closed"):
                    self.alerts[alert_id] = "queued"
        return queued


@dataclass
class FakeRepos:
    runs: FakeRuns


@dataclass
class FakeQueue:
    events: List[str]
    sent: List[Tuple[str, str, str]] = field(default_factory=list)

    async def enqueue_process_many(self, tenant_id: str, alerts: Sequence[Tuple[str, str]]) -> List[str]:
        if alerts:
            self.events.append("enqueue")
        for alert_id, severity in alerts:
            self.sent.append((tenant_id, alert_id, severity))
        return [f"{i}-0" for i in range(len(alerts))]


def _setup(run_statuses: Dict[str, str], alert_statuses: Dict[str, str]) -> Tuple[FakeRepos, FakeQueue, List[str]]:
    events: List[str] = []
    return FakeRepos(FakeRuns(run_statuses, alert_statuses, events)), FakeQueue(events), events


async def test_dispatch_marks_queued_and_enqueues_after_commit() -> None:
    repos, queue, events = _setup({}, {})
    n = await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high"), Ingested("a2", "low")])  # type: ignore[arg-type]
    assert n == 2
    assert queue.sent == [("tenant-a", "a1", "high"), ("tenant-a", "a2", "low")]
    assert repos.runs.alerts == {"a1": "queued", "a2": "queued"}
    # One batch transaction, then one pipelined enqueue (PERF-3), never the other way round.
    assert events == ["commit", "enqueue"] and repos.runs.calls == 1


async def test_dispatch_skips_runs_that_left_queued() -> None:
    repos, queue, _ = _setup({"a1": "running", "a2": "completed"}, {"a1": "processing", "a2": "closed"})
    n = await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high"), Ingested("a2", "low")])  # type: ignore[arg-type]
    assert n == 0
    assert queue.sent == []
    assert repos.runs.alerts == {"a1": "processing", "a2": "closed"}


async def test_dispatch_enqueues_queued_run_even_if_alert_moved_on() -> None:
    repos, queue, _ = _setup({"a1": "queued"}, {"a1": "processing"})
    assert await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "medium")]) == 1  # type: ignore[arg-type]
    assert repos.runs.alerts["a1"] == "processing"


async def test_dispatch_nothing_is_a_noop() -> None:
    repos, queue, events = _setup({}, {})
    assert await dispatch_new_alerts(repos, queue, "tenant-a", []) == 0  # type: ignore[arg-type]
    assert events == []


async def test_enqueue_failure_propagates_after_commit() -> None:
    repos, queue, _ = _setup({}, {})

    async def boom(*_: Any) -> List[str]:
        raise ConnectionError("redis down")

    queue.enqueue_process_many = boom  # type: ignore[method-assign]
    with pytest.raises(ConnectionError):
        await dispatch_new_alerts(repos, queue, "tenant-a", [Ingested("a1", "high")])  # type: ignore[arg-type]
    assert repos.runs.alerts == {"a1": "queued"}
