from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List, Optional

import pytest

from lg_sotf.audit import logger as audit_logger
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories, Source
from lg_sotf.observability.metrics import ESCALATIONS_OPEN, QUEUE_DEPTH
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.queue.streams import CONSUMER_GROUP
from lg_sotf.runtime import scheduler as scheduler_module
from lg_sotf.runtime.leader import LeaderLease
from lg_sotf.runtime.orphans import orphan_thresholds
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.runtime.conftest import RecordingEvents, eventually


@dataclass(frozen=True)
class Ingested:
    alert_id: str
    severity: str


@dataclass
class Result:
    inserted: List[Ingested]


@dataclass
class FakeIngestion:
    repos: Repositories
    fail_sources: set = field(default_factory=set)
    polled: List[str] = field(default_factory=list)
    closed: bool = False

    async def poll_source(self, tenant_id: str, source: Source, **_: Any) -> Result:
        self.polled.append(source.id)
        if source.id in self.fail_sources:
            raise ConnectionError("upstream SIEM unreachable")
        alert_id = await make_alert(self.repos, tenant_id, severity="critical", source_id=source.id)
        await self.repos.sources.record_poll_result(tenant_id, source.id, ok=True)
        return Result([Ingested(alert_id, "critical")])

    async def close(self) -> None:
        self.closed = True


def _scheduler(
    settings: Settings,
    db: Database,
    redis_client: Any,
    ingestion: Optional[FakeIngestion] = None,
    events: Optional[RecordingEvents] = None,
    **kwargs: Any,
) -> Scheduler:
    ing = ingestion or FakeIngestion(Repositories.create(db))
    return Scheduler(
        settings,
        db,
        redis_client,
        lambda: ing,
        WorkQueue(redis_client, settings),
        events or RecordingEvents(),
        **kwargs,
    )


async def _dispatched_alert(repos: Repositories, settings: Settings, redis_client: Any, severity: str = "high") -> str:
    alert_id = await make_alert(repos, TENANT_A, severity=severity)
    await dispatch_new_alerts(repos, WorkQueue(redis_client, settings), TENANT_A, [Ingested(alert_id, severity)])
    return alert_id


async def test_only_one_scheduler_leads_and_failover_on_connection_loss(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    first = _scheduler(s, repos.db, redis_client)
    second = _scheduler(s, repos.db, redis_client)
    try:
        await first.tick()
        await second.tick()
        assert first.is_leader and not second.is_leader
        await first.wait_for_jobs()
        assert {name: (job.runs, job.failures) for name, job in first.jobs.items()} == {
            name: (1, 0) for name in first.jobs
        }
        assert all(job.runs == 0 for job in second.jobs.values())

        leader_conn = first._lease._conn
        assert leader_conn is not None
        pid = leader_conn.get_server_pid()
        async with repos.db.connection() as conn:
            assert await conn.fetchval("SELECT pg_terminate_backend($1)", pid)
        await asyncio.sleep(0.2)

        await first.tick()
        assert not first.is_leader
        await second.tick()
        assert second.is_leader
        await second.wait_for_jobs()
        assert second.jobs["sla"].runs == 1
    finally:
        await first._lease.release()
        await second._lease.release()


async def test_run_loop_stops_and_releases_leadership(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    ingestion = FakeIngestion(repos)
    sched = _scheduler(s, repos.db, redis_client, ingestion)
    await repos.sources.create(TENANT_A, "splunk", "SIEM", source_id="splunk-1")
    task = asyncio.create_task(sched.run())
    await eventually(lambda: _true(sched.is_leader))
    await eventually(lambda: _true(ingestion.polled == ["splunk-1"]))
    sched.request_stop()
    await asyncio.wait_for(task, 10)
    assert not sched.is_leader
    assert ingestion.closed
    other = LeaderLease.from_settings(s)
    try:
        assert await other.refresh()
    finally:
        await other.release()


async def _true(value: bool) -> bool:
    return value


async def test_poll_sources_dispatches_and_isolates_failures(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    await repos.sources.create(TENANT_A, "splunk", "Good", source_id="good")
    await repos.sources.create(TENANT_B, "wazuh", "Bad", source_id="bad")
    await repos.sources.create(TENANT_A, "webhook", "Push", source_id="push")
    ingestion = FakeIngestion(repos, fail_sources={"bad"})
    sched = _scheduler(s, repos.db, redis_client, ingestion)

    await sched.poll_due_sources()
    await sched.wait_for_jobs()

    assert sorted(ingestion.polled) == ["bad", "good"]
    streams = WorkQueue(redis_client, s).streams
    assert await redis_client.xlen(streams.high) == 1
    alerts = await repos.alerts.list(TENANT_A)
    assert [a.status for a in alerts.items] == ["queued"]
    bad = await repos.sources.get(TENANT_B, "bad")
    assert bad.consecutive_failures == 1
    assert bad.last_error == "ConnectionError: upstream SIEM unreachable"
    assert bad.next_poll_at is not None and bad.next_poll_at > datetime.now(UTC)

    ingestion.polled.clear()
    await sched.poll_due_sources()
    await sched.wait_for_jobs()
    assert ingestion.polled == []


async def test_stale_sweep_requeues_with_severity_and_dead_letters_poison(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"max_deliveries": 2})
    events = RecordingEvents()
    sched = _scheduler(s, repos.db, redis_client, events=events)
    streams = WorkQueue(redis_client, s).streams
    retry = await _dispatched_alert(repos, s, redis_client, severity="low")
    poison = await _dispatched_alert(repos, s, redis_client, severity="critical")
    await redis_client.delete(streams.high, streams.normal)

    past = datetime.now(UTC) - timedelta(minutes=5)
    await repos.runs.start(TENANT_A, retry, "dead-worker", lease_s=1, now=past)
    await repos.runs.start(TENANT_A, poison, "dead-worker", lease_s=1, now=past)
    await repos.runs.fail(TENANT_A, poison, "boom", worker_id="dead-worker")
    await repos.runs.start(TENANT_A, poison, "dead-worker", lease_s=1, now=past)

    await sched.sweep_stale_runs()

    assert (await repos.runs.get(TENANT_A, retry)).status == "queued"
    entries = await redis_client.xrange(streams.normal)
    assert [e[1][b"alert_id"].decode() for e in entries] == [retry]
    assert await redis_client.xlen(streams.high) == 0

    assert (await repos.runs.get(TENANT_A, poison)).status == "dead_lettered"
    assert (await repos.alerts.get(TENANT_A, poison)).status == "failed"
    assert len(events.events) == 1
    event = events.events[0][1]
    assert (event["type"], event["alert_id"], event["data"]["status"]) == ("alert.updated", poison, "failed")


async def test_sla_sweep_escalates_then_expires_with_audit(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    events = RecordingEvents()
    sched = _scheduler(s, repos.db, redis_client, events=events)
    now = datetime.now(UTC)
    a1 = await make_alert(repos, TENANT_A)
    a2 = await make_alert(repos, TENANT_B)
    a3 = await make_alert(repos, TENANT_A)
    l1, _ = await repos.escalations.create_or_attach(TENANT_A, a1, reason="r", sla_deadline=now - timedelta(seconds=1))
    l3, _ = await repos.escalations.create_or_attach(
        TENANT_B, a2, reason="r", level="L3", sla_deadline=now - timedelta(seconds=1)
    )
    ok, _ = await repos.escalations.create_or_attach(TENANT_A, a3, reason="r", sla_deadline=now + timedelta(hours=1))

    await sched.sweep_sla()

    raised = await repos.escalations.get(TENANT_A, l1.id)
    assert (raised.level, raised.status) == ("L2", "open")
    assert raised.sla_deadline is not None and raised.sla_deadline > now + timedelta(minutes=4)
    assert (await repos.escalations.get(TENANT_B, l3.id)).status == "expired"
    assert (await repos.escalations.get(TENANT_A, ok.id)).level == "L1"

    audit_a = (await repos.audit.list(TENANT_A)).items
    assert [(e.action, e.resource_id, e.actor_id) for e in audit_a] == [
        ("escalation.sla_escalated", l1.id, "scheduler")
    ]
    audit_b = (await repos.audit.list(TENANT_B)).items
    assert [e.action for e in audit_b] == ["escalation.sla_expired"]
    kinds = sorted((t, e["type"], e["data"]["status"]) for t, e in events.events)
    assert kinds == [(TENANT_A, "escalation.updated", "open"), (TENANT_B, "escalation.updated", "expired")]
    timeline_a1 = (await repos.alert_events.list_for_alert(TENANT_A, a1)).items
    assert [(e.event_type, e.data["to_level"]) for e in timeline_a1] == [("escalation.sla_escalated", "L2")]
    timeline_a2 = (await repos.alert_events.list_for_alert(TENANT_B, a2)).items
    assert [e.event_type for e in timeline_a2] == ["escalation.sla_expired"]

    await sched.sweep_sla()
    assert (await repos.escalations.get(TENANT_A, l1.id)).level == "L2"


async def test_sla_breach_audit_goes_through_the_audit_logger(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The breach entry is redacted and logged like every other audit entry, in the breach's transaction."""
    lines: List[Any] = []

    class Spy:
        def info(self, event: str, **fields: Any) -> None:
            lines.append((event, fields))

    monkeypatch.setattr(audit_logger, "_log", Spy())
    sched = _scheduler(runtime_settings(), repos.db, redis_client, events=RecordingEvents())
    alert_id = await make_alert(repos, TENANT_A)
    late, _ = await repos.escalations.create_or_attach(
        TENANT_A, alert_id, reason="r", sla_deadline=datetime.now(UTC) - timedelta(seconds=1)
    )
    await sched.sweep_sla()
    assert [(f["audit_action"], f["resource_id"], f["persisted"]) for e, f in lines if e == "audit"] == [
        ("escalation.sla_escalated", late.id, True)
    ]


async def test_dispatch_is_idempotent(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    queue = WorkQueue(redis_client, s)
    alert_id = await make_alert(repos, TENANT_A, severity="medium")
    batch = [Ingested(alert_id, "medium")]
    assert await dispatch_new_alerts(repos, queue, TENANT_A, batch) == 1
    first_run = await repos.runs.get(TENANT_A, alert_id)
    assert await dispatch_new_alerts(repos, queue, TENANT_A, batch) == 1
    assert (await repos.runs.get(TENANT_A, alert_id)).updated_at == first_run.updated_at
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "queued"

    await repos.runs.start(TENANT_A, alert_id, "w", lease_s=30)
    assert await dispatch_new_alerts(repos, queue, TENANT_A, batch) == 0
    assert (await repos.runs.get(TENANT_A, alert_id)).status == "running"


async def test_maintenance_and_metrics(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    sched = _scheduler(s, repos.db, redis_client)
    assert await sched.run_maintenance() is None
    async with repos.db.connection() as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM pg_class WHERE relname LIKE 'alert_events_p%' AND relkind = 'r'"
        )
    assert count >= 3

    await _dispatched_alert(repos, s, redis_client, severity="high")
    a2 = await make_alert(repos, TENANT_A)
    await repos.escalations.create_or_attach(TENANT_A, a2, reason="r")
    await sched.export_metrics()
    assert QUEUE_DEPTH.labels(stream="high")._value.get() == 1
    assert QUEUE_DEPTH.labels(stream="normal")._value.get() == 0
    assert ESCALATIONS_OPEN._value.get() == 1


async def _age_run(repos: Repositories, alert_id: str, seconds: int = 3600) -> None:
    async with repos.db.tenant_tx(TENANT_A) as conn:
        await conn.execute(
            "UPDATE workflow_runs SET updated_at = now() - make_interval(secs => $3) "
            "WHERE tenant_id = $1 AND alert_id = $2",
            TENANT_A,
            alert_id,
            float(seconds),
        )


async def test_orphaned_runs_are_enqueued_again_once_per_threshold(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 10, "max_deliveries": 2})
    sched = _scheduler(s, repos.db, redis_client)
    streams = WorkQueue(redis_client, s).streams
    lost_queued = await _dispatched_alert(repos, s, redis_client, severity="critical")
    lost_failed = await _dispatched_alert(repos, s, redis_client, severity="low")
    fresh = await _dispatched_alert(repos, s, redis_client, severity="high")
    waiting = await _dispatched_alert(repos, s, redis_client, severity="high")
    await repos.runs.start(TENANT_A, lost_failed, "w", lease_s=30)
    await repos.runs.fail(TENANT_A, lost_failed, "RuntimeError: boom", worker_id="w")
    await repos.runs.start(TENANT_A, waiting, "w", lease_s=30)
    await repos.runs.mark_waiting(TENANT_A, waiting, "waiting_human", worker_id="w")
    for alert_id in (lost_queued, lost_failed, waiting):
        await _age_run(repos, alert_id)
    await redis_client.delete(streams.high, streams.normal)  # Redis lost its data

    assert await sched.recover_orphaned_runs() == 2

    high = [e[1][b"alert_id"].decode() for e in await redis_client.xrange(streams.high)]
    normal = [e[1][b"alert_id"].decode() for e in await redis_client.xrange(streams.normal)]
    assert (high, normal) == ([lost_queued], [lost_failed])
    assert fresh not in high + normal
    assert await sched.recover_orphaned_runs() == 0


async def test_orphan_recovery_skips_queued_runs_while_the_queue_is_backlogged(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 10, "max_deliveries": 2})
    sched = _scheduler(s, repos.db, redis_client)
    queue = WorkQueue(redis_client, s)
    backlogged = await make_alert(repos, TENANT_A, severity="medium")
    await repos.runs.upsert_queued(TENANT_A, backlogged)
    await _age_run(repos, backlogged)
    failed = await make_alert(repos, TENANT_A, severity="medium")
    await repos.runs.start(TENANT_A, failed, "w", lease_s=30)
    await repos.runs.fail(TENANT_A, failed, "RuntimeError: boom", worker_id="w")
    await _age_run(repos, failed)
    old_ms = int((datetime.now(UTC) - timedelta(minutes=10)).timestamp() * 1000)
    await redis_client.xadd(
        queue.streams.normal, {"tenant_id": TENANT_A, "alert_id": backlogged, "kind": "process"}, id=f"{old_ms}-0"
    )

    assert await sched.recover_orphaned_runs() == 1
    entries = [e[1][b"alert_id"].decode() for e in await redis_client.xrange(queue.streams.normal)]
    assert entries == [backlogged, failed]


class _RecordingLog:
    """Stands in for a module ``log``: records (level, event, fields) for every call."""

    def __init__(self) -> None:
        self.records: List[tuple] = []

    def __getattr__(self, level: str) -> Callable[..., None]:
        def record(event: str, **fields: Any) -> None:
            self.records.append((level, event, fields))

        return record

    def events(self) -> List[str]:
        return [event for _level, event, _fields in self.records]


def _spy_on_orphan_claims(monkeypatch: pytest.MonkeyPatch) -> List[dict]:
    calls: List[dict] = []
    real = scheduler_module.claim_orphaned_runs

    async def spy(db: Database, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return await real(db, **kwargs)

    monkeypatch.setattr(scheduler_module, "claim_orphaned_runs", spy)
    return calls


async def _queued_orphan_with_undelivered_entry(
    repos: Repositories, redis_client: Any, settings: Settings, entry_id: str
) -> str:
    """A queued run unchanged for an hour, and one entry the ``workers`` group has not been handed yet."""
    stream = WorkQueue(redis_client, settings).streams.normal
    await redis_client.xgroup_create(stream, CONSUMER_GROUP, id="$", mkstream=True)
    alert_id = await make_alert(repos, TENANT_A, severity="medium")
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    await _age_run(repos, alert_id)
    await redis_client.xadd(stream, {"tenant_id": TENANT_A, "alert_id": alert_id, "kind": "process"}, id=entry_id)
    return alert_id


async def test_deep_backlog_sweep_claims_failed_runs_only(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 10, "max_deliveries": 2})
    sched = _scheduler(s, repos.db, redis_client)
    calls = _spy_on_orphan_claims(monkeypatch)
    recorder = _RecordingLog()
    monkeypatch.setattr(scheduler_module, "log", recorder)
    hour_ago_ms = int((datetime.now(UTC) - timedelta(hours=1)).timestamp() * 1000)
    await _queued_orphan_with_undelivered_entry(repos, redis_client, s, f"{hour_ago_ms}-0")

    assert await sched.recover_orphaned_runs() == 0

    assert calls and all(c["queued_older_than_s"] is None for c in calls)
    assert calls[0]["failed_older_than_s"] == orphan_thresholds(s)[1]
    [(level, _event, fields)] = [r for r in recorder.records if r[1] == "scheduler.orphan_queued_skipped"]
    assert level == "warning" and fields["backlog_s"] >= 3600 - 60


async def test_fresh_backlog_sweep_still_claims_queued_runs(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 10, "max_deliveries": 2})
    sched = _scheduler(s, repos.db, redis_client)
    calls = _spy_on_orphan_claims(monkeypatch)
    recorder = _RecordingLog()
    monkeypatch.setattr(scheduler_module, "log", recorder)
    alert_id = await _queued_orphan_with_undelivered_entry(repos, redis_client, s, "*")

    assert await sched.recover_orphaned_runs() == 1

    queued_s, _failed_s = orphan_thresholds(s)
    assert calls and calls[0]["queued_older_than_s"] == queued_s
    assert "scheduler.orphan_queued_skipped" not in recorder.events()
    entries = [e[1][b"alert_id"].decode() for e in await redis_client.xrange(WorkQueue(redis_client, s).streams.normal)]
    assert entries == [alert_id, alert_id]


async def test_graceful_stop_lets_running_jobs_finish(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    sched = _scheduler(s, repos.db, redis_client, stop_grace_s=5)
    started = asyncio.Event()
    finished: List[str] = []

    async def slow_job() -> None:
        started.set()
        await asyncio.sleep(0.3)
        finished.append("sla")

    sched.jobs["sla"].fn = slow_job
    task = asyncio.create_task(sched.run())
    await asyncio.wait_for(started.wait(), 5)
    sched.request_stop()
    await asyncio.wait_for(task, 10)
    assert finished == ["sla"]
    assert not sched.is_leader


async def test_stop_grace_is_bounded(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    sched = _scheduler(s, repos.db, redis_client, stop_grace_s=0.2)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def hanging_job() -> None:
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    sched.jobs["sla"].fn = hanging_job
    task = asyncio.create_task(sched.run())
    await asyncio.wait_for(started.wait(), 5)
    sched.request_stop()
    await asyncio.wait_for(task, 5)
    assert cancelled.is_set()


async def test_leader_session_uses_lease_scaled_keepalives(runtime_settings: Callable[..., Settings]) -> None:
    s = runtime_settings(scheduler={"leader_lease_s": 30})
    lease = LeaderLease.from_settings(s)
    try:
        assert await lease.refresh()
        conn = lease._conn
        assert conn is not None
        values = {
            name: await conn.fetchval(f"SHOW {name}")
            for name in ("tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "tcp_user_timeout")
        }
    finally:
        await lease.release()
    assert values == {
        "tcp_keepalives_idle": "10",
        "tcp_keepalives_interval": "5",
        "tcp_keepalives_count": "3",
        "tcp_user_timeout": "30000",
    }
