from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from lg_sotf.core.exceptions import InvalidResumePayload
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.llm.usage import get_usage_recorder
from lg_sotf.observability.metrics import RUNS
from lg_sotf.queue.consumer import CONSUMER_GROUP, StreamConsumer
from lg_sotf.queue.dlq import DeadLetterQueue
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.worker import Worker
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.runtime.conftest import FakeEngine, Outcome, RecordingEvents, eventually, returns


class Ingested:
    def __init__(self, alert_id: str, severity: str) -> None:
        self.alert_id = alert_id
        self.severity = severity


def _runs(outcome: str) -> float:
    return RUNS.labels(outcome=outcome)._value.get()


def _worker(
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


async def _dispatch(
    repos: Repositories, settings: Settings, redis_client: Any, tenant: str, severity: str = "high"
) -> str:
    alert_id = await make_alert(repos, tenant, severity=severity)
    await dispatch_new_alerts(repos, WorkQueue(redis_client, settings), tenant, [Ingested(alert_id, severity)])
    return alert_id


async def _status(repos: Repositories, tenant: str, alert_id: str) -> str:
    return (await repos.runs.get(tenant, alert_id)).status


async def _stream_empty(redis_client: Any, settings: Settings) -> bool:
    q = WorkQueue(redis_client, settings).streams
    return await redis_client.xlen(q.high) + await redis_client.xlen(q.normal) == 0


async def test_completed_run_is_recorded_then_acked(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    engine = FakeEngine(returns("completed"))
    worker = _worker(s, repos.db, redis_client, engine)
    before = _runs("completed")
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await eventually(lambda: _stream_empty(redis_client, s))
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.status == "completed" and run.completed_at is not None
    assert engine.calls == [("process", TENANT_A, alert_id, None)]
    assert _runs("completed") == before + 1
    assert worker.stats.completed == 1


async def test_waiting_then_resume(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()

    async def behaviour(kind: str, tenant: str, alert: str, payload: Optional[dict]) -> Outcome:
        return Outcome("waiting_human" if kind == "process" else "completed")

    engine = FakeEngine(behaviour)
    worker = _worker(s, repos.db, redis_client, engine)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    payload = {
        "type": "analyst_decision",
        "escalation_id": "e1",
        "decision": "false_positive",
        "approved_actions": [],
        "decided_by": "u1",
        "notes": "",
    }
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "waiting_human"))
        await WorkQueue(redis_client, s).enqueue_resume(TENANT_A, alert_id, payload)
        await eventually(lambda: _status_is(repos, alert_id, "completed"))
        await eventually(lambda: _stream_empty(redis_client, s))
    assert [c[0] for c in engine.calls] == ["process", "resume"]
    assert engine.calls[1][3] == payload


async def _status_is(repos: Repositories, alert_id: str, status: str, tenant: str = TENANT_A) -> bool:
    return await _status(repos, tenant, alert_id) == status


async def test_duplicate_message_for_completed_run_is_dropped(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    engine = FakeEngine(returns("completed"))
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    await WorkQueue(redis_client, s).enqueue_process(TENANT_A, alert_id, "high")
    worker = _worker(s, repos.db, redis_client, engine)
    async with running(worker):
        await eventually(lambda: _stream_empty(redis_client, s))
    assert len(engine.calls) == 1
    assert worker.stats.skipped == 1


async def test_failure_marks_run_failed_leaves_pending_then_dead_letters(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 1, "max_deliveries": 2})

    async def boom(*_: Any) -> Outcome:
        raise RuntimeError("model exploded")

    engine = FakeEngine(boom)
    events = RecordingEvents()
    worker = _worker(s, repos.db, redis_client, engine, events)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    streams = WorkQueue(redis_client, s).streams
    before = _runs("dead_lettered")
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "failed"))
        run = await repos.runs.get(TENANT_A, alert_id)
        assert run.last_error == "RuntimeError: model exploded"
        pending = await redis_client.xpending(streams.high, CONSUMER_GROUP)
        assert pending["pending"] == 1
        await eventually(lambda: _status_is(repos, alert_id, "dead_lettered"), within=10)
        await eventually(lambda: _stream_empty(redis_client, s))

    assert len(engine.calls) == 2
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "failed"
    (letter,) = await DeadLetterQueue(redis_client, s).list()
    assert letter.alert_id == alert_id
    assert "exceeded 2 deliveries" in letter.reason
    assert letter.deliveries == "3"
    assert _runs("dead_lettered") == before + 1
    assert events.events[-1][1]["type"] == "alert.updated"
    assert events.events[-1][1]["data"] == {"status": "failed", "reason": "dead_lettered"}


async def test_run_exceeding_timeout_is_failed(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"run_timeout_s": 0.3})
    engine = FakeEngine(returns("completed", delay=30))
    worker = _worker(s, repos.db, redis_client, engine)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    before = _runs("timeout")
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "failed"))
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.last_error == "TimeoutError: run exceeded 0.3s"
    assert _runs("timeout") == before + 1
    assert not await _stream_empty(redis_client, s)


async def test_graceful_drain_finishes_inflight_run(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    started = asyncio.Event()

    async def slow(*_: Any) -> Outcome:
        started.set()
        await asyncio.sleep(0.5)
        return Outcome("completed")

    worker = _worker(s, repos.db, redis_client, FakeEngine(slow))
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    task = asyncio.create_task(worker.run())
    await asyncio.wait_for(started.wait(), 5)
    worker.request_stop()
    await asyncio.wait_for(task, 10)
    assert await _status(repos, TENANT_A, alert_id) == "completed"
    assert await _stream_empty(redis_client, s)


async def test_drain_timeout_cancels_straggler_and_leaves_message_pending(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"drain_timeout_s": 0.2})
    started = asyncio.Event()

    async def hang(*_: Any) -> Outcome:
        started.set()
        await asyncio.sleep(60)
        return Outcome("completed")

    worker = _worker(s, repos.db, redis_client, FakeEngine(hang), lease_s=30)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    task = asyncio.create_task(worker.run())
    await asyncio.wait_for(started.wait(), 5)
    worker.request_stop()
    await asyncio.wait_for(task, 10)
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.status == "running"
    assert run.lease_expires_at is not None
    streams = WorkQueue(redis_client, s).streams
    assert (await redis_client.xpending(streams.high, CONSUMER_GROUP))["pending"] == 1


async def test_per_tenant_cap_defers_without_blocking_other_tenants(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"concurrency": 4, "per_tenant_concurrency": 1})
    engine = FakeEngine(returns("completed", delay=0.2))
    worker = _worker(s, repos.db, redis_client, engine)
    a_ids = [await _dispatch(repos, s, redis_client, TENANT_A) for _ in range(3)]
    b_id = await _dispatch(repos, s, redis_client, TENANT_B)
    async with running(worker):
        await eventually(lambda: _status_is(repos, b_id, "completed", TENANT_B))
        a_done = [await _status(repos, TENANT_A, a) for a in a_ids].count("completed")
        assert a_done < 3
        for a in a_ids:
            await eventually(lambda a=a: _status_is(repos, a, "completed"))
    assert engine.max_active[TENANT_A] == 1
    assert worker.stats.deferred >= 1


async def test_heartbeat_extends_lease_during_long_run(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    engine = FakeEngine(returns("completed", delay=1.2))
    worker = _worker(s, repos.db, redis_client, engine, lease_s=0.4)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "running"))
        first = (await repos.runs.get(TENANT_A, alert_id)).lease_expires_at
        await asyncio.sleep(0.6)
        run = await repos.runs.get(TENANT_A, alert_id)
        assert run.status == "running"
        assert run.lease_expires_at is not None and first is not None and run.lease_expires_at > first
        await eventually(lambda: _status_is(repos, alert_id, "completed"))
    assert len(engine.calls) == 1


async def test_lost_lease_cancels_the_run(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    cancelled = asyncio.Event()

    async def hang(*_: Any) -> Outcome:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return Outcome("completed")

    worker = _worker(s, repos.db, redis_client, FakeEngine(hang), lease_s=0.3)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    before = _runs("lease_lost")
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "running"))
        async with repos.db.tenant_tx(TENANT_A) as conn:
            await conn.execute(
                "UPDATE workflow_runs SET worker_id = 'someone-else' WHERE tenant_id = $1 AND alert_id = $2",
                TENANT_A,
                alert_id,
            )
        await asyncio.wait_for(cancelled.wait(), 5)
        await eventually(lambda: _stream_empty(redis_client, s))
    assert _runs("lease_lost") == before + 1
    assert (await repos.runs.get(TENANT_A, alert_id)).worker_id == "someone-else"


async def test_resume_for_missing_run_is_dead_lettered(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    engine = FakeEngine(returns("completed"))
    worker = _worker(s, repos.db, redis_client, engine)
    await WorkQueue(redis_client, s).enqueue_resume(TENANT_A, "missing", {"type": "approval"})
    async with running(worker):
        await eventually(lambda: _stream_empty(redis_client, s))
    assert engine.calls == []
    (letter,) = await DeadLetterQueue(redis_client, s).list()
    assert letter.alert_id == "missing"


async def test_usage_is_flushed_to_daily_table(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    worker = _worker(s, repos.db, redis_client, FakeEngine(returns("completed")))
    get_usage_recorder().record(
        model="fake-fast", agent="triage", outcome="success", tenant_id=TENANT_A, input_tokens=100, output_tokens=20
    )
    async with running(worker):
        pass
    async with repos.db.tenant_tx(TENANT_A) as conn:
        row = await conn.fetchrow(
            "SELECT calls, input_tokens, output_tokens FROM llm_usage_daily WHERE tenant_id = $1", TENANT_A
        )
    assert dict(row) == {"calls": 1, "input_tokens": 100, "output_tokens": 20}
    assert get_usage_recorder().pending_rows() == []


async def test_unknown_outcome_status_is_recorded_as_failure(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    worker = _worker(s, repos.db, redis_client, FakeEngine(returns("finished-ish")))
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "failed"))
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.last_error is not None and run.last_error.startswith("ValueError: engine returned an unknown run status")
    assert not await _stream_empty(redis_client, s)


def _decision(escalation_id: str) -> dict:
    return {
        "type": "analyst_decision",
        "escalation_id": escalation_id,
        "decision": "true_positive",
        "approved_actions": [],
        "decided_by": "u1",
        "notes": "",
    }


def _interrupting_engine(repos: Repositories, resume: Callable[[str], Awaitable[Outcome]]) -> FakeEngine:
    """Process interrupts for an analyst (moving the alert like the real engine); resume is scripted."""

    async def behaviour(kind: str, tenant: str, alert: str, payload: Optional[dict]) -> Outcome:
        if kind == "process":
            await repos.alerts.update_status(tenant, alert, "processing")
            await repos.alerts.update_status(tenant, alert, "waiting_human")
            return Outcome("waiting_human", "waiting_human")
        assert payload is not None
        return await resume(payload["escalation_id"])

    return FakeEngine(behaviour)


async def _dlq_size(redis_client: Any, settings: Settings) -> int:
    return len(await DeadLetterQueue(redis_client, settings).list())


async def test_rejected_resume_keeps_waiting_run_and_later_decision_applies(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 1, "max_deliveries": 2})

    async def resume(escalation_id: str) -> Outcome:
        if escalation_id == "stale":
            raise InvalidResumePayload("escalation_id does not match the pending escalation")
        return Outcome("completed")

    engine = _interrupting_engine(repos, resume)
    worker = _worker(s, repos.db, redis_client, engine)
    queue = WorkQueue(redis_client, s)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    before = _runs("rejected")
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "waiting_human"))
        await queue.enqueue_resume(TENANT_A, alert_id, _decision("stale"))
        await eventually(lambda: _dlq_size_is(redis_client, s, 1))
        assert await _status(repos, TENANT_A, alert_id) == "waiting_human"
        assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"

        await queue.enqueue_resume(TENANT_A, alert_id, _decision("e-current"))
        await eventually(lambda: _status_is(repos, alert_id, "completed"))
    resumes = [c[3]["escalation_id"] for c in engine.calls if c[0] == "resume"]
    assert resumes == ["stale", "e-current"]
    (letter,) = await DeadLetterQueue(redis_client, s).list()
    assert letter.kind == "resume"
    assert letter.reason.startswith("rejected: InvalidResumePayload")
    assert _runs("rejected") == before + 1


async def _dlq_size_is(redis_client: Any, settings: Settings, size: int) -> bool:
    return await _dlq_size(redis_client, settings) == size


async def test_resume_failing_before_the_graph_moves_restores_waiting_after_exhaustion(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"visibility_timeout_s": 1, "max_deliveries": 2})

    async def resume(escalation_id: str) -> Outcome:
        if escalation_id == "flaky":
            raise RuntimeError("escalation store unavailable")
        return Outcome("completed")

    engine = _interrupting_engine(repos, resume)
    worker = _worker(s, repos.db, redis_client, engine)
    queue = WorkQueue(redis_client, s)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "waiting_human"))
        await queue.enqueue_resume(TENANT_A, alert_id, _decision("flaky"))
        await eventually(lambda: _dlq_size_is(redis_client, s, 1), within=15)
        assert await _status(repos, TENANT_A, alert_id) == "waiting_human"

        await queue.enqueue_resume(TENANT_A, alert_id, _decision("e-current"))
        await eventually(lambda: _status_is(repos, alert_id, "completed"))
    resumes = [c[3]["escalation_id"] for c in engine.calls if c[0] == "resume"]
    assert resumes == ["flaky", "flaky", "e-current"]
    (letter,) = await DeadLetterQueue(redis_client, s).list()
    assert "exceeded 2 deliveries" in letter.reason


async def test_deferral_does_not_reset_the_retry_budget(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(
        worker={"concurrency": 2, "per_tenant_concurrency": 1, "visibility_timeout_s": 1, "max_deliveries": 2}
    )
    poison_calls: list[str] = []
    poison: dict[str, str] = {}

    async def behaviour(kind: str, tenant: str, alert: str, payload: Optional[dict]) -> Outcome:
        if alert == poison.get("id"):
            poison_calls.append(alert)
            raise RuntimeError("poison")
        await asyncio.sleep(0.3)
        return Outcome("completed")

    engine = FakeEngine(behaviour)
    worker = _worker(s, repos.db, redis_client, engine)
    await _dispatch(repos, s, redis_client, TENANT_B)  # another tenant competes, so the cap applies
    poison["id"] = await _dispatch(repos, s, redis_client, TENANT_A)
    others = [await _dispatch(repos, s, redis_client, TENANT_A) for _ in range(12)]
    async with running(worker):
        await eventually(lambda: _status_is(repos, poison["id"], "dead_lettered"), within=30)
        for other in others:
            await eventually(lambda other=other: _status_is(repos, other, "completed"), within=30)
    assert len(poison_calls) == 2
    assert worker.stats.deferred >= 1
    assert (await repos.alerts.get(TENANT_A, poison["id"])).status == "failed"


async def test_saturated_worker_stays_live(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"concurrency": 1})
    started = asyncio.Event()

    async def slow(*_: Any) -> Outcome:
        started.set()
        await asyncio.sleep(2.0)
        return Outcome("completed")

    worker = _worker(s, repos.db, redis_client, FakeEngine(slow), liveness_tick_s=0.1, stall_limit_s=0.5)
    await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await asyncio.wait_for(started.wait(), 5)
        samples = []
        for _ in range(12):
            await asyncio.sleep(0.1)
            samples.append(worker.is_alive())
        assert worker.inflight == 1
    assert all(samples)


async def test_liveness_fails_when_the_event_loop_is_blocked(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    worker = _worker(s, repos.db, redis_client, FakeEngine(returns("completed")), stall_limit_s=0.3)
    async with running(worker):
        await asyncio.sleep(0.2)
        assert worker.is_alive()
        time.sleep(0.5)  # noqa: ASYNC251 - deliberately blocks the loop, as a stuck synchronous call would
        assert not worker.is_alive()


async def test_drain_timeout_is_honoured_when_saturated(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings(worker={"concurrency": 1, "drain_timeout_s": 0.3, "run_timeout_s": 10.0})
    started = asyncio.Event()

    async def hang(*_: Any) -> Outcome:
        started.set()
        await asyncio.sleep(30)
        return Outcome("completed")

    worker = _worker(s, repos.db, redis_client, FakeEngine(hang), lease_s=30)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    task = asyncio.create_task(worker.run())
    await asyncio.wait_for(started.wait(), 5)
    await asyncio.sleep(0.2)
    begun = time.monotonic()
    worker.request_stop()
    await asyncio.wait_for(task, 10)
    assert time.monotonic() - begun < 2.0
    assert await _status(repos, TENANT_A, alert_id) == "running"
    streams = WorkQueue(redis_client, s).streams
    assert (await redis_client.xpending(streams.high, CONSUMER_GROUP))["pending"] == 1


async def test_a_tenant_alone_uses_every_slot(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    """PERF-1: per_tenant_concurrency is a noisy-neighbour limit, not a cap on single-tenant installs."""
    s = runtime_settings(worker={"concurrency": 4, "per_tenant_concurrency": 1})
    engine = FakeEngine(returns("completed", delay=0.3))
    worker = _worker(s, repos.db, redis_client, engine)
    ids = [await _dispatch(repos, s, redis_client, TENANT_A) for _ in range(4)]
    async with running(worker):
        for alert_id in ids:
            await eventually(lambda alert_id=alert_id: _status_is(repos, alert_id, "completed"))
    assert engine.max_active[TENANT_A] == 4
    assert worker.stats.deferred == 0


async def test_heartbeat_stops_even_when_its_cancellation_is_swallowed(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    """H1: Python 3.11 wait_for (inside redis-py) can swallow cancel(); the run must still finish."""
    s = runtime_settings()
    engine = FakeEngine(returns("completed", delay=0.5))
    worker = _worker(s, repos.db, redis_client, engine, lease_s=0.15)
    real_touch = worker._consumer.touch

    async def swallowing_touch(msg: Any) -> None:
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            return  # exactly what wait_for does when the inner command finished at that moment
        await real_touch(msg)

    worker._consumer.touch = swallowing_touch  # type: ignore[method-assign]
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    async with running(worker):
        await eventually(lambda: _status_is(repos, alert_id, "completed"), within=10)
        await eventually(lambda: _no_inflight(worker), within=10)


async def _no_inflight(worker: Any) -> bool:
    return worker.inflight == 0
