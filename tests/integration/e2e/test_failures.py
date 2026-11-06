"""Crash safety and poison messages with the real worker, queue and workflow engine."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, List

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.queue.dlq import DeadLetterQueue
from lg_sotf.runtime.ops import dlq_requeue
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.services.response import ResponseService
from tests.integration.db._support import TENANT_A
from tests.integration.e2e._support import SUSPICIOUS_EVENT, Stack, analyst_decides, count_calls, eventually, running

pytestmark = pytest.mark.integration


async def _ingest_one(stack: Stack) -> str:
    result = await stack.ingest(TENANT_A, "api", [SUSPICIOUS_EVENT])
    assert await stack.dispatch(TENANT_A, result) == 1
    return result.inserted[0].alert_id


async def _node_events(repos: Repositories, alert_id: str) -> List[str]:
    return [e.node for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id, limit=200)).items]


async def _pending_deliveries(stack: Stack) -> List[int]:
    rows = await stack.redis.xpending_range(stack.queue.streams.normal, "workers", min="-", max="+", count=10)
    return [int(r["times_delivered"]) for r in rows]


async def test_worker_killed_mid_run_is_reclaimed_and_continues_from_checkpoint(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory(visibility_timeout_s=1, drain_timeout_s=0.2)
    alert_id = await _ingest_one(stack)

    crashed_engine = await stack.engine()
    in_correlation = asyncio.Event()

    async def hang(*args: Any, **kwargs: Any) -> Any:
        in_correlation.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(crashed_engine.agents.correlation, "run", hang)
    first = stack.worker(crashed_engine, "w1", lease_s=1.0)
    first_task = asyncio.create_task(first.run())
    await asyncio.wait_for(in_correlation.wait(), timeout=20)

    # Simulated process death: the worker task is cancelled with nothing acked or recorded.
    first_task.cancel()
    await asyncio.gather(first_task, return_exceptions=True)
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.status == "running" and run.worker_id == "w1"
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "processing"
    assert await _pending_deliveries(stack) == [1]

    engine = await stack.engine()
    triage = count_calls(monkeypatch, engine.agents.triage, "run")
    correlation = count_calls(monkeypatch, engine.agents.correlation, "run")
    second = stack.worker(engine, "w2", lease_s=1.0)
    async with running(second):
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
        await eventually(stack.stream_empty)

    assert triage == [] and correlation == [1]
    nodes = await _node_events(repos, alert_id)
    assert nodes.count("gate") == 1 and nodes.count("triage") == 1 and nodes.count("correlation") == 1
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.attempt == 2 and run.thread_id == thread_id_for(TENANT_A, alert_id)
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"
    assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is not None


async def test_worker_killed_during_resume_continues_after_the_applied_decision(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory(visibility_timeout_s=1, drain_timeout_s=0.2)
    alert_id = await _ingest_one(stack)
    user_id = str((await repos.users.create(TENANT_A, "analyst@example.com", "analyst")).id)
    original_plan = ResponseService.plan
    plans: List[int] = []
    in_plan = asyncio.Event()

    async def hangs_first_time(self: ResponseService, *args: Any, **kwargs: Any) -> Any:
        plans.append(1)
        if len(plans) == 1:
            in_plan.set()
            await asyncio.Event().wait()
        return await original_plan(self, *args, **kwargs)

    monkeypatch.setattr(ResponseService, "plan", hangs_first_time)
    first = stack.worker(await stack.engine(), "w1", lease_s=1.0)
    first_task = asyncio.create_task(first.run())
    await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
    escalation_id = await analyst_decides(stack, TENANT_A, alert_id, "true_positive", user_id)
    await asyncio.wait_for(in_plan.wait(), timeout=20)
    first_task.cancel()
    await asyncio.gather(first_task, return_exceptions=True)
    assert await _run_is(stack, alert_id, "running")

    engine = await stack.engine()
    analysis = count_calls(monkeypatch, engine.agents.analysis, "run")
    second = stack.worker(engine, "w2", lease_s=1.0)
    async with running(second):
        await eventually(lambda: _run_is(stack, alert_id, "waiting_approval"))
        await eventually(stack.stream_empty)

    assert analysis == [] and len(plans) == 2
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_approval"
    assert (await repos.escalations.get(TENANT_A, escalation_id)).status == "decided"
    decisions = [
        e
        for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id, limit=200)).items
        if e.event_type == "analyst.decision"
    ]
    assert len(decisions) == 1
    ledger = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    assert any(a.status == "awaiting_approval" for a in ledger)
    assert len({(a.action_type, a.target) for a in ledger}) == len(ledger)


async def test_node_failure_is_retried_by_the_queue_from_its_checkpoint(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory(visibility_timeout_s=1)
    alert_id = await _ingest_one(stack)
    engine = await stack.engine()
    triage = count_calls(monkeypatch, engine.agents.triage, "run")
    original = engine.agents.correlation.run
    correlation: List[int] = []

    async def fails_once(*args: Any, **kwargs: Any) -> Any:
        correlation.append(1)
        if len(correlation) == 1:
            raise RuntimeError("correlation backend crashed")
        return await original(*args, **kwargs)

    monkeypatch.setattr(engine.agents.correlation, "run", fails_once)
    worker = stack.worker(engine)

    async with running(worker):
        await eventually(lambda: _run_is(stack, alert_id, "failed"))
        run = await repos.runs.get(TENANT_A, alert_id)
        assert run.last_error is not None and run.last_error.startswith("RuntimeError")
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
        await eventually(stack.stream_empty)

    assert len(triage) == 1 and len(correlation) == 2
    assert (await repos.runs.get(TENANT_A, alert_id)).attempt == 2
    assert worker.stats.failed == 1 and worker.stats.waiting == 1
    statuses = [e["data"]["status"] for e in stack.events.of(alert_id, "alert.updated") if "status" in e["data"]]
    assert statuses == ["processing", "failed", "processing", "waiting_human"]


async def test_poison_alert_is_dead_lettered_after_max_deliveries(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory(visibility_timeout_s=1, max_deliveries=2)
    alert_id = await _ingest_one(stack)
    engine = await stack.engine()
    calls: List[int] = []

    async def always_fails(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        raise RuntimeError("triage model returned garbage")

    monkeypatch.setattr(engine.agents.triage, "run", always_fails)
    worker = stack.worker(engine)

    async with running(worker):
        await eventually(lambda: _run_is(stack, alert_id, "dead_lettered"))
        await eventually(stack.stream_empty)

    assert len(calls) == 2
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.attempt == 3 and run.last_error is not None and "exceeded 2 deliveries" in run.last_error
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "failed"
    letters = await DeadLetterQueue(stack.redis, stack.settings).list()
    assert [(d.tenant_id, d.alert_id, d.kind) for d in letters] == [(TENANT_A, alert_id, "process")]
    assert "RuntimeError" in letters[0].reason
    dead = [e for e in stack.events.of(alert_id, "alert.updated") if e["data"].get("reason") == "dead_lettered"]
    assert dead and dead[-1]["data"]["status"] == "failed"
    assert worker.stats.dead_lettered == 1 and worker.stats.failed == 2

    # Once the cause is fixed, an operator requeues the dead letter and the run finishes from its checkpoint.
    monkeypatch.undo()
    results = await dlq_requeue(stack.settings, [letters[0].entry_id])
    assert [r.ok for r in results] == [True]
    fixed = stack.worker(await stack.engine(), "w2")
    async with running(fixed):
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
        await eventually(stack.stream_empty)
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"
    assert await DeadLetterQueue(stack.redis, stack.settings).list() == []


async def _run_is(stack: Stack, alert_id: str, status: str) -> bool:
    return await stack.run_status(TENANT_A, alert_id) == status


async def test_engine_without_indicator_key_refuses_to_start(stack_factory: Callable[..., Stack]) -> None:
    """Correlation hashes every indicator; a worker without the key must fail at startup, not per alert."""
    stack = stack_factory()
    security = stack.settings.security.model_copy(update={"indicator_hmac_key": None})
    settings = stack.settings.model_copy(update={"security": security})
    with pytest.raises(SecurityConfigError, match="indicator_hmac_key"):
        await WorkflowEngine.create(settings=settings, db=stack.db, redis=stack.redis, events=stack.events)
