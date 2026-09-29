"""Recovery of work whose queue message never existed or was lost (H2, H3).

Contract section 1: Redis holds nothing that cannot be rebuilt from
PostgreSQL. A poll cancelled mid-way (rolling deploy, leadership loss) must
not strand the alerts it already committed, and a committed analyst
decision whose resume message was lost must still reach its run.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, Mapping, Optional
from uuid import uuid4

import pytest

from lg_sotf.ingestion.service import IngestionService
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime import ops
from lg_sotf.runtime.leader import LeaderLease
from lg_sotf.runtime.resumes import rebuild_resume_payload
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.services.review import ReviewService
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.e2e.conftest import eventually, running
from tests.integration.e2e.test_review_response import related_event
from tests.integration.ingestion.test_poll import ScriptedConnector, page

pytestmark = pytest.mark.integration


class _SlowSecondPage(ScriptedConnector):
    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator:
        yield self.scripted[0]
        await asyncio.sleep(3600)  # the next page's request is in flight when the pod stops
        yield self.scripted[1]


class _AlwaysLeader(LeaderLease):
    def __init__(self) -> None:
        pass

    async def refresh(self) -> bool:
        return True

    @property
    def is_leader(self) -> bool:
        return True

    async def release(self) -> None:
        pass


async def _stream_entries(redis_client: Any, queue: WorkQueue) -> int:
    return int(await redis_client.xlen(queue.streams.high)) + int(await redis_client.xlen(queue.streams.normal))


async def test_cancelled_poll_strands_no_alert(
    repos: Any, db: Any, make_settings: Any, redis_client: Any, unique_prefix: str
) -> None:
    settings = make_settings(
        redis={"key_prefix": unique_prefix},
        ingestion={"page_size": 2, "max_pages_per_poll": 10},
        scheduler={"tick_s": 0.05},
    )
    await repos.sources.create(TENANT_A, "splunk", "splunk src", source_id="splunk-1")

    def factory(source: Any, credentials: Any) -> ScriptedConnector:
        return _SlowSecondPage(source, [page(0, 2, watermark_min=1), page(2, 2, watermark_min=2)], settings=settings)

    queue = WorkQueue(redis_client, settings)
    scheduler = Scheduler(
        settings,
        db,
        redis_client,
        lambda: IngestionService(db, settings, repos=repos, connector_factory=factory),
        queue,
        None,
        lease=_AlwaysLeader(),
        stop_grace_s=0.3,
    )
    task = asyncio.create_task(scheduler.run())
    await asyncio.sleep(1.0)
    scheduler.request_stop()  # SIGTERM during a rolling upgrade: the poll outlives the grace period
    await task
    async with db.system_tx() as conn:
        rows = await conn.fetch(
            "SELECT a.status, r.status AS run FROM alerts a "
            "LEFT JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.id"
        )
    assert rows and all(r["status"] == "queued" and r["run"] == "queued" for r in rows), [dict(r) for r in rows]
    assert await _stream_entries(redis_client, queue) == len(rows)


async def test_new_alerts_without_a_run_are_dispatched(repos: Any, db: Any, make_settings: Any, redis_client: Any, unique_prefix: str) -> None:
    """A crash between an API insert and its dispatch leaves the alert 'new' with no run."""
    settings = make_settings(redis={"key_prefix": unique_prefix})
    alert_id = await make_alert(repos, TENANT_A)
    queue = WorkQueue(redis_client, settings)
    scheduler = Scheduler(settings, db, redis_client, lambda: None, queue, None, lease=_AlwaysLeader())  # type: ignore[arg-type]
    assert await scheduler.recover_stranded_alerts(older_than_s=3600) == 0
    assert await scheduler.recover_stranded_alerts(older_than_s=0) == 1
    assert (await repos.runs.get(TENANT_A, alert_id)).status == "queued"
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "queued"
    assert await _stream_entries(redis_client, queue) == 1


async def test_lost_resume_is_rebuilt_from_the_database(stack_factory: Any, repos: Any, redis_client: Any) -> None:
    stack = stack_factory()
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:8]}@example.com", "analyst")).id
    review = ReviewService(repos, stack.settings, stack.events)
    first = await stack.ingest(TENANT_A, "api", [related_event(1)])
    alert_id = first.inserted[0].alert_id
    async with running(stack.worker(await stack.engine())):
        await stack.dispatch(TENANT_A, first)
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
    escalation = (await repos.escalations.list(TENANT_A, limit=10)).items[0]
    await review.decide(TENANT_A, escalation.id, analyst, "analyst", "false_positive", "fp", [], escalation.version)
    await redis_client.flushdb()  # the resume never reaches the stream (Redis failover without persistence)

    payload = await rebuild_resume_payload(repos, TENANT_A, alert_id)
    assert payload is not None and payload["decision"] == "false_positive"
    assert payload["escalation_id"] == escalation.id and payload["approver_role"] == "analyst"

    scheduler = Scheduler(stack.settings, stack.db, redis_client, lambda: None, stack.queue, None)  # type: ignore[arg-type]
    assert await scheduler.recover_lost_resumes(older_than_s=3600) == 0  # still within the threshold
    assert await scheduler.recover_lost_resumes(older_than_s=0) == 1
    async with running(stack.worker(await stack.engine(), name="w2")):
        await eventually(lambda: _run_is(stack, alert_id, "completed"), within=30)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "benign")


async def test_enqueue_resume_cli_rebuilds_a_lost_resume(stack_factory: Any, repos: Any, redis_client: Any) -> None:
    stack = stack_factory()
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:8]}@example.com", "analyst")).id
    first = await stack.ingest(TENANT_A, "api", [related_event(2)])
    alert_id = first.inserted[0].alert_id
    async with running(stack.worker(await stack.engine())):
        await stack.dispatch(TENANT_A, first)
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
    with pytest.raises(ops.OperationError, match="no decided escalation"):
        await ops.enqueue_lost_resume(stack.settings, tenant_id=TENANT_A, alert_id=alert_id)
    escalation = (await repos.escalations.list(TENANT_A, limit=10)).items[0]
    await ReviewService(repos, stack.settings).decide(
        TENANT_A, escalation.id, analyst, "analyst", "false_positive", None, [], escalation.version
    )
    await redis_client.flushdb()
    entry = await ops.enqueue_lost_resume(stack.settings, tenant_id=TENANT_A, alert_id=alert_id)
    assert entry
    async with running(stack.worker(await stack.engine(), name="w3")):
        await eventually(lambda: _run_is(stack, alert_id, "completed"), within=30)


async def _run_is(stack: Any, alert_id: str, status: str) -> bool:
    return await stack.run_status(TENANT_A, alert_id) == status


async def test_checkpointer_survives_a_database_restart(stack_factory: Any, repos: Any, e2e_database_url: str) -> None:
    """M1: dead pooled checkpointer connections are replaced, not handed to the next run."""
    import asyncpg

    from tests.integration.e2e.test_pipeline import BENIGN_EVENT

    stack = stack_factory(visibility_timeout_s=1200)
    engine = await stack.engine()
    worker = stack.worker(engine)
    first = await stack.ingest(TENANT_A, "api", [BENIGN_EVENT])
    second = await stack.ingest(TENANT_A, "api", [dict(BENIGN_EVENT, source_alert_id="bk-restart-2")])
    a1, a2 = first.inserted[0].alert_id, second.inserted[0].alert_id
    async with running(worker):
        await stack.dispatch(TENANT_A, first)
        await eventually(lambda: _run_is(stack, a1, "completed"))
        conn = await asyncpg.connect(e2e_database_url)
        try:
            await conn.fetchval(
                "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid()"
            )
        finally:
            await conn.close()
        await asyncio.sleep(0.5)
        await stack.dispatch(TENANT_A, second)
        await eventually(lambda: _run_is(stack, a2, "completed"), within=20)
    run = await repos.runs.get(TENANT_A, a2)
    assert run.attempt == 1 and run.last_error is None


async def test_decision_applies_quickly_after_a_worker_dies_mid_resume(
    stack_factory: Any, repos: Any, redis_client: Any
) -> None:
    """M6: a refused resume is retried within seconds, not after worker.visibility_timeout_s."""
    import time

    from lg_sotf.queue.consumer import StreamConsumer

    stack = stack_factory(visibility_timeout_s=60)
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:8]}@example.com", "analyst")).id
    result = await stack.ingest(TENANT_A, "api", [related_event(7)])
    alert_id = result.inserted[0].alert_id
    engine = await stack.engine()
    async with running(stack.worker(engine, name="w0")):
        await stack.dispatch(TENANT_A, result)
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
    escalation = await repos.escalations.get_active_for_alert(TENANT_A, alert_id)
    decision = await ReviewService(repos, stack.settings, stack.events).decide(
        TENANT_A, escalation.id, analyst, "analyst", "false_positive", None, [], escalation.version
    )
    for request in decision:
        await stack.queue.enqueue_resume(TENANT_A, request.alert_id, request.payload)
    # A worker reads the resume, claims the run and is killed (no heartbeat, no cleanup).
    dead = StreamConsumer(redis_client, stack.settings, "dead-worker")
    await dead.ensure_groups()
    await dead.announce_alive(1.5)
    [_msg] = await dead.read(1)
    await repos.runs.start(TENANT_A, alert_id, "dead-worker", lease_s=1.5, kind="resume")
    started = time.monotonic()
    scheduler = Scheduler(stack.settings, stack.db, redis_client, lambda: None, stack.queue, None)  # type: ignore[arg-type]
    await asyncio.sleep(1.6)  # lease and liveness key lapse
    await scheduler.sweep_stale_runs()  # the stale sweep wins the race against the dead-consumer claim
    async with running(stack.worker(engine, name="w2")):
        await eventually(lambda: _alert_closed(repos, alert_id), within=20)
    assert time.monotonic() - started < 20


async def _alert_closed(repos: Any, alert_id: str) -> bool:
    return (await repos.alerts.get(TENANT_A, alert_id)).status == "closed"
