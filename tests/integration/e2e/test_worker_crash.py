"""A worker killed with SIGKILL mid-burst: every alert it held settles within the lease bound.

The killed worker runs on its own event loop in a thread. Killing it stops
that loop, so none of its code runs again (no ``finally``, drain, ack or
consumer cleanup), and then drops its Postgres and Redis connections the way
the kernel does when a process dies. ``worker.visibility_timeout_s`` stays at
its 1200 s default: recovery must not depend on it.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import pytest
from redis.asyncio import Redis

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.urls import with_query_params
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.queue.consumer import CONSUMER_GROUP, StreamConsumer, ensure_groups
from lg_sotf.queue.events import EventBus
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.runtime.worker import Worker
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A
from tests.integration.e2e._support import WAITING_OR_DONE, Stack, eventually, running

pytestmark = pytest.mark.integration

LEASE_S = 2.0
SWEEP_S = 1.0
BURST = 60
CLAIMED_BEFORE_KILL = 4
# Settling a burst of this size once recovery has started; far below the 1200 s visibility timeout.
PROCESSING_ALLOWANCE_S = 15.0
RECOVERY_BOUND_S = 2 * LEASE_S + SWEEP_S + PROCESSING_ALLOWANCE_S

# Loops of killed workers stay referenced so their suspended coroutines are never finalized.
_KILLED: List[Any] = []


def burst_event(n: int) -> Dict[str, Any]:
    return {
        "source_alert_id": f"burst-{n}",
        "title": "Possible C2 beacon from workstation" if n % 2 else "Scheduled backup maintenance test job",
        "severity": "medium" if n % 2 else "low",
        "occurred_at": "2024-03-05T10:05:00Z",
        "entities": {"ips": [f"185.220.{n // 250}.{n % 250 + 1}"], "hosts": [f"ws-{n:03d}"]},
    }


class KillableWorker:
    """A real worker (own pools, engine and consumer) that :meth:`kill` stops like SIGKILL.

    It claims ``claim_budget`` runs, which hang in correlation so their leases
    are live at the kill; later claims block, so the entries the worker has read
    but not yet claimed sit in its pending list with their runs still ``queued``.
    """

    def __init__(self, settings: Settings, name: str, *, claim_budget: int) -> None:
        self.name = name
        self.tag = f"killable-{name}-{id(self):x}"
        url = with_query_params(settings.database.url.get_secret_value(), {"application_name": self.tag})
        self._settings = settings.model_copy(
            update={"database": settings.database.model_copy(update={"url": type(settings.database.url)(url)})}
        )
        self._claim_budget = claim_budget
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread = threading.Thread(target=self._thread_main, name=self.tag, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=60) or self._error is not None:
            raise RuntimeError(f"killable worker did not start: {self._error!r}")

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        _KILLED.append(loop)
        try:
            loop.run_until_complete(self._main())
        except RuntimeError:
            pass  # the loop was stopped: killed
        except BaseException as exc:  # noqa: BLE001 - reported to start()
            self._error = exc
            self._ready.set()

    async def _main(self) -> None:
        s = self._settings
        db = Database(s.database, application_name=self.tag)
        await db.open()
        redis = Redis.from_url(s.redis.url.get_secret_value(), decode_responses=False, client_name=self.tag)
        events = EventBus(redis, s)
        engine = await WorkflowEngine.create(settings=s, db=db, redis=redis, events=events, checkpoint_pool_size=4)

        async def hang(*args: Any, **kwargs: Any) -> Any:
            await asyncio.Event().wait()

        engine.agents.correlation.run = hang  # type: ignore[method-assign]
        consumer = StreamConsumer(redis, s, self.name)
        worker = Worker(s, db, redis, engine, consumer, events, worker_id=self.name, lease_s=LEASE_S)
        start = worker.repos.runs.start
        claims = 0

        async def gated_start(*args: Any, **kwargs: Any) -> Any:
            nonlocal claims
            if claims >= self._claim_budget:
                await asyncio.Event().wait()
            claims += 1
            return await start(*args, **kwargs)

        worker.repos.runs.start = gated_start  # type: ignore[method-assign]
        _KILLED.append((db, redis, engine, worker))
        self._ready.set()
        await worker.run()

    async def kill(self, db: Database, redis: Any) -> None:
        assert self._loop is not None
        self._loop.call_soon_threadsafe(self._loop.stop)
        await asyncio.to_thread(self._thread.join, 20)
        assert not self._thread.is_alive()
        async with db.system_tx() as conn:
            await conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1", self.tag
            )
        for client in await redis.client_list():
            if client.get("name") == self.tag:
                await redis.client_kill_filter(_id=client["id"])


async def pending_alerts(stack: Stack, consumer: str) -> List[str]:
    """Alert ids of the entries in ``consumer``'s pending list."""
    alert_ids: List[str] = []
    for stream in stack.queue.streams.work:
        rows = await stack.redis.xpending_range(
            stream, CONSUMER_GROUP, min="-", max="+", count=1000, consumername=consumer
        )
        for row in rows:
            entries = await stack.redis.xrange(stream, min=row["message_id"], max=row["message_id"])
            alert_ids.extend(fields[b"alert_id"].decode() for _, fields in entries)
    return alert_ids


async def runs_leased_by(repos: Repositories, worker_id: str) -> int:
    async with repos.runs.db.system_tx() as conn:
        return int(
            await conn.fetchval(
                "SELECT count(*) FROM workflow_runs WHERE status = 'running' AND worker_id = $1", worker_id
            )
        )


@pytest.mark.parametrize("restart_name", ["w-restarted", "w-killed"], ids=["new-consumer-name", "same-consumer-name"])
async def test_sigkilled_worker_backlog_settles_within_lease_bound(
    stack_factory: Callable[..., Stack], repos: Repositories, restart_name: str
) -> None:
    stack = stack_factory(
        concurrency=16,
        per_tenant_concurrency=8,
        visibility_timeout_s=1200,
        max_deliveries=5,
        scheduler={"stale_run_sweep_interval_s": SWEEP_S},
    )
    assert stack.settings.worker.visibility_timeout_s == 1200
    result = await stack.ingest(TENANT_A, "api", [burst_event(n) for n in range(BURST)])
    alert_ids = [a.alert_id for a in result.inserted]
    assert len(alert_ids) == BURST
    assert await stack.dispatch(TENANT_A, result) == BURST
    await ensure_groups(stack.redis, stack.queue.streams)

    killed = KillableWorker(stack.settings, "w-killed", claim_budget=CLAIMED_BEFORE_KILL)
    killed.start()

    async def mid_burst() -> bool:
        held = len(await pending_alerts(stack, "w-killed"))
        return held > CLAIMED_BEFORE_KILL and await runs_leased_by(repos, "w-killed") == CLAIMED_BEFORE_KILL

    await eventually(mid_burst, within=30)
    await killed.kill(stack.db, stack.redis)

    held = await pending_alerts(stack, "w-killed")
    statuses = {a: await stack.run_status(TENANT_A, a) for a in held}
    assert sorted(set(statuses.values())) == ["queued", "running"], statuses
    assert not await stack.all_settled(TENANT_A, alert_ids)

    survivor = stack.worker(await stack.engine(), restart_name, lease_s=LEASE_S)
    scheduler = Scheduler(
        stack.settings,
        stack.db,
        stack.redis,
        lambda: IngestionService(stack.db, stack.settings),
        stack.queue,
        stack.events,
    )
    scheduler_task = asyncio.create_task(scheduler.run())
    started = time.monotonic()
    try:
        async with running(survivor):
            try:
                await eventually(lambda: stack.all_settled(TENANT_A, alert_ids), within=RECOVERY_BOUND_S, interval=0.2)
            except AssertionError:
                stuck = {a: await stack.run_status(TENANT_A, a) for a in alert_ids}
                stuck = {a: s for a, s in stuck.items() if s not in WAITING_OR_DONE}
                held_by_killed = {a: s for a, s in stuck.items() if a in statuses}
                raise AssertionError(
                    f"{len(stuck)} alerts unsettled after {RECOVERY_BOUND_S}s; held by the killed worker: "
                    f"{held_by_killed} (at the kill: {statuses})"
                ) from None
            elapsed = time.monotonic() - started
    finally:
        scheduler.request_stop()
        await asyncio.wait_for(scheduler_task, timeout=20)

    assert elapsed < RECOVERY_BOUND_S
    for alert_id in alert_ids:
        run = await repos.runs.get(TENANT_A, alert_id)
        assert run.status != "dead_lettered", (alert_id, run.last_error)
        assert (await repos.alerts.get(TENANT_A, alert_id)).status != "failed"
