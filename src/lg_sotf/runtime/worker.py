"""Queue worker: claims workflow runs and executes them with the workflow engine.

Per message (contract section 7 and the ``workflow_runs`` claim rules):

1. ``runs.start``: terminal or waiting runs are acked and dropped; a live
   lease or a resume that arrived early leaves the message pending so it is
   redelivered after the visibility timeout. Once the message has exceeded
   ``worker.max_deliveries`` such an unclaimable message is dropped (live
   lease: a duplicate) or dead-lettered (a resume for a run that is not
   waiting).
2. A claim beyond ``worker.max_deliveries`` attempts (``workflow_runs.attempt``,
   which survives redelivery and fair-share deferral) dead-letters the run,
   fails the alert and moves the message to the DLQ. A run whose alert is
   still waiting for a human is put back to waiting instead: only the
   message is dead-lettered.
3. The engine runs under ``worker.run_timeout_s`` while a heartbeat extends
   the run lease and keeps the stream entry from being reclaimed. Losing the
   lease cancels the run.
4. The outcome is written to ``workflow_runs`` and only then is the message
   acked. On failure the run is marked ``failed`` and the message stays
   pending for a retry. A resume payload the engine rejects
   (:class:`InvalidResumePayload`) is permanent: the run goes back to the
   state it was claimed from and only the message is dead-lettered.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple, Type

from lg_sotf.core.exceptions import InvalidResumePayload
from lg_sotf.db.errors import InvalidTransition, LeaseLost, NotFound, RunNotClaimable
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, Repositories, WorkflowRun
from lg_sotf.db.repos.runs import WAITING_RUN_STATUSES
from lg_sotf.llm.usage import LLMUsageRow, get_usage_recorder
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.observability.metrics import record_run
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.events import make_event
from lg_sotf.queue.streams import Message
from lg_sotf.security.redaction import redact_text
from lg_sotf.settings import Settings

log = get_logger(__name__)

TERMINAL_REASONS = frozenset({"completed", "dead_lettered", "waiting"})
USAGE_FLUSH_INTERVAL_S = 30.0
DEFAULT_LEASE_S = 60.0
MAX_ERROR_MESSAGE_CHARS = 300
_READ_ERROR_BACKOFF_S = (0.5, 1.0, 2.0, 5.0)
_DEFER_BACKOFF_S = 0.25
LIVENESS_TICK_S = 5.0
LIVENESS_GRACE_S = 30.0
# Engine errors that no retry can fix: the message is dead-lettered at once.
PERMANENT_ERRORS: Tuple[Type[BaseException], ...] = (InvalidResumePayload,)


class RunOutcomeLike(Protocol):
    @property
    def status(self) -> str: ...


class EngineLike(Protocol):
    async def run(self, tenant_id: str, alert_id: str) -> RunOutcomeLike: ...

    async def resume(self, tenant_id: str, alert_id: str, payload: dict[str, Any]) -> RunOutcomeLike: ...

    async def close(self) -> None: ...


class EventPublisherLike(Protocol):
    async def publish(self, tenant_id: str, event: dict[str, Any]) -> None: ...


class _LeaseLostError(Exception):
    """Internal: the heartbeat found the run leased by someone else."""


def default_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


def sanitize_error(exc: BaseException) -> str:
    """``Type: message`` short enough for ``workflow_runs.last_error``, with credentials redacted.

    Exception messages can quote input, so they are cut short; never log or
    store the full text.
    """
    message = str(exc).replace("\n", " ").strip()
    if len(message) > MAX_ERROR_MESSAGE_CHARS:
        message = message[: MAX_ERROR_MESSAGE_CHARS - 3] + "..."
    message = redact_text(message)[0] if message else ""
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


def waiting_status_to_restore(claimed_from: Optional[str], alert_status: Optional[str]) -> Optional[str]:
    """The waiting state a claimed run must return to instead of failing or being dead-lettered.

    A run claimed from ``waiting_*`` goes back there. A run claimed from
    ``failed`` (or an expired lease) whose alert is still ``waiting_*`` never
    got past the interrupt, so it is waiting too. ``None``: the run really
    ran and may be failed or dead-lettered.
    """
    if claimed_from in WAITING_RUN_STATUSES:
        return claimed_from
    if alert_status in WAITING_RUN_STATUSES:
        return alert_status
    return None


@dataclass
class WorkerStats:
    started: int = 0
    completed: int = 0
    waiting: int = 0
    failed: int = 0
    skipped: int = 0
    deferred: int = 0
    dead_lettered: int = 0


class Worker:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        redis: Any,
        engine: EngineLike,
        consumer: StreamConsumer,
        events: Optional[EventPublisherLike],
        *,
        worker_id: Optional[str] = None,
        lease_s: float = DEFAULT_LEASE_S,
        usage_flush_interval_s: float = USAGE_FLUSH_INTERVAL_S,
        liveness_tick_s: float = LIVENESS_TICK_S,
        stall_limit_s: Optional[float] = None,
    ) -> None:
        if lease_s <= 0:
            raise ValueError("lease_s must be positive")
        if liveness_tick_s <= 0:
            raise ValueError("liveness_tick_s must be positive")
        self._settings = settings
        self._cfg = settings.worker
        self._db = db
        self._redis = redis
        self._repos = Repositories.create(db)
        self._engine = engine
        self._consumer = consumer
        self._events = events
        self.worker_id = worker_id or consumer.name
        self._lease_s = lease_s
        self._heartbeat_s = max(lease_s / 3.0, 0.05)
        self._usage_flush_interval_s = usage_flush_interval_s
        self._liveness_tick_s = liveness_tick_s
        if stall_limit_s is None:
            longest_wait_s = max(settings.worker.block_ms / 1000.0 + settings.redis.socket_timeout_s, liveness_tick_s)
            stall_limit_s = longest_wait_s + LIVENESS_GRACE_S
        self._stall_limit_s = stall_limit_s
        self._stop = asyncio.Event()
        self._inflight: Set[asyncio.Task[None]] = set()
        self._tenant_running: Dict[str, int] = {}
        self._loop_tick = time.monotonic()
        self._running = False
        self.stats = WorkerStats()

    @property
    def repos(self) -> Repositories:
        return self._repos

    @property
    def inflight(self) -> int:
        return len(self._inflight)

    def request_stop(self) -> None:
        self._stop.set()

    def is_alive(self) -> bool:
        """Liveness: the consume loop has ticked recently.

        The loop ticks after every read and every ``liveness_tick_s`` while
        all slots are busy, so a saturated worker stays live; only a stuck
        event loop or a hung read goes stale.
        """
        if not self._running:
            return not self._stop.is_set()
        return time.monotonic() - self._loop_tick < self._stall_limit_s

    async def run(self) -> None:
        """Consume until :meth:`request_stop`, then drain and return."""
        await self._consumer.ensure_groups()
        flusher = asyncio.create_task(self._flush_usage_periodically(), name="usage-flush")
        self._running = True
        log.info("worker.started", worker_id=self.worker_id, concurrency=self._cfg.concurrency)
        try:
            await self._consume()
        finally:
            self._running = False
            await self._drain()
            flusher.cancel()
            await asyncio.gather(flusher, return_exceptions=True)
            await self.flush_usage()
            try:
                await self._consumer.remove_if_idle()
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup on shutdown
                log.warning("worker.consumer_cleanup_failed", error=type(exc).__name__)
            log.info("worker.stopped", worker_id=self.worker_id)

    async def _consume(self) -> None:
        errors = 0
        while not self._stop.is_set():
            self._loop_tick = time.monotonic()
            free = self._cfg.concurrency - len(self._inflight)
            if free <= 0:
                await self._wait_for_free_slot()
                continue
            try:
                messages = await self._consumer.read(free)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - Redis outages must not kill the worker
                delay = _READ_ERROR_BACKOFF_S[min(errors, len(_READ_ERROR_BACKOFF_S) - 1)]
                errors += 1
                log.warning("worker.read_failed", error=type(exc).__name__, retry_in_s=delay)
                await self._sleep_unless_stopped(delay)
                continue
            errors = 0
            self._loop_tick = time.monotonic()
            deferred = 0
            for msg in messages:
                if not self._try_reserve_tenant(msg.tenant_id):
                    await self._defer(msg)
                    deferred += 1
                    continue
                task = asyncio.create_task(self._run_message(msg), name=f"run:{msg.entry_id}")
                self._inflight.add(task)
                task.add_done_callback(self._inflight.discard)
            if messages and deferred == len(messages):
                await self._sleep_unless_stopped(_DEFER_BACKOFF_S)

    async def _wait_for_free_slot(self) -> None:
        """Wait until a run finishes or a stop is requested, ticking liveness meanwhile."""
        stop_waiter = asyncio.create_task(self._stop.wait())
        try:
            while not self._stop.is_set():
                done, _ = await asyncio.wait(
                    set(self._inflight) | {stop_waiter},
                    timeout=self._liveness_tick_s,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                self._loop_tick = time.monotonic()
                if done:
                    return
        finally:
            stop_waiter.cancel()
            await asyncio.gather(stop_waiter, return_exceptions=True)

    async def _sleep_unless_stopped(self, delay: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except TimeoutError:
            pass

    def _try_reserve_tenant(self, tenant_id: str) -> bool:
        running = self._tenant_running.get(tenant_id, 0)
        if running >= self._cfg.per_tenant_concurrency:
            return False
        self._tenant_running[tenant_id] = running + 1
        return True

    def _release_tenant(self, tenant_id: str) -> None:
        remaining = self._tenant_running.get(tenant_id, 0) - 1
        if remaining > 0:
            self._tenant_running[tenant_id] = remaining
        else:
            self._tenant_running.pop(tenant_id, None)

    async def _defer(self, msg: Message) -> None:
        """Send a message of a tenant at its concurrency cap to the back of its stream.

        The copy starts with a fresh delivery count, so the retry budget is
        enforced on ``workflow_runs.attempt`` rather than on deliveries.
        """
        try:
            await self._consumer.requeue(msg)
        except Exception as exc:  # noqa: BLE001 - the entry stays pending and is reclaimed later
            log.warning("worker.defer_failed", error=type(exc).__name__)
            return
        self.stats.deferred += 1

    async def _drain(self) -> None:
        if not self._inflight:
            return
        log.info("worker.draining", inflight=len(self._inflight), timeout_s=self._cfg.drain_timeout_s)
        _done, pending = await asyncio.wait(set(self._inflight), timeout=self._cfg.drain_timeout_s)
        if pending:
            # Their messages stay pending and their leases expire; others pick them up.
            log.warning("worker.drain_timeout_cancelling", count=len(pending))
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def _run_message(self, msg: Message) -> None:
        try:
            with bound_context(tenant_id=msg.tenant_id, alert_id=msg.alert_id):
                await self.process(msg)
        except asyncio.CancelledError:
            log.warning("worker.run_cancelled", entry_id=msg.entry_id)
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected bookkeeping failure; the entry is retried
            log.error("worker.message_failed", entry_id=msg.entry_id, error=type(exc).__name__)
        finally:
            self._release_tenant(msg.tenant_id)

    async def process(self, msg: Message) -> None:
        """Handle one message end to end (public for tests and tooling)."""
        try:
            claimed = await self._repos.runs.start(
                msg.tenant_id, msg.alert_id, self.worker_id, lease_s=self._lease_s, kind=msg.kind
            )
        except RunNotClaimable as exc:
            await self._handle_unclaimable(msg, exc)
            return
        except NotFound:
            await self._dead_letter_message(msg, "resume for a run that does not exist")
            log.warning("worker.resume_without_run")
            return

        if claimed.attempt > self._cfg.max_deliveries:
            await self._handle_exhausted(msg, claimed)
            return

        self.stats.started += 1
        started = time.monotonic()
        try:
            outcome = await self._execute_with_lease(msg)
        except _LeaseLostError:
            # The stale-run sweep requeued the run and enqueued a new message; this one is redundant.
            await self._consumer.ack(msg)
            record_run("lease_lost")
            log.warning("worker.lease_lost")
            return
        except asyncio.CancelledError:
            raise
        except PERMANENT_ERRORS as exc:
            await self._reject(msg, claimed, exc)
            return
        except Exception as exc:  # noqa: BLE001 - recorded on the run; the queue retries it
            await self._record_failure(msg, exc)
            return

        if outcome.status not in ("completed", "waiting_human", "waiting_approval"):
            await self._record_failure(msg, ValueError(f"engine returned an unknown run status: {outcome.status!r}"))
            return
        try:
            if outcome.status == "completed":
                await self._repos.runs.complete(msg.tenant_id, msg.alert_id, worker_id=self.worker_id)
                self.stats.completed += 1
            else:
                await self._repos.runs.mark_waiting(
                    msg.tenant_id, msg.alert_id, outcome.status, worker_id=self.worker_id
                )
                self.stats.waiting += 1
        except LeaseLost:
            await self._consumer.ack(msg)
            record_run("lease_lost")
            log.warning("worker.lease_lost_on_finish")
            return
        await self._consumer.ack(msg)
        record_run(outcome.status)
        log.info(
            "worker.run_finished",
            outcome=outcome.status,
            kind=msg.kind,
            seconds=round(time.monotonic() - started, 3),
        )

    async def _handle_unclaimable(self, msg: Message, exc: RunNotClaimable) -> None:
        if exc.reason in TERMINAL_REASONS:
            await self._consumer.ack(msg)
            self.stats.skipped += 1
            record_run("skipped")
            log.info("worker.run_skipped", reason=exc.reason, kind=msg.kind)
            return
        if msg.deliveries <= self._cfg.max_deliveries:
            log.info("worker.run_not_claimable", reason=exc.reason, kind=msg.kind, deliveries=msg.deliveries)
            return
        if exc.reason == "leased":
            # Another worker executes the run under a live lease; this entry is a duplicate.
            await self._consumer.ack(msg)
            self.stats.skipped += 1
            record_run("skipped")
            log.info("worker.stale_duplicate_dropped", deliveries=msg.deliveries, kind=msg.kind)
            return
        # A resume for a run that never became waiting: the payload cannot apply; the run is left alone.
        await self._dead_letter_message(
            msg, f"exceeded {self._cfg.max_deliveries} deliveries; run not claimable ({exc.reason})"
        )

    async def _dead_letter_message(self, msg: Message, reason: str) -> None:
        """Move only the message to the DLQ; the run is not touched."""
        await self._consumer.dead_letter(msg, reason)
        self.stats.dead_lettered += 1
        record_run("dead_lettered")
        log.warning("worker.message_dead_lettered", kind=msg.kind, deliveries=msg.deliveries)

    async def _alert_status(self, msg: Message) -> Optional[str]:
        try:
            return (await self._repos.alerts.get(msg.tenant_id, msg.alert_id)).status
        except NotFound:
            return None

    async def _restore_waiting(self, msg: Message, status: str) -> bool:
        """Hand a claimed run back to ``status`` (waiting); False when the claim was lost meanwhile."""
        try:
            await self._repos.runs.mark_waiting(msg.tenant_id, msg.alert_id, status, worker_id=self.worker_id)
        except (LeaseLost, InvalidTransition) as exc:
            log.warning("worker.restore_waiting_skipped", error=type(exc).__name__)
            return False
        return True

    async def _reject(self, msg: Message, claimed: WorkflowRun, exc: BaseException) -> None:
        """The engine refused the message for good: undo the claim and dead-letter only the message."""
        error = sanitize_error(exc)
        restore = waiting_status_to_restore(claimed.claimed_from, await self._alert_status(msg))
        if restore is not None:
            await self._restore_waiting(msg, restore)
        else:
            # Keep the run retryable by its own message, with the error that failed it before.
            try:
                await self._repos.runs.fail(
                    msg.tenant_id, msg.alert_id, claimed.last_error or error, worker_id=self.worker_id
                )
            except (LeaseLost, InvalidTransition) as err:
                log.warning("worker.fail_not_recorded", error=type(err).__name__)
        await self._consumer.dead_letter(msg, f"rejected: {error}")
        self.stats.dead_lettered += 1
        record_run("rejected")
        log.warning("worker.message_rejected", kind=msg.kind, error=type(exc).__name__, run_status=restore or "failed")

    async def _handle_exhausted(self, msg: Message, claimed: WorkflowRun) -> None:
        """The run used up its attempts: dead-letter it (or put it back to waiting) and the message."""
        reason = f"exceeded {self._cfg.max_deliveries} deliveries"
        if claimed.last_error:
            reason = f"{reason}; last error: {claimed.last_error}"
        restore = waiting_status_to_restore(claimed.claimed_from, await self._alert_status(msg))
        if restore is not None:
            # The alert is waiting for a human: the run is fine, the message is the problem.
            await self._restore_waiting(msg, restore)
            await self._dead_letter_message(msg, reason)
            return
        alert_failed = await self._mark_dead_lettered(msg, reason)
        if alert_failed and self._events is not None:
            try:
                await self._events.publish(
                    msg.tenant_id,
                    make_event(
                        "alert.updated", msg.tenant_id, msg.alert_id, {"status": "failed", "reason": "dead_lettered"}
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - events are best-effort notifications
                log.warning("worker.event_publish_failed", error=type(exc).__name__)
        await self._consumer.dead_letter(msg, reason)
        self.stats.dead_lettered += 1
        record_run("dead_lettered")
        log.error("worker.dead_lettered", deliveries=msg.deliveries, attempt=claimed.attempt, kind=msg.kind)

    async def _execute_with_lease(self, msg: Message) -> RunOutcomeLike:
        engine_task: asyncio.Task[RunOutcomeLike] = asyncio.create_task(self._call_engine(msg))
        lease_lost = asyncio.Event()
        heartbeat = asyncio.create_task(self._heartbeat(msg, engine_task, lease_lost))
        try:
            return await engine_task
        except asyncio.CancelledError:
            if lease_lost.is_set() and not self._current_task_cancelling():
                raise _LeaseLostError() from None
            raise
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            if not engine_task.done():
                engine_task.cancel()
                await asyncio.gather(engine_task, return_exceptions=True)

    @staticmethod
    def _current_task_cancelling() -> bool:
        task = asyncio.current_task()
        return bool(task is not None and task.cancelling())

    async def _call_engine(self, msg: Message) -> RunOutcomeLike:
        async with asyncio.timeout(self._cfg.run_timeout_s):
            if msg.kind == "resume":
                return await self._engine.resume(msg.tenant_id, msg.alert_id, dict(msg.payload))
            return await self._engine.run(msg.tenant_id, msg.alert_id)

    async def _heartbeat(
        self, msg: Message, engine_task: asyncio.Task[RunOutcomeLike], lease_lost: asyncio.Event
    ) -> None:
        last_ok = time.monotonic()
        while True:
            await asyncio.sleep(self._heartbeat_s)
            try:
                held = await self._repos.runs.heartbeat(
                    msg.tenant_id, msg.alert_id, self.worker_id, lease_s=self._lease_s
                )
            except Exception as exc:  # noqa: BLE001 - transient DB errors; give up only once the lease has run out
                log.warning("worker.heartbeat_failed", error=type(exc).__name__)
                held = time.monotonic() - last_ok < self._lease_s
            else:
                if held:
                    last_ok = time.monotonic()
            if not held:
                lease_lost.set()
                engine_task.cancel()
                return
            try:
                await self._consumer.touch(msg)
            except Exception as exc:  # noqa: BLE001 - worst case the entry is reclaimed as a duplicate
                log.warning("worker.touch_failed", error=type(exc).__name__)

    async def _record_failure(self, msg: Message, exc: BaseException) -> None:
        outcome = "timeout" if isinstance(exc, TimeoutError) else "failed"
        error = sanitize_error(exc)
        if isinstance(exc, TimeoutError):
            error = f"TimeoutError: run exceeded {self._cfg.run_timeout_s:g}s"
        self.stats.failed += 1
        record_run(outcome)
        log.warning(
            "worker.run_failed", outcome=outcome, error=type(exc).__name__, kind=msg.kind, deliveries=msg.deliveries
        )
        try:
            await self._repos.runs.fail(msg.tenant_id, msg.alert_id, error, worker_id=self.worker_id)
        except LeaseLost:
            log.warning("worker.lease_lost_on_fail")
        except InvalidTransition as err:
            log.warning("worker.fail_not_recorded", current=err.current)

    async def _mark_dead_lettered(self, msg: Message, reason: str) -> bool:
        """Dead-letter the run and fail the alert in one transaction; returns whether the alert changed."""
        async with self._db.tenant_tx(msg.tenant_id) as conn:
            try:
                await self._repos.runs.dead_letter(msg.tenant_id, msg.alert_id, reason, conn=conn)
            except InvalidTransition as exc:
                log.warning("worker.run_dead_letter_skipped", current=exc.current)
            try:
                await self._repos.alerts.update_status(msg.tenant_id, msg.alert_id, "failed", conn=conn)
            except NotFound:
                return False
            except InvalidTransition as exc:
                log.warning("worker.alert_fail_skipped", current=exc.current)
                return False
        return True

    async def flush_usage(self) -> int:
        """Write buffered LLM usage to ``llm_usage_daily``; failures keep the buffer for the next flush."""

        async def sink(rows: List[LLMUsageRow]) -> None:
            await self._repos.llm_usage.upsert_daily([LLMUsageDelta(**row) for row in rows])

        try:
            return await get_usage_recorder().flush(sink)
        except Exception as exc:  # noqa: BLE001 - retried on the next flush
            log.warning("worker.usage_flush_failed", error=type(exc).__name__)
            return 0

    async def _flush_usage_periodically(self) -> None:
        while True:
            await asyncio.sleep(self._usage_flush_interval_s)
            await self.flush_usage()


async def run_worker(settings: Settings, *, metrics_host: str, metrics_port: int) -> None:
    """Process entry point for ``lg-sotf worker``: wire dependencies, serve health, run until signalled."""
    from lg_sotf.core.workflow import WorkflowEngine
    from lg_sotf.observability.tracing import shutdown_tracing
    from lg_sotf.queue.events import EventBus
    from lg_sotf.queue.redis import create_redis
    from lg_sotf.runtime.health import HealthServer, database_check, redis_check
    from lg_sotf.runtime.shutdown import GracefulShutdown, cancel_current_task

    worker_id = default_worker_id()
    db = Database(settings.database, application_name="lg-sotf-worker")
    redis = create_redis(settings)
    engine: Optional[EngineLike] = None
    try:
        await db.open()
        events = EventBus(redis, settings)
        engine = await WorkflowEngine.create(settings=settings, db=db, redis=redis, events=events)
        consumer = StreamConsumer(redis, settings, worker_id)
        worker = Worker(settings, db, redis, engine, consumer, events, worker_id=worker_id)
        shutdown = GracefulShutdown(worker.request_stop, on_force=cancel_current_task())
        shutdown.install()
        health = HealthServer(
            {"database": database_check(db), "redis": redis_check(redis)},
            host=metrics_host,
            port=metrics_port,
            live=worker.is_alive,
        )
        try:
            async with health:
                await worker.run()
        finally:
            shutdown.uninstall()
    finally:
        if engine is not None:
            await engine.close()
        await redis.aclose()
        await db.close()
        shutdown_tracing()
