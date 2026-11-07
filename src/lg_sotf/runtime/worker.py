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
   lease cancels the run. Cancellation can be swallowed on Python 3.11
   (``asyncio.wait_for`` inside redis-py), so the heartbeat stops on an
   event rather than on ``cancel()``, every cancel is repeated until the task
   is done (:func:`~lg_sotf.runtime.shutdown.cancel_and_wait`), and the run
   timeout is also enforced from outside the engine task.
4. The outcome is written to ``workflow_runs`` and only then is the message
   acked. On failure the run is marked ``failed`` and the message stays
   pending for a retry. A resume payload the engine rejects
   (:class:`InvalidResumePayload`) is permanent: the run goes back to the
   state it was claimed from and only the message is dead-lettered.
5. Messages of a suspended tenant are acked without claiming the run: a
   queued run stays ``queued`` and a waiting run keeps waiting (its decision
   is stored on the escalation). The recovery sweeps skip suspended tenants
   and pick the runs up again once the tenant is reactivated. Tenant status
   is cached for :data:`TENANT_STATUS_TTL_S`.

A ``process`` run that finishes its automated triage (completed or waiting
for a human) is counted in ``usage_daily.alerts_processed`` in the same
transaction as its final status.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Protocol, Set, Tuple, Type

from lg_sotf.db.errors import InvalidTransition, LeaseLost, NotFound, RunNotClaimable
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, Repositories, WorkflowRun
from lg_sotf.db.repos.runs import WAITING_RUN_STATUSES
from lg_sotf.errors import InvalidResumePayload
from lg_sotf.llm.usage import LLMUsageRow, get_usage_recorder
from lg_sotf.observability.logging import bound_context, get_logger, log_failure
from lg_sotf.observability.metrics import record_run
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.events import make_event
from lg_sotf.queue.streams import Message
from lg_sotf.runtime.shutdown import cancel_and_wait, wait_or_stop
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
# Extra time the outer watchdog gives the engine's own run timeout before cancelling it.
RUN_TIMEOUT_GRACE_S = 5.0
# How long another tenant counts as "active" after its last run or deferral in this worker.
TENANT_ACTIVITY_WINDOW_S = 30.0
# How long a tenant's active/suspended status is trusted before it is read again.
TENANT_STATUS_TTL_S = 15.0
# A resume that arrives while its run is not (yet) waiting is retried after this backoff
# (doubling per attempt) instead of idling until worker.visibility_timeout_s.
RESUME_RETRY_BASE_S = 1.0
RESUME_RETRY_MAX_S = 30.0
RETRYABLE_RESUME_REASONS = frozenset({"not_waiting", "leased"})
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
        clock: Callable[[], float] = time.monotonic,
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
        self._clock = clock  # liveness, tenant activity windows, lease bookkeeping (tests inject a fake)
        if stall_limit_s is None:
            longest_wait_s = max(settings.worker.block_ms / 1000.0 + settings.redis.socket_timeout_s, liveness_tick_s)
            stall_limit_s = longest_wait_s + LIVENESS_GRACE_S
        self._stall_limit_s = stall_limit_s
        self._stop = asyncio.Event()
        self._inflight: Set[asyncio.Task[None]] = set()
        self._tenant_running: Dict[str, int] = {}
        self._tenant_seen: Dict[str, float] = {}
        self._tenant_status: Dict[str, Tuple[float, bool]] = {}
        self._retries: Set[asyncio.Task[None]] = set()
        self._loop_tick = self._clock()
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
        return self._clock() - self._loop_tick < self._stall_limit_s

    async def run(self) -> None:
        """Consume until :meth:`request_stop`, then drain and return.

        While running, the consumer's liveness key is refreshed every
        heartbeat and expires ``lease_s`` after the process dies; other
        workers then claim the entries it held, so a crash is recovered
        within about one lease rather than ``worker.visibility_timeout_s``.
        """
        await self._consumer.ensure_groups()
        await self._consumer.announce_alive(self._lease_s)
        await self._consumer.requeue_own_pending()
        liveness = asyncio.create_task(self._announce_liveness(), name="consumer-liveness")
        flusher = asyncio.create_task(self._flush_usage_periodically(), name="usage-flush")
        self._running = True
        log.info("worker.started", worker_id=self.worker_id, concurrency=self._cfg.concurrency)
        try:
            await self._consume()
        finally:
            self._running = False
            await self._drain()
            # Re-cancelled until done: a cancel can be swallowed inside a Redis command (cancel_and_wait).
            await cancel_and_wait([flusher, liveness])
            # Scheduled resume retries: their entries stay pending and are recovered like any other.
            await cancel_and_wait(list(self._retries))
            await self.flush_usage()
            try:
                await self._consumer.remove_if_idle()
                await self._consumer.withdraw()
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup on shutdown
                log_failure(log, "worker.consumer_cleanup_failed", exc, level="warning")
            log.info("worker.stopped", worker_id=self.worker_id)

    async def _announce_liveness(self) -> None:
        while True:
            await asyncio.sleep(self._heartbeat_s)
            try:
                await self._consumer.announce_alive(self._lease_s)
            except Exception as exc:  # noqa: BLE001 - a lapse only lets others claim entries; the run lease guards
                log_failure(log, "worker.liveness_announce_failed", exc, level="warning")

    async def _consume(self) -> None:
        errors = 0
        while not self._stop.is_set():
            self._loop_tick = self._clock()
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
                log_failure(log, "worker.read_failed", exc, level="warning", retry_in_s=delay)
                await self._sleep_unless_stopped(delay)
                continue
            errors = 0
            self._loop_tick = self._clock()
            deferred = 0
            now = self._clock()
            for msg in messages:
                # Every tenant in this batch competes for the slots, whatever its position.
                self._tenant_seen[msg.tenant_id] = now
            for msg in messages:
                if not self._try_reserve_tenant(msg.tenant_id):
                    await self._defer(msg)
                    deferred += 1
                    continue
                task = asyncio.create_task(self._run_message(msg), name=f"run:{msg.entry_id}")
                self._inflight.add(task)
                task.add_done_callback(self._inflight.discard)
            if messages and deferred == len(messages):
                # Every message belonged to a tenant at its cap: wait until a run finishes
                # (a slot for that tenant may open) instead of spinning requeue loops.
                if self._inflight:
                    await self._wait_for_free_slot(timeout_s=max(_DEFER_BACKOFF_S, self._liveness_tick_s))
                else:
                    await self._sleep_unless_stopped(_DEFER_BACKOFF_S)

    async def _wait_for_free_slot(self, timeout_s: Optional[float] = None) -> None:
        """Wait until a run finishes or a stop is requested (or ``timeout_s``), ticking liveness meanwhile."""
        stop_waiter = asyncio.create_task(self._stop.wait())
        deadline = None if timeout_s is None else self._clock() + timeout_s
        try:
            while not self._stop.is_set() and (deadline is None or self._clock() < deadline):
                done, _ = await asyncio.wait(
                    set(self._inflight) | {stop_waiter},
                    timeout=self._liveness_tick_s,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                self._loop_tick = self._clock()
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

    def _other_tenants_active(self, tenant_id: str) -> bool:
        now = self._clock()
        if any(t != tenant_id and n > 0 for t, n in self._tenant_running.items()):
            return True
        return any(t != tenant_id and now - seen < TENANT_ACTIVITY_WINDOW_S for t, seen in self._tenant_seen.items())

    def _try_reserve_tenant(self, tenant_id: str) -> bool:
        """Claim a slot for ``tenant_id``; the per-tenant cap applies only while other tenants compete.

        ``worker.per_tenant_concurrency`` is a noisy-neighbour limit: a tenant
        alone on this worker (a single-organisation install, or a quiet
        period) may use every slot.
        """
        now = self._clock()
        self._tenant_seen[tenant_id] = now
        if len(self._tenant_seen) > 10_000:
            self._tenant_seen = {t: s for t, s in self._tenant_seen.items() if now - s < TENANT_ACTIVITY_WINDOW_S}
        running = self._tenant_running.get(tenant_id, 0)
        if running >= self._cfg.per_tenant_concurrency and self._other_tenants_active(tenant_id):
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
            log_failure(log, "worker.defer_failed", exc, level="warning")
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
            await cancel_and_wait(pending)

    async def _run_message(self, msg: Message) -> None:
        try:
            with bound_context(tenant_id=msg.tenant_id, alert_id=msg.alert_id):
                await self.process(msg)
        except asyncio.CancelledError:
            log.warning("worker.run_cancelled", entry_id=msg.entry_id)
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected bookkeeping failure; the entry is retried
            log_failure(log, "worker.message_failed", exc, entry_id=msg.entry_id)
        finally:
            self._release_tenant(msg.tenant_id)

    async def _tenant_active(self, tenant_id: str) -> bool:
        """Whether the tenant may run work (cached); unknown tenants and lookup errors count as active."""
        now = self._clock()
        hit = self._tenant_status.get(tenant_id)
        if hit is not None and hit[0] > now:
            return hit[1]
        try:
            active = (await self._repos.tenants.get(tenant_id)).is_active
        except NotFound:
            active = True  # runs.start finds no run and handles the message
        except Exception as exc:  # noqa: BLE001 - runs.start surfaces a real database outage
            log_failure(log, "worker.tenant_status_unavailable", exc, level="warning")
            return True
        if len(self._tenant_status) > 10_000:
            self._tenant_status.clear()
        self._tenant_status[tenant_id] = (now + TENANT_STATUS_TTL_S, active)
        return active

    async def process(self, msg: Message) -> None:
        """Handle one message end to end (public for tests and tooling)."""
        if not await self._tenant_active(msg.tenant_id):
            # The run is left as it is; the sweeps re-enqueue it once the tenant is reactivated.
            await self._consumer.ack(msg)
            self.stats.skipped += 1
            record_run("skipped")
            log.info("worker.tenant_suspended_skipped", kind=msg.kind)
            return
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
        started = self._clock()
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
        # A fresh triage pass (not a resume, not a run claimed back from waiting) is metered once.
        metered = msg.kind == "process" and claimed.claimed_from not in WAITING_RUN_STATUSES
        try:
            async with self._db.tenant_tx(msg.tenant_id) as conn:
                if outcome.status == "completed":
                    await self._repos.runs.complete(msg.tenant_id, msg.alert_id, worker_id=self.worker_id, conn=conn)
                else:
                    await self._repos.runs.mark_waiting(
                        msg.tenant_id, msg.alert_id, outcome.status, worker_id=self.worker_id, conn=conn
                    )
                if metered:
                    await self._repos.usage.add_processed(msg.tenant_id, msg.alert_id, conn=conn)
            if outcome.status == "completed":
                self.stats.completed += 1
            else:
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
            seconds=round(self._clock() - started, 3),
        )

    async def _handle_unclaimable(self, msg: Message, exc: RunNotClaimable) -> None:
        if exc.reason in TERMINAL_REASONS:
            await self._consumer.ack(msg)
            self.stats.skipped += 1
            record_run("skipped")
            log.info("worker.run_skipped", reason=exc.reason, kind=msg.kind)
            return
        if msg.attempts <= self._cfg.max_deliveries:
            log.info("worker.run_not_claimable", reason=exc.reason, kind=msg.kind, deliveries=msg.attempts)
            if msg.kind == "resume" and exc.reason in RETRYABLE_RESUME_REASONS:
                self._schedule_resume_retry(msg)
            return
        if exc.reason == "leased" and msg.kind == "resume":
            # A long run is still executing; the decision must not be dropped as a duplicate.
            # The entry stays pending and is redelivered after the visibility timeout.
            log.info("worker.resume_waits_for_run", deliveries=msg.attempts)
            return
        if exc.reason == "leased":
            # Another worker executes the run under a live lease; this entry is a duplicate.
            await self._consumer.ack(msg)
            self.stats.skipped += 1
            record_run("skipped")
            log.info("worker.stale_duplicate_dropped", deliveries=msg.attempts, kind=msg.kind)
            return
        # A resume for a run that never became waiting: the payload cannot apply; the run is left alone.
        await self._dead_letter_message(
            msg, f"exceeded {self._cfg.max_deliveries} deliveries; run not claimable ({exc.reason})"
        )

    def _schedule_resume_retry(self, msg: Message) -> None:
        """Retry a resume whose run is not waiting yet (still running, or requeued after a crash)
        after a short backoff: an analyst's decision should apply within seconds, not after
        ``worker.visibility_timeout_s``. The entry stays pending meanwhile, so a crash loses nothing."""
        delay = min(RESUME_RETRY_BASE_S * (2 ** max(msg.attempts - 1, 0)), RESUME_RETRY_MAX_S)

        async def retry() -> None:
            if await wait_or_stop(self._stop, delay):
                return
            try:
                await self._consumer.requeue(msg, count_attempt=True)
            except Exception as exc:  # noqa: BLE001 - the pending entry is reclaimed after the visibility timeout
                log_failure(log, "worker.resume_retry_failed", exc, level="warning")

        task = asyncio.create_task(retry(), name=f"resume-retry:{msg.entry_id}")
        self._retries.add(task)
        task.add_done_callback(self._retries.discard)

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
            log_failure(log, "worker.restore_waiting_skipped", exc, level="warning")
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
                log_failure(log, "worker.fail_not_recorded", err, level="warning")
        await self._consumer.dead_letter(msg, f"rejected: {error}")
        self.stats.dead_lettered += 1
        record_run("rejected")
        log_failure(log, "worker.message_rejected", exc, level="warning", kind=msg.kind, run_status=restore or "failed")

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
                log_failure(log, "worker.event_publish_failed", exc, level="warning")
        await self._consumer.dead_letter(msg, reason)
        self.stats.dead_lettered += 1
        record_run("dead_lettered")
        log.error("worker.dead_lettered", deliveries=msg.deliveries, attempt=claimed.attempt, kind=msg.kind)

    async def _execute_with_lease(self, msg: Message) -> RunOutcomeLike:
        engine_task: asyncio.Task[RunOutcomeLike] = asyncio.create_task(self._call_engine(msg))
        lease_lost = asyncio.Event()
        stop_heartbeat = asyncio.Event()
        heartbeat = asyncio.create_task(self._heartbeat(msg, engine_task, lease_lost, stop_heartbeat))
        try:
            # Watchdog: the engine's own asyncio.timeout relies on a cancel that can be swallowed.
            done, _ = await asyncio.wait({engine_task}, timeout=self._cfg.run_timeout_s + RUN_TIMEOUT_GRACE_S)
            if not done:
                await cancel_and_wait([engine_task])
                raise TimeoutError(f"run exceeded {self._cfg.run_timeout_s:g}s")
            if lease_lost.is_set():
                raise _LeaseLostError()
            return engine_task.result()
        except asyncio.CancelledError:
            if lease_lost.is_set() and not self._current_task_cancelling():
                raise _LeaseLostError() from None
            raise
        finally:
            stop_heartbeat.set()
            await cancel_and_wait([heartbeat])
            if not engine_task.done():
                await cancel_and_wait([engine_task])

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
        self,
        msg: Message,
        engine_task: asyncio.Task[RunOutcomeLike],
        lease_lost: asyncio.Event,
        stop: asyncio.Event,
    ) -> None:
        """Extend the lease until ``stop`` is set or the run ends.

        The loop checks ``stop`` and the engine task after every await, so it
        ends even when a ``cancel()`` was swallowed inside a Redis command.
        """
        last_ok = self._clock()
        while not stop.is_set() and not engine_task.done():
            if await wait_or_stop(stop, self._heartbeat_s) or engine_task.done():
                return
            try:
                held = await self._repos.runs.heartbeat(
                    msg.tenant_id, msg.alert_id, self.worker_id, lease_s=self._lease_s
                )
            except Exception as exc:  # noqa: BLE001 - transient DB errors; give up only once the lease has run out
                log_failure(log, "worker.heartbeat_failed", exc, level="warning")
                held = self._clock() - last_ok < self._lease_s
            else:
                if held:
                    last_ok = self._clock()
            if stop.is_set():
                return
            if not held:
                lease_lost.set()
                await cancel_and_wait([engine_task])
                return
            try:
                await self._consumer.touch(msg)
            except Exception as exc:  # noqa: BLE001 - worst case the entry is reclaimed as a duplicate
                log_failure(log, "worker.touch_failed", exc, level="warning")

    async def _record_failure(self, msg: Message, exc: BaseException) -> None:
        outcome = "timeout" if isinstance(exc, TimeoutError) else "failed"
        error = sanitize_error(exc)
        if isinstance(exc, TimeoutError):
            error = f"TimeoutError: run exceeded {self._cfg.run_timeout_s:g}s"
        self.stats.failed += 1
        record_run(outcome)
        log_failure(
            log, "worker.run_failed", exc, level="warning", outcome=outcome, kind=msg.kind, deliveries=msg.deliveries
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
            log_failure(log, "worker.usage_flush_failed", exc, level="warning")
            return 0

    async def _flush_usage_periodically(self) -> None:
        while True:
            await asyncio.sleep(self._usage_flush_interval_s)
            await self.flush_usage()


MAX_DERIVED_POOL = 50


def worker_pool_size(settings: Settings) -> int:
    """asyncpg pool size of a worker: ``database.pool_max``, raised to half of
    ``worker.concurrency`` (capped) so a worker tuned for more runs in flight does not
    queue them on a pool sized for the default. See docs/deployment.md for the
    resulting ``max_connections`` budget."""
    return max(settings.database.pool_max, min(settings.worker.concurrency // 2, MAX_DERIVED_POOL))


async def run_worker(settings: Settings, *, metrics_host: str, metrics_port: int) -> None:
    """Process entry point for ``lg-sotf worker``: wire dependencies, serve health, run until signalled."""
    from lg_sotf.core.workflow import WorkflowEngine
    from lg_sotf.observability.tracing import shutdown_tracing
    from lg_sotf.queue.events import EventBus
    from lg_sotf.queue.redis import create_redis
    from lg_sotf.runtime.health import HealthServer, database_check, redis_check
    from lg_sotf.runtime.shutdown import GracefulShutdown, cancel_current_task
    from lg_sotf.security.crypto import load_secret_box

    # Invalid encryption keys stop the worker here, as they stop the API (ADR-0006).
    box = load_secret_box(settings)
    worker_id = default_worker_id()
    db = Database(settings.database, application_name="lg-sotf-worker", max_size=worker_pool_size(settings))
    redis = create_redis(settings)
    engine: Optional[EngineLike] = None
    try:
        await db.open()
        events = EventBus(redis, settings)
        engine = await WorkflowEngine.create(settings=settings, db=db, redis=redis, events=events, secret_box=box)
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
