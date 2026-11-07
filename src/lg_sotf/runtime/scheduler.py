"""Scheduler: periodic platform jobs, run only by the elected leader.

Jobs (each in its own task, never overlapping with itself):

* ``poll_sources``   due pull sources -> ``IngestionService.poll_source`` -> dispatch
* ``stale_runs``     requeue runs whose worker lease expired; fail poison runs
* ``orphaned_runs``  re-enqueue queued/failed runs left without queue work
* ``sla``            escalate (L1 -> L2 -> L3) or expire escalations past their SLA
* ``maintenance``    create partitions ahead, purge expired data
* ``metrics``        queue depth/pending and open escalation gauges
* ``notifications``  deliver the integrations outbox (Slack, Teams, email, webhooks, tickets)
* ``ticket_sync``    poll linked open tickets for external resolution
* ``outbox_purge``   delete old sent/dead outbox rows
* ``response_background`` execute scheduler-owned response actions: rollbacks, retries, late approvals,
  deferred and handed-off executions; expire old approvals (:mod:`lg_sotf.services.background`)
* ``verify_actions`` re-query executed actions to verify them (:mod:`lg_sotf.services.verification`)

The scheduler connects as the schema owner because the sweeps span tenants
(``system_tx``) and maintenance runs DDL. On a graceful stop running jobs get
``stop_grace_s`` to finish; on loss of leadership they are cancelled at once.
Each polled page is committed with its alerts' queued runs and dispatched
right after, so a cancelled poll strands nothing: whatever a cancelled job
left half done (queued runs without a message, ``new`` alerts without a
run) is recovered by ``orphaned_runs``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Sequence, Tuple

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.partitions import ensure_partitions
from lg_sotf.db.pool import Database, owner_dsn
from lg_sotf.db.repos import Escalation, Repositories, Source, WorkflowRun
from lg_sotf.db.repos.escalations import ESCALATION_LEVELS
from lg_sotf.db.retention import purge_expired
from lg_sotf.integrations.delivery import OutboxDelivery, sync_tickets
from lg_sotf.integrations.events import ESCALATION_SLA_BREACHED
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.observability.metrics import set_escalations_open, set_queue_depth, set_queue_pending
from lg_sotf.queue.consumer import queue_stats
from lg_sotf.queue.events import make_event
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.leader import LeaderLease
from lg_sotf.runtime.orphans import (
    STRANDED_NEW_AFTER_S,
    claim_orphaned_runs,
    find_stranded_new_alerts,
    oldest_undelivered_age_s,
    orphan_thresholds,
)
from lg_sotf.runtime.resumes import recover_lost_resumes
from lg_sotf.runtime.shutdown import cancel_and_wait, wait_or_stop
from lg_sotf.runtime.worker import EventPublisherLike, sanitize_error
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.background import BackgroundExecutor
from lg_sotf.services.dispatch import DispatchableAlert, dispatch_new_alerts
from lg_sotf.services.response import ResponseService
from lg_sotf.services.verification import VerificationService
from lg_sotf.settings import Settings

log = get_logger(__name__)

SWEEP_BATCH = 100
MAX_SWEEP_BATCHES = 10
METRICS_INTERVAL_S = 15.0
MIN_SLA_WINDOW = timedelta(minutes=5)
DEFAULT_SLA_WINDOW = timedelta(hours=1)
INCOMPLETE_MAINTENANCE_RETRY_S = 60.0
MAX_UNDISPATCHED = 10_000
MIN_ORPHAN_SWEEP_INTERVAL_S = 300.0
DEFAULT_STOP_GRACE_S = 10.0
ACTOR_ID = "scheduler"


class IngestResultLike(Protocol):
    @property
    def inserted(self) -> Sequence[DispatchableAlert]: ...


class IngestionLike(Protocol):
    async def poll_source(
        self, tenant_id: str, source: Source, *, on_page: Optional[Callable[[Any], Awaitable[None]]] = None
    ) -> IngestResultLike: ...

    async def close(self) -> None: ...


IngestionFactory = Callable[[], IngestionLike]


@dataclass
class _Job:
    name: str
    interval_s: float
    fn: Callable[[], Awaitable[Optional[float]]]
    """Returns an override delay until the next run, or None for the regular interval."""
    next_due: float = 0.0
    task: Optional[asyncio.Task[None]] = None
    runs: int = 0
    failures: int = 0


@dataclass(frozen=True)
class _PendingAlert:
    alert_id: str
    severity: str


class Scheduler:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        redis: Any,
        ingestion_factory: IngestionFactory,
        queue: WorkQueue,
        events: Optional[EventPublisherLike],
        *,
        lease: Optional[LeaderLease] = None,
        max_concurrent_polls: int = 8,
        stop_grace_s: float = DEFAULT_STOP_GRACE_S,
        delivery: Optional[OutboxDelivery] = None,
        responses: Optional[ResponseService] = None,
        secret_box: Optional[SecretBox] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if max_concurrent_polls < 1:
            raise ValueError("max_concurrent_polls must be >= 1")
        if stop_grace_s < 0:
            raise ValueError("stop_grace_s must be >= 0")
        self._stop_grace_s = stop_grace_s
        self._clock = clock  # job due times and liveness (tests inject a fake)
        self._wall_clock = wall_clock  # backlog age against stream ids, SLA deadlines
        self._settings = settings
        self._db = db
        self._redis = redis
        self._repos = Repositories.create(db)
        self._audit = AuditLogger(self._repos)
        self._ingestion_factory = ingestion_factory
        self._ingestion: Optional[IngestionLike] = None
        self._queue = queue
        self._events = events
        self._lease = lease or LeaderLease.from_settings(settings)
        self._max_polls = max_concurrent_polls
        self._polls: Dict[Tuple[str, str], asyncio.Task[None]] = {}
        self._undispatched: List[Tuple[str, str, str]] = []
        self._stop = asyncio.Event()
        self._loop_tick = self._clock()
        self._running = False
        self._delivery = delivery
        self._responses = responses
        self._box = secret_box  # the process's (run_scheduler); decrypts integration credentials
        self._background: Optional[BackgroundExecutor] = None
        self._verification: Optional[VerificationService] = None
        cfg = settings.scheduler
        response = settings.response
        self.jobs: Dict[str, _Job] = {
            job.name: job
            for job in (
                _Job("poll_sources", cfg.tick_s, self.poll_due_sources),
                _Job("stale_runs", cfg.stale_run_sweep_interval_s, self.sweep_stale_runs),
                _Job(
                    "orphaned_runs",
                    max(cfg.stale_run_sweep_interval_s, MIN_ORPHAN_SWEEP_INTERVAL_S),
                    self._orphaned_runs_job,
                ),
                _Job("sla", cfg.sla_sweep_interval_s, self.sweep_sla),
                _Job("maintenance", cfg.maintenance_interval_s, self.run_maintenance),
                _Job("metrics", METRICS_INTERVAL_S, self.export_metrics),
                # Not gated by integrations.enabled: rollbacks, late approvals and verification need them.
                _Job("response_background", response.background_interval_s, self.run_response_background),
                _Job("verify_actions", response.verify_interval_s, self.verify_actions),
            )
        }
        if settings.integrations.enabled:
            for job in (
                _Job("notifications", cfg.tick_s, self.deliver_notifications),
                _Job("ticket_sync", settings.integrations.ticket_sync_interval_s, self.sync_tickets),
                _Job("outbox_purge", cfg.maintenance_interval_s, self.purge_outbox),
            ):
                self.jobs[job.name] = job

    @property
    def repos(self) -> Repositories:
        return self._repos

    @property
    def is_leader(self) -> bool:
        return self._lease.is_leader

    def request_stop(self) -> None:
        self._stop.set()

    def is_alive(self) -> bool:
        if not self._running:
            return not self._stop.is_set()
        return self._clock() - self._loop_tick < self._settings.scheduler.tick_s * 3 + 30.0

    async def run(self) -> None:
        self._running = True
        log.info("scheduler.started")
        try:
            while not self._stop.is_set():
                self._loop_tick = self._clock()
                await self.tick()
                await wait_or_stop(self._stop, self._settings.scheduler.tick_s)
        finally:
            self._running = False
            await self._stand_down(grace_s=self._stop_grace_s)
            await self._lease.release()
            log.info("scheduler.stopped")

    async def tick(self) -> None:
        """One scheduling step: refresh leadership, start due jobs."""
        was_leader = self._lease.is_leader
        leader = await self._lease.refresh()
        if not leader:
            if was_leader:
                log.warning("scheduler.leadership_lost")
                await self._stand_down()
            return
        if not was_leader:
            log.info("scheduler.leadership_acquired")
            now = self._clock()
            for job in self.jobs.values():
                job.next_due = now
        now = self._clock()
        for job in self.jobs.values():
            if job.next_due <= now and (job.task is None or job.task.done()):
                job.next_due = now + job.interval_s
                job.task = asyncio.create_task(self._run_job(job), name=f"job:{job.name}")

    async def _run_job(self, job: _Job) -> None:
        started = self._clock()
        try:
            override = await job.fn()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one failing job must not stop the others
            job.failures += 1
            log.error("scheduler.job_failed", job=job.name, error=type(exc).__name__)
            return
        job.runs += 1
        if override is not None:
            job.next_due = min(job.next_due, self._clock() + override)
        log.debug("scheduler.job_done", job=job.name, seconds=round(self._clock() - started, 3))

    async def _stand_down(self, *, grace_s: float = 0.0) -> None:
        tasks = [job.task for job in self.jobs.values() if job.task is not None and not job.task.done()]
        tasks.extend(t for t in self._polls.values() if not t.done())
        if tasks and grace_s > 0:
            _done, pending = await asyncio.wait(tasks, timeout=grace_s)
            if pending:
                log.warning("scheduler.jobs_cancelled_after_grace", count=len(pending), grace_s=grace_s)
        await cancel_and_wait(tasks)
        for job in self.jobs.values():
            job.task = None
        self._polls.clear()
        if self._ingestion is not None:
            ingestion, self._ingestion = self._ingestion, None
            try:
                await ingestion.close()
            except Exception as exc:  # noqa: BLE001 - shutdown cleanup
                log.warning("scheduler.ingestion_close_failed", error=type(exc).__name__)

    async def wait_for_jobs(self) -> None:
        """Wait until every running job and source poll has finished (tests and tooling)."""
        while True:
            tasks = [j.task for j in self.jobs.values() if j.task is not None and not j.task.done()]
            tasks.extend(t for t in self._polls.values() if not t.done())
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- poll sources -------------------------------------------------------

    def _ingestion_service(self) -> IngestionLike:
        if self._ingestion is None:
            self._ingestion = self._ingestion_factory()
        return self._ingestion

    async def poll_due_sources(self) -> None:
        await self._retry_undispatched()
        free = self._max_polls - len(self._polls)
        if free <= 0:
            return
        due = await self._repos.sources.list_due_sources_all_tenants(limit=free + len(self._polls))
        for source in due:
            key = (source.tenant_id, source.id)
            if key in self._polls:
                continue
            if len(self._polls) >= self._max_polls:
                break
            task = asyncio.create_task(self._poll_one(source), name=f"poll:{source.tenant_id}:{source.id}")
            self._polls[key] = task
            task.add_done_callback(self._poll_finished(key))

    def _poll_finished(self, key: Tuple[str, str]) -> Callable[[asyncio.Task[None]], None]:
        def done(_task: asyncio.Task[None]) -> None:
            self._polls.pop(key, None)

        return done

    async def _poll_one(self, source: Source) -> None:
        with bound_context(tenant_id=source.tenant_id):
            enqueued = 0
            handed_over: set[str] = set()

            async def dispatch_page(page: Any) -> None:
                nonlocal enqueued
                inserted = [a for a in page.inserted if a.alert_id not in handed_over]
                handed_over.update(a.alert_id for a in inserted)
                if not inserted:
                    return
                try:
                    enqueued += await dispatch_new_alerts(
                        self._repos, self._queue, source.tenant_id, inserted, events=self._events
                    )
                except Exception as exc:  # noqa: BLE001 - runs are queued; enqueue is retried every tick
                    log.error("scheduler.dispatch_failed", source_id=source.id, error=type(exc).__name__)
                    self._remember_undispatched(source.tenant_id, [(a.alert_id, a.severity) for a in inserted])

            try:
                result = await self._ingestion_service().poll_source(
                    source.tenant_id, source, on_page=dispatch_page
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - isolate per-source failures
                log.warning("scheduler.poll_failed", source_id=source.id, error=type(exc).__name__)
                try:
                    await self._repos.sources.record_poll_result(
                        source.tenant_id, source.id, ok=False, error=sanitize_error(exc)
                    )
                except Exception as record_exc:  # noqa: BLE001 - the source is retried when next due
                    log.warning("scheduler.poll_result_not_recorded", error=type(record_exc).__name__)
                return
            inserted = list(result.inserted)
            if not inserted:
                return
            await dispatch_page(result)  # anything the ingestion did not hand over page by page
            log.info("scheduler.source_polled", source_id=source.id, inserted=len(inserted), enqueued=enqueued)

    def _remember_undispatched(self, tenant_id: str, alerts: Sequence[Tuple[str, str]]) -> None:
        room = MAX_UNDISPATCHED - len(self._undispatched)
        if room < len(alerts):
            log.error("scheduler.undispatched_overflow", dropped=len(alerts) - max(room, 0))
        self._undispatched.extend((tenant_id, a, s) for a, s in alerts[: max(room, 0)])

    async def _retry_undispatched(self) -> None:
        if not self._undispatched:
            return
        pending, self._undispatched = self._undispatched, []
        by_tenant: Dict[str, List[_PendingAlert]] = {}
        for tenant_id, alert_id, severity in pending:
            by_tenant.setdefault(tenant_id, []).append(_PendingAlert(alert_id, severity))
        for tenant_id, alerts in by_tenant.items():
            try:
                await dispatch_new_alerts(self._repos, self._queue, tenant_id, alerts, events=self._events)
            except Exception as exc:  # noqa: BLE001 - keep them for the next tick
                log.warning("scheduler.dispatch_retry_failed", error=type(exc).__name__)
                self._remember_undispatched(tenant_id, [(a.alert_id, a.severity) for a in alerts])

    # -- stale runs ----------------------------------------------------------

    async def sweep_stale_runs(self) -> None:
        await self._settle_orphaned_actions()
        max_attempts = self._settings.worker.max_deliveries
        for _ in range(MAX_SWEEP_BATCHES):
            sweep = await self._repos.runs.requeue_stale_all_tenants(max_attempts=max_attempts, limit=SWEEP_BATCH)
            for run in sweep.requeued:
                await self._enqueue_requeued(run)
            for run in sweep.dead_lettered:
                await self._fail_dead_lettered(run)
            if sweep.requeued or sweep.dead_lettered:
                log.info("scheduler.stale_runs", requeued=len(sweep.requeued), dead_lettered=len(sweep.dead_lettered))
            if len(sweep.requeued) + len(sweep.dead_lettered) < SWEEP_BATCH:
                return

    def responses(self) -> ResponseService:
        """The scheduler's response service (one per process: it holds the Microsoft token cache)."""
        if self._responses is None:
            self._responses = ResponseService(self._repos, self._settings, self._events, secret_box=self._box)
        return self._responses

    async def _settle_orphaned_actions(self) -> None:
        # Actions left 'executing' by a dead-lettered run would otherwise stay there forever.
        try:
            settled = await self.responses().fail_orphaned_executing()
        except Exception as exc:  # noqa: BLE001 - retried on the next sweep
            log.warning("scheduler.orphaned_actions_failed", error=type(exc).__name__)
            return
        if settled:
            log.info("scheduler.orphaned_actions", settled=settled)

    async def _enqueue_requeued(self, run: WorkflowRun) -> None:
        try:
            severity = (await self._repos.alerts.get(run.tenant_id, run.alert_id)).severity
        except NotFound:
            severity = "medium"
        try:
            await self._queue.enqueue_process(run.tenant_id, run.alert_id, severity)
        except Exception as exc:  # noqa: BLE001 - retried with the undispatched backlog
            log.error("scheduler.requeue_enqueue_failed", error=type(exc).__name__)
            self._remember_undispatched(run.tenant_id, [(run.alert_id, severity)])

    async def _fail_dead_lettered(self, run: WorkflowRun) -> None:
        with bound_context(tenant_id=run.tenant_id, alert_id=run.alert_id):
            log.error("scheduler.run_dead_lettered", attempts=run.attempt)
            try:
                await self._repos.alerts.update_status(run.tenant_id, run.alert_id, "failed")
            except (NotFound, InvalidTransition) as exc:
                log.warning("scheduler.alert_fail_skipped", error=type(exc).__name__)
                return
            await self._publish(
                run.tenant_id,
                make_event(
                    "alert.updated", run.tenant_id, run.alert_id, {"status": "failed", "reason": "dead_lettered"}
                ),
            )

    # -- orphaned runs -----------------------------------------------------------

    async def _orphaned_runs_job(self) -> None:
        await self.recover_stranded_alerts()
        await self.recover_orphaned_runs()
        await self.recover_lost_resumes()

    async def recover_stranded_alerts(self, *, older_than_s: float = STRANDED_NEW_AFTER_S) -> int:
        """Dispatch alerts left ``new`` without a run (crash or cancel between insert and dispatch)."""
        stranded = await find_stranded_new_alerts(self._db, older_than_s=older_than_s, limit=SWEEP_BATCH)
        by_tenant: Dict[str, List[_PendingAlert]] = {}
        for alert in stranded:
            by_tenant.setdefault(alert.tenant_id, []).append(_PendingAlert(alert.alert_id, alert.severity))
        recovered = 0
        for tenant_id, alerts in by_tenant.items():
            try:
                recovered += await dispatch_new_alerts(self._repos, self._queue, tenant_id, alerts, events=self._events)
            except Exception as exc:  # noqa: BLE001 - found again on the next sweep
                log.error("scheduler.stranded_dispatch_failed", error=type(exc).__name__)
        if recovered:
            log.warning("scheduler.stranded_alerts_dispatched", count=recovered)
        return recovered

    async def recover_lost_resumes(self, *, older_than_s: Optional[float] = None) -> int:
        """Re-enqueue analyst decisions and approvals whose resume message was lost (contract section 1)."""
        threshold = float(self._settings.worker.visibility_timeout_s) if older_than_s is None else older_than_s
        total = 0
        for _ in range(MAX_SWEEP_BATCHES):
            enqueued, examined = await recover_lost_resumes(
                self._db, self._repos, self._queue, older_than_s=threshold, limit=SWEEP_BATCH
            )
            total += enqueued
            if examined < SWEEP_BATCH or enqueued == 0:
                break
        return total

    async def recover_orphaned_runs(self) -> int:
        """Re-enqueue queued/failed runs that have not changed for longer than their threshold."""
        queued_s, failed_s = orphan_thresholds(self._settings)
        include_queued: Optional[float] = queued_s
        backlog_s = await oldest_undelivered_age_s(self._redis, self._queue.streams, clock=self._wall_clock)
        if backlog_s >= queued_s:
            # Queued runs may just be waiting in a deep backlog; re-enqueueing them would double it.
            include_queued = None
            log.warning("scheduler.orphan_queued_skipped", backlog_s=round(backlog_s, 1))
        recovered = 0
        for _ in range(MAX_SWEEP_BATCHES):
            orphans = await claim_orphaned_runs(
                self._db, queued_older_than_s=include_queued, failed_older_than_s=failed_s, limit=SWEEP_BATCH
            )
            for run in orphans:
                try:
                    await self._queue.enqueue_process(run.tenant_id, run.alert_id, run.severity)
                except Exception as exc:  # noqa: BLE001 - retried with the undispatched backlog
                    log.error("scheduler.orphan_enqueue_failed", error=type(exc).__name__)
                    self._remember_undispatched(run.tenant_id, [(run.alert_id, run.severity)])
            recovered += len(orphans)
            if len(orphans) < SWEEP_BATCH:
                break
        if recovered:
            # No contract metric exists for this yet; alert on this log event.
            log.warning("scheduler.orphaned_runs_requeued", count=recovered)
        return recovered

    # -- SLA -------------------------------------------------------------------

    async def sweep_sla(self) -> None:
        for _ in range(MAX_SWEEP_BATCHES):
            breached = await self._repos.escalations.find_sla_breached_all_tenants(limit=SWEEP_BATCH)
            for esc in breached:
                await self._handle_breach(esc)
            if len(breached) < SWEEP_BATCH:
                return

    @staticmethod
    def next_sla_deadline(esc: Escalation, now: datetime) -> datetime:
        """The next level gets the same response window the escalation started with."""
        window = DEFAULT_SLA_WINDOW
        if esc.sla_deadline is not None:
            window = max(esc.sla_deadline - esc.created_at, MIN_SLA_WINDOW)
        return now + window

    async def _handle_breach(self, esc: Escalation) -> None:
        now = datetime.fromtimestamp(self._wall_clock(), UTC)
        with bound_context(tenant_id=esc.tenant_id, alert_id=esc.alert_id):
            try:
                async with self._db.tenant_tx(esc.tenant_id) as conn:
                    if esc.level != ESCALATION_LEVELS[-1]:
                        updated = await self._repos.escalations.escalate_level(
                            esc.tenant_id,
                            esc.id,
                            sla_deadline=self.next_sla_deadline(esc, now),
                            expected_version=esc.version,
                            conn=conn,
                        )
                        action = "escalation.sla_escalated"
                    else:
                        updated = await self._repos.escalations.expire(
                            esc.tenant_id, esc.id, expected_version=esc.version, conn=conn
                        )
                        action = "escalation.sla_expired"
                    # The alert timeline shows the breach; an expired L3 leaves the alert waiting_human.
                    await self._repos.alert_events.append(
                        esc.tenant_id,
                        esc.alert_id,
                        action,
                        actor_type="system",
                        actor_id=ACTOR_ID,
                        data={"escalation_id": esc.id, "from_level": esc.level, "to_level": updated.level},
                        conn=conn,
                    )
                    await self._audit.record(
                        esc.tenant_id,
                        action,
                        "escalation",
                        esc.id,
                        actor_type="system",
                        actor_id=ACTOR_ID,
                        details={
                            "alert_id": esc.alert_id,
                            "from_level": esc.level,
                            "to_level": updated.level,
                            "status": updated.status,
                        },
                        conn=conn,
                    )
                    await enqueue_event(
                        conn,
                        esc.tenant_id,
                        ESCALATION_SLA_BREACHED,
                        alert_id=esc.alert_id,
                        dedupe_key=f"{ESCALATION_SLA_BREACHED}:{esc.id}:{updated.version}",
                        escalation=updated,
                        escalation_extra={"from_level": esc.level, "sla_expired": updated.status == "expired" or None},
                    )
            except (Conflict, NotFound) as exc:
                # An analyst claimed or decided it meanwhile (version moved on); nothing to do.
                log.info("scheduler.sla_skipped", escalation_id=esc.id, error=type(exc).__name__)
                return
            log.info("scheduler.sla_breach_handled", escalation_id=esc.id, action=action, escalation_level=updated.level)
            await self._publish(
                esc.tenant_id,
                make_event(
                    "escalation.updated",
                    esc.tenant_id,
                    esc.alert_id,
                    {"escalation_id": esc.id, "status": updated.status, "level": updated.level, "reason": "sla_breach"},
                ),
            )

    # -- maintenance -----------------------------------------------------------

    async def run_maintenance(self) -> Optional[float]:
        async with self._db.system_tx() as conn:
            created = await ensure_partitions(conn)
        report = await purge_expired(self._db, self._settings.retention)
        log.info("scheduler.maintenance", partitions_created=len(created), **report.as_dict())
        if not report.complete:
            return min(INCOMPLETE_MAINTENANCE_RETRY_S, self._settings.scheduler.maintenance_interval_s)
        return None

    # -- integrations ----------------------------------------------------------

    def delivery(self) -> OutboxDelivery:
        if self._delivery is None:
            self._delivery = OutboxDelivery(self._repos, self._settings, secret_box=self._box)
        return self._delivery

    async def deliver_notifications(self) -> None:
        """Drain due outbox rows, a bounded number of batches per run (see lg_sotf.integrations.delivery)."""
        batch = self._settings.integrations.batch_size
        for _ in range(MAX_SWEEP_BATCHES):
            if await self.delivery().run_once() < batch:
                return

    async def sync_tickets(self) -> None:
        polled = await sync_tickets(self._repos, self._settings, self.delivery().tickets, self._events)
        if polled:
            log.info("scheduler.tickets_synced", polled=polled)

    async def purge_outbox(self) -> None:
        purged = await self.delivery().purge()
        if purged:
            log.info("scheduler.outbox_purged", deleted=purged)

    # -- response actions -------------------------------------------------------

    async def run_response_background(self) -> None:
        """Execute due scheduler-owned actions (see :mod:`lg_sotf.services.background`)."""
        if self._background is None:
            self._background = BackgroundExecutor(self.responses())
        ran = await self._background.run_once()
        if ran:
            log.info("scheduler.response_background", actions=ran)

    async def verify_actions(self) -> None:
        """Run due verification checks (see :mod:`lg_sotf.services.verification`)."""
        if self._verification is None:
            self._verification = VerificationService(self.responses())
        checked = await self._verification.run_due()
        if checked:
            log.info("scheduler.actions_verified", checked=checked)

    # -- metrics ---------------------------------------------------------------

    async def export_metrics(self) -> None:
        for stats in await queue_stats(self._redis, self._queue.streams):
            set_queue_depth(stats.label, stats.depth)
            set_queue_pending(stats.label, stats.pending)
        set_escalations_open(await self._repos.escalations.count_active_all_tenants())

    async def _publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        if self._events is None:
            return
        try:
            await self._events.publish(tenant_id, event)
        except Exception as exc:  # noqa: BLE001 - events are best-effort notifications
            log.warning("scheduler.event_publish_failed", error=type(exc).__name__)


async def run_scheduler(settings: Settings, *, metrics_host: str, metrics_port: int) -> None:
    """Process entry point for ``lg-sotf scheduler``."""
    from lg_sotf.queue.events import EventBus
    from lg_sotf.queue.redis import create_redis
    from lg_sotf.runtime.health import HealthServer, database_check, redis_check
    from lg_sotf.runtime.shutdown import GracefulShutdown, cancel_current_task
    from lg_sotf.security.crypto import load_secret_box

    # Invalid encryption keys stop the scheduler here, as they stop the API (ADR-0006).
    box = load_secret_box(settings)
    db = Database(settings.database, dsn=owner_dsn(settings), application_name="lg-sotf-scheduler")
    redis = create_redis(settings)
    try:
        await db.open()
        events = EventBus(redis, settings)
        queue = WorkQueue(redis, settings)

        def ingestion_factory() -> IngestionLike:
            from lg_sotf.ingestion.service import IngestionService
            from lg_sotf.llm import TokenBudget

            # LLM normalization fallback during polls is charged to the tenant's daily budget.
            budget = TokenBudget(redis, settings, usage_seed=Repositories.create(db).llm_usage.day_tokens)
            service: IngestionLike = IngestionService(db, settings, secret_box=box, budget=budget)
            return service

        scheduler = Scheduler(settings, db, redis, ingestion_factory, queue, events, secret_box=box)
        shutdown = GracefulShutdown(scheduler.request_stop, on_force=cancel_current_task())
        shutdown.install()
        health = HealthServer(
            {"database": database_check(db), "redis": redis_check(redis)},
            host=metrics_host,
            port=metrics_port,
            live=scheduler.is_alive,
        )
        try:
            async with health:
                await scheduler.run()
        finally:
            shutdown.uninstall()
    finally:
        await redis.aclose()
        await db.close()
