"""Workflow runs: one row per alert, claimed by workers with an expiring lease."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, FrozenSet, List, Literal, Optional, Sequence, Tuple

from lg_sotf.db.errors import InvalidTransition, LeaseLost, NotFound, RunNotClaimable
from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    fetch_one,
    require_aware,
    retries_stale_statement,
    to_model,
    to_models,
    truncate,
)
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.models.vocabulary import RUN_STATUSES as RUN_STATUSES
from lg_sotf.models.vocabulary import TERMINAL_RUN_STATUSES, WAITING_RUN_STATUSES

MAX_ERROR_CHARS = 4_000
# Most queued runs list_queued returns at once (a reactivation requeues at most this many).
MAX_QUEUED_LISTED = 10_000

ClaimKind = Literal["process", "resume"]
# ``running`` is claimable only once its lease has expired (the holder died).
CLAIMABLE_FROM: Dict[str, FrozenSet[str]] = {
    "process": frozenset({"queued", "failed", "running"}),
    "resume": frozenset({"waiting_human", "waiting_approval", "failed", "running"}),
}


class WorkflowRun(Record):
    tenant_id: str
    alert_id: str
    thread_id: str
    status: str
    attempt: int
    """Claims in the current phase; a resume from ``waiting_*`` starts a new phase at 1."""
    worker_id: Optional[str]
    lease_expires_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]
    """Set when the run reaches ``completed`` or ``dead_lettered``."""
    graph_version: Optional[int] = None
    """The graph its checkpointed thread started on; None: no thread yet, or one older than graph versions (1)."""
    claimed_from: Optional[str] = None
    """Only on :meth:`RunsRepo.start` results: the status the claim replaced (None if it created the run)."""


class StaleRunSweep(Record):
    requeued: List[WorkflowRun]
    """Back to ``queued``; the sweeper enqueues a ``process`` message for each."""
    dead_lettered: List[WorkflowRun]
    """Leases expired ``max_attempts`` times (poison alerts); not to be enqueued again."""


class OrphanedRunRef(Record):
    """A queued or failed run with no queue message (:meth:`RunsRepo.claim_orphaned_all_tenants`)."""

    tenant_id: str
    alert_id: str
    status: str
    attempt: int
    severity: str


class StrandedRunRef(Record):
    """A waiting run whose resume should already have happened (:meth:`RunsRepo.find_stranded_waiting_all_tenants`)."""

    tenant_id: str
    alert_id: str
    status: str


_CLAIM_ORPHANS_SQL = """
WITH picked AS (
    SELECT tenant_id, alert_id FROM workflow_runs
    WHERE (($1::float8 IS NOT NULL AND status = 'queued' AND updated_at < now() - make_interval(secs => $1))
           OR (status = 'failed' AND updated_at < now() - make_interval(secs => $2)))
      AND tenant_id IN (SELECT id FROM tenants WHERE status = 'active')
    ORDER BY updated_at
    LIMIT $3
    FOR UPDATE SKIP LOCKED
)
UPDATE workflow_runs r SET updated_at = now()
FROM picked p, alerts a
WHERE r.tenant_id = p.tenant_id AND r.alert_id = p.alert_id
  AND a.tenant_id = r.tenant_id AND a.id = r.alert_id
RETURNING r.tenant_id, r.alert_id, r.status, r.attempt, a.severity
"""
_STRANDED_WAITING_SQL = """
SELECT r.tenant_id, r.alert_id, r.status
FROM workflow_runs r
WHERE r.updated_at < now() - make_interval(secs => $1)
  AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id AND t.status = 'active')
  AND (
    (r.status = 'waiting_human' AND EXISTS (
        SELECT 1 FROM escalations e
        WHERE e.tenant_id = r.tenant_id AND e.status = 'decided'
          AND e.decided_at < now() - make_interval(secs => $1)
          AND (e.alert_id = r.alert_id OR r.alert_id = ANY(e.related_alert_ids))
          AND NOT EXISTS (
              SELECT 1 FROM escalations o
              WHERE o.tenant_id = r.tenant_id AND o.status IN ('open', 'claimed', 'expired')
                AND (o.alert_id = r.alert_id OR r.alert_id = ANY(o.related_alert_ids))
          )
    ))
    OR (r.status = 'waiting_approval' AND (
        EXISTS (SELECT 1 FROM response_actions a
                WHERE a.tenant_id = r.tenant_id AND a.alert_id = r.alert_id AND a.status = 'approved'
                  AND a.execution_owner = 'workflow'
                  AND COALESCE(a.approved_at, a.updated_at) < now() - make_interval(secs => $1))
        OR NOT EXISTS (SELECT 1 FROM response_actions a
                       WHERE a.tenant_id = r.tenant_id AND a.alert_id = r.alert_id
                         AND a.status = 'awaiting_approval' AND a.execution_owner = 'workflow')
    ))
  )
ORDER BY r.updated_at
LIMIT $2
"""


class RunsRepo(Repository):
    async def upsert_queued(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        requeue_terminal: bool = False,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        """Ensure a run row exists before enqueueing work for an alert.

        An existing run is left untouched, except that ``requeue_terminal``
        (reprocess) resets a completed, failed or dead-lettered run to
        ``queued`` with a fresh attempt counter.
        """
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO workflow_runs (tenant_id, alert_id, thread_id, status)
                VALUES ($1, $2, $3, 'queued')
                ON CONFLICT (tenant_id, alert_id) DO UPDATE SET
                    status = 'queued', attempt = 0, worker_id = NULL, lease_expires_at = NULL,
                    last_error = NULL, completed_at = NULL
                WHERE $4 AND workflow_runs.status IN ('completed', 'failed', 'dead_lettered')
                RETURNING *
                """,
                tenant_id,
                alert_id,
                thread_id_for(tenant_id, alert_id),
                requeue_terminal,
            )
            if row is None:
                row = await fetch_one(
                    c,
                    "SELECT * FROM workflow_runs WHERE tenant_id = $1 AND alert_id = $2", tenant_id, alert_id
                )
        return WorkflowRun.model_validate(dict(row))

    async def queue_alerts(
        self, tenant_id: str, alert_ids: Sequence[str], *, conn: Optional[Connection] = None
    ) -> List[str]:
        """Batch form of :meth:`upsert_queued` plus the alert's ``new -> queued`` step.

        Creates missing runs as ``queued``, moves those alerts that are
        ``new`` (or ``failed``/``closed``, as a dispatch may) to ``queued``, and
        returns the ids whose run is ``queued`` (the ones to enqueue): three
        statements for the whole batch instead of two round trips per alert.
        """
        ids = list(dict.fromkeys(a for a in alert_ids if a))
        if not ids:
            return []
        threads = [thread_id_for(tenant_id, a) for a in ids]
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                """
                INSERT INTO workflow_runs (tenant_id, alert_id, thread_id, status)
                SELECT $1, a, t, 'queued' FROM unnest($2::text[], $3::text[]) AS x(a, t)
                ON CONFLICT (tenant_id, alert_id) DO NOTHING
                """,
                tenant_id,
                ids,
                threads,
            )
            rows = await c.fetch(
                "SELECT alert_id FROM workflow_runs WHERE tenant_id = $1 AND alert_id = ANY($2::text[]) AND status = 'queued'",
                tenant_id,
                ids,
            )
            queued = [r["alert_id"] for r in rows]
            if queued:
                await c.execute(
                    """
                    UPDATE alerts SET status = 'queued', closed_at = NULL
                    WHERE tenant_id = $1 AND id = ANY($2::text[]) AND status IN ('new', 'failed', 'closed')
                    """,
                    tenant_id,
                    queued,
                )
        order = {a: i for i, a in enumerate(ids)}
        return sorted(queued, key=order.__getitem__)

    async def list_queued(
        self, tenant_id: str, *, limit: int = 1_000, conn: Optional[Connection] = None
    ) -> List[Tuple[str, str]]:
        """``(alert_id, severity)`` of the tenant's queued runs, oldest first (re-enqueue after a reactivation)."""
        check_limit(limit, MAX_QUEUED_LISTED)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT r.alert_id, a.severity FROM workflow_runs r
                JOIN alerts a ON a.tenant_id = r.tenant_id AND a.id = r.alert_id
                WHERE r.tenant_id = $1 AND r.status = 'queued'
                ORDER BY r.updated_at
                LIMIT $2
                """,
                tenant_id,
                limit,
            )
        return [(r["alert_id"], r["severity"]) for r in rows]

    @retries_stale_statement
    async def start(
        self,
        tenant_id: str,
        alert_id: str,
        worker_id: str,
        *,
        lease_s: float,
        kind: ClaimKind = "process",
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        """Claim the run for one execution by ``worker_id``.

        ``kind="process"`` claims a queued or failed run, or a running run
        whose lease expired, and creates the run if it does not exist.
        ``kind="resume"`` claims a run waiting for an analyst or approval
        (or, when retrying a resume, a failed or lease-expired run). A live
        lease is never re-claimed, not even by the same ``worker_id``, so one
        run never executes twice concurrently. The result's ``claimed_from``
        is the status that was replaced. Raises :class:`RunNotClaimable`
        (see its ``reason``) or :class:`NotFound` for a missing run on resume.
        """
        if lease_s <= 0:
            raise ValueError("lease_s must be positive")
        check_choice(kind, tuple(CLAIMABLE_FROM), "claim kind")
        require_aware(now, "now")
        run_key = f"{tenant_id}:{alert_id}"
        async with self._tenant(tenant_id, conn) as c:
            for _ in range(2):
                current = await c.fetchrow(
                    """
                    SELECT *, (status = 'running' AND lease_expires_at > COALESCE($3::timestamptz, now())) AS live
                    FROM workflow_runs WHERE tenant_id = $1 AND alert_id = $2
                    FOR UPDATE
                    """,
                    tenant_id,
                    alert_id,
                    now,
                )
                if current is not None:
                    break
                if kind == "resume":
                    raise NotFound("workflow run", run_key)
                created = await c.fetchrow(
                    """
                    INSERT INTO workflow_runs (tenant_id, alert_id, thread_id, status, attempt, worker_id,
                                               lease_expires_at)
                    VALUES ($1, $2, $3, 'running', 1, $4, COALESCE($5::timestamptz, now()) + make_interval(secs => $6))
                    ON CONFLICT (tenant_id, alert_id) DO NOTHING
                    RETURNING *
                    """,
                    tenant_id,
                    alert_id,
                    thread_id_for(tenant_id, alert_id),
                    worker_id,
                    now,
                    float(lease_s),
                )
                if created is not None:
                    return WorkflowRun.model_validate(dict(created))
            if current is None:
                raise NotFound("workflow run", run_key)
            previous = current["status"]
            reason = self._refusal(kind, previous, current["live"])
            if reason is not None:
                raise RunNotClaimable(tenant_id, alert_id, reason, WorkflowRun.model_validate(dict(current)))
            row = await fetch_one(
                c,
                """
                UPDATE workflow_runs SET
                    status = 'running',
                    attempt = CASE WHEN status IN ('waiting_human', 'waiting_approval') THEN 1 ELSE attempt + 1 END,
                    worker_id = $3,
                    lease_expires_at = COALESCE($4::timestamptz, now()) + make_interval(secs => $5)
                WHERE tenant_id = $1 AND alert_id = $2
                RETURNING *
                """,
                tenant_id, alert_id, worker_id, now, float(lease_s),
            )
        return WorkflowRun.model_validate({**dict(row), "claimed_from": previous})

    @staticmethod
    def _refusal(kind: str, status: str, lease_live: bool) -> Optional[str]:
        if status in TERMINAL_RUN_STATUSES:
            return status
        if status == "running" and lease_live:
            return "leased"
        if status in CLAIMABLE_FROM[kind]:
            return None
        return "waiting" if status in WAITING_RUN_STATUSES else "not_waiting"

    @retries_stale_statement
    async def heartbeat(
        self,
        tenant_id: str,
        alert_id: str,
        worker_id: str,
        *,
        lease_s: float,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Extend the lease; False means the worker lost it and must stop."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE workflow_runs
                SET lease_expires_at = COALESCE($4::timestamptz, now()) + make_interval(secs => $5)
                WHERE tenant_id = $1 AND alert_id = $2 AND status = 'running' AND worker_id = $3
                """,
                tenant_id,
                alert_id,
                worker_id,
                now,
                float(lease_s),
            )
        return status.endswith(" 1")

    async def mark_waiting(
        self,
        tenant_id: str,
        alert_id: str,
        status: str,
        *,
        worker_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        """Record that the graph is interrupted awaiting an analyst or an approval."""
        check_choice(status, WAITING_RUN_STATUSES, "waiting status")
        return await self._finish(tenant_id, alert_id, status, ("running",), worker_id, conn=conn)

    async def complete(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        worker_id: Optional[str] = None,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        require_aware(now, "now")
        return await self._finish(
            tenant_id,
            alert_id,
            "completed",
            ("running",),
            worker_id,
            finished_at=now,
            finished=True,
            conn=conn,
        )

    async def fail(
        self,
        tenant_id: str,
        alert_id: str,
        error: str,
        *,
        worker_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        """Record a failed attempt; the queue redelivers and a later :meth:`start` retries it.

        ``error`` must not contain secrets or raw alert content.
        """
        return await self._finish(
            tenant_id, alert_id, "failed", ("running", "queued"), worker_id, error=error, conn=conn
        )

    async def dead_letter(
        self,
        tenant_id: str,
        alert_id: str,
        error: str,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        require_aware(now, "now")
        return await self._finish(
            tenant_id,
            alert_id,
            "dead_lettered",
            ("queued", "running", "waiting_human", "waiting_approval", "failed"),
            None,
            error=error,
            finished_at=now,
            finished=True,
            conn=conn,
        )

    @retries_stale_statement
    async def _finish(
        self,
        tenant_id: str,
        alert_id: str,
        to_status: str,
        allowed_from: Sequence[str],
        worker_id: Optional[str],
        *,
        error: Optional[str] = None,
        finished_at: Optional[datetime] = None,
        finished: bool = False,
        conn: Optional[Connection] = None,
    ) -> WorkflowRun:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE workflow_runs SET
                    status = $3,
                    worker_id = NULL,
                    lease_expires_at = NULL,
                    last_error = COALESCE($6, CASE WHEN $3 = 'completed' THEN NULL ELSE last_error END),
                    completed_at = CASE WHEN $8 THEN COALESCE($7::timestamptz, now()) ELSE completed_at END
                WHERE tenant_id = $1 AND alert_id = $2 AND status = ANY($4::text[])
                  AND ($5::text IS NULL OR worker_id = $5)
                RETURNING *
                """,
                tenant_id,
                alert_id,
                to_status,
                list(allowed_from),
                worker_id,
                truncate(error, MAX_ERROR_CHARS),
                finished_at,
                finished,
            )
            if row is None:
                current = await c.fetchrow(
                    "SELECT * FROM workflow_runs WHERE tenant_id = $1 AND alert_id = $2", tenant_id, alert_id
                )
        if row is not None:
            return WorkflowRun.model_validate(dict(row))
        run = to_model(WorkflowRun, current)
        if run is None:
            raise NotFound("workflow run", f"{tenant_id}:{alert_id}")
        if run.status == to_status:
            return run
        if worker_id is not None and run.status == "running" and run.worker_id != worker_id:
            raise LeaseLost(f"run {tenant_id}:{alert_id} is leased by another worker")
        raise InvalidTransition("workflow run", f"{tenant_id}:{alert_id}", run.status, to_status)

    @retries_stale_statement
    async def set_graph_version(
        self, tenant_id: str, alert_id: str, version: int, *, conn: Optional[Connection] = None
    ) -> None:
        """Record the graph version a fresh thread starts on (no run row, as in an eval run: nothing to stamp)."""
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                "UPDATE workflow_runs SET graph_version = $3 WHERE tenant_id = $1 AND alert_id = $2",
                tenant_id,
                alert_id,
                version,
            )

    @retries_stale_statement
    async def get(self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None) -> WorkflowRun:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM workflow_runs WHERE tenant_id = $1 AND alert_id = $2", tenant_id, alert_id
            )
        run = to_model(WorkflowRun, row)
        if run is None:
            raise NotFound("workflow run", f"{tenant_id}:{alert_id}")
        return run

    async def find_stale_all_tenants(self, *, now: Optional[datetime] = None, limit: int = 100) -> List[WorkflowRun]:
        """Running runs whose lease has expired (the worker died or stalled)."""
        require_aware(now, "now")
        async with self._system() as c:
            rows = await c.fetch(
                """
                SELECT * FROM workflow_runs
                WHERE status = 'running' AND lease_expires_at < COALESCE($1::timestamptz, now())
                ORDER BY lease_expires_at
                LIMIT $2
                """,
                now,
                limit,
            )
        return to_models(WorkflowRun, rows)

    async def requeue_stale_all_tenants(
        self,
        *,
        max_attempts: int,
        now: Optional[datetime] = None,
        limit: int = 100,
    ) -> StaleRunSweep:
        """Atomically recover runs whose lease expired (the worker died or stalled).

        A run already claimed ``max_attempts`` times (the scheduler passes
        ``worker.max_deliveries``) is dead-lettered instead of requeued, so an
        alert that kills its worker cannot loop forever through fresh queue
        messages. A run whose alert is still ``waiting_human``/``waiting_approval``
        (the worker died while claiming a resume, before the run moved on) goes
        back to that waiting status instead: its resume message is retried and
        no process run is needed. Each stale run is returned by exactly one
        caller, so the sweeper enqueues it once; the old worker's next
        heartbeat returns False.
        """
        require_aware(now, "now")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        async with self._system() as c:
            rows = await c.fetch(
                """
                WITH p AS (SELECT COALESCE($1::timestamptz, now()) AS at)
                UPDATE workflow_runs r SET
                    status = CASE WHEN r.attempt >= $3 THEN 'dead_lettered'
                                  WHEN s.alert_status IN ('waiting_human', 'waiting_approval') THEN s.alert_status
                                  ELSE 'queued' END,
                    worker_id = NULL,
                    lease_expires_at = NULL,
                    last_error = CASE WHEN r.attempt >= $3
                                      THEN format('lease expired on attempt %s of %s', r.attempt, $3::int)
                                      ELSE r.last_error END,
                    completed_at = CASE WHEN r.attempt >= $3 THEN p.at ELSE r.completed_at END
                FROM p, (
                    SELECT w.tenant_id, w.alert_id, a.status AS alert_status
                    FROM workflow_runs w
                    LEFT JOIN alerts a ON a.tenant_id = w.tenant_id AND a.id = w.alert_id
                    WHERE w.status = 'running' AND w.lease_expires_at < COALESCE($1::timestamptz, now())
                    ORDER BY w.lease_expires_at
                    LIMIT $2
                    FOR UPDATE OF w SKIP LOCKED
                ) s
                WHERE r.tenant_id = s.tenant_id AND r.alert_id = s.alert_id
                RETURNING r.*
                """,
                now,
                limit,
                max_attempts,
            )
        runs = to_models(WorkflowRun, rows)
        return StaleRunSweep(
            requeued=[r for r in runs if r.status == "queued"],
            dead_lettered=[r for r in runs if r.status == "dead_lettered"],
        )

    async def counts_by_status(
        self, tenant_id: str, *, active_only: bool = False, conn: Optional[Connection] = None
    ) -> Dict[str, int]:
        """Runs per status; ``active_only`` counts only runs that have not finished
        (``completed``/``dead_lettered`` excluded), which ``ix_workflow_runs_active`` serves
        without reading the tenant's whole history."""
        sql = (
            "SELECT status, count(*) AS n FROM workflow_runs WHERE tenant_id = $1 "
            "AND status NOT IN ('completed', 'dead_lettered') GROUP BY status"
            if active_only
            else "SELECT status, count(*) AS n FROM workflow_runs WHERE tenant_id = $1 GROUP BY status"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, tenant_id)
        return {r["status"]: r["n"] for r in rows}

    async def counts_by_status_all_tenants(self) -> Dict[str, int]:
        """Platform-wide counts for queue/run gauges."""
        async with self._system() as c:
            rows = await c.fetch("SELECT status, count(*) AS n FROM workflow_runs GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    # -- recovery sweeps (runtime/orphans.py, runtime/resumes.py) --------------------------------

    async def claim_orphaned_all_tenants(
        self, *, queued_older_than_s: Optional[float], failed_older_than_s: float, limit: int
    ) -> List[OrphanedRunRef]:
        """Pick orphaned runs of active tenants, oldest first, and touch ``updated_at`` so each is returned
        once per threshold. ``queued_older_than_s=None`` skips queued runs (schema owner, ``system_tx``)."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        async with self._system() as c:
            rows = await c.fetch(
                _CLAIM_ORPHANS_SQL,
                None if queued_older_than_s is None else float(queued_older_than_s),
                float(failed_older_than_s),
                limit,
            )
        return to_models(OrphanedRunRef, rows)

    async def find_stranded_waiting_all_tenants(self, *, older_than_s: float, limit: int) -> List[StrandedRunRef]:
        """Runs of active tenants waiting for a decision or approval that was made longer than
        ``older_than_s`` ago (see :mod:`lg_sotf.runtime.resumes`; schema owner, read-only ``system_tx``)."""
        async with self._system(readonly=True) as c:
            rows = await c.fetch(_STRANDED_WAITING_SQL, float(older_than_s), limit)
        return to_models(StrandedRunRef, rows)

    async def touch(self, tenant_id: str, alert_id: str, *, status: str, conn: Optional[Connection] = None) -> bool:
        """Bump ``updated_at`` while the run is still ``status`` (a recovered run waits a full threshold again)."""
        async with self._tenant(tenant_id, conn) as c:
            outcome = await c.execute(
                "UPDATE workflow_runs SET updated_at = now() WHERE tenant_id = $1 AND alert_id = $2 AND status = $3",
                tenant_id,
                alert_id,
                status,
            )
        return outcome.endswith(" 1")
