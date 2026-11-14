"""Proof-of-value runs (migration 0019; :mod:`lg_sotf.domain.pov` defines the windows and the status).

The API creates, reads and cancels runs in the tenant's scope. The backtest
queue (:meth:`PovRunsRepo.claim_backtest`, :meth:`PovRunsRepo.finish_backtest`)
spans tenants and writes the backtest columns: it runs in system
transactions, from the scheduler only (the runtime role may not write those
columns).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from uuid import UUID

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pagination import Page, check_limit, decode_cursor_uuid, paginate
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    fetch_int,
    fetch_one,
    require_aware,
    to_model,
    to_models,
    truncate,
)
from lg_sotf.domain.pov import (
    MAX_BACKTEST_ATTEMPTS,
    MAX_BACKTEST_ERROR_CHARS,
    PovBacktestStatus,
    PovWindows,
)

_FINAL_BACKTEST_STATUSES = ("completed", "no_data", "failed")

# The oldest run of an active tenant whose backtest is still to run: never started, or left
# ``running`` by a scheduler that stopped. One interrupted too often is recorded as failed instead.
_CLAIM_SQL = """
UPDATE pov_runs r
SET backtest_attempts = r.backtest_attempts + (r.backtest_attempts < $1)::int,
    backtest_status = CASE WHEN r.backtest_attempts < $1 THEN 'running' ELSE 'failed' END,
    backtest_started_at = CASE WHEN r.backtest_attempts < $1 THEN now() ELSE r.backtest_started_at END,
    backtest_finished_at = CASE WHEN r.backtest_attempts < $1 THEN NULL ELSE now() END,
    backtest_error = CASE WHEN r.backtest_attempts < $1 THEN NULL ELSE $2 END
WHERE r.id = (
    SELECT q.id FROM pov_runs q
    JOIN tenants t ON t.id = q.tenant_id AND t.status = 'active'
    WHERE q.backtest_status IN ('pending', 'running') AND q.cancelled_at IS NULL
    ORDER BY q.created_at, q.id
    LIMIT 1
    FOR UPDATE OF q SKIP LOCKED
)
RETURNING r.*
"""
_INTERRUPTED = f"the backtest was interrupted {MAX_BACKTEST_ATTEMPTS} times and was not run again"


class PovRun(Record):
    id: UUID
    tenant_id: str
    name: str
    backtest_start: datetime
    backtest_end: datetime
    shadow_start: datetime
    shadow_end: datetime
    backtest_status: PovBacktestStatus
    backtest_attempts: int
    backtest_started_at: Optional[datetime]
    backtest_finished_at: Optional[datetime]
    backtest_error: Optional[str]
    backtest_result: Optional[Dict[str, Any]]
    created_by: Optional[str]
    created_at: datetime
    cancelled_at: Optional[datetime]
    cancelled_by: Optional[str]


class PovRunsRepo(Repository):
    async def create(
        self, tenant_id: str, name: str, windows: PovWindows, *, created_by: Optional[str],
        conn: Optional[Connection] = None,
    ) -> PovRun:
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO pov_runs (tenant_id, name, backtest_start, backtest_end, shadow_start, shadow_end,
                                      created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING *
                """,
                tenant_id, name, windows.backtest_start, windows.backtest_end, windows.shadow_start,
                windows.shadow_end, created_by,
            )
        return PovRun.model_validate(dict(row))

    async def get(self, tenant_id: str, run_id: UUID, *, conn: Optional[Connection] = None) -> PovRun:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM pov_runs WHERE tenant_id = $1 AND id = $2", tenant_id, run_id)
        run = to_model(PovRun, row)
        if run is None:
            raise NotFound("proof-of-value run", run_id)
        return run

    async def list(
        self, tenant_id: str, *, limit: int = 50, cursor: Optional[str] = None, conn: Optional[Connection] = None
    ) -> Page[PovRun]:
        """The tenant's runs, newest first."""
        check_limit(limit)
        args: List[Any] = [tenant_id]
        where = ""
        if cursor:
            args += decode_cursor_uuid(cursor)
            where = "AND (created_at, id) < ($2, $3)"
        query = (
            f"SELECT * FROM pov_runs WHERE tenant_id = $1 {where} "  # noqa: S608 - a constant fragment
            f"ORDER BY created_at DESC, id DESC LIMIT ${len(args) + 1}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(query, *args, limit + 1)
        return paginate(to_models(PovRun, rows), limit, lambda r: (r.created_at, str(r.id)))

    async def in_progress(
        self, tenant_id: str, now: datetime, *, conn: Optional[Connection] = None
    ) -> Optional[PovRun]:
        """The run that is not cancelled and whose shadow period has not ended at ``now`` (the newest, if several)."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM pov_runs WHERE tenant_id = $1 AND cancelled_at IS NULL AND shadow_end > $2 "
                "ORDER BY created_at DESC, id DESC LIMIT 1",
                tenant_id, now,
            )
        return to_model(PovRun, row)

    async def count_created_since(
        self, tenant_id: str, since: datetime, *, conn: Optional[Connection] = None
    ) -> int:
        """Runs created since ``since``, cancelled ones included (each may have started a backtest)."""
        require_aware(since, "since")
        async with self._tenant(tenant_id, conn) as c:
            return await fetch_int(
                c, "SELECT count(*) FROM pov_runs WHERE tenant_id = $1 AND created_at >= $2", tenant_id, since
            )

    async def cancel(
        self, tenant_id: str, run_id: UUID, *, cancelled_by: Optional[str], now: datetime,
        conn: Optional[Connection] = None,
    ) -> Optional[PovRun]:
        """Cancel a run that is still in progress at ``now``; ``None`` when it is over or cancelled already."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "UPDATE pov_runs SET cancelled_at = $3, cancelled_by = $4 "
                "WHERE tenant_id = $1 AND id = $2 AND cancelled_at IS NULL AND shadow_end > $3 RETURNING *",
                tenant_id, run_id, now, cancelled_by,
            )
        return to_model(PovRun, row)

    # -- the backtest queue (scheduler; system transactions) --------------------

    async def claim_backtest(self, *, conn: Optional[Connection] = None) -> Optional[PovRun]:
        """Take the next backtest to run, across tenants, and mark it ``running``.

        Returns the run as claimed. A run whose backtest was already started
        :data:`MAX_BACKTEST_ATTEMPTS` times comes back ``failed`` (nothing to
        run); ``None`` when no backtest is waiting. One caller at a time: a
        ``running`` backtest found here is taken to be abandoned.
        """
        async with self._system(conn) as c:
            row = await c.fetchrow(_CLAIM_SQL, MAX_BACKTEST_ATTEMPTS, _INTERRUPTED)
        return to_model(PovRun, row)

    async def finish_backtest(
        self, run: PovRun, status: PovBacktestStatus, *, result: Optional[Mapping[str, Any]] = None,
        error: Optional[str] = None, conn: Optional[Connection] = None,
    ) -> bool:
        """Record the outcome of the backtest claimed as ``run``; ``False`` when another attempt took it over."""
        check_choice(status, _FINAL_BACKTEST_STATUSES, "backtest status")
        if (result is not None) != (status == "completed"):
            raise ValueError("a completed backtest, and only a completed one, has a result")
        async with self._system(conn) as c:
            row = await c.fetchrow(
                "UPDATE pov_runs SET backtest_status = $3, backtest_result = $4, backtest_error = $5, "
                "backtest_finished_at = now() "
                "WHERE id = $1 AND backtest_status = 'running' AND backtest_attempts = $2 RETURNING id",
                run.id, run.backtest_attempts, status, None if result is None else dict(result),
                truncate(error, MAX_BACKTEST_ERROR_CHARS),
            )
        return row is not None
