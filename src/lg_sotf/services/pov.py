"""Proof-of-value runs (PRD-11.1): create, read and cancel a tenant's runs.

Creating a run records it and nothing else: the windows
(:func:`lg_sotf.domain.pov.plan_windows`), the audit entry. It changes no
alert, plans no response and notifies nobody. The scheduler then runs the
backtest (:mod:`lg_sotf.eval.pov`), which only reads; the shadow period only
observes the alerts that arrive.

A tenant has one run in progress at a time, and at most
:data:`~lg_sotf.domain.pov.MAX_RUNS_PER_DAY` runs created in 24 hours (each
starts a backtest that calls the model); both are checked under a per-tenant
lock.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db import locks
from lg_sotf.db.pagination import Page
from lg_sotf.db.repos.pov_runs import PovRun
from lg_sotf.domain.pov import MAX_RUNS_PER_DAY, plan_windows
from lg_sotf.observability.logging import get_logger

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)


class PovError(ValueError):
    """A request on a PoV run that cannot be done (the message is safe to show); ``code``:
    ``pov_run_in_progress``, ``too_many_pov_runs`` or ``pov_run_not_in_progress``."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class PovService:
    def __init__(self, repos: Repositories) -> None:
        self._repos = repos
        self._audit = AuditLogger(repos)

    async def create(
        self, tenant_id: str, *, name: str, backtest_days: int, shadow_days: int, actor: Actor,
        now: Optional[datetime] = None,
    ) -> PovRun:
        """Record a run whose history window ends, and whose shadow period starts, now."""
        now = now or datetime.now(UTC)
        windows = plan_windows(now, backtest_days=backtest_days, shadow_days=shadow_days)
        repo = self._repos.pov_runs
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.POV_RUN, tenant_id)
            if await repo.in_progress(tenant_id, now, conn=conn) is not None:
                raise PovError(
                    "this tenant already has a proof-of-value run in progress; cancel it or wait for it to end",
                    "pov_run_in_progress",
                )
            if await repo.count_created_since(tenant_id, now - timedelta(days=1), conn=conn) >= MAX_RUNS_PER_DAY:
                raise PovError(
                    f"at most {MAX_RUNS_PER_DAY} proof-of-value runs can be created in 24 hours", "too_many_pov_runs"
                )
            run = await repo.create(tenant_id, name, windows, created_by=actor.id, conn=conn)
            await self._audit.record(
                tenant_id, "pov_run.created", "pov_run", str(run.id), actor_type=actor.type, actor_id=actor.id,
                details={
                    "name": name, "backtest_start": windows.backtest_start.isoformat(),
                    "backtest_end": windows.backtest_end.isoformat(),
                    "shadow_start": windows.shadow_start.isoformat(), "shadow_end": windows.shadow_end.isoformat(),
                },
                conn=conn,
            )
        log.info("pov_run.created", backtest_days=backtest_days, shadow_days=shadow_days)
        return run

    async def get(self, tenant_id: str, run_id: UUID) -> PovRun:
        return await self._repos.pov_runs.get(tenant_id, run_id)

    async def runs(self, tenant_id: str, *, limit: int = 50, cursor: Optional[str] = None) -> Page[PovRun]:
        return await self._repos.pov_runs.list(tenant_id, limit=limit, cursor=cursor)

    async def cancel(self, tenant_id: str, run_id: UUID, *, actor: Actor, now: Optional[datetime] = None) -> PovRun:
        """Cancel a run in progress: its backtest is not started (one already running finishes) and its
        shadow period ends. ``NotFound`` for an unknown run."""
        now = now or datetime.now(UTC)
        repo = self._repos.pov_runs
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await repo.get(tenant_id, run_id, conn=conn)
            run = await repo.cancel(tenant_id, run_id, cancelled_by=actor.id, now=now, conn=conn)
            if run is None:
                raise PovError("this proof-of-value run is over or cancelled already", "pov_run_not_in_progress")
            await self._audit.record(
                tenant_id, "pov_run.cancelled", "pov_run", str(run.id), actor_type=actor.type, actor_id=actor.id,
                conn=conn,
            )
        log.info("pov_run.cancelled")
        return run
