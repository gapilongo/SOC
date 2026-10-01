"""Background execution: the scheduler's executor for ledger rows no workflow run will execute.

Rows are owned by the scheduler (``execution_owner='scheduler'``) when they
are rollbacks, retries, approvals that arrived after the alert's run ended,
executions a stateful connector deferred (throttling, an unknown write
outcome) or stateful executions orphaned by a run that ended mid-call.

:meth:`BackgroundExecutor.run_once` (scheduler job ``response_background``,
every ``response.background_interval_s``), in order:

1. **Approval TTL**: scheduler rows still ``approved``
   ``response.approval_ttl_s`` after approval are blocked
   (``approval_expired``).
2. **Stranded approvals**: workflow rows still ``approved`` whose run has
   ended. Approved at or after the run's end: handed to the scheduler
   (audited ``response_action.handed_off``, reason ``late_approval``),
   unless the approval is older than ``response.approval_ttl_s`` (an old
   approval found after an upgrade, say): then blocked
   (``approval_expired``), never executed. Approved while the run was still
   active and the run ended without them: blocked
   (``approval_superseded``); a superseded approval is never revived.
3. **Claims**: due scheduler rows (``FOR UPDATE SKIP LOCKED``, leased for
   ``response.background_deadline_s`` + 60 s), at most two at a time per
   tenant and ``response.background_concurrency`` overall. ``approved``
   rows go through the normal claim (guardrails, with the restorative
   exemptions for rollbacks, the hourly cap and blast radius, the audit);
   ``executing`` rows whose lease expired are run again with their pinned
   connector, or failed with ``attempts_exhausted`` after
   ``response.max_execution_attempts``. Each connector call gets
   ``response.background_deadline_s``.
4. **Orphans**: workflow rows left ``executing`` by an ended run
   (:meth:`~lg_sotf.services.response.ResponseService.fail_orphaned_executing`).

The kill switches still win: with dry run forced, a background row is
recorded ``dry_run`` like any other.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Dict, List, Tuple
from uuid import UUID

from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.services.response import APPROVAL_EXPIRED_REASON, APPROVAL_SUPERSEDED_REASON, ResponseService

log = get_logger(__name__)

PER_TENANT_CONCURRENCY = 2
LEASE_MARGIN_S = 60.0
STRANDED_BATCH = 100


class BackgroundExecutor:
    """Runs the scheduler's response work (see the module docstring)."""

    def __init__(self, responses: ResponseService) -> None:
        self._responses = responses
        self._repos = responses.repos
        self._settings = responses.settings

    async def expire_approvals(self) -> int:
        ttl = float(self._settings.response.approval_ttl_s)
        async with self._repos.db.system_tx() as conn:
            due = await self._repos.actions.expire_approvals(ttl_s=ttl, conn=conn)
        expired = 0
        for tenant_id, action_id in due:
            if await self._responses.block_approved(tenant_id, action_id, APPROVAL_EXPIRED_REASON, {"ttl_s": ttl}):
                expired += 1
        if expired:
            log.warning("response.approvals_expired", count=expired)
        return expired

    async def settle_stranded(self) -> Tuple[int, int]:
        """(handed off, blocked: superseded or expired) workflow approvals whose run has ended."""
        ttl = float(self._settings.response.approval_ttl_s)
        async with self._repos.db.system_tx() as conn:
            stranded = await self._repos.actions.stranded_approvals(limit=STRANDED_BATCH, ttl_s=ttl, conn=conn)
        handed = superseded = expired = 0
        for tenant_id, action_id, late, too_old in stranded:
            if late and too_old:
                if await self._responses.block_approved(
                    tenant_id, action_id, APPROVAL_EXPIRED_REASON,
                    {"ttl_s": ttl, "note": "approved after the alert's run ended, longer ago than the approval TTL"},
                ):
                    expired += 1
            elif late:
                handed += len(await self._responses.hand_off(tenant_id, [action_id], reason="late_approval"))
            elif await self._responses.block_approved(
                tenant_id, action_id, APPROVAL_SUPERSEDED_REASON, {"note": "the alert's run ended without executing it"}
            ):
                superseded += 1
        if handed or superseded or expired:
            log.info("response.stranded_approvals", handed_off=handed, superseded=superseded, expired=expired)
        return handed, superseded + expired

    async def run_claimed(self, claimed: List[Tuple[str, UUID, str]]) -> None:
        deadline_s = float(self._settings.response.background_deadline_s)
        overall = asyncio.Semaphore(int(self._settings.response.background_concurrency))
        per_tenant: Dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(PER_TENANT_CONCURRENCY))

        async def run(tenant_id: str, action_id: UUID) -> None:
            async with per_tenant[tenant_id], overall:
                with bound_context(tenant_id=tenant_id):
                    try:
                        status = await self._responses.execute_background(tenant_id, action_id, deadline_s=deadline_s)
                    except Exception as exc:  # noqa: BLE001 - the lease brings the row back after it ends
                        log.error("response.background_failed", error_type=type(exc).__name__)
                        return
                    log.info("response.background_executed", status=status)

        await asyncio.gather(*(run(tenant_id, action_id) for tenant_id, action_id, _status in claimed))

    async def run_once(self, *, limit: int = 20) -> int:
        """One pass (module docstring); returns how many rows were claimed and run."""
        await self.expire_approvals()
        await self.settle_stranded()
        lease_s = float(self._settings.response.background_deadline_s) + LEASE_MARGIN_S
        async with self._repos.db.system_tx() as conn:
            claimed = await self._repos.actions.claim_background(limit=limit, lease_s=lease_s, conn=conn)
        if claimed:
            await self.run_claimed(claimed)
        await self._responses.fail_orphaned_executing()
        return len(claimed)


__all__ = ["BackgroundExecutor"]
