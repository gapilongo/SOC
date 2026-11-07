"""Executing approved actions: the claim, the connector call, its outcome and the hand-off to the scheduler.

:class:`ActionExecutor` claims an approved row (guardrails again, then the
hourly cap and blast radius under the per-tenant advisory lock), runs it
through the connector the routing snapshot picks, and writes the outcome
with its audit entry through the :class:`~lg_sotf.services.response.ledger.ActionLedger`.

Execution runs up to :data:`EXECUTION_CONCURRENCY` actions at a time within
an execution budget of :data:`EXECUTION_BUDGET_FRACTION` of
``worker.node_timeout_s``, so the ``execute_actions`` node is never cancelled
half-way through a connector call. An action still running when the budget
ends is recorded ``failed`` (``error="deadline"``, outcome unknown: the
receiver deduplicates a later retry by action id); one the budget leaves no
time to start is recorded ``failed`` with ``error="execution_budget_exhausted"``
without being sent. A stateful (Microsoft) action is never abandoned that
way: running out of budget mid-call, or too little budget to start with the
connector's own margins, defers it to the scheduler, which re-runs and
reconciles it; a database error during the call propagates (the row stays
``executing`` and is run again). A stateful row that already started is
never recorded ``dry_run`` or a plain misconfiguration when it is run again:
while a kill switch is on it is held (``deferred``, ``halted``) until its
attempts run out, a misconfigured integration fails it retryably, and every
such failure keeps what its checkpoints show was done (``partial``,
reversible). :meth:`ResponseService.fail_orphaned_executing` settles actions
left ``executing`` by a run that will never finish them.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional, Sequence, Tuple
from uuid import UUID

from lg_sotf.db import AlreadyInState, Connection, InvalidTransition, locks
from lg_sotf.db.repos._base import UNSET
from lg_sotf.db.repos.actions import VerificationWrite
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.domain.actions import ACTION_CATALOG, BLAST_RADIUS_REASON, HOURLY_CAP_REASON, guardrail_result
from lg_sotf.domain.connectors import call_deadline
from lg_sotf.models.vocabulary import SCHEDULER_OWNER, WORKFLOW_OWNER
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.services.connectors import (
    STATEFUL_CONNECTORS,
    Connector,
    ConnectorResult,
    DryRunConnector,
    LedgerUnavailable,
    MisconfiguredConnector,
    VerifyPlan,
)
from lg_sotf.services.connectors.microsoft import DEADLINE_MARGIN_S, MIN_HANDLER_S, started, with_progress
from lg_sotf.services.connectors.routing import ConnectorRouter
from lg_sotf.services.response.guardrails import check_guardrails
from lg_sotf.services.response.ledger import SCHEDULER_ACTOR, ActionLedger
from lg_sotf.services.response.policy import ResponsePolicy
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories, ResponseAction

log = get_logger(__name__)


# Execution: parallel connector calls per node run, and the share of the node timeout they may use.
EXECUTION_CONCURRENCY = 4
EXECUTION_BUDGET_FRACTION = 0.75
MIN_EXECUTION_S = 1.0
# A stateful connector keeps DEADLINE_MARGIN_S for its ledger write and needs MIN_HANDLER_S for the handler;
# a request may overrun its timeout by 0.5 s. With less budget left, the action is deferred to the scheduler.
MIN_STATEFUL_EXECUTION_S = DEADLINE_MARGIN_S + MIN_HANDLER_S + 0.5
# How long a started stateful row waits while a kill switch holds it (each wait counts one attempt).
HALTED_RETRY_S = 300.0
ORPHAN_GRACE_S = 60.0
# Connector results are stored in response_actions.result; larger details keep their essential keys.
MAX_RESULT_BYTES = 8 * 1024
MAX_VERIFICATION_DETAIL_BYTES = 12 * 1024
RESULT_ESSENTIAL_KEYS = (
    "connector", "capability", "integration_id", "live", "summary", "changed", "already", "error", "http_status",
    "ms_code", "request_id", "retryable", "hint", "deferred", "rehearsal", "would_execute", "attempts",
)


def bounded_detail(detail: Mapping[str, Any], limit: int = MAX_RESULT_BYTES) -> Dict[str, Any]:
    """``detail`` as stored in ``response_actions.result``: at most ``limit`` bytes of JSON.

    An oversized detail keeps its essential keys (who, what, error) and
    records ``truncated: true``.
    """
    out = dict(detail)
    if len(json.dumps(out, default=str)) <= limit:
        return out
    kept = {k: out[k] for k in RESULT_ESSENTIAL_KEYS if k in out}
    kept = {k: (v[:500] if isinstance(v, str) else v) for k, v in kept.items()}
    kept["truncated"] = True
    if len(json.dumps(kept, default=str)) > limit:
        kept = {"error": str(out.get("error") or "")[:100] or None, "truncated": True}
    return kept


def cap_reached(
    policy: ResponsePolicy, action_type: str, used: int, by_type: Mapping[str, int]
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """(reason, detail) when the hourly cap or the type's blast radius is reached, else ``None``."""
    type_limit = policy.blast_radius.get(action_type)
    if used >= policy.max_actions_per_hour:
        return HOURLY_CAP_REASON, {"cap": policy.max_actions_per_hour, "used": used}
    if type_limit is not None and by_type.get(action_type, 0) >= type_limit:
        return BLAST_RADIUS_REASON, {"limit": type_limit, "used": by_type.get(action_type, 0)}
    return None


def verification_write(plan: VerifyPlan, *, now: datetime, ceiling_s: float) -> VerificationWrite:
    """The verification written with ``succeeded``: proven, or pending for the plan's window.

    The window starts ``now``, when the change was accepted, not at the
    row's first claim (``executed_at``): a change made after deferrals
    (throttling, a long purge) still gets its whole window, capped by
    ``ceiling_s`` (``response.verify_max_s``).
    """
    detail = bounded_detail(plan.detail, MAX_VERIFICATION_DETAIL_BYTES)
    if plan.state == "verified":
        return VerificationWrite("verified", detail)
    deadline = now + timedelta(seconds=min(max(plan.max_duration_s, 1.0), ceiling_s))
    after = min(now + timedelta(seconds=max(plan.first_check_s, 0.0)), deadline)
    return VerificationWrite(
        "pending", {**detail, "first_check_s": float(plan.first_check_s)}, verify_after=after,
        verify_deadline=deadline,
    )


class ActionExecutor:
    """Runs approved ledger rows through their connectors (module docstring); built by ``ResponseService``."""

    def __init__(
        self, repos: Repositories, settings: Settings, ledger: ActionLedger, router: ConnectorRouter, *,
        budget_s: float,
    ) -> None:
        self._repos = repos
        self._settings = settings
        self._ledger = ledger
        self._router = router
        self._execution_budget_s = budget_s

    async def _is_sample(self, tenant_id: str, alert_id: str) -> bool:
        return (await self._repos.alerts.get(tenant_id, alert_id)).source_id == SAMPLE_SOURCE_ID

    async def execute(
        self,
        tenant_id: str,
        alert_id: str,
        action_ids: Sequence[str],
        *,
        now: Optional[datetime] = None,
        budget_s: Optional[float] = None,
    ) -> Dict[str, str]:
        """Run this alert's approved workflow actions. Returns ``{action_id: status}`` for the actions considered.

        Guardrails are evaluated again before each claim. Actions left
        ``executing`` by an interrupted earlier attempt are run again with the
        connector recorded on the row: connectors are idempotent per action
        id, and the alert's run lease guarantees no other worker is executing
        them. Terminal actions are never executed twice. Scheduler-owned
        rows are skipped (the background executor runs them).

        Each action's connector comes from one routing snapshot
        (:mod:`lg_sotf.services.connectors.routing`). A stateful connector
        may answer ``deferred``: the row stays ``executing``, is handed to
        the scheduler and is reported as ``executing``.

        Up to :data:`EXECUTION_CONCURRENCY` actions run at once, and all of
        them within ``budget_s`` (default :attr:`execution_budget_s`): a
        connector call still running when the budget ends is abandoned and
        recorded ``failed`` (``error="deadline"``), and an action there is no
        time left to start is recorded ``failed`` without being sent
        (``error="execution_budget_exhausted"``).
        """
        if not action_ids:
            return {}
        tenant = await self._repos.tenants.get(tenant_id)
        policy = ResponsePolicy.resolve(tenant.settings, self._settings)
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        mine = [a for a in actions if a.alert_id == alert_id and a.execution_owner == WORKFLOW_OWNER]
        if not mine:
            return {}
        snapshot = await self._router.snapshot(tenant_id, tenant.settings)
        sample = await self._is_sample(tenant_id, alert_id) if snapshot.needs_sample_check(mine) else False
        loop = asyncio.get_running_loop()
        ends_at = loop.time() + (self._execution_budget_s if budget_s is None else budget_s)
        slots = asyncio.Semaphore(EXECUTION_CONCURRENCY)

        async def run(action: ResponseAction) -> str:
            async with slots:
                connector = snapshot.connector_for(action, sample=sample)
                return await self._execute_one(tenant_id, action, connector, policy, now, ends_at)

        tasks = [asyncio.create_task(run(a)) for a in mine]
        try:
            statuses = await asyncio.gather(*tasks)
        except BaseException:
            # The first failure propagates unchanged (retry policies match on its type); stop the rest first.
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return {str(a.id): status for a, status in zip(mine, statuses, strict=True)}

    async def _execute_one(
        self,
        tenant_id: str,
        action: ResponseAction,
        connector: Connector,
        policy: ResponsePolicy,
        now: Optional[datetime],
        ends_at: float,
    ) -> str:
        if action.status == "executing":
            log.warning("response.resuming_interrupted_action", action_type=action.action_type)
            executing: Optional[ResponseAction] = action
            held = self._rerun_held(action, connector)
            if held is not None:
                return await self._finish(tenant_id, action, connector, held)
        elif action.status == "approved":
            executing = await self._claim(tenant_id, action, connector, policy, now)
        else:
            return action.status
        if executing is None:
            return (await self._repos.actions.get(tenant_id, action.id)).status
        remaining = ends_at - asyncio.get_running_loop().time()
        if connector.name in STATEFUL_CONNECTORS and remaining < MIN_STATEFUL_EXECUTION_S:
            # Not sent: the scheduler runs it with a full deadline (never abandoned half-way).
            log.warning("response.execution_budget_exhausted", action_type=action.action_type, deferred=True)
            result = ConnectorResult(
                "deferred",
                {"connector": connector.name, "deferred": "execution_budget", "changed": False,
                 "summary": "not started: too little of this workflow step's budget was left; the scheduler runs it"},
                retry_after_s=30.0,
            )
            return await self._finish(tenant_id, executing, connector, result)
        if remaining < MIN_EXECUTION_S and not isinstance(connector, DryRunConnector):
            log.warning("response.execution_budget_exhausted", action_type=action.action_type)
            result = ConnectorResult(
                "failed",
                {
                    "error": "execution_budget_exhausted",
                    "note": "not sent: the execution budget of this workflow step ran out before it could start",
                },
            )
            return await self._finish(tenant_id, executing, connector, result)
        return await self._run_connector(tenant_id, executing, connector, timeout_s=max(remaining, MIN_EXECUTION_S))

    async def execute_background(self, tenant_id: str, action_id: UUID, *, deadline_s: float) -> str:
        """Run one scheduler-owned row the background executor claimed (its lease is held).

        ``approved`` rows go through :meth:`_claim` (guardrails, restorative
        exemptions for rollbacks, caps, blast radius); ``executing`` rows are
        run again with their pinned connector, or failed with
        ``attempts_exhausted`` after ``response.max_execution_attempts``.
        Returns the row's status afterwards.
        """
        action = await self._repos.actions.get(tenant_id, action_id)
        if action.execution_owner != SCHEDULER_OWNER or action.status not in ("approved", "executing"):
            return action.status
        tenant = await self._repos.tenants.get(tenant_id)
        policy = ResponsePolicy.resolve(tenant.settings, self._settings)
        snapshot = await self._router.snapshot(tenant_id, tenant.settings)
        sample = await self._is_sample(tenant_id, action.alert_id) if snapshot.needs_sample_check([action]) else False
        connector = snapshot.connector_for(action, sample=sample)
        limit = int(self._settings.response.max_execution_attempts)
        if action.status == "approved":
            executing = await self._claim(tenant_id, action, connector, policy, None)
            if executing is None:
                return (await self._repos.actions.get(tenant_id, action.id)).status
        elif action.attempts >= limit:
            held = self._rerun_held(action, connector)
            if held is not None and held.status == "failed":
                return await self._finish(tenant_id, action, connector, held)  # its integration is unavailable
            halted = held is not None  # still held by a kill switch
            result = ConnectorResult(
                "failed",
                {
                    "connector": action.connector,
                    "error": "halted" if halted else "attempts_exhausted",
                    "attempts": action.attempts,
                    "retryable": True,
                    "summary": f"not run again: {action.attempts} attempts already made"
                    + (" while dry run was forced" if halted else ""),
                },
            )
            return await self._finish(tenant_id, action, connector, result)
        else:
            rerun = await self._repos.actions.count_attempt(tenant_id, action.id)
            if rerun is None:
                return (await self._repos.actions.get(tenant_id, action.id)).status
            executing = rerun
            held_result = self._rerun_held(executing, connector)
            if held_result is not None:
                return await self._finish(tenant_id, executing, connector, held_result)
        return await self._run_connector(tenant_id, executing, connector, timeout_s=deadline_s)

    @staticmethod
    def _rerun_held(action: ResponseAction, connector: Connector) -> Optional[ConnectorResult]:
        """What a re-run of a started stateful row gets instead of a dry run or a plain misconfiguration.

        The row's checkpoints show that an earlier attempt got as far as a
        write, so recording ``dry_run`` ("nothing was executed") would hide
        it and block its rollback. While a kill switch forces the dry-run
        connector it is held (``deferred``, ``halted``; each wait counts one
        attempt, then it fails with ``halted``); a misconfigured integration
        (disabled or deleted) fails it retryably. ``_finish`` keeps what the
        checkpoints show was done. ``None``: run it normally.
        """
        if action.connector not in STATEFUL_CONNECTORS or not started(action.external_ref):
            return None
        if isinstance(connector, DryRunConnector):
            return ConnectorResult(
                "deferred",
                {"connector": action.connector, "deferred": "halted", "changed": False, "attempts": action.attempts,
                 "summary": "held: dry run is forced (a kill switch is on); it runs again when the switch is off"},
                retry_after_s=HALTED_RETRY_S,
            )
        if isinstance(connector, MisconfiguredConnector):
            return ConnectorResult(
                "failed",
                {"connector": action.connector, "error": "connector_misconfigured", "reason": connector.reason,
                 "retryable": True, "changed": False,
                 "summary": "not run again: the Microsoft integration this action is pinned to is not available"},
            )
        return None

    async def fail_orphaned_executing(self, tenant_id: Optional[str] = None, *, limit: int = 100) -> int:
        """Settle workflow actions left ``executing`` whose run will never finish them.

        An action stays ``executing`` when its worker died mid-call; the run
        normally resumes and re-runs it, but a run that was dead-lettered (or
        completed on another path) never will. After a grace period (the
        execution budget plus 60 s, so a call still in flight is not
        touched), actions of stateful connectors (Microsoft) are handed to
        the scheduler, which re-runs and reconciles them; the others are
        failed with ``error="orphaned_execution"``: the external outcome is
        unknown, and the receiver can be asked by the action id (its
        idempotency key). ``tenant_id=None`` sweeps every tenant (scheduler;
        system transaction). Returns how many actions were settled.
        """
        grace = self._execution_budget_s + ORPHAN_GRACE_S
        if tenant_id is None:
            rows = await self._repos.actions.find_orphaned_executing_all_tenants(limit=limit, grace_s=grace)
        else:
            rows = await self._repos.actions.find_orphaned_executing(tenant_id, limit=limit, grace_s=grace)
        settled = 0
        for owner, action_id, connector in rows:
            if connector in STATEFUL_CONNECTORS:
                handed = await self._ledger.hand_off(owner, [action_id], reason="orphaned_execution")
                settled += len(handed)
                continue
            try:
                await self._ledger.transition_audited(
                    owner,
                    action_id,
                    "failed",
                    details={"reason": "orphaned_execution"},
                    expected_from="executing",
                    result={
                        "error": "orphaned_execution",
                        "note": "the workflow run ended while this action was executing; its outcome is unknown",
                    },
                )
            except (AlreadyInState, InvalidTransition):
                continue
            settled += 1
        if settled:
            log.warning("response.orphaned_actions_settled", count=settled)
        return settled

    async def _block_approved(
        self, tenant_id: str, action: ResponseAction, code: str, detail: Mapping[str, Any], conn: Optional[Connection] = None
    ) -> ResponseAction:
        return await self._repos.actions.transition(
            tenant_id,
            action.id,
            "blocked",
            expected_from="approved",
            blocked_reason=code,
            result=guardrail_result(code, **detail),
            conn=conn,
        )

    async def _claim(
        self,
        tenant_id: str,
        action: ResponseAction,
        connector: Connector,
        policy: ResponsePolicy,
        now: Optional[datetime],
    ) -> Optional[ResponseAction]:
        """Move an approved action to ``executing``; ``None`` when it was blocked or taken by someone else.

        For real connectors the hourly cap, the blast-radius check and the
        claim run in one transaction under a per-tenant advisory lock, so
        concurrent workers cannot overshoot either limit. The claim records
        the connector, the integration it uses and one more attempt. A
        rollback of a restorative type is checked with the restorative
        exemptions (:func:`check_guardrails`).
        """
        blocked: Optional[ResponseAction] = None
        executing: Optional[ResponseAction] = None
        spec = ACTION_CATALOG.get(action.action_type)
        restorative = bool(spec is not None and spec.restorative and action.rollback_of is not None)
        integration_id: Optional[UUID] = getattr(connector, "integration_id", None)
        try:
            guard = check_guardrails(action.action_type, action.target, policy, restorative=restorative)
            if guard is not None or isinstance(connector, DryRunConnector):
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    if guard is not None:
                        blocked = await self._block_approved(
                            tenant_id, action, guard.code, {"detail": guard.detail, "stage": "execution"}, conn
                        )
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            integration_id=integration_id, bump_attempts=True, conn=conn,
                        )
                    await self._audit_claim(tenant_id, blocked, executing, connector, conn)
            else:
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    await locks.tenant_xact_lock(conn, locks.ACTION_CAP, tenant_id)
                    window_start = now - timedelta(hours=1) if now is not None else None
                    used, by_type = await self._repos.actions.executed_counts(tenant_id, window_start, conn=conn)
                    cap_block = cap_reached(policy, action.action_type, used, by_type)
                    if cap_block is not None:
                        blocked = await self._block_approved(tenant_id, action, cap_block[0], cap_block[1], conn)
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            integration_id=integration_id, bump_attempts=True, conn=conn,
                        )
                    await self._audit_claim(tenant_id, blocked, executing, connector, conn)
        except (AlreadyInState, InvalidTransition):
            return None
        if blocked is not None:
            log.warning("response.execution_blocked", action_type=action.action_type, reason=blocked.blocked_reason)
            await self._ledger.publish_action(tenant_id, blocked)
            return None
        assert executing is not None
        await self._ledger.publish_action(tenant_id, executing)
        return executing

    async def _audit_claim(
        self,
        tenant_id: str,
        blocked: Optional[ResponseAction],
        executing: Optional[ResponseAction],
        connector: Connector,
        conn: Connection,
    ) -> None:
        """Audit a claim inside its transaction (published by the caller after commit)."""
        if blocked is not None:
            await self._ledger.record_transition(tenant_id, blocked, "response_action.blocked", {"stage": "execution"}, conn=conn)
        elif executing is not None:
            await self._ledger.record_transition(
                tenant_id, executing, "response_action.executing", {"connector": connector.name}, conn=conn
            )

    async def _run_connector(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, *, timeout_s: Optional[float] = None
    ) -> str:
        scope = asyncio.timeout(timeout_s)
        loop = asyncio.get_running_loop()
        token = call_deadline.set(loop.time() + timeout_s if timeout_s is not None else None)
        try:
            async with scope:
                result = await connector.execute(executing)
        except TimeoutError as exc:
            if not scope.expired():
                log_failure(
                    log, "response.connector_failed", exc, level="warning", connector=connector.name,
                    error_type=type(exc).__name__,
                )
                result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
            elif connector.name in STATEFUL_CONNECTORS:
                # A write may be in flight: the scheduler re-runs the action, and the handler reconciles.
                log.warning("response.connector_deadline", connector=connector.name, action_type=executing.action_type,
                            deferred=True)
                result = ConnectorResult(
                    "deferred",
                    {"connector": connector.name, "deferred": "deadline", "changed": False,
                     "summary": "the call ran out of time; the scheduler runs it again and reconciles what was done"},
                    retry_after_s=30.0,
                )
            else:
                log.warning("response.connector_deadline", connector=connector.name, action_type=executing.action_type)
                result = ConnectorResult(
                    "failed",
                    {
                        "error": "deadline",
                        "note": "abandoned when the execution budget ran out; the receiver may have acted (same action id)",
                    },
                )
        except (AssertionError, LedgerUnavailable):
            # A ledger error mid-call is not the action's outcome: the row stays executing and is run again.
            raise
        except Exception as exc:  # noqa: BLE001 - any connector failure is recorded on the ledger as 'failed'
            log_failure(
                log, "response.connector_failed", exc, level="warning", connector=connector.name,
                error_type=type(exc).__name__,
            )
            result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
        finally:
            call_deadline.reset(token)
        return await self._finish(tenant_id, executing, connector, result)

    async def _finish(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, result: ConnectorResult
    ) -> str:
        """Write the connector's outcome (and verification schedule) with its audit entry; returns the new status.

        ``deferred`` keeps the row ``executing``, hands it to the scheduler
        and returns ``executing``.
        """
        if executing.connector in STATEFUL_CONNECTORS:
            # A failure the connector did not describe keeps what the row's checkpoints show was done.
            result = with_progress(executing.action_type, result, executing.external_ref)
        detail = bounded_detail(result.detail)
        if result.status == "deferred":
            return await self._defer(tenant_id, executing, connector, result, detail)
        status = result.status if result.status in ("succeeded", "failed", "dry_run") else "failed"
        changes: Dict[str, Any] = {}
        if result.external_ref is not None:
            changes["external_ref"] = result.external_ref
        if status == "succeeded" and result.verify is not None:
            ceiling_s = float(self._settings.response.verify_max_s)
            changes["verification"] = verification_write(result.verify, now=datetime.now(UTC), ceiling_s=ceiling_s)
        try:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                final = await self._repos.actions.transition(
                    tenant_id, executing.id, status, expected_from="executing", result=detail, conn=conn, **changes
                )
                await self._ledger.record_transition(
                    tenant_id, final, f"response_action.{status}", {"connector": connector.name}, conn=conn
                )
                if final.verification == "verified":
                    await self._ledger.record_verification_outcome(tenant_id, final, conn=conn)
        except (AlreadyInState, InvalidTransition):
            # Settled elsewhere meanwhile (a lost lease): the ledger keeps the other outcome.
            log.warning("response.finish_lost", action_type=executing.action_type)
            return (await self._repos.actions.get(tenant_id, executing.id)).status
        await self._ledger.publish_action(tenant_id, final)
        return final.status

    async def _defer(
        self,
        tenant_id: str,
        executing: ResponseAction,
        connector: Connector,
        result: ConnectorResult,
        detail: Mapping[str, Any],
    ) -> str:
        retry_after = float(result.retry_after_s or 30.0)
        try:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                deferred = await self._repos.actions.defer(
                    tenant_id,
                    executing.id,
                    retry_after_s=retry_after,
                    detail=detail,
                    external_ref=result.external_ref if result.external_ref is not None else UNSET,
                    conn=conn,
                )
                await self._ledger.audit_action(
                    tenant_id, deferred, "response_action.deferred",
                    {"connector": connector.name, "retry_after_s": round(retry_after, 1),
                     "reason": detail.get("deferred")},
                    actor_type="system", actor_id=SCHEDULER_ACTOR, conn=conn,
                )
        except (AlreadyInState, InvalidTransition):
            return (await self._repos.actions.get(tenant_id, executing.id)).status
        log.info("response.deferred", action_type=executing.action_type, retry_after_s=round(retry_after, 1))
        await self._ledger.publish_action(tenant_id, deferred)
        return deferred.status
