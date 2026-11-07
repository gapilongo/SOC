"""Verification: proving by re-query that a succeeded action is in effect.

``succeeded`` means Microsoft accepted the change; ``verification`` is a
separate axis written when the connector returned a
:class:`~lg_sotf.domain.connectors.VerifyPlan`:

* ``verified``: a re-read shows the change (e.g. the account is disabled,
  the isolation machine action completed);
* ``failed``: the observed state contradicts it (the machine action ended
  ``Failed``/``TimeOut``/``Cancelled``, a synced user was re-enabled);
* ``inconclusive``: the check could not be completed (the deadline passed,
  403 on the read, invalid credentials, the integration is gone or
  disabled, no verifier);
* ``pending``: not decided yet; checked again with backoff.

The scheduler job ``verify_actions`` (:meth:`VerificationService.run_due`)
claims due checks (``FOR UPDATE SKIP LOCKED``, 120 s lease), runs at most
``response.verify_concurrency`` at a time, each within
``response.verify_check_timeout_s`` and in the tenant's scope. Verification
only reads, so the dry-run switches do not stop it. A still-pending check,
or a transient failure (throttled, Microsoft server or network errors, no
token right now), is scheduled again after
``max(retry_after_s, min(900, first_check_s * 2^attempts))`` seconds with
0.8-1.2 jitter, never past the deadline.

A final outcome writes, in one transaction, the audit entry
(``response_action.verified`` / ``.verification_failed`` /
``.verification_inconclusive``), the alert timeline entry
(``action.verified`` / ``action.verification_failed``) and, for failed or
inconclusive, the ``action.verification_failed`` integration event.

An action being rolled back (its rollback is executing or succeeded) is no
longer verified: the rollback undoes on purpose what the check would look
for. Its verification ends ``inconclusive`` with reason ``rolled_back``,
audited, without a timeline entry or an event (it is not a failure). While
the rollback is only approved, the check waits instead (a check could see
the undo begin, and the rollback may still expire or be blocked when it is
claimed): the verification stays ``pending`` (reason ``rollback_approved``)
and is checked again with the usual backoff, never past the deadline.

:meth:`VerificationService.recheck` (``POST /actions/{id}/verify``) re-opens
a final verification for one more hour of checks.
"""

from __future__ import annotations

import asyncio
import random
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from uuid import UUID

from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.repos.actions import FINAL_VERIFICATION_STATES, VerificationWrite
from lg_sotf.domain.connectors import VerificationResult
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.http import MicrosoftApiError, ReadOnlyViolation
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from lg_sotf.observability.logging import bound_context, get_logger, log_failure
from lg_sotf.services.connectors.routing import RoutingSnapshot
from lg_sotf.services.response import ActionRequestError, ResponseService, bounded_detail

log = get_logger(__name__)

CLAIM_LEASE_S = 120.0
# A rollback in these statuses is undoing (or has undone) the original: its checks would report the undo.
ROLLING_BACK_STATUSES = frozenset({"executing", "succeeded"})
# An approved rollback may still run, expire or be blocked at its claim: the original's check waits for it.
ROLLBACK_PENDING_STATUSES = frozenset({"approved"})
MAX_BACKOFF_S = 900.0
DEFAULT_FIRST_CHECK_S = 30.0
RECHECK_WINDOW_S = 3_600.0
RECHECK_MIN_INTERVAL = timedelta(minutes=5)
CREDENTIAL_ERRORS = frozenset({"credentials_invalid", "consent_missing", "app_not_in_tenant", "conditional_access_blocked"})
TRANSIENT_KINDS = frozenset({"throttled", "server", "network", "deadline"})
MAX_DETAIL_BYTES = 12 * 1024


def classify_error(exc: BaseException) -> Tuple[str, Dict[str, Any]]:
    """``("transient", detail)`` or ``("inconclusive", detail)`` for an exception raised by a verifier."""
    if isinstance(exc, MicrosoftAuthError):
        if exc.ledger_error in CREDENTIAL_ERRORS:
            return "inconclusive", {"reason": "credentials", "error": exc.ledger_error, "aadsts": exc.aadsts}
        return "transient", {"reason": exc.ledger_error, "retry_after_s": exc.retry_after_s}
    if isinstance(exc, MicrosoftApiError):
        if exc.kind == "forbidden":
            return "inconclusive", {"reason": "permission_denied", "http_status": exc.status, "ms_code": exc.code or None}
        if exc.kind in TRANSIENT_KINDS:
            return "transient", {"reason": exc.ledger_error, "http_status": exc.status or None,
                                 "retry_after_s": exc.retry_after_s}
        return "inconclusive", {"reason": exc.ledger_error, "http_status": exc.status or None, "ms_code": exc.code or None}
    if isinstance(exc, InvalidTarget):
        return "inconclusive", {"reason": exc.code}
    if isinstance(exc, ReadOnlyViolation):
        return "inconclusive", {"reason": "verifier_error", "error": "the verifier attempted a write (refused)"}
    if isinstance(exc, TimeoutError):
        return "transient", {"reason": "timeout"}
    return "transient", {"reason": "verifier_error", "error_type": type(exc).__name__}


class VerificationService:
    """Runs due verification checks and re-checks (see the module docstring)."""

    def __init__(self, responses: ResponseService, *, rand: Callable[[], float] = random.random) -> None:
        self._responses = responses
        self._repos = responses.repos
        self._settings = responses.settings
        self._rand = rand

    async def run_due(self, *, limit: int = 100) -> int:
        """Claim and run the due checks (at most ``limit``); returns how many were checked."""
        async with self._repos.db.system_tx() as conn:
            due = await self._repos.actions.claim_due_verifications(limit=limit, lease_s=CLAIM_LEASE_S, conn=conn)
        if not due:
            return 0
        slots = asyncio.Semaphore(int(self._settings.response.verify_concurrency))
        snapshots: Dict[str, asyncio.Task[RoutingSnapshot]] = {}

        async def snapshot(tenant_id: str) -> RoutingSnapshot:
            if tenant_id not in snapshots:
                snapshots[tenant_id] = asyncio.create_task(self._snapshot(tenant_id))
            return await snapshots[tenant_id]

        async def run(tenant_id: str, action_id: UUID) -> None:
            async with slots:
                with bound_context(tenant_id=tenant_id):
                    try:
                        await self.check(tenant_id, action_id, snapshot=await snapshot(tenant_id))
                    except Exception as exc:  # noqa: BLE001 - the claim lease brings it back later
                        log_failure(
                            log, "verification.check_failed", exc, level="warning", error_type=type(exc).__name__
                        )

        await asyncio.gather(*(run(t, a) for t, a in due))
        return len(due)

    async def _snapshot(self, tenant_id: str) -> RoutingSnapshot:
        tenant = await self._repos.tenants.get(tenant_id)
        return await self._responses.routing(tenant_id, tenant.settings)

    def _backoff(self, action: Any, retry_after_s: Optional[float]) -> float:
        detail = action.verification_detail if isinstance(action.verification_detail, Mapping) else {}
        try:
            first = float(detail.get("first_check_s") or DEFAULT_FIRST_CHECK_S)
        except (TypeError, ValueError):
            first = DEFAULT_FIRST_CHECK_S
        base: float = min(MAX_BACKOFF_S, max(1.0, first) * (2 ** min(int(action.verify_attempts), 20)))
        wait = max(float(retry_after_s or 0.0), base)
        return wait * (0.8 + 0.4 * self._rand())

    async def check(self, tenant_id: str, action_id: UUID, *, snapshot: Optional[RoutingSnapshot] = None) -> Any:
        """Run one check of a pending verification and record its outcome; returns the row afterwards."""
        action = await self._repos.actions.get(tenant_id, action_id)
        if action.verification != "pending":
            return action
        rollback = await self._repos.actions.live_rollback(tenant_id, action.id)
        if rollback is not None and rollback.status in ROLLING_BACK_STATUSES:
            return await self._final(
                tenant_id, action, "inconclusive", {"reason": "rolled_back", "rollback_id": str(rollback.id)},
                notify=False,
            )
        if rollback is not None and rollback.status in ROLLBACK_PENDING_STATUSES:
            waiting = {"reason": "rollback_approved", "rollback_id": str(rollback.id)}
            return await self._pending(tenant_id, action, waiting, None, datetime.now(UTC))
        if snapshot is None:
            snapshot = await self._snapshot(tenant_id)
        now = datetime.now(UTC)
        verifier = snapshot.verifier(action)
        if verifier is None:
            reason = "integration_unavailable" if action.connector == "microsoft" else "no_verifier"
            return await self._final(tenant_id, action, "inconclusive", {"reason": reason})
        timeout = float(self._settings.response.verify_check_timeout_s)
        try:
            async with asyncio.timeout(timeout):
                result: VerificationResult = await verifier.verify(action)
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified: transient or inconclusive
            kind, detail = classify_error(exc)
            if kind == "inconclusive":
                return await self._final(tenant_id, action, "inconclusive", detail)
            log.info("verification.transient", reason=detail.get("reason"))
            return await self._pending(tenant_id, action, {"last_error": detail}, detail.get("retry_after_s"), now)
        if result.state in FINAL_VERIFICATION_STATES:
            detail = dict(result.detail)
            if result.state != "verified":
                detail.setdefault("reason", "contradicted" if result.state == "failed" else "unknown")
            return await self._final(tenant_id, action, result.state, detail)
        return await self._pending(tenant_id, action, dict(result.detail), result.retry_after_s, now)

    async def _pending(
        self, tenant_id: str, action: Any, detail: Dict[str, Any], retry_after_s: Optional[float], now: datetime
    ) -> Any:
        deadline = action.verify_deadline or now
        if now >= deadline:
            return await self._final(tenant_id, action, "inconclusive", {"reason": "deadline", "last": detail})
        wait = self._backoff(action, retry_after_s)
        next_check = min(now + timedelta(seconds=wait), deadline)
        previous = action.verification_detail if isinstance(action.verification_detail, Mapping) else {}
        merged = {**{k: v for k, v in previous.items() if k == "first_check_s"}, **detail}
        write = VerificationWrite(
            "pending", bounded_detail(merged, MAX_DETAIL_BYTES), verify_after=next_check, verify_deadline=deadline
        )
        try:
            return await self._repos.actions.record_verification(tenant_id, action.id, write)
        except (InvalidTransition, NotFound):
            return await self._repos.actions.get(tenant_id, action.id)

    async def _final(
        self, tenant_id: str, action: Any, state: str, detail: Mapping[str, Any], *, notify: bool = True
    ) -> Any:
        """Record a final outcome; ``notify=False`` audits it without the timeline entry and the event."""
        write = VerificationWrite(state, bounded_detail(dict(detail), MAX_DETAIL_BYTES))  # type: ignore[arg-type]
        try:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                updated = await self._repos.actions.record_verification(tenant_id, action.id, write, conn=conn)
                await self._responses.record_verification_outcome(tenant_id, updated, conn=conn, notify=notify)
        except (InvalidTransition, NotFound):
            return await self._repos.actions.get(tenant_id, action.id)
        log.info("verification.final", action_type=updated.action_type, outcome=state, reason=detail.get("reason"))
        await self._responses.publish_action(tenant_id, updated)
        return updated

    async def recheck(self, tenant_id: str, action_id: UUID, *, user: UUID) -> Any:
        """Verify a finished Microsoft action again (one more hour of checks, starting now).

        Raises :class:`~lg_sotf.services.response.ActionRequestError`: 409
        when the action has no final verification to re-open, 429 within five
        minutes of the last verification or change.
        """
        action = await self._repos.actions.get(tenant_id, action_id)
        if (
            action.connector != "microsoft"
            or action.status != "succeeded"
            or action.verification not in FINAL_VERIFICATION_STATES
        ):
            raise ActionRequestError(
                409, "verify_unavailable", "only a succeeded Microsoft action with a finished verification can be re-checked"
            )
        now = datetime.now(UTC)
        recent = now - RECHECK_MIN_INTERVAL
        if (action.verified_at is not None and action.verified_at > recent) or action.updated_at > recent:
            raise ActionRequestError(429, "rate_limited", "the action was verified or changed less than 5 minutes ago")
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            updated = await self._repos.actions.reopen_verification(
                tenant_id, action.id, window_s=RECHECK_WINDOW_S, conn=conn
            )
            await self._responses.audit_action(
                tenant_id, updated, "response_action.verification_rechecked", {"previous": action.verification},
                actor_type="user", actor_id=str(user), conn=conn,
            )
        await self._responses.publish_action(tenant_id, updated)
        return updated


__all__ = ["VerificationService", "classify_error"]
