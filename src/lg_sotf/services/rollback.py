"""Rolling back an executed response action: a new ledger row of the inverse type.

A rollback never edits the original row. :meth:`RollbackService.request`
proposes a row of ``ACTION_CATALOG[type].inverse`` (``release_host`` for
``isolate_host``, ``unblock_ip`` for ``block_ip`` ...) with the same alert
and target and ``rollback_of`` set, pinned to the original's connector and
integration, and always executed by the scheduler. It goes through the
normal rules: the guardrails with the restorative exemptions (undoing our
own change stays possible after an asset became protected), autonomy for
the inverse's own risk, and the role/risk approval rules (the requester's
approval counts when their role may approve that risk; otherwise the row
waits for an admin, and the ``action.awaiting_approval`` event lets Slack
approvers act on it).

Eligibility (:meth:`RollbackService.eligibility`), with the reason code
when a rollback is not available:

* the original ``succeeded``, or ``failed`` with ``external_ref.partial``
  (``not_executed``);
* it is not itself a rollback (``is_rollback``; rollback of a rollback is
  not supported);
* its type has an inverse (``irreversible``);
* the connector supports it: the webhook always (the SOAR undoes it), the
  Microsoft connector when ``external_ref.reversible`` (else
  ``nothing_changed`` when the action changed nothing, e.g. the host was
  already isolated, or ``irreversible``), before
  ``external_ref.rollback_until`` (``window_expired``) and while the
  integration it is pinned to still exists (``integration_gone``: a
  rollback is pinned to it and a re-created integration is another one);
  any other connector: ``connector_unsupported``;
* no live rollback exists (``rollback_exists``).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional, Tuple
from uuid import UUID

from lg_sotf.domain.actions import guardrail_result
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.response import (
    ACTION_CATALOG,
    ActionRequestError,
    Disposition,
    GuardrailBlock,
    ResponseService,
    approval_allowed,
    check_guardrails,
)

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

log = get_logger(__name__)

ROLLBACK_REASONS: Mapping[str, str] = {
    "not_executed": "only a succeeded action (or a partially failed one) can be rolled back",
    "is_rollback": "a rollback cannot itself be rolled back",
    "irreversible": "this action cannot be undone",
    "nothing_changed": "the action changed nothing, so there is nothing to undo",
    "window_expired": "the rollback window of this action has passed",
    "rollback_exists": "a rollback of this action already exists",
    "connector_unsupported": "the connector that executed this action cannot roll it back",
    "integration_gone": "the Microsoft integration that executed this action was deleted; undo it in Microsoft",
}
ROLLBACK_CONNECTORS = frozenset({"webhook", "microsoft"})
MAX_REASON_CHARS = 500


@dataclass(frozen=True)
class RollbackEligibility:
    """Whether an action can be rolled back now; ``action_type``/``risk`` of its inverse when it has one."""

    available: bool
    action_type: Optional[str] = None
    risk: Optional[str] = None
    until: Optional[datetime] = None
    reason: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def dispose_rollback(
    guard: Optional[GuardrailBlock], *, risk: str, role: str, autonomy: Optional[str], approve: bool, requester: str
) -> Disposition:
    """A rollback request's status: blocked by a guardrail, approved by the requester when their role may
    approve ``risk`` (and ``approve`` is set), else awaiting an approval."""
    if guard is not None:
        return Disposition("blocked", f"blocked: {guard.explanation}")
    if approve and approval_allowed(risk, role, autonomy):
        return Disposition(
            "approved", f"approved: rollback requested and approved by {requester} ({risk} risk)", requester
        )
    return Disposition(
        "awaiting_approval", f"awaiting approval: rolling back needs an approval for {risk} risk",
        approval_reason="admin_approval_required" if approve else "rollback_review",
    )


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class RollbackService:
    """Eligibility and rollback requests (see the module docstring)."""

    def __init__(self, responses: ResponseService) -> None:
        self._responses = responses
        self._repos = responses.repos

    def eligibility(
        self, action: ResponseAction, live_rollback: Optional[ResponseAction], *, now: datetime
    ) -> RollbackEligibility:
        spec = ACTION_CATALOG.get(action.action_type)
        inverse = spec.inverse if spec is not None else None
        inverse_spec = ACTION_CATALOG.get(inverse) if inverse else None
        risk = inverse_spec.risk if inverse_spec is not None else None
        ref = action.external_ref if isinstance(action.external_ref, Mapping) else {}
        until = _parse_time(ref.get("rollback_until"))

        def no(reason: str) -> RollbackEligibility:
            return RollbackEligibility(False, inverse, risk, until, reason)

        partial = action.status == "failed" and ref.get("partial") is True
        if action.status != "succeeded" and not partial:
            return no("not_executed")
        if action.rollback_of is not None:
            return no("is_rollback")
        if inverse is None or inverse_spec is None:
            return no("irreversible")
        if action.connector == "microsoft":
            if ref.get("reversible") is not True:
                result = action.result if isinstance(action.result, Mapping) else {}
                changed = result.get("changed")
                return no("nothing_changed" if changed is False or result.get("already") else "irreversible")
            if until is not None and until <= now:
                return no("window_expired")
            if action.integration_id is None:
                return no("integration_gone")
        elif action.connector not in ROLLBACK_CONNECTORS:
            return no("connector_unsupported")
        if live_rollback is not None:
            return no("rollback_exists")
        return RollbackEligibility(True, inverse, risk, until, None)

    async def eligibility_of(self, tenant_id: str, action: ResponseAction) -> RollbackEligibility:
        live = await self._repos.actions.live_rollback(tenant_id, action.id)
        return self.eligibility(action, live, now=datetime.now(UTC))

    async def request(
        self,
        tenant_id: str,
        action_id: UUID,
        *,
        user: UUID,
        role: str,
        reason: str,
        approve: bool = True,
    ) -> Tuple[ResponseAction, ResponseAction, bool]:
        """Propose (and, when allowed, approve) the rollback of ``action_id``: ``(rollback, original, created)``.

        An existing live rollback is returned with ``created=False``. Raises
        :class:`~lg_sotf.services.response.ActionRequestError` (409
        ``rollback_unavailable`` with the reason code) when the action cannot
        be rolled back.
        """
        reason = (reason or "").strip()[:MAX_REASON_CHARS]
        if not reason:
            raise ActionRequestError(422, "invalid_request", "a reason is required")
        requester = f"user:{user}"
        responses = self._responses
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            original = await self._repos.actions.lock(tenant_id, action_id, conn=conn)
            live = await self._repos.actions.live_rollback(tenant_id, original.id, conn=conn)
            if live is not None:
                return live, original, False
            eligibility = self.eligibility(original, None, now=datetime.now(UTC))
            if not eligibility.available or eligibility.action_type is None or eligibility.risk is None:
                code = eligibility.reason or "irreversible"
                raise ActionRequestError(409, "rollback_unavailable", ROLLBACK_REASONS.get(code, code), reason=code)
            inverse, risk = eligibility.action_type, eligibility.risk
            tenant = await self._repos.tenants.get(tenant_id, conn=conn)
            policy = responses.policy(tenant.settings)
            autonomy = policy.autonomy.get(risk)
            guard = check_guardrails(inverse, original.target, policy, restorative=True)
            params: Dict[str, Any] = {
                "rollback": {"of": str(original.id), "reason": reason, "requested_by": requester},
                "alert": original.params.get("alert"),
            }
            # What the original needed besides its target to find the object again (message match, host scope).
            for key in ("match", "scope"):
                if key in original.params:
                    params[key] = original.params[key]
            disposition = dispose_rollback(
                guard, risk=risk, role=role, autonomy=autonomy, approve=approve, requester=requester
            )
            status = disposition.status
            if disposition.approval_reason is not None:
                params["approval_reason"] = disposition.approval_reason
            params["explanation"] = disposition.explanation
            generation = await self._repos.actions.rollback_generation(tenant_id, original.id, conn=conn)
            rollback, created = await self._repos.actions.propose(
                tenant_id,
                original.alert_id,
                inverse,
                original.target,
                risk,
                params=params,
                requested_by=requester,
                status="proposed",
                rollback_of=original.id,
                scope=f"rollback:{original.id}:{generation}",
                execution_owner="scheduler",
                connector=original.connector,
                integration_id=original.integration_id,
                conn=conn,
            )
            await responses.record_transition(
                tenant_id, rollback, "response_action.proposed", {"rollback_of": str(original.id)},
                actor_type="user", actor_id=str(user), conn=conn,
            )
            if status == "blocked":
                assert guard is not None
                rollback = await self._repos.actions.transition(
                    tenant_id, rollback.id, "blocked", expected_from="proposed", blocked_reason=guard.code,
                    result=guardrail_result(guard.code, detail=guard.detail, stage="rollback"),
                    conn=conn,
                )
                await responses.record_transition(
                    tenant_id, rollback, "response_action.blocked", {"stage": "rollback"}, actor_type="user",
                    actor_id=str(user), conn=conn,
                )
            elif status == "approved":
                rollback = await self._repos.actions.transition(
                    tenant_id, rollback.id, "approved", expected_from="proposed", approved_by=requester, conn=conn
                )
                await responses.record_transition(
                    tenant_id, rollback, "response_action.approved", {"decided_by": str(user), "role": role},
                    actor_type="user", actor_id=str(user), conn=conn,
                )
            else:
                rollback = await self._repos.actions.transition(
                    tenant_id, rollback.id, "awaiting_approval", expected_from="proposed", conn=conn
                )
                await responses.record_transition(
                    tenant_id, rollback, "response_action.awaiting_approval", {"rollback_of": str(original.id)},
                    actor_type="user", actor_id=str(user), conn=conn,
                )
            await responses.audit_action(
                tenant_id, original, "response_action.rollback_requested",
                {"reason": reason, "rollback_id": str(rollback.id), "rollback_status": rollback.status, "role": role},
                actor_type="user", actor_id=str(user), conn=conn,
            )
            await self._repos.alert_events.append(
                tenant_id,
                original.alert_id,
                "action.rollback_requested",
                actor_type="user",
                actor_id=str(user),
                data={"action_id": str(original.id), "rollback_id": str(rollback.id), "action_type": inverse,
                      "status": rollback.status},
                conn=conn,
            )
        log.info("response.rollback_requested", action_type=inverse, status=rollback.status, created=created)
        await responses.publish_action(tenant_id, rollback)
        await responses.publish_action(tenant_id, original)
        return rollback, original, created


__all__ = ["ROLLBACK_REASONS", "RollbackEligibility", "RollbackService", "dispose_rollback"]
