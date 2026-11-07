"""The action ledger's write side: every transition with its audit entry, integration event and live update.

:meth:`ActionLedger.transition_audited` makes a ledger transition and its
audit entry in one transaction (an integration event for the statuses in
:data:`ACTION_EVENTS` commits with them) and publishes the live update after
commit. :meth:`ActionLedger.record_transition` and
:meth:`ActionLedger.audit_action` write the audit entry of a change made in a
caller's transaction (the review and rollback services use them through
:class:`~lg_sotf.services.response.ResponseService`), and
:meth:`ActionLedger.record_verification_outcome` the audit, timeline entry
and outbox event of a final verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db import Connection
from lg_sotf.domain.events import EventPublisher, publish_event
from lg_sotf.integrations.events import (
    ACTION_AWAITING_APPROVAL,
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_VERIFICATION_FAILED,
)
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.observability.metrics import record_action

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories, ResponseAction


# Ledger statuses that raise an integration event (lg_sotf.integrations), written with their audit entry.
ACTION_EVENTS: Dict[str, str] = {
    "awaiting_approval": ACTION_AWAITING_APPROVAL,
    "succeeded": ACTION_EXECUTED,
    "dry_run": ACTION_EXECUTED,
    "failed": ACTION_FAILED,
}

SCHEDULER_ACTOR = "scheduler"


class ActionLedger:
    """Ledger transitions and their audit entries, integration events and live updates (module docstring)."""

    def __init__(self, repos: Repositories, events: Optional[EventPublisher] = None) -> None:
        self._repos = repos
        self._events = events
        self._audit = AuditLogger(repos)

    async def record_verification_outcome(
        self, tenant_id: str, action: ResponseAction, *, conn: Connection, notify: bool = True
    ) -> None:
        """Audit, timeline entry and (failed or inconclusive) outbox event of a final verification, in ``conn``'s tx.

        ``notify=False`` (an outcome that is not news, e.g. a verification
        ended by the action's rollback) writes the audit entry only.
        """
        state = action.verification
        detail = dict(action.verification_detail or {})
        reason = detail.get("reason") if isinstance(detail.get("reason"), str) else None
        audit_action = {
            "verified": "response_action.verified",
            "failed": "response_action.verification_failed",
            "inconclusive": "response_action.verification_inconclusive",
        }.get(str(state))
        if audit_action is None:
            return
        await self.audit_action(
            tenant_id, action, audit_action, {"outcome": state, "detail": detail}, actor_type="system",
            actor_id=SCHEDULER_ACTOR, conn=conn,
        )
        if not notify:
            return
        await self._repos.alert_events.append(
            tenant_id,
            action.alert_id,
            "action.verified" if state == "verified" else "action.verification_failed",
            actor_type="system",
            actor_id=SCHEDULER_ACTOR,
            data={"action_id": str(action.id), "action_type": action.action_type, "outcome": state, "reason": reason},
            conn=conn,
        )
        if state in ("failed", "inconclusive"):
            await enqueue_event(
                conn,
                tenant_id,
                ACTION_VERIFICATION_FAILED,
                alert_id=action.alert_id,
                dedupe_key=f"{ACTION_VERIFICATION_FAILED}:{action.id}:{action.verify_attempts}",
                action=action,
            )

    async def transition_audited(
        self,
        tenant_id: str,
        action_id: Any,
        to_status: str,
        *,
        audit_action: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        **changes: Any,
    ) -> ResponseAction:
        """A ledger transition and its audit entry in one transaction; the event is published after commit.

        If the audit append fails the transition rolls back too, so a retry
        repeats both: the audit trail never misses a transition that happened.
        """
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            updated = await self._repos.actions.transition(tenant_id, action_id, to_status, conn=conn, **changes)
            await self.record_transition(
                tenant_id, updated, audit_action or f"response_action.{to_status}", details or {},
                actor_type=actor_type, actor_id=actor_id, conn=conn,
            )
        await self.publish_action(tenant_id, updated)
        return updated

    async def audit_action(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str,
        actor_id: Optional[str],
        conn: Connection,
    ) -> None:
        """An audit entry about an action without a status event (hand-offs, deferrals, verification, requests)."""
        await self._audit.record(
            tenant_id,
            audit_action,
            "response_action",
            str(action.id),
            actor_type=actor_type,
            actor_id=actor_id,
            details={
                "alert_id": action.alert_id,
                "action_type": action.action_type,
                "risk_level": action.risk_level,
                "status": action.status,
                **dict(details),
            },
            conn=conn,
        )

    async def record_transition(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        event_type = ACTION_EVENTS.get(action.status)
        if conn is None and event_type is not None:
            # The integration event must commit with the audit entry: give both one transaction.
            async with self._repos.db.tenant_tx(tenant_id) as scoped:
                await self.record_transition(
                    tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=scoped
                )
            await self.publish_action(tenant_id, action)
            return
        assert conn is not None  # every caller passes its transaction (AuditLogger.record refuses None)
        await self._audit.record(
            tenant_id,
            audit_action,
            "response_action",
            str(action.id),
            actor_type=actor_type,
            actor_id=(actor_id or ("workflow" if actor_type == "agent" else None)),
            details={
                "alert_id": action.alert_id,
                "action_type": action.action_type,
                "risk_level": action.risk_level,
                "status": action.status,
                "blocked_reason": action.blocked_reason,
                **dict(details),
            },
            conn=conn,
        )
        if event_type is not None:
            await enqueue_event(
                conn,
                tenant_id,
                event_type,
                alert_id=action.alert_id,
                dedupe_key=f"{event_type}:{action.id}",
                action=action,
            )
        # Inside a caller's transaction the caller publishes after commit (publish_action).
        record_action(action.action_type, action.status)

    async def publish_action(self, tenant_id: str, action: ResponseAction) -> None:
        await publish_event(
            self._events,
            "action.updated",
            tenant_id,
            action.alert_id,
            {"action_id": str(action.id), "action_type": action.action_type, "status": action.status},
        )
