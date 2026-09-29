"""Human review: claiming and deciding escalations, approving and rejecting response actions.

This is what the API's escalation and action endpoints call (contract
section 10). Every method authorises the caller's role, records the change
(with optimistic locking where the contract asks for it), writes the audit
trail and publishes events, and returns the resume messages the caller must
enqueue with :meth:`WorkQueue.enqueue_resume
<lg_sotf.queue.producer.WorkQueue.enqueue_resume>` **after** the call returns
(the database changes are committed by then)::

    for alert_id, payload in await review.decide(...):
        await queue.enqueue_resume(tenant_id, alert_id, payload)

Roles (contract section 10): ``viewer`` may do nothing here; ``analyst``
may claim and decide escalations and approve low/medium risk actions;
``admin`` may also approve high and critical risk actions. Nobody may
approve an action whose risk level the tenant's autonomy policy disables.
Rejecting is allowed to analysts and admins for any risk.

Approval semantics are per action: approving some pending actions of an
alert leaves the others pending (the run returns to ``await_approval``)
unless ``reject_remaining=True`` is passed, which explicitly rejects the
alert's other pending actions.

A ``false_positive`` decision may create a *disabled* suppression rule
suggestion matching the alert's fingerprint (``source_feedback_id`` links it
to the analyst's feedback); an admin reviews and enables it.

Grouped escalations: the decision is recorded once and every attached alert's
run is resumed, but what it means for an attached alert is limited (see
:mod:`lg_sotf.services.escalation`): pre-approvals apply to the reviewed
(parent) alert only, and a benign decision closes an attached alert only
when it is the same detection and not more severe; otherwise the workflow
gives that alert its own escalation. ``approved_actions`` entries naming only
an action type are resolved against the parent alert's targets and stored as
explicit ``"action_type:target"`` entries, so an approval never reaches a
target the approver did not see.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, NamedTuple, Optional, Sequence, Union
from uuid import UUID

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.core.routing import BENIGN_DECISIONS
from lg_sotf.core.suppression import InvalidRule, validate_rule_match
from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.repos.escalations import DECISIONS, Escalation
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.escalation import EscalationService, own_review_reason, resolve_review_policy
from lg_sotf.services.response import (
    ACTION_CATALOG,
    ResponseService,
    approval_allowed,
    candidate_targets,
    plan_entities,
)
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Alert, Repositories, ResponseAction

log = get_logger(__name__)

ROLES = ("viewer", "analyst", "admin")
REVIEWER_ROLES = frozenset({"analyst", "admin"})
MAX_NOTES_CHARS = 4_000
MAX_APPROVED_ACTIONS = 50
# Per entry, as the workflow's resume payload accepts it.
MAX_APPROVED_ENTRY_CHARS = 256
MAX_ACTION_IDS = 100
_ALERT_KEYS_SQL = "SELECT id, fingerprint, severity FROM alerts WHERE tenant_id = $1 AND id = ANY($2::text[])"
# EscalationsRepo.decide accepts only open/claimed escalations; a late decision on an expired one.
_DECIDE_EXPIRED_SQL = """
    UPDATE escalations
    SET status = 'decided', decision = $4, decided_by = $5, decision_notes = $6, approved_actions = $7,
        decided_at = $8, claimed_at = COALESCE(claimed_at, $8), assigned_to = COALESCE(assigned_to, $5),
        version = version + 1
    WHERE tenant_id = $1 AND id = $2 AND status = 'expired' AND version = $3
    RETURNING *
"""
SUPPRESSION_SUGGESTION_DAYS = 90
FEEDBACK_FIELDS = ("confidence", "triage_correct", "correlation_helpful", "analysis_accurate")


class ReviewError(ValueError):
    """The request is invalid (message is safe to return to the client)."""


class ReviewDenied(PermissionError):
    """The caller's role does not allow this (message is safe to return to the client)."""


class ResumeRequest(NamedTuple):
    """A resume message to enqueue: ``queue.enqueue_resume(tenant_id, alert_id, payload)``."""

    alert_id: str
    payload: Dict[str, Any]


class DecisionResult(List[ResumeRequest]):
    """The resume messages of a decision (a list), plus what else the decision produced.

    ``approved_actions``: the pre-approvals as recorded (explicit
    ``"action_type:target"`` entries for the escalation's own alert).
    ``own_review_alert_ids``: attached alerts the decision will not close
    because they are a different detection or more severe; the workflow gives
    each its own escalation when it resumes.
    """

    def __init__(
        self,
        requests: Sequence[ResumeRequest],
        *,
        escalation: Escalation,
        feedback_id: Optional[str],
        suppression_suggestion_id: Optional[str],
        approved_actions: Sequence[str] = (),
        own_review_alert_ids: Sequence[str] = (),
    ) -> None:
        super().__init__(requests)
        self.escalation = escalation
        self.feedback_id = feedback_id
        self.suppression_suggestion_id = suppression_suggestion_id
        self.approved_actions = list(approved_actions)
        self.own_review_alert_ids = list(own_review_alert_ids)


@dataclass(frozen=True)
class _ActionCheck:
    action: ResponseAction
    autonomy: str


def _user_uuid(user: Union[UUID, str]) -> UUID:
    if isinstance(user, UUID):
        return user
    try:
        return UUID(str(user))
    except ValueError as exc:
        raise ReviewError("user must be a user id (UUID)") from exc


def _require_role(role: str, allowed: frozenset[str] = REVIEWER_ROLES) -> str:
    if role not in ROLES:
        raise ReviewError(f"unknown role {str(role)[:32]!r}")
    if role not in allowed:
        raise ReviewDenied(f"role {role!r} may not review escalations or actions")
    return role


class ReviewService:
    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        events: Optional[EventPublisher] = None,
        *,
        responses: Optional[ResponseService] = None,
    ) -> None:
        self._repos = repos
        self._settings = settings
        self._events = events
        self._audit = AuditLogger(repos)
        self._responses = responses or ResponseService(repos, settings, events)

    # ------------------------------------------------------------ escalations

    async def claim(
        self,
        tenant_id: str,
        escalation_id: str,
        user: Union[UUID, str],
        expected_version: int,
        *,
        role: str = "analyst",
        now: Optional[datetime] = None,
    ) -> Escalation:
        """Assign the escalation to ``user``. :class:`~lg_sotf.db.errors.Conflict` when the version moved."""
        _require_role(role)
        user_id = _user_uuid(user)
        current = await self._repos.escalations.get(tenant_id, escalation_id)
        if current.status == "claimed" and current.assigned_to not in (None, user_id) and role != "admin":
            raise ReviewDenied("the escalation is claimed by another analyst; only an admin may take it over")
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            claimed = await self._repos.escalations.claim(
                tenant_id, escalation_id, user_id, expected_version, now=now, conn=conn
            )
            await self._audit.record(
                tenant_id,
                "escalation.claimed" if current.assigned_to in (None, user_id) else "escalation.reassigned",
                "escalation",
                escalation_id,
                actor_type="user",
                actor_id=str(user_id),
                details={"alert_id": claimed.alert_id, "version": claimed.version, "previous_assignee": _s(current.assigned_to)},
                conn=conn,
            )
        await self._publish_escalation(tenant_id, claimed, {"status": claimed.status, "assigned_to": str(user_id)})
        return claimed

    async def decide(
        self,
        tenant_id: str,
        escalation_id: str,
        user: Union[UUID, str],
        role: str,
        decision: str,
        notes: Optional[str],
        approved_actions: Sequence[str],
        expected_version: int,
        *,
        feedback: Optional[Mapping[str, Any]] = None,
        suggest_suppression: Optional[bool] = None,
        now: Optional[datetime] = None,
    ) -> DecisionResult:
        """Record the analyst decision and return one resume message per waiting alert.

        The escalation's own alert and every attached alert are resumed with
        the decision (what it means for attached alerts is limited, see the
        module docstring and :attr:`DecisionResult.own_review_alert_ids`).
        ``approved_actions`` (``"action_type"`` or ``"action_type:target"``)
        pre-approves actions for the escalation's own alert only and only
        with ``true_positive``; a bare ``"action_type"`` is resolved to that
        alert's targets. Entries above the caller's approval authority are
        refused (:class:`ReviewDenied`). ``feedback`` may carry
        ``confidence`` (0-100), ``triage_correct``, ``correlation_helpful``
        and ``analysis_accurate``.

        An escalation the SLA sweep *expired* can still be decided (the
        alert's run keeps waiting on it); the audit entry records
        ``after_sla_expiry``. Decided and cancelled escalations cannot.
        """
        _require_role(role)
        user_id = _user_uuid(user)
        now = now or datetime.now(UTC)
        if decision not in DECISIONS:
            raise ReviewError(f"decision must be one of {', '.join(DECISIONS)}")
        notes = (notes or "").strip()[:MAX_NOTES_CHARS] or None
        requested = [str(a).strip() for a in approved_actions if str(a).strip()]
        if len(requested) > MAX_APPROVED_ACTIONS:
            raise ReviewError(f"at most {MAX_APPROVED_ACTIONS} approved actions")
        if requested and decision != "true_positive":
            raise ReviewError("approved_actions are only accepted with a true_positive decision")
        extra = self._feedback_fields(feedback)

        tenant = await self._repos.tenants.get(tenant_id)
        policy = self._responses.policy(tenant.settings)
        for entry in requested:
            action_type, sep, target = entry.partition(":")
            spec = ACTION_CATALOG.get(action_type)
            if spec is None:
                raise ReviewError(f"unknown action type {action_type[:64]!r}")
            if sep and not target.strip():
                raise ReviewError(f"approved action {action_type!r} names an empty target")
            if len(entry) > MAX_APPROVED_ENTRY_CHARS:
                raise ReviewError(f"approved action entries are at most {MAX_APPROVED_ENTRY_CHARS} characters")
            if not approval_allowed(spec.risk, role, policy.autonomy.get(spec.risk)):
                raise ReviewDenied(f"role {role!r} may not approve {spec.risk} risk action {action_type!r}")

        current = await self._repos.escalations.get(tenant_id, escalation_id)
        if current.status == "claimed" and current.assigned_to not in (None, user_id) and role != "admin":
            raise ReviewDenied("the escalation is claimed by another analyst")
        late = current.status == "expired"
        started = current.claimed_at or current.created_at
        duration = max(0, int((now - started).total_seconds())) if started else None
        approved = await self._resolve_approvals(tenant_id, current.alert_id, requested)

        suggestion_id: Optional[str] = None
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            if late:
                decided = await self._decide_expired(
                    tenant_id, escalation_id, decision, user_id, expected_version, notes, approved, now, conn
                )
            else:
                decided = await self._repos.escalations.decide(
                    tenant_id,
                    escalation_id,
                    decision=decision,
                    decided_by=user_id,
                    expected_version=expected_version,
                    notes=notes,
                    approved_actions=approved,
                    now=now,
                    conn=conn,
                )
            fb, _ = await self._repos.feedback.create(
                tenant_id,
                escalation_id,
                decided.alert_id,
                decision,
                user_id=user_id,
                notes=notes,
                review_duration_s=duration,
                conn=conn,
                **extra,
            )
            own_review = await self._own_review(tenant_id, decided, decision, conn)
            await self._audit.record(
                tenant_id,
                "escalation.decided",
                "escalation",
                escalation_id,
                actor_type="user",
                actor_id=str(user_id),
                details={
                    "alert_id": decided.alert_id,
                    "decision": decision,
                    "role": role,
                    "attached_alerts": len(decided.related_alert_ids),
                    "approved_actions": approved[:20],
                    "own_review_alerts": len(own_review),
                    "version": decided.version,
                    "after_sla_expiry": late,
                },
                conn=conn,
            )
            if decision == "false_positive" and self._suggest(tenant.settings, suggest_suppression):
                suggestion_id = await self._suggest_suppression(tenant_id, decided, fb.id, user_id, now, conn)

        requests = [
            ResumeRequest(
                alert_id,
                {
                    "type": "analyst_decision",
                    "escalation_id": escalation_id,
                    "decision": decision,
                    # Pre-approvals name the reviewed alert's targets: attached alerts never receive them.
                    "approved_actions": approved if alert_id == decided.alert_id else [],
                    "decided_by": str(user_id),
                    "notes": notes or "",
                    "approver_role": role,
                },
            )
            for alert_id in EscalationService.alerts_to_resume(decided)
        ]
        for request in requests:
            await publish_event(
                self._events,
                "escalation.updated",
                tenant_id,
                request.alert_id,
                {"escalation_id": escalation_id, "status": decided.status, "decision": decision},
            )
        log.info(
            "review.decided", decision=decision, resumes=len(requests), own_review=len(own_review),
            suggestion=suggestion_id is not None,
        )
        return DecisionResult(
            requests,
            escalation=decided,
            feedback_id=fb.id,
            suppression_suggestion_id=suggestion_id,
            approved_actions=approved,
            own_review_alert_ids=own_review,
        )

    @staticmethod
    async def _decide_expired(
        tenant_id: str,
        escalation_id: str,
        decision: str,
        user_id: UUID,
        expected_version: int,
        notes: Optional[str],
        approved: Sequence[str],
        now: datetime,
        conn: Any,
    ) -> Escalation:
        """Record a decision on an escalation the SLA sweep expired (same optimistic lock as an active one).

        Expiry only means the SLA was missed: the alert's run still waits on
        this escalation, so refusing the decision would strand the alert.
        """
        row = await conn.fetchrow(
            _DECIDE_EXPIRED_SQL, tenant_id, escalation_id, expected_version, decision, user_id, notes, list(approved), now
        )
        if row is not None:
            return Escalation.model_validate(dict(row))
        current = await conn.fetchrow("SELECT status, version FROM escalations WHERE tenant_id = $1 AND id = $2", tenant_id, escalation_id)
        if current is None:
            raise NotFound("escalation", escalation_id)
        if current["version"] != expected_version:
            raise Conflict(
                f"escalation {escalation_id} was modified (version {current['version']}, expected {expected_version})"
            )
        raise InvalidTransition("escalation", escalation_id, str(current["status"]), "decided")

    async def _resolve_approvals(self, tenant_id: str, alert_id: str, requested: Sequence[str]) -> List[str]:
        """Explicit ``action_type:target`` entries; a bare type becomes one entry per target the planner proposes."""
        entities: Dict[str, List[str]] = {}
        if any(":" not in entry for entry in requested):
            alert: Alert = await self._repos.alerts.get(tenant_id, alert_id)
            canonical: Dict[str, Any] = dict(alert.normalized)
            canonical.setdefault("raw", alert.raw)
            entities = plan_entities(canonical)
        resolved: List[str] = []
        for entry in requested:
            action_type, sep, _ = entry.partition(":")
            if sep:
                resolved.append(entry)
                continue
            for candidate in candidate_targets(action_type, entities, alert_id):
                item = f"{action_type}:{candidate}"
                if len(item) > MAX_APPROVED_ENTRY_CHARS:
                    log.warning("review.approval_target_too_long", action_type=action_type)
                    continue
                resolved.append(item)
        resolved = list(dict.fromkeys(resolved))
        if len(resolved) > MAX_APPROVED_ACTIONS:
            raise ReviewError(f"at most {MAX_APPROVED_ACTIONS} approved actions after resolving targets")
        return resolved

    async def _own_review(self, tenant_id: str, escalation: Escalation, decision: str, conn: Any) -> List[str]:
        """Attached alerts a benign ``decision`` will not close (predicts the workflow's decision scope)."""
        attached = [a for a in escalation.related_alert_ids if a != escalation.alert_id]
        if not attached or decision not in BENIGN_DECISIONS:
            return []
        rows = {r["id"]: r for r in await conn.fetch(_ALERT_KEYS_SQL, tenant_id, [escalation.alert_id, *attached])}
        parent = rows.get(escalation.alert_id)
        out: List[str] = []
        for alert_id in attached:
            row = rows.get(alert_id)
            reason = own_review_reason(
                decision,
                parent_fingerprint=parent["fingerprint"] if parent else None,
                parent_severity=parent["severity"] if parent else None,
                fingerprint=row["fingerprint"] if row else None,
                severity=row["severity"] if row else None,
            )
            if reason is not None:
                out.append(alert_id)
        return out

    @staticmethod
    def _feedback_fields(feedback: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in (feedback or {}).items():
            if key not in FEEDBACK_FIELDS:
                raise ReviewError(f"unknown feedback field {str(key)[:32]!r}")
            if value is None:
                continue
            if key == "confidence":
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                    raise ReviewError("feedback confidence must be an integer 0-100")
            elif not isinstance(value, bool):
                raise ReviewError(f"feedback {key} must be true or false")
            out[key] = value
        return out

    def _suggest(self, tenant_settings: Mapping[str, Any], requested: Optional[bool]) -> bool:
        if requested is not None:
            return requested
        return resolve_review_policy(tenant_settings, self._settings).suggest_suppressions

    async def _suggest_suppression(
        self, tenant_id: str, escalation: Escalation, feedback_id: str, user_id: UUID, now: datetime, conn: Any
    ) -> Optional[str]:
        """A disabled rule matching the alert's fingerprint (and source), for an admin to review and enable."""
        alert = await self._repos.alerts.get(tenant_id, escalation.alert_id, conn=conn)
        if not alert.fingerprint:
            return None
        match: Dict[str, Any] = {"fingerprint": alert.fingerprint, "source_id": alert.source_id}
        try:
            validate_rule_match(match)
        except InvalidRule:
            log.warning("review.suppression_suggestion_invalid")
            return None
        rule = await self._repos.suppressions.create(
            tenant_id,
            f"Suggested from false positive: {alert.title}"[:200],
            match,
            created_by=user_id,
            source_feedback_id=feedback_id,
            expires_at=now + timedelta(days=SUPPRESSION_SUGGESTION_DAYS),
            enabled=False,
            conn=conn,
        )
        await self._audit.record(
            tenant_id,
            "suppression.suggested",
            "suppression_rule",
            rule.id,
            actor_type="user",
            actor_id=str(user_id),
            details={"alert_id": alert.id, "escalation_id": escalation.id, "enabled": False},
            conn=conn,
        )
        return rule.id

    # ---------------------------------------------------------------- actions

    async def approve_actions(
        self,
        tenant_id: str,
        action_ids: Sequence[Union[UUID, str]],
        user: Union[UUID, str],
        role: str,
        *,
        reject_remaining: bool = False,
    ) -> List[ResumeRequest]:
        """Approve pending actions (all or none: every action is authorised first).

        Returns one ``approval`` resume message per affected alert. With
        ``reject_remaining`` the alerts' other pending actions are rejected.
        Actions already approved are accepted again without change.
        """
        _require_role(role)
        user_id = _user_uuid(user)
        checks = await self._load(tenant_id, action_ids)
        for check in checks:
            action = check.action
            if action.status in ("approved", "executing", "succeeded", "failed", "dry_run"):
                continue
            if action.status != "awaiting_approval":
                raise InvalidTransition("response action", action.id, action.status, "approved")
            if not approval_allowed(action.risk_level, role, check.autonomy):
                reason = "disabled by the tenant's autonomy policy" if check.autonomy == "disabled" else f"above the {role} role's authority"
                raise ReviewDenied(f"{action.risk_level} risk action {action.action_type!r} cannot be approved: {reason}")
        approved: Dict[str, List[str]] = {}
        changed: List[ResponseAction] = []
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            for check in checks:
                action = check.action
                approved.setdefault(action.alert_id, [])
                if action.status == "awaiting_approval":
                    updated = await self._repos.actions.transition(
                        tenant_id, action.id, "approved", expected_from="awaiting_approval",
                        approved_by=str(user_id), conn=conn,
                    )
                    await self._responses.record_transition(
                        tenant_id, updated, "response_action.approved",
                        {"decided_by": str(user_id), "role": role}, actor_type="user", actor_id=str(user_id), conn=conn,
                    )
                    changed.append(updated)
                approved[action.alert_id].append(str(action.id))
            rejected: Dict[str, List[str]] = {}
            if reject_remaining:
                named = {str(c.action.id) for c in checks}
                for alert_id in approved:
                    for other in await self._pending_for_alert(tenant_id, alert_id, conn):
                        if str(other.id) in named:
                            continue
                        updated = await self._reject(tenant_id, other, user_id, role, "rejected_with_remaining", conn)
                        changed.append(updated)
                        rejected.setdefault(alert_id, []).append(str(other.id))
        for action in changed:
            await self._responses.publish_action(tenant_id, action)
        return [
            ResumeRequest(
                alert_id,
                {
                    "type": "approval",
                    "approved_action_ids": ids,
                    "rejected_action_ids": rejected.get(alert_id, []),
                    "decided_by": str(user_id),
                    "reject_remaining": reject_remaining,
                },
            )
            for alert_id, ids in approved.items()
        ]

    async def reject_actions(
        self,
        tenant_id: str,
        action_ids: Sequence[Union[UUID, str]],
        user: Union[UUID, str],
        role: str,
        *,
        reject_remaining: bool = False,
    ) -> List[ResumeRequest]:
        """Reject pending actions; returns one ``approval`` resume message per affected alert."""
        _require_role(role)
        user_id = _user_uuid(user)
        checks = await self._load(tenant_id, action_ids)
        for check in checks:
            if check.action.status not in ("awaiting_approval", "rejected"):
                raise InvalidTransition("response action", check.action.id, check.action.status, "rejected")
        rejected: Dict[str, List[str]] = {}
        changed: List[ResponseAction] = []
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            for check in checks:
                action = check.action
                if action.status == "awaiting_approval":
                    changed.append(await self._reject(tenant_id, action, user_id, role, "rejected_by_reviewer", conn))
                rejected.setdefault(action.alert_id, []).append(str(action.id))
            if reject_remaining:
                named = {str(c.action.id) for c in checks}
                for alert_id in list(rejected):
                    for other in await self._pending_for_alert(tenant_id, alert_id, conn):
                        if str(other.id) not in named:
                            changed.append(await self._reject(tenant_id, other, user_id, role, "rejected_with_remaining", conn))
                            rejected[alert_id].append(str(other.id))
        for action in changed:
            await self._responses.publish_action(tenant_id, action)
        return [
            ResumeRequest(
                alert_id,
                {
                    "type": "approval",
                    "approved_action_ids": [],
                    "rejected_action_ids": ids,
                    "decided_by": str(user_id),
                    "reject_remaining": reject_remaining,
                },
            )
            for alert_id, ids in rejected.items()
        ]

    async def _reject(
        self, tenant_id: str, action: ResponseAction, user_id: UUID, role: str, reason: str, conn: Any
    ) -> ResponseAction:
        updated = await self._repos.actions.transition(
            tenant_id, action.id, "rejected", expected_from="awaiting_approval", blocked_reason=reason, conn=conn
        )
        await self._responses.record_transition(
            tenant_id, updated, "response_action.rejected",
            {"decided_by": str(user_id), "role": role}, actor_type="user", actor_id=str(user_id), conn=conn,
        )
        return updated

    async def _pending_for_alert(self, tenant_id: str, alert_id: str, conn: Any) -> List[ResponseAction]:
        page = await self._repos.actions.list(
            tenant_id, status="awaiting_approval", alert_id=alert_id, limit=200, conn=conn
        )
        return list(page.items)

    async def _load(self, tenant_id: str, action_ids: Sequence[Union[UUID, str]]) -> List[_ActionCheck]:
        if not action_ids:
            raise ReviewError("no action ids given")
        if len(action_ids) > MAX_ACTION_IDS:
            raise ReviewError(f"at most {MAX_ACTION_IDS} actions per request")
        try:
            ids = list(dict.fromkeys(i if isinstance(i, UUID) else UUID(str(i)) for i in action_ids))
        except ValueError as exc:
            raise ReviewError("action ids must be UUIDs") from exc
        actions = await self._repos.actions.get_many(tenant_id, ids)
        found = {a.id for a in actions}
        missing = [i for i in ids if i not in found]
        if missing:
            raise NotFound("response action", missing[0])
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self._responses.policy(tenant.settings)
        return [_ActionCheck(a, policy.autonomy.get(a.risk_level, "approval")) for a in actions]

    async def _publish_escalation(self, tenant_id: str, escalation: Escalation, data: Mapping[str, Any]) -> None:
        for alert_id in EscalationService.alerts_to_resume(escalation):
            await publish_event(
                self._events, "escalation.updated", tenant_id, alert_id, {"escalation_id": escalation.id, **data}
            )


def _s(value: Any) -> Optional[str]:
    return None if value is None else str(value)
