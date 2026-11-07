"""Analyst escalations: level, priority, SLA and grouping policy on top of the escalations repository.

Grouping
--------

When an alert needs a human and the tenant already has an open or claimed
escalation, created within the grouping window, for an alert that shares a
key indicator with it (an indicator sighting of type ip/domain/url/hash by
default; ``host`` and ``user`` are opt-in because a busy workstation or
account links unrelated detections) or has the same fingerprint, the alert is
attached to that escalation (``related_alert_ids``) instead of opening a new
one. The parent's priority and level are raised to the attached alert's if
higher and its SLA deadline moved earlier if needed; the version is bumped so
an analyst holding a stale copy gets a conflict and sees the grown case. One
decision on the parent then resumes every attached alert's run
(:meth:`alerts_to_resume`).

What an attached alert inherits from the parent's decision
(:meth:`decision_scope`, applied by the workflow's ``await_analyst`` node):

* ``true_positive`` and ``needs_more_info`` apply, but an inherited decision
  never carries pre-approved actions and never counts as analyst evidence
  for containment: the attached alert's own actions go through the normal
  autonomy policy and per-action approval.
* ``false_positive`` / ``benign_positive`` close the attached alert (and let
  the verdict cache learn its fingerprint) only when it is the same detection
  as the reviewed alert (same fingerprint) and not more severe. Otherwise the
  alert is *detached*: it gets its own escalation (:meth:`open_detached`,
  ``summary.detached_from`` = the parent) and its run waits for that
  decision, so an alert nobody looked at is never closed as benign.

``related_alert_ids`` holds only attached alerts (whose runs wait on this
escalation). Correlated alerts that merely share indicators are context and
live in ``summary["correlated_alert_ids"]``.

Grouping, creation and attachment for a tenant are serialised by a
transaction-scoped advisory lock, so two related alerts escalating at the
same moment end up in one escalation.

Policy (``tenants.settings["review"]``, all optional)::

    {"sla_minutes": {"L1": 30, "L2": 60, "L3": 120},
     "level_thresholds": {"L2": 8, "L3": 9},        # priority at or above -> level
     "min_level": {"critical": "L2"},              # per alert severity
     "grouping": {"enabled": true, "window_minutes": 60, "max_attached": 50,
                  "by_fingerprint": true, "by_indicators": true,
                  "indicator_types": ["ip", "domain", "url", "hash"]},   # + "host", "user", "process"
     "suggest_suppressions": true}

Install defaults come from ``settings.agents["human_loop"]`` (same keys;
``sla_minutes`` was already read from there). Invalid tenant values are
ignored with a warning: a bad setting never stops alerts from being escalated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db import Connection, locks
from lg_sotf.db.repos.escalations import ESCALATION_LEVELS, Escalation
from lg_sotf.domain.events import EventPublisher, publish_event
from lg_sotf.domain.routing import BENIGN_DECISIONS
from lg_sotf.integrations.events import ESCALATION_CREATED, ESCALATION_DECIDED
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.models.vocabulary import SEVERITY_RANK
from lg_sotf.models.vocabulary import EscalationLevel as Level
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)

DEFAULT_SLA_MINUTES: Dict[str, int] = {"L1": 30, "L2": 60, "L3": 120}
HIGH_PRIORITY_THRESHOLD = 8
CRITICAL_PRIORITY_THRESHOLD = 9
REASON_WEIGHTS: Dict[str, int] = {
    "high_risk": 3,
    "complex_attack": 2,
    "regulatory_compliance": 2,
    "conflicting_evidence": 1,
    "grey_zone": 1,
    "model_refused": 1,
    "inconclusive": 1,
    "policy_exception": 1,
    "analyst_request": 1,
    "response_review": 1,
    "group_review": 1,
    "false_positive_review": 0,
}
SEVERITY_WEIGHTS: Dict[str, int] = {"critical": 2, "high": 1, "medium": 0, "low": -1, "info": -2}
MAX_RELATED = 50
MAX_CORRELATED = 20
DEFAULT_KEY_INDICATOR_TYPES = ("ip", "domain", "url", "hash")
GROUPABLE_INDICATOR_TYPES = ("ip", "domain", "url", "hash", "host", "user", "process")
# Why an attached alert does not inherit a benign group decision (summary.own_review_reason).
OWN_REVIEW_REASONS: Dict[str, str] = {
    "different_fingerprint": "is a different detection than the alert that was reviewed",
    "higher_severity": "is more severe than the alert that was reviewed",
}


def compute_priority(
    *, severity: str, threat_score: float, confidence: float, correlations_count: int, reason_code: str
) -> int:
    """1-10, higher is more urgent."""
    priority = int(threat_score // 10)
    if confidence < 30:
        priority += 2
    elif confidence < 50:
        priority += 1
    if correlations_count >= 10:
        priority += 2
    elif correlations_count >= 5:
        priority += 1
    priority += REASON_WEIGHTS.get(reason_code, 0)
    priority += SEVERITY_WEIGHTS.get(severity, 0)
    return max(1, min(10, priority))


def compute_level(
    *,
    priority: int,
    threat_score: float,
    severity: str,
    reason_code: str,
    l2_threshold: int = HIGH_PRIORITY_THRESHOLD,
    l3_threshold: int = CRITICAL_PRIORITY_THRESHOLD,
) -> str:
    if priority >= l3_threshold:
        return "L3"
    if priority >= l2_threshold:
        return "L2"
    if reason_code in ("regulatory_compliance", "complex_attack") or threat_score >= 80 or severity == "critical":
        return "L2"
    return "L1"


def max_level(*levels: str) -> str:
    return max(levels, key=ESCALATION_LEVELS.index)


@dataclass(frozen=True)
class _Placement:
    """Where a new escalation goes in the queue: its priority, level and SLA deadline."""

    priority: int
    level: str
    sla_deadline: datetime


def _place(
    policy: ReviewPolicy,
    severity: str,
    threat_score: float,
    confidence: float,
    n_correlations: int,
    reason_code: str,
    now: datetime,
) -> _Placement:
    """Priority from the alert's signals, level from the tenant's thresholds, deadline from the level's SLA."""
    priority = compute_priority(
        severity=severity,
        threat_score=threat_score,
        confidence=confidence,
        correlations_count=n_correlations,
        reason_code=reason_code,
    )
    level = policy.level_for(priority=priority, threat_score=threat_score, severity=severity, reason_code=reason_code)
    return _Placement(priority, level, now + timedelta(minutes=policy.sla_minutes[level]))


class GroupingPolicy(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    enabled: bool = True
    window_minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)
    max_attached: int = Field(default=MAX_RELATED, ge=0, le=MAX_RELATED)
    by_fingerprint: bool = True
    by_indicators: bool = True
    indicator_types: Tuple[str, ...] = DEFAULT_KEY_INDICATOR_TYPES

    @field_validator("indicator_types")
    @classmethod
    def _types(cls, value: Tuple[str, ...]) -> Tuple[str, ...]:
        unknown = [t for t in value if t not in GROUPABLE_INDICATOR_TYPES]
        if unknown:
            raise ValueError(f"indicator_types must be among {', '.join(GROUPABLE_INDICATOR_TYPES)}")
        return tuple(dict.fromkeys(value))


class ReviewPolicy(BaseModel):
    """Effective review policy for one tenant (tenant ``review`` settings over install defaults)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    sla_minutes: Dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_SLA_MINUTES))
    level_thresholds: Dict[str, int] = Field(
        default_factory=lambda: {"L2": HIGH_PRIORITY_THRESHOLD, "L3": CRITICAL_PRIORITY_THRESHOLD}
    )
    min_level: Dict[str, Level] = Field(default_factory=dict)
    grouping: GroupingPolicy = GroupingPolicy()
    suggest_suppressions: bool = True

    @field_validator("sla_minutes")
    @classmethod
    def _sla(cls, value: Dict[str, int]) -> Dict[str, int]:
        merged = dict(DEFAULT_SLA_MINUTES)
        for level, minutes in value.items():
            if level not in ESCALATION_LEVELS or not 1 <= int(minutes) <= 30 * 24 * 60:
                raise ValueError("sla_minutes must map L1/L2/L3 to 1..43200 minutes")
            merged[level] = int(minutes)
        return merged

    @field_validator("level_thresholds")
    @classmethod
    def _thresholds(cls, value: Dict[str, int]) -> Dict[str, int]:
        merged = {"L2": HIGH_PRIORITY_THRESHOLD, "L3": CRITICAL_PRIORITY_THRESHOLD}
        for level, threshold in value.items():
            if level not in ("L2", "L3") or not 1 <= int(threshold) <= 11:
                raise ValueError("level_thresholds must map L2/L3 to 1..11")
            merged[level] = int(threshold)
        return merged

    def level_for(self, *, priority: int, threat_score: float, severity: str, reason_code: str) -> str:
        level = compute_level(
            priority=priority,
            threat_score=threat_score,
            severity=severity,
            reason_code=reason_code,
            l2_threshold=self.level_thresholds["L2"],
            l3_threshold=self.level_thresholds["L3"],
        )
        floor = self.min_level.get(severity)
        return max_level(level, floor) if floor else level


def _merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def resolve_review_policy(tenant_settings: Mapping[str, Any], settings: Settings) -> ReviewPolicy:
    install = settings.agents.get("human_loop") or {}
    install_keys = {k: install[k] for k in ReviewPolicy.model_fields if k in install}
    try:
        base = ReviewPolicy.model_validate(install_keys)
    except (ValidationError, ValueError, TypeError):
        log.warning("escalation.install_review_policy_invalid")
        base = ReviewPolicy()
    tenant = tenant_settings.get("review")
    if not isinstance(tenant, Mapping):
        return base
    try:
        return ReviewPolicy.model_validate(_merge(base.model_dump(), tenant))
    except (ValidationError, ValueError, TypeError):
        log.warning("escalation.tenant_review_policy_invalid")
        return base


@dataclass(frozen=True)
class EscalationTicket:
    id: str
    level: str
    priority: int
    created: bool
    sla_deadline: Optional[datetime]
    attached: bool = False
    version: int = 1


def own_review_reason(
    decision: str,
    *,
    parent_fingerprint: Optional[str],
    parent_severity: Optional[str],
    fingerprint: Optional[str],
    severity: Optional[str],
) -> Optional[str]:
    """Why an attached alert may not inherit the group's ``decision`` (a :data:`OWN_REVIEW_REASONS` key), or ``None``.

    Only benign decisions are restricted: they close the alert and teach the
    verdict cache its fingerprint, so they apply only to the same detection
    (equal, non-empty fingerprint) at the same or a lower severity. Unknown
    severities count as more severe.
    """
    if decision not in BENIGN_DECISIONS:
        return None
    if not fingerprint or fingerprint != parent_fingerprint:
        return "different_fingerprint"
    if SEVERITY_RANK.get(str(severity), len(SEVERITY_RANK)) > SEVERITY_RANK.get(str(parent_severity), -1):
        return "higher_severity"
    return None


@dataclass(frozen=True)
class DecisionScope:
    """How a decision on ``escalation`` applies to one alert whose run waits on it.

    ``inherited``: the decision was made on the group's parent alert, not on
    this one. ``own_review_reason`` set: the decision must not be applied to
    this alert, which needs its own escalation (:meth:`EscalationService.open_detached`).
    """

    escalation: Escalation
    inherited: bool
    parent_alert_id: str
    own_review_reason: Optional[str] = None


class EscalationService:
    def __init__(self, repos: Repositories, events: Optional[EventPublisher], settings: Settings) -> None:
        self._repos = repos
        self._events = events
        self._settings = settings
        self._audit = AuditLogger(repos)
        self._defaults = resolve_review_policy({}, settings)

    def sla_minutes(self, level: str) -> int:
        """Install-default SLA for ``level`` (tenants may override, see :meth:`policy`)."""
        return self._defaults.sla_minutes[level]

    async def policy(self, tenant_id: str) -> ReviewPolicy:
        tenant = await self._repos.tenants.get(tenant_id)
        return resolve_review_policy(tenant.settings, self._settings)

    async def open_or_attach(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        severity: str,
        confidence: float,
        threat_score: float,
        reason: str,
        reason_code: str = "grey_zone",
        summary: Optional[Mapping[str, Any]] = None,
        correlated_alert_ids: Sequence[str] = (),
        fingerprint: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> EscalationTicket:
        """The escalation this alert waits on: its own, one it is attached to, a related one, or a new one.

        Idempotent per tenant and alert (the node may run again on resume).
        """
        now = now or datetime.now(UTC)
        policy = await self.policy(tenant_id)
        place = _place(policy, severity, threat_score, confidence, len(correlated_alert_ids), reason_code, now)
        priority, level, deadline = place.priority, place.level, place.sla_deadline
        body = dict(summary or {})
        body["correlated_alert_ids"] = [str(a) for a in correlated_alert_ids][:MAX_CORRELATED]

        # Related alerts are only candidates (the parent lookup re-checks them under the
        # lock), so the indicator lookups run before the per-tenant grouping lock is taken:
        # the lock is held for the parent lookup and the attach/create step only.
        related = await self._related_candidates(tenant_id, alert_id, policy, now)
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.ESCALATION_GROUP, tenant_id)
            own = await self._repos.escalations.get_active_for_alert(tenant_id, alert_id, conn=conn)
            if own is not None:
                return _ticket(own, created=False)
            attached_to = await self._repos.escalations.find_attached_to(tenant_id, alert_id, conn=conn)
            if attached_to is not None:
                return _ticket(attached_to, created=False, attached=True)
            parent = await self._find_parent(conn, tenant_id, alert_id, fingerprint, policy, now, related)
            attached = await self._attach(conn, tenant_id, alert_id, parent, place) if parent is not None else None
            if attached is None:
                escalation, created = await self._repos.escalations.create_or_attach(
                    tenant_id,
                    alert_id,
                    reason=reason[:500],
                    level=level,
                    priority=priority,
                    summary=body,
                    related_alert_ids=[],
                    sla_deadline=deadline,
                    conn=conn,
                )
                if created:
                    await self._announce_created(
                        conn,
                        escalation,
                        "escalation.created",
                        {"alert_id": alert_id, "level": level, "priority": priority, "reason_code": reason_code},
                        {"confidence": confidence, "threat_score": threat_score, "verdict": body.get("verdict")},
                    )
        if attached is not None:
            await self._announce_attached(tenant_id, alert_id, attached)
            return _ticket(attached, created=False, attached=True)
        if created:
            await self._publish(
                tenant_id, "escalation.created", alert_id, {"escalation_id": escalation.id, "level": level, "priority": priority}
            )
        return _ticket(escalation, created=created)

    async def _attach(
        self, conn: Connection, tenant_id: str, alert_id: str, parent: Escalation, place: _Placement
    ) -> Optional[Escalation]:
        """Attach the alert to ``parent`` (raising its level and priority, moving its deadline earlier if needed)
        and audit it; ``None`` when ``parent`` can take no more alerts."""
        attached = await self._repos.escalations.attach(
            tenant_id,
            parent.id,
            alert_id,
            priority=place.priority,
            level=max_level(parent.level, place.level),
            sla_deadline=place.sla_deadline,
            conn=conn,
        )
        if attached is not None:
            await self._audit.record(
                tenant_id,
                "escalation.alert_attached",
                "escalation",
                attached.id,
                actor_type="agent",
                actor_id="workflow",
                details={
                    "alert_id": alert_id,
                    "parent_alert_id": attached.alert_id,
                    "attached_count": len(attached.related_alert_ids),
                    "level": attached.level,
                    "priority": attached.priority,
                },
                conn=conn,
            )
        return attached

    async def _announce_attached(self, tenant_id: str, alert_id: str, escalation: Escalation) -> None:
        """After commit: the grown escalation, to the parent alert's and the attached alert's viewers."""
        data = {
            "escalation_id": escalation.id,
            "status": escalation.status,
            "attached_alert_id": alert_id,
            "attached_count": len(escalation.related_alert_ids),
            "level": escalation.level,
            "priority": escalation.priority,
        }
        await self._publish(tenant_id, "escalation.updated", escalation.alert_id, data)
        await self._publish(tenant_id, "escalation.updated", alert_id, data)
        log.info("escalation.alert_attached", attached_count=len(escalation.related_alert_ids))

    async def _find_parent(
        self,
        conn: Connection,
        tenant_id: str,
        alert_id: str,
        fingerprint: Optional[str],
        policy: ReviewPolicy,
        now: datetime,
        related: Sequence[str] = (),
    ) -> Optional[Escalation]:
        grouping = policy.grouping
        if not grouping.enabled or grouping.max_attached <= 0:
            return None
        since = now - timedelta(minutes=grouping.window_minutes)
        fp = fingerprint if grouping.by_fingerprint and fingerprint else None
        if not related and fp is None:
            return None
        return await self._repos.escalations.find_group_parent(
            tenant_id, alert_id, since=since, related=related, fingerprint=fp, max_attached=grouping.max_attached,
            conn=conn,
        )

    async def _related_candidates(
        self, tenant_id: str, alert_id: str, policy: ReviewPolicy, now: datetime
    ) -> List[str]:
        grouping = policy.grouping
        if not grouping.enabled or grouping.max_attached <= 0 or not grouping.by_indicators:
            return []
        since = now - timedelta(minutes=grouping.window_minutes)
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            return await self._related_by_indicators(conn, tenant_id, alert_id, since, grouping.indicator_types)

    async def _related_by_indicators(
        self, conn: Connection, tenant_id: str, alert_id: str, since: datetime, types: Sequence[str]
    ) -> List[str]:
        sightings = await self._repos.indicators.sightings_for_alert(tenant_id, alert_id, conn=conn)
        keys = [(s.indicator_type, s.value_hash) for s in sightings if s.indicator_type in types]
        if not keys:
            return []
        related = await self._repos.indicators.related_alerts(
            tenant_id, keys, since=since, limit=100, exclude_alert_id=alert_id, conn=conn
        )
        return [r.alert_id for r in related]

    @staticmethod
    def alerts_to_resume(escalation: Escalation) -> List[str]:
        """The escalation's own alert followed by every attached alert (each run waits on this escalation)."""
        return list(dict.fromkeys([escalation.alert_id, *escalation.related_alert_ids]))

    async def decision_scope(
        self,
        tenant_id: str,
        alert_id: str,
        escalation_id: str,
        *,
        decision: str,
        fingerprint: Optional[str],
        severity: Optional[str],
    ) -> DecisionScope:
        """How the decision on ``escalation_id`` applies to ``alert_id`` (see the module docstring)."""
        esc = await self._repos.escalations.get(tenant_id, escalation_id)
        if esc.alert_id == alert_id:
            return DecisionScope(esc, inherited=False, parent_alert_id=alert_id)
        reason: Optional[str] = None
        if decision in BENIGN_DECISIONS:
            parent = await self._repos.alerts.get(tenant_id, esc.alert_id)
            reason = own_review_reason(
                decision,
                parent_fingerprint=parent.fingerprint,
                parent_severity=parent.severity,
                fingerprint=fingerprint,
                severity=severity,
            )
        return DecisionScope(esc, inherited=True, parent_alert_id=esc.alert_id, own_review_reason=reason)

    async def open_detached(
        self,
        tenant_id: str,
        alert_id: str,
        parent: Escalation,
        *,
        reason_code: str,
        decision: str,
        severity: str,
        confidence: float,
        threat_score: float,
        summary: Optional[Mapping[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> EscalationTicket:
        """Give an attached alert its own escalation after a group decision that does not fit it.

        Idempotent per (alert, parent): the workflow node calling this runs
        again on every resume, so an escalation already detached from
        ``parent`` for this alert is returned whatever its status (and an
        active escalation the alert already has is reused). The new
        escalation is never grouped into another one.
        """
        now = now or datetime.now(UTC)
        policy = await self.policy(tenant_id)
        place = _place(policy, severity, threat_score, confidence, 0, "group_review", now)
        priority, level, deadline = place.priority, place.level, place.sla_deadline
        explanation = OWN_REVIEW_REASONS.get(reason_code, "needs its own review")
        reason = (
            f"The grouped escalation this alert was attached to was decided {decision}, "
            f"but this alert {explanation}: it needs its own decision."
        )
        body = {
            **dict(summary or {}),
            "detached_from": parent.id,
            "parent_alert_id": parent.alert_id,
            "parent_decision": decision,
            "own_review_reason": reason_code,
            "correlated_alert_ids": [parent.alert_id],
        }
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.ESCALATION_GROUP, tenant_id)
            detached = await self._repos.escalations.find_detached(tenant_id, alert_id, parent.id, conn=conn)
            if detached is not None:
                return _ticket(detached, created=False)
            escalation, created = await self._repos.escalations.create_or_attach(
                tenant_id,
                alert_id,
                reason=reason[:500],
                level=level,
                priority=priority,
                summary=body,
                related_alert_ids=[],
                sla_deadline=deadline,
                conn=conn,
            )
            if created:
                await self._announce_created(
                    conn,
                    escalation,
                    "escalation.detached",
                    {
                        "alert_id": alert_id,
                        "parent_escalation_id": parent.id,
                        "parent_alert_id": parent.alert_id,
                        "parent_decision": decision,
                        "reason": reason_code,
                        "level": level,
                        "priority": priority,
                    },
                    {"confidence": confidence, "threat_score": threat_score},
                )
        if created:
            log.info("escalation.alert_detached", reason=reason_code, escalation_level=level)
            await self._publish(
                tenant_id,
                "escalation.created",
                alert_id,
                {"escalation_id": escalation.id, "level": level, "priority": priority, "detached_from": parent.id},
            )
        return _ticket(escalation, created=created)

    async def close_after_resume(
        self,
        tenant_id: str,
        escalation_id: str,
        *,
        decision: str,
        decided_by: str,
        notes: Optional[str],
        approved_actions: Sequence[str],
    ) -> Optional[Escalation]:
        """Make sure an escalation the workflow resumed from is no longer active.

        The API records decisions (:meth:`ReviewService.decide
        <lg_sotf.services.review.ReviewService.decide>`, with the analyst's
        version) before enqueueing the resumes, so normally this is a no-op;
        for attached alerts it always is (the parent was decided once). If it
        is still active, the decision is recorded when ``decided_by`` is a
        user id, otherwise the escalation is cancelled so the alert can be
        escalated again later; either way the change is audited.
        """
        esc = await self._repos.escalations.get(tenant_id, escalation_id)
        if not esc.is_active:
            return esc
        user_id = _as_uuid(decided_by)
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            if user_id is not None:
                updated = await self._repos.escalations.decide(
                    tenant_id,
                    escalation_id,
                    decision=decision,
                    decided_by=user_id,
                    expected_version=esc.version,
                    notes=notes,
                    approved_actions=list(approved_actions),
                    conn=conn,
                )
                action = "escalation.decided"
            else:
                updated = await self._repos.escalations.cancel(
                    tenant_id, escalation_id, expected_version=esc.version, conn=conn
                )
                action = "escalation.cancelled"
            await self._audit.record(
                tenant_id,
                action,
                "escalation",
                escalation_id,
                actor_type="system",
                actor_id="workflow",
                details={"alert_id": esc.alert_id, "decision": decision, "decided_by": decided_by[:128]},
                conn=conn,
            )
            if updated.status == "decided":
                await enqueue_event(
                    conn,
                    tenant_id,
                    ESCALATION_DECIDED,
                    alert_id=updated.alert_id,
                    dedupe_key=f"{ESCALATION_DECIDED}:{escalation_id}",
                    escalation=updated,
                )
        await self._publish(tenant_id, "escalation.updated", esc.alert_id, {"escalation_id": escalation_id, "status": updated.status})
        return updated

    async def _announce_created(
        self,
        conn: Connection,
        escalation: Escalation,
        audit_action: str,
        details: Mapping[str, Any],
        alert_overrides: Mapping[str, Any],
    ) -> None:
        """In the creating transaction: the agent's audit entry and the outbound ``escalation.created`` event."""
        await self._audit.record(
            escalation.tenant_id,
            audit_action,
            "escalation",
            escalation.id,
            actor_type="agent",
            actor_id="workflow",
            details=details,
            conn=conn,
        )
        await enqueue_event(
            conn,
            escalation.tenant_id,
            ESCALATION_CREATED,
            alert_id=escalation.alert_id,
            dedupe_key=f"{ESCALATION_CREATED}:{escalation.id}",
            escalation=escalation,
            alert_overrides=alert_overrides,
        )

    async def _publish(self, tenant_id: str, event_type: str, alert_id: str, data: Dict[str, Any]) -> None:
        await publish_event(self._events, event_type, tenant_id, alert_id, data)


def _ticket(esc: Escalation, *, created: bool, attached: bool = False) -> EscalationTicket:
    return EscalationTicket(esc.id, esc.level, esc.priority, created, esc.sla_deadline, attached, esc.version)


def _as_uuid(value: str) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except ValueError:
        return None
