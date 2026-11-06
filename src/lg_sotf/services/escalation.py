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
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.core.routing import BENIGN_DECISIONS
from lg_sotf.db import locks
from lg_sotf.db.repos.escalations import ESCALATION_LEVELS, Escalation
from lg_sotf.integrations.events import ESCALATION_CREATED, ESCALATION_DECIDED
from lg_sotf.integrations.outbox import enqueue_event
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
SEVERITY_RANK: Dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_RELATED = 50
MAX_CORRELATED = 20
DEFAULT_KEY_INDICATOR_TYPES = ("ip", "domain", "url", "hash")
GROUPABLE_INDICATOR_TYPES = ("ip", "domain", "url", "hash", "host", "user", "process")
# Why an attached alert does not inherit a benign group decision (summary.own_review_reason).
OWN_REVIEW_REASONS: Dict[str, str] = {
    "different_fingerprint": "is a different detection than the alert that was reviewed",
    "higher_severity": "is more severe than the alert that was reviewed",
}
_DETACHED_SQL = """
    SELECT * FROM escalations
    WHERE tenant_id = $1 AND alert_id = $2 AND summary->>'detached_from' = $3
    ORDER BY created_at DESC LIMIT 1
"""
_ATTACHED_TO_SQL = """
    SELECT * FROM escalations
    WHERE tenant_id = $1 AND status IN ('open', 'claimed') AND $2 = ANY(related_alert_ids)
    ORDER BY created_at LIMIT 1
"""
_FIND_PARENT_SQL = """
    SELECT e.* FROM escalations e
    WHERE e.tenant_id = $1 AND e.status IN ('open', 'claimed') AND e.alert_id <> $2
      AND e.created_at >= $3
      AND cardinality(e.related_alert_ids) < $6
      AND (
            e.alert_id = ANY($4::text[])
         OR e.related_alert_ids && $4::text[]
         OR ($5::text IS NOT NULL AND EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.tenant_id = e.tenant_id AND a.id = e.alert_id AND a.fingerprint = $5))
      )
    ORDER BY e.created_at, e.id
    LIMIT 1
    FOR UPDATE OF e
"""
_ATTACH_SQL = """
    UPDATE escalations
    SET related_alert_ids = array_append(related_alert_ids, $3),
        priority = GREATEST(priority, $4),
        level = $5,
        sla_deadline = CASE WHEN sla_deadline IS NULL THEN $6 ELSE LEAST(sla_deadline, $6) END,
        summary = summary || jsonb_build_object('attached_count', cardinality(related_alert_ids) + 1),
        version = version + 1
    WHERE tenant_id = $1 AND id = $2 AND NOT ($3 = ANY(related_alert_ids))
    RETURNING *
"""

Level = Literal["L1", "L2", "L3"]


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
        priority = compute_priority(
            severity=severity,
            threat_score=threat_score,
            confidence=confidence,
            correlations_count=len(correlated_alert_ids),
            reason_code=reason_code,
        )
        level = policy.level_for(priority=priority, threat_score=threat_score, severity=severity, reason_code=reason_code)
        deadline = now + timedelta(minutes=policy.sla_minutes[level])
        body = dict(summary or {})
        body["correlated_alert_ids"] = [str(a) for a in correlated_alert_ids][:MAX_CORRELATED]

        attached_from: Optional[Escalation] = None
        # Related alerts are only candidates (the parent lookup re-checks them under the
        # lock), so the indicator lookups run before the per-tenant grouping lock is taken:
        # the lock is held for the parent lookup and the attach/create step only.
        related = await self._related_candidates(tenant_id, alert_id, policy, now)
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.ESCALATION_GROUP, tenant_id)
            own = await self._repos.escalations.get_active_for_alert(tenant_id, alert_id, conn=conn)
            if own is not None:
                return _ticket(own, created=False)
            row = await conn.fetchrow(_ATTACHED_TO_SQL, tenant_id, alert_id)
            if row is not None:
                return _ticket(Escalation.model_validate(dict(row)), created=False, attached=True)
            parent = await self._find_parent(conn, tenant_id, alert_id, fingerprint, policy, now, related)
            if parent is not None:
                new_level = max_level(parent.level, level)
                row = await conn.fetchrow(
                    _ATTACH_SQL, tenant_id, parent.id, alert_id, priority, new_level, deadline
                )
                if row is not None:
                    attached_from = parent
                    escalation = Escalation.model_validate(dict(row))
                    await self._audit.record(
                        tenant_id,
                        "escalation.alert_attached",
                        "escalation",
                        escalation.id,
                        actor_type="agent",
                        actor_id="workflow",
                        details={
                            "alert_id": alert_id,
                            "parent_alert_id": escalation.alert_id,
                            "attached_count": len(escalation.related_alert_ids),
                            "level": escalation.level,
                            "priority": escalation.priority,
                        },
                        conn=conn,
                    )
            if attached_from is None:
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
                    await self._audit.record(
                        tenant_id,
                        "escalation.created",
                        "escalation",
                        escalation.id,
                        actor_type="agent",
                        actor_id="workflow",
                        details={"alert_id": alert_id, "level": level, "priority": priority, "reason_code": reason_code},
                        conn=conn,
                    )
                    await enqueue_event(
                        conn,
                        tenant_id,
                        ESCALATION_CREATED,
                        alert_id=alert_id,
                        dedupe_key=f"{ESCALATION_CREATED}:{escalation.id}",
                        escalation=escalation,
                        alert_overrides={
                            "confidence": confidence,
                            "threat_score": threat_score,
                            "verdict": body.get("verdict"),
                        },
                    )
        if attached_from is not None:
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
            return _ticket(escalation, created=False, attached=True)
        if created:
            await self._publish(
                tenant_id, "escalation.created", alert_id, {"escalation_id": escalation.id, "level": level, "priority": priority}
            )
        return _ticket(escalation, created=created)

    async def _find_parent(
        self,
        conn: Any,
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
        row = await conn.fetchrow(
            _FIND_PARENT_SQL, tenant_id, alert_id, since, list(related), fp, grouping.max_attached
        )
        return Escalation.model_validate(dict(row)) if row is not None else None

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
        self, conn: Any, tenant_id: str, alert_id: str, since: datetime, types: Sequence[str]
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
        priority = compute_priority(
            severity=severity,
            threat_score=threat_score,
            confidence=confidence,
            correlations_count=0,
            reason_code="group_review",
        )
        level = policy.level_for(priority=priority, threat_score=threat_score, severity=severity, reason_code="group_review")
        deadline = now + timedelta(minutes=policy.sla_minutes[level])
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
            row = await conn.fetchrow(_DETACHED_SQL, tenant_id, alert_id, parent.id)
            if row is not None:
                return _ticket(Escalation.model_validate(dict(row)), created=False)
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
                await self._audit.record(
                    tenant_id,
                    "escalation.detached",
                    "escalation",
                    escalation.id,
                    actor_type="agent",
                    actor_id="workflow",
                    details={
                        "alert_id": alert_id,
                        "parent_escalation_id": parent.id,
                        "parent_alert_id": parent.alert_id,
                        "parent_decision": decision,
                        "reason": reason_code,
                        "level": level,
                        "priority": priority,
                    },
                    conn=conn,
                )
                await enqueue_event(
                    conn,
                    tenant_id,
                    ESCALATION_CREATED,
                    alert_id=alert_id,
                    dedupe_key=f"{ESCALATION_CREATED}:{escalation.id}",
                    escalation=escalation,
                    alert_overrides={"confidence": confidence, "threat_score": threat_score},
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

    async def _publish(self, tenant_id: str, event_type: str, alert_id: str, data: Dict[str, Any]) -> None:
        await publish_event(self._events, event_type, tenant_id, alert_id, data)


def _ticket(esc: Escalation, *, created: bool, attached: bool = False) -> EscalationTicket:
    return EscalationTicket(esc.id, esc.level, esc.priority, created, esc.sla_deadline, attached, esc.version)


def _as_uuid(value: str) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except ValueError:
        return None
