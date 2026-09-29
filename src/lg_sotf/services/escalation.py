"""Analyst escalations: level, priority and SLA policy on top of the escalations repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional, Sequence
from uuid import UUID

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Escalation, Repositories


DEFAULT_SLA_MINUTES: Dict[str, int] = {"L1": 30, "L2": 60, "L3": 120}
HIGH_PRIORITY_THRESHOLD = 8
CRITICAL_PRIORITY_THRESHOLD = 9
REASON_WEIGHTS: Dict[str, int] = {
    "high_risk": 3,
    "complex_attack": 2,
    "regulatory_compliance": 2,
    "conflicting_evidence": 1,
    "grey_zone": 1,
    "inconclusive": 1,
    "policy_exception": 1,
    "analyst_request": 1,
    "false_positive_review": 0,
}
SEVERITY_WEIGHTS: Dict[str, int] = {"critical": 2, "high": 1, "medium": 0, "low": -1, "info": -2}
MAX_RELATED = 50


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


def compute_level(*, priority: int, threat_score: float, severity: str, reason_code: str) -> str:
    if priority >= CRITICAL_PRIORITY_THRESHOLD:
        return "L3"
    if priority >= HIGH_PRIORITY_THRESHOLD:
        return "L2"
    if reason_code in ("regulatory_compliance", "complex_attack") or threat_score >= 80 or severity == "critical":
        return "L2"
    return "L1"


@dataclass(frozen=True)
class EscalationTicket:
    id: str
    level: str
    priority: int
    created: bool
    sla_deadline: Optional[datetime]


class EscalationService:
    def __init__(self, repos: Repositories, events: Optional[EventPublisher], settings: Settings) -> None:
        self._repos = repos
        self._events = events
        self._settings = settings
        self._audit = AuditLogger(repos)
        configured = (settings.agents.get("human_loop") or {}).get("sla_minutes") or {}
        self._sla = {level: int(configured.get(level, default)) for level, default in DEFAULT_SLA_MINUTES.items()}

    def sla_minutes(self, level: str) -> int:
        return self._sla[level]

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
        related_alert_ids: Sequence[str] = (),
        now: Optional[datetime] = None,
    ) -> EscalationTicket:
        """Return the alert's active escalation, creating it if needed (idempotent per tenant+alert)."""
        existing = await self._repos.escalations.get_active_for_alert(tenant_id, alert_id)
        if existing is not None:
            return EscalationTicket(existing.id, existing.level, existing.priority, False, existing.sla_deadline)
        priority = compute_priority(
            severity=severity,
            threat_score=threat_score,
            confidence=confidence,
            correlations_count=len(related_alert_ids),
            reason_code=reason_code,
        )
        level = compute_level(priority=priority, threat_score=threat_score, severity=severity, reason_code=reason_code)
        deadline = (now or datetime.now(UTC)) + timedelta(minutes=self._sla[level])
        escalation, created = await self._repos.escalations.create_or_attach(
            tenant_id,
            alert_id,
            reason=reason[:500],
            level=level,
            priority=priority,
            summary=dict(summary or {}),
            related_alert_ids=list(related_alert_ids)[:MAX_RELATED],
            sla_deadline=deadline,
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
            )
            await self._publish(
                tenant_id,
                "escalation.created",
                alert_id,
                {"escalation_id": escalation.id, "level": level, "priority": priority},
            )
        return EscalationTicket(escalation.id, escalation.level, escalation.priority, created, escalation.sla_deadline)

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

        The API records decisions (``escalations.decide`` with the analyst's
        version) before enqueueing the resume, so normally this is a no-op.
        If it is still active, the decision is recorded when ``decided_by``
        is a user id, otherwise the escalation is cancelled so the alert can
        be escalated again later; either way the change is audited.
        """
        esc = await self._repos.escalations.get(tenant_id, escalation_id)
        if not esc.is_active:
            return esc
        user_id = _as_uuid(decided_by)
        if user_id is not None:
            updated = await self._repos.escalations.decide(
                tenant_id,
                escalation_id,
                decision=decision,
                decided_by=user_id,
                expected_version=esc.version,
                notes=notes,
                approved_actions=list(approved_actions),
            )
            action = "escalation.decided"
        else:
            updated = await self._repos.escalations.cancel(tenant_id, escalation_id, expected_version=esc.version)
            action = "escalation.cancelled"
        await self._audit.record(
            tenant_id,
            action,
            "escalation",
            escalation_id,
            actor_type="system",
            actor_id="workflow",
            details={"alert_id": esc.alert_id, "decision": decision, "decided_by": decided_by[:128]},
        )
        await self._publish(tenant_id, "escalation.updated", esc.alert_id, {"escalation_id": escalation_id, "status": updated.status})
        return updated

    async def _publish(self, tenant_id: str, event_type: str, alert_id: str, data: Dict[str, Any]) -> None:
        await publish_event(self._events, event_type, tenant_id, alert_id, data)


def _as_uuid(value: str) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except ValueError:
        return None
