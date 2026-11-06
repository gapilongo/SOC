"""What an escalation row shows besides its own columns: owner names, the alert's rule and entities, a reason line.

Built from stored data only, read in one read-only tenant transaction per
page (two bounded lookups: the owners' e-mail addresses and the escalations'
alerts):

* ``assigned_to_email`` / ``decided_by_email``: the tenant user's address
  (``None`` for a user who no longer exists);
* ``rule``, ``source_id``, ``source_name``, ``alert_severity`` and
  ``entities_preview``: from the escalation's primary alert
  (:class:`~lg_sotf.db.repos.views.AlertDigest`,
  :func:`~lg_sotf.domain.digests.entities_preview`);
* ``ai_reason``: the first sentence of the analysis conclusion stored in the
  escalation summary, and ``ai_reason_source`` whether the model (``model``)
  or the rules (``rules``) wrote it (``None`` on escalations created before
  that was recorded);
* ``routing``: the routing code, confidence and review band the workflow
  recorded when it opened the escalation (``summary.routing``, ``None`` on
  older escalations).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence
from uuid import UUID

from lg_sotf.db.repos import AlertDigest, Escalation, Repositories
from lg_sotf.domain.digests import entities_preview, one_line


@dataclass(frozen=True)
class EscalationView:
    assigned_to_email: Optional[str] = None
    decided_by_email: Optional[str] = None
    alert_severity: Optional[str] = None
    rule: Optional[str] = None
    source_id: Optional[str] = None
    source_name: Optional[str] = None
    entities_preview: Optional[Dict[str, Any]] = None
    ai_reason: Optional[str] = None
    ai_reason_source: Optional[str] = None
    routing: Optional[Dict[str, Any]] = None


def routing_of(summary: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """``summary.routing`` when it is well formed (a code, an optional confidence and band)."""
    routing = summary.get("routing")
    if not isinstance(routing, Mapping) or not isinstance(routing.get("code"), str):
        return None
    confidence = routing.get("confidence")
    band = routing.get("band")
    low, high = (_int(band.get("min")), _int(band.get("max"))) if isinstance(band, Mapping) else (None, None)
    return {
        "code": routing["code"],
        "confidence": float(confidence) if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) else None,
        "band": {"min": low, "max": high} if low is not None and high is not None else None,
    }


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def reason_source(summary: Mapping[str, Any]) -> Optional[str]:
    llm_used = summary.get("llm_used")
    if not isinstance(llm_used, bool):
        return None
    return "model" if llm_used else "rules"


def escalation_view(
    escalation: Escalation, emails: Mapping[UUID, str], alert: Optional[AlertDigest]
) -> EscalationView:
    summary = escalation.summary or {}
    reason = one_line(summary.get("conclusion"))
    return EscalationView(
        assigned_to_email=emails.get(escalation.assigned_to) if escalation.assigned_to else None,
        decided_by_email=emails.get(escalation.decided_by) if escalation.decided_by else None,
        alert_severity=alert.severity if alert else None,
        rule=alert.rule if alert else None,
        source_id=alert.source_id if alert else None,
        source_name=alert.source_name if alert else None,
        entities_preview=entities_preview(alert.entities) if alert else None,
        ai_reason=reason,
        ai_reason_source=reason_source(summary) if reason else None,
        routing=routing_of(summary),
    )


async def escalation_views(
    repos: Repositories, tenant_id: str, escalations: Sequence[Escalation]
) -> Dict[str, EscalationView]:
    """:func:`escalation_view` of each escalation, by id."""
    if not escalations:
        return {}
    users = [u for e in escalations for u in (e.assigned_to, e.decided_by) if u is not None]
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        emails = await repos.views.user_emails(tenant_id, users, conn=conn)
        alerts = await repos.views.alert_digests(tenant_id, [e.alert_id for e in escalations], conn=conn)
    return {e.id: escalation_view(e, emails, alerts.get(e.alert_id)) for e in escalations}
