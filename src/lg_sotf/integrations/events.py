"""Integration events and their payload (schema ``lg-sotf.event.v1``).

An event is a *summary* of a state change, never the raw alert: the alert's
title, severity, status, verdict, confidence and a capped, redacted sample of
its entities, plus the escalation or action it concerns. Every channel
(Slack, Teams, email, the generic webhook) renders from this one payload, so
no channel can leak more than it holds.

Payload (keys are stable; new keys may be added)::

    {
      "schema": "lg-sotf.event.v1",
      "id": "<event uuid>",                    # same for every integration notified of this event
      "event": "escalation.created",
      "occurred_at": "2026-09-30T12:00:00+00:00",
      "tenant_id": "acme",
      "severity": "high",                     # the alert's severity
      "alert": {"id", "title", "severity", "status", "verdict", "confidence", "threat_score",
                "category", "source_id", "entities": {"hosts": [...], "ips": [...], ...}},
      "escalation": {"id", "level", "priority", "status", "reason", "decision", "sla_deadline",
                     "from_level", "attached_alerts"} | null,
      "action": {"id", "type", "target", "risk_level", "status", "approval_reason", "error", "dry_run",
                 "rollback_of", "verification": {"outcome", "reason"} | null} | null,
      "links": {"alert": "https://soc.example.com/alerts?alert=<id>"}   # added at delivery
    }
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote

from lg_sotf.models.vocabulary import ESCALATION_LEVELS as LEVELS
from lg_sotf.models.vocabulary import SEVERITIES, SEVERITY_RANK
from lg_sotf.security.redaction import redact_text

SCHEMA = "lg-sotf.event.v1"

ESCALATION_CREATED = "escalation.created"
ESCALATION_SLA_BREACHED = "escalation.sla_breached"
ESCALATION_DECIDED = "escalation.decided"
ACTION_AWAITING_APPROVAL = "action.awaiting_approval"
ACTION_EXECUTED = "action.executed"
ACTION_FAILED = "action.failed"
# A succeeded action whose re-query contradicted the change, or could not prove it (outcome failed/inconclusive).
ACTION_VERIFICATION_FAILED = "action.verification_failed"
ALERT_CRITICAL_RECEIVED = "alert.critical_received"
TEST_EVENT = "integration.test"

EVENT_TYPES: Tuple[str, ...] = (
    ESCALATION_CREATED,
    ESCALATION_SLA_BREACHED,
    ESCALATION_DECIDED,
    ACTION_AWAITING_APPROVAL,
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_VERIFICATION_FAILED,
    ALERT_CRITICAL_RECEIVED,
)
# What a ticketing integration does with its events: open a ticket, sync the analyst's decision to it.
TICKETING_EVENTS: Tuple[str, ...] = (ESCALATION_CREATED, ESCALATION_DECIDED)
EVENT_LABELS: Dict[str, str] = {
    ESCALATION_CREATED: "Escalation opened",
    ESCALATION_SLA_BREACHED: "Escalation SLA breached",
    ESCALATION_DECIDED: "Escalation decided",
    ACTION_AWAITING_APPROVAL: "Action awaiting approval",
    ACTION_EXECUTED: "Action executed",
    ACTION_FAILED: "Action failed",
    ACTION_VERIFICATION_FAILED: "Action not verified",
    ALERT_CRITICAL_RECEIVED: "Critical alert received",
    TEST_EVENT: "Test message",
}


# Summary caps: notifications carry enough to triage from a phone, never the alert body.
MAX_TITLE_CHARS = 300
MAX_TEXT_CHARS = 500
MAX_ENTITY_CHARS = 200
MAX_ENTITIES_PER_KIND = 5
ENTITY_KINDS: Tuple[str, ...] = ("hosts", "users", "ips", "domains", "urls", "hashes", "processes", "emails")


def severity_at_least(severity: Optional[str], minimum: str) -> bool:
    """Unknown severities count as the highest (a notification is never lost to a typo)."""
    return SEVERITY_RANK.get(str(severity), len(SEVERITIES)) >= SEVERITY_RANK.get(minimum, 0)


def level_at_least(level: Optional[str], minimum: Optional[str]) -> bool:
    if not minimum:
        return True
    try:
        return LEVELS.index(str(level)) >= LEVELS.index(minimum)
    except ValueError:
        return True


def clean_text(value: Any, limit: int = MAX_TEXT_CHARS) -> Optional[str]:
    """Redacted, single-spaced, capped text (``None`` stays ``None``)."""
    if value is None:
        return None
    text, _ = redact_text(" ".join(str(value).split()))
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 1)


def capped_entities(entities: Any) -> Dict[str, List[str]]:
    """At most :data:`MAX_ENTITIES_PER_KIND` redacted values per kind; command lines are never included."""
    if not isinstance(entities, Mapping):
        return {}
    out: Dict[str, List[str]] = {}
    for kind in ENTITY_KINDS:
        values = entities.get(kind)
        if not isinstance(values, (list, tuple)):
            continue
        cleaned = [clean_text(v, MAX_ENTITY_CHARS) for v in values if isinstance(v, (str, int))][:MAX_ENTITIES_PER_KIND]
        kept = [v for v in cleaned if v]
        if kept:
            out[kind] = kept
    return out


def alert_summary(row: Mapping[str, Any], overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Summary of an ``alerts`` row (``normalized`` only for its entities; ``raw`` is never read)."""
    summary = row.get("summary") if isinstance(row.get("summary"), Mapping) else {}
    normalized = row.get("normalized") if isinstance(row.get("normalized"), Mapping) else {}
    extra = dict(overrides or {})
    verdict = extra.get("verdict") or row.get("disposition") or (summary or {}).get("verdict")
    return {
        "id": str(row.get("id")),
        "title": clean_text(row.get("title"), MAX_TITLE_CHARS) or "(untitled alert)",
        "severity": row.get("severity"),
        "status": row.get("status"),
        "verdict": clean_text(verdict, 40),
        "confidence": _number(extra.get("confidence", row.get("confidence"))),
        "threat_score": _number(extra.get("threat_score", row.get("threat_score"))),
        "category": clean_text(row.get("category"), 100),
        "source_id": clean_text(row.get("source_id"), 128),
        "entities": capped_entities((normalized or {}).get("entities")),
    }


def escalation_summary(esc: Any, **extra: Any) -> Dict[str, Any]:
    """Summary of an :class:`~lg_sotf.db.repos.Escalation` (or a mapping with the same keys)."""

    def get(name: str) -> Any:
        return esc.get(name) if isinstance(esc, Mapping) else getattr(esc, name, None)

    deadline = get("sla_deadline")
    related = get("related_alert_ids") or []
    out: Dict[str, Any] = {
        "id": str(get("id")),
        "level": get("level"),
        "priority": get("priority"),
        "status": get("status"),
        "reason": clean_text(get("reason"), MAX_TEXT_CHARS),
        "decision": get("decision"),
        "sla_deadline": deadline.isoformat() if isinstance(deadline, datetime) else deadline,
        "attached_alerts": len(related),
    }
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def action_summary(action: Any, **extra: Any) -> Dict[str, Any]:
    """Summary of a :class:`~lg_sotf.db.repos.ResponseAction`: never its params, connector result or external state.

    ``verification`` is ``{"outcome", "reason"}`` once the action has a
    verification state (``reason`` a short code, e.g. ``deadline``).
    """
    params = action.params if isinstance(getattr(action, "params", None), Mapping) else {}
    result = action.result if isinstance(getattr(action, "result", None), Mapping) else {}
    outcome = getattr(action, "verification", None)
    detail = getattr(action, "verification_detail", None)
    reason = detail.get("reason") if isinstance(detail, Mapping) else None
    rollback_of = getattr(action, "rollback_of", None)
    out: Dict[str, Any] = {
        "id": str(action.id),
        "type": action.action_type,
        "target": clean_text(action.target, MAX_ENTITY_CHARS),
        "risk_level": action.risk_level,
        "status": action.status,
        "approval_reason": params.get("approval_reason") if isinstance(params.get("approval_reason"), str) else None,
        "error": clean_text(result.get("error"), 100) if action.status == "failed" else None,
        "dry_run": action.status == "dry_run",
        "rollback_of": str(rollback_of) if rollback_of is not None else None,
        "verification": (
            {"outcome": str(outcome), "reason": clean_text(reason, 100) if isinstance(reason, str) else None}
            if isinstance(outcome, str)
            else None
        ),
    }
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def build_event(
    event_type: str,
    tenant_id: str,
    *,
    alert: Mapping[str, Any],
    escalation: Optional[Mapping[str, Any]] = None,
    action: Optional[Mapping[str, Any]] = None,
    event_id: Optional[uuid.UUID] = None,
    occurred_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "id": str(event_id or uuid.uuid4()),
        "event": event_type,
        "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
        "tenant_id": tenant_id,
        "severity": alert.get("severity"),
        "alert": dict(alert),
        "escalation": dict(escalation) if escalation is not None else None,
        "action": dict(action) if action is not None else None,
    }


def ui_base_url(settings: Any) -> str:
    """Where links in notifications point: ``integrations.ui_base_url``, else ``api.public_url``."""
    base = settings.integrations.ui_base_url or settings.api.public_url
    return str(base).rstrip("/")


def alert_link(base_url: str, alert_id: Optional[str]) -> Optional[str]:
    if not alert_id:
        return None
    return f"{base_url.rstrip('/')}/alerts?alert={quote(str(alert_id), safe='')}"


def with_links(payload: Mapping[str, Any], base_url: str) -> Dict[str, Any]:
    """The payload as delivered: plus ``links`` built from the install's UI URL."""
    out = dict(payload)
    alert = payload.get("alert") if isinstance(payload.get("alert"), Mapping) else {}
    links: Dict[str, str] = {}
    link = alert_link(base_url, (alert or {}).get("id"))
    if link:
        links["alert"] = link
    if isinstance(payload.get("escalation"), Mapping):
        links["escalations"] = f"{base_url.rstrip('/')}/escalations"
    if isinstance(payload.get("action"), Mapping):
        links["actions"] = f"{base_url.rstrip('/')}/actions"
    out["links"] = links
    return out


def make_test_event(tenant_id: str, integration_name: str) -> Dict[str, Any]:
    """Payload of the message ``POST /integrations/{id}/test`` sends (no tenant data in it)."""
    alert: Dict[str, Any] = {
        "id": "test",
        "title": f"LG-SOTF test message for integration {clean_text(integration_name, 200)}",
        "severity": "info",
        "status": "test",
        "verdict": None,
        "confidence": None,
        "threat_score": None,
        "category": None,
        "source_id": None,
        "entities": {},
    }
    return build_event(TEST_EVENT, tenant_id, alert=alert)
