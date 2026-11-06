"""Writing integration events to the outbox, inside the caller's transaction.

The services call these helpers with the connection of the transaction that
makes the state change (an escalation is created, a decision is recorded, an
action changes state), so the notification commits or rolls back with it:
no event is announced for a change that did not happen, and none is lost
between the commit and a publish. The scheduler delivers the rows
(:mod:`lg_sotf.integrations.delivery`).

Each helper costs one indexed query on the tenant's enabled integrations
when none matches (the common case). Enqueueing is idempotent through
``dedupe_key``, so a workflow node that runs again on resume never queues a
second message.

Matching (per enabled integration):

* notification kinds (``slack``, ``teams``, ``email``, ``webhook``): the
  event is in ``events`` and the alert's severity is at least
  ``min_severity`` -> ``notify``;
* ticketing kinds (``jira``, ``servicenow``): ``escalation.created`` in
  ``events``, severity at least ``min_severity`` and the escalation level at
  least ``config.min_level`` -> ``ticket_create``; ``escalation.decided`` in
  ``events`` -> ``ticket_update`` (a comment and, when configured, the
  resolve transition on the escalation's ticket).

Onboarding sample alerts (source ``demo:samples``) never reach an
integration: they would page on-call staff and open real tickets.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.db import Connection
from lg_sotf.db.repos.outbox import ENQUEUE_SQL, NewOutboxEntry
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.integrations.config import MICROSOFT_KIND, NOTIFY_KINDS, TICKETING_KINDS
from lg_sotf.integrations.events import (
    ALERT_CRITICAL_RECEIVED,
    ESCALATION_CREATED,
    ESCALATION_DECIDED,
    action_summary,
    alert_summary,
    build_event,
    escalation_summary,
    level_at_least,
    severity_at_least,
)
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

_INTEGRATIONS_SQL = """
    SELECT id, kind, events, min_severity, config FROM integrations
    WHERE tenant_id = $1 AND enabled AND $2 = ANY(events)
"""
_ALERTS_SQL = """
    SELECT id, title, severity, status, disposition, confidence, threat_score, category, source_id,
           summary, jsonb_build_object('entities', normalized->'entities') AS normalized
    FROM alerts WHERE tenant_id = $1 AND id = ANY($2::text[]) AND source_id IS DISTINCT FROM $3
"""


def operation_for(integration: Mapping[str, Any], event_type: str, severity: Optional[str], level: Optional[str]) -> Optional[str]:
    """What ``integration`` does with the event, or ``None`` (see the module docstring).

    The ``microsoft`` kind (the direct response connector) receives no events.
    """
    kind = integration.get("kind")
    if kind == MICROSOFT_KIND or event_type not in (integration.get("events") or ()):
        return None
    config = integration.get("config") if isinstance(integration.get("config"), Mapping) else {}
    minimum = str(integration.get("min_severity") or "info")
    if kind in NOTIFY_KINDS:
        return "notify" if severity_at_least(severity, minimum) else None
    if kind in TICKETING_KINDS:
        if event_type == ESCALATION_CREATED:
            if severity_at_least(severity, minimum) and level_at_least(level, (config or {}).get("min_level")):
                return "ticket_create"
            return None
        if event_type == ESCALATION_DECIDED:
            return "ticket_update"
    return None


async def _matching(conn: Connection, tenant_id: str, event_type: str) -> List[Mapping[str, Any]]:
    return [dict(r) for r in await conn.fetch(_INTEGRATIONS_SQL, tenant_id, event_type)]


async def _alerts(conn: Connection, tenant_id: str, alert_ids: Sequence[str]) -> Dict[str, Mapping[str, Any]]:
    rows = await conn.fetch(_ALERTS_SQL, tenant_id, list(alert_ids), SAMPLE_SOURCE_ID)
    return {str(r["id"]): dict(r) for r in rows}


async def _insert(conn: Connection, tenant_id: str, entries: List[NewOutboxEntry]) -> int:
    if not entries:
        return 0
    status = await conn.execute(
        ENQUEUE_SQL,
        tenant_id,
        [e.model_dump(mode="json") for e in entries],
    )
    return int(str(status).split()[-1]) if status else 0


async def enqueue_event(
    conn: Connection,
    tenant_id: str,
    event_type: str,
    *,
    alert_id: str,
    dedupe_key: str,
    escalation: Any = None,
    action: Any = None,
    level: Optional[str] = None,
    alert_overrides: Optional[Mapping[str, Any]] = None,
    escalation_extra: Optional[Mapping[str, Any]] = None,
) -> int:
    """Queue ``event_type`` about ``alert_id`` for every matching integration; returns rows queued.

    ``conn`` must be inside the tenant transaction that makes the change.
    ``escalation`` / ``action`` are the repository records the event is about.
    """
    integrations = await _matching(conn, tenant_id, event_type)
    if not integrations:
        return 0
    alerts = await _alerts(conn, tenant_id, [alert_id])
    row = alerts.get(alert_id)
    if row is None:
        return 0
    alert = alert_summary(row, alert_overrides)
    esc_level = level or (getattr(escalation, "level", None) if escalation is not None else None)
    ops = {str(i["id"]): operation_for(i, event_type, alert["severity"], esc_level) for i in integrations}
    targets = [(i, ops[str(i["id"])]) for i in integrations if ops[str(i["id"])]]
    if not targets:
        return 0
    event_id = uuid.uuid4()
    payload = build_event(
        event_type,
        tenant_id,
        alert=alert,
        escalation=escalation_summary(escalation, **dict(escalation_extra or {})) if escalation is not None else None,
        action=action_summary(action) if action is not None else None,
        event_id=event_id,
    )
    escalation_id = str(escalation.id) if escalation is not None else None
    entries = [
        NewOutboxEntry(
            integration_id=i["id"],
            event_id=event_id,
            event_type=event_type,
            operation=str(op),
            dedupe_key=dedupe_key[:300],
            alert_id=alert_id,
            escalation_id=escalation_id,
            payload=payload,
        )
        for i, op in targets
    ]
    queued = await _insert(conn, tenant_id, entries)
    if queued:
        log.info("integrations.event_queued", event_type=event_type, integrations=queued)
    return queued


async def enqueue_critical_alerts(conn: Connection, tenant_id: str, alert_ids: Sequence[str]) -> int:
    """``alert.critical_received`` for newly dispatched critical alerts (one message per alert, ever)."""
    if not alert_ids:
        return 0
    integrations = await _matching(conn, tenant_id, ALERT_CRITICAL_RECEIVED)
    if not integrations:
        return 0
    rows = await _alerts(conn, tenant_id, alert_ids)
    entries: List[NewOutboxEntry] = []
    for alert_id in alert_ids:
        row = rows.get(alert_id)
        if row is None:
            continue
        alert = alert_summary(row)
        targets = [i for i in integrations if operation_for(i, ALERT_CRITICAL_RECEIVED, alert["severity"], None)]
        if not targets:
            continue
        event_id = uuid.uuid4()
        payload = build_event(ALERT_CRITICAL_RECEIVED, tenant_id, alert=alert, event_id=event_id)
        entries.extend(
            NewOutboxEntry(
                integration_id=i["id"],
                event_id=event_id,
                event_type=ALERT_CRITICAL_RECEIVED,
                operation="notify",
                dedupe_key=f"{ALERT_CRITICAL_RECEIVED}:{alert_id}"[:300],
                alert_id=alert_id,
                payload=payload,
            )
            for i in targets
        )
    return await _insert(conn, tenant_id, entries)
