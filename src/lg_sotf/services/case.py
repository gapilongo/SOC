"""The case view (PRD-2.9): reads the stored rows of one case, the domain assembles them.

A case is today's escalation with its alerts. Read-only: the escalation,
its alerts, their timelines, blind-audit samples and response actions, and
the e-mail addresses of the people they name, in one tenant transaction
(RLS); the guardrail view of the actions in its own read-only transaction
(:mod:`lg_sotf.services.action_views`). No model is called and nothing is
written; the shape and the plain sentences are :mod:`lg_sotf.domain.case`.

An alert that waits for its blind-audit label shows nothing of the AI's
side, as on every other read: its timeline keeps the arrival and the notes,
and its response actions are left out.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, List, Optional, Sequence, Set
from uuid import UUID

from lg_sotf.db.repos import AlertEvent, AuditLabel, CaseAlertRow, Escalation, Repositories, ResponseAction
from lg_sotf.db.repos.views import MAX_LOOKUP_IDS
from lg_sotf.domain.case import (
    AuditFacts,
    Case,
    CaseEscalation,
    CaseEvent,
    CaseFacts,
    MemberFacts,
    assemble,
)
from lg_sotf.domain.case.facts import MAX_ALERTS
from lg_sotf.domain.case.model import CaseAction
from lg_sotf.domain.case.timeline import INNER_NODES
from lg_sotf.domain.investigation import AlertFacts
from lg_sotf.services.action_views import action_views
from lg_sotf.services.investigation import planned_action
from lg_sotf.settings import Settings

#: The workflow's steps the case never reads. ``decide`` is read: it records the policy rule and the closure tier.
SKIPPED_NODES = tuple(node for node in INNER_NODES if node != "decide")


def member_ids(escalation: Escalation) -> List[str]:
    """The alerts of the case that are read: the primary alert, then the newest :data:`MAX_ALERTS` - 1 that joined."""
    related = [a for a in dict.fromkeys(escalation.related_alert_ids) if a != escalation.alert_id]
    return [escalation.alert_id, *related[-(MAX_ALERTS - 1):]]


def _escalation(escalation: Escalation) -> CaseEscalation:
    return CaseEscalation(
        id=escalation.id,
        tenant_id=escalation.tenant_id,
        alert_id=escalation.alert_id,
        status=escalation.status,
        version=escalation.version,
        created_at=escalation.created_at,
        summary=escalation.summary or {},
        sla_deadline=escalation.sla_deadline,
        assigned_to=str(escalation.assigned_to) if escalation.assigned_to else None,
        claimed_at=escalation.claimed_at,
        decision=escalation.decision,
        decision_notes=escalation.decision_notes,
        decided_by=str(escalation.decided_by) if escalation.decided_by else None,
        decided_at=escalation.decided_at,
    )


def _member(
    row: CaseAlertRow, events: Sequence[AlertEvent], label: Optional[AuditLabel], hidden: bool
) -> MemberFacts:
    return MemberFacts(
        # The case reads no closure blocker, so it needs no workflow view of the alert (and no raw payload).
        alert=AlertFacts(
            id=row.id, tenant_id=row.tenant_id, status=row.status, severity=row.severity, summary=row.summary or {},
            view={}, ingested_at=row.ingested_at, closed_at=row.closed_at,
        ),
        title=row.title,
        occurred_at=row.occurred_at,
        disposition=row.disposition,
        entities=row.entities or {},
        events=[
            CaseEvent(ts=e.ts, event_type=e.event_type, node=e.node, data=e.data or {}, actor_type=e.actor_type,
                      actor_id=e.actor_id)
            for e in events
        ],
        audit=AuditFacts(label=label.label, agreement=label.agreement, labelled_at=label.labelled_at) if label else None,
        hidden=hidden,
    )


def _user_ids(escalation: Escalation, events: Sequence[AlertEvent]) -> List[UUID]:
    """The users the case names: its owner, who decided it, and the people on its alerts' timelines."""
    found: Dict[UUID, None] = {u: None for u in (escalation.assigned_to, escalation.decided_by) if u is not None}
    for event in events:
        if event.actor_type != "user" or not event.actor_id:
            continue
        try:
            found[UUID(event.actor_id)] = None
        except ValueError:
            continue  # not an account of this tenant (an API key, a delegated analyst)
    return list(found)[:MAX_LOOKUP_IDS]


async def _actions(
    repos: Repositories, settings: Settings, tenant_id: str, actions: Sequence[ResponseAction], hidden: Set[str]
) -> List[CaseAction]:
    shown = [a for a in actions if a.alert_id not in hidden]
    views = await action_views(repos, settings, tenant_id, shown)
    return [
        CaseAction(**planned_action(a, views.get(a.id)).model_dump(), alert_id=a.alert_id, created_at=a.created_at)
        for a in shown
    ]


async def case(
    repos: Repositories, settings: Settings, tenant_id: str, case_id: str, *, now: Optional[datetime] = None
) -> Case:
    """The case view of the tenant's escalation ``case_id`` (``NotFound`` when it is not the tenant's)."""
    now = now or datetime.now(UTC)
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        escalation = await repos.escalations.get(tenant_id, case_id, conn=conn)
        listed = member_ids(escalation)
        rows = await repos.views.case_alerts(tenant_id, listed, conn=conn)
        # The primary alert always exists (a foreign key); an attached one the retention purge removed is skipped.
        ids = [alert_id for alert_id in listed if alert_id in rows]
        hidden = await repos.blind_audit.pending_alert_ids(tenant_id, ids, conn=conn)
        events = await repos.views.case_events(tenant_id, ids, skip_nodes=SKIPPED_NODES, conn=conn)
        labels = await repos.views.case_audit_labels(tenant_id, ids, conn=conn)
        actions = await repos.views.case_actions(tenant_id, ids, conn=conn)
        emails = await repos.views.user_emails(tenant_id, _user_ids(escalation, events), conn=conn)
    by_alert: Dict[str, List[AlertEvent]] = {alert_id: [] for alert_id in ids}
    for event in events:
        by_alert[event.alert_id].append(event)
    total = len({escalation.alert_id, *escalation.related_alert_ids}) - (len(listed) - len(ids))
    return assemble(
        CaseFacts(
            escalation=_escalation(escalation),
            now=now,
            members=[_member(rows[i], by_alert[i], labels.get(i), i in hidden) for i in ids],
            total_alerts=total,
            emails={str(user_id): email for user_id, email in emails.items()},
            actions=await _actions(repos, settings, tenant_id, actions, hidden),
        )
    )
