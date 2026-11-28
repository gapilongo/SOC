"""The case read model (PRD-2.9): one case, its alerts, and who or what closed each one and why.

A case is today's escalation: the alert it was opened for and the alerts
attached to it (grouped with it, linked to it by the safety net of AI
closure, or reopened into it). :func:`assemble` is a pure function of stored
data (:class:`~lg_sotf.domain.case.facts.CaseFacts`): no model call, no
write, no I/O. The service :mod:`lg_sotf.services.case` reads the rows; the
shape is :class:`~lg_sotf.domain.case.model.Case`.

* :mod:`.alerts`: one alert's state, role in the case, and who or what closed it;
* :mod:`.timeline`: the case's and its alerts' events, merged, in plain words;
* :mod:`.words`: the fixed sentences, and what the backend cannot give yet.
"""

from __future__ import annotations

from collections import Counter
from typing import List, Optional, Sequence, Tuple

from lg_sotf.domain.case import words
from lg_sotf.domain.case.alerts import case_alert, person
from lg_sotf.domain.case.facts import (
    MAX_ENTITIES,
    MAX_NOTES_CHARS,
    MAX_TITLE_CHARS,
    MAX_VALUE_CHARS,
    AuditFacts,
    CaseEscalation,
    CaseEvent,
    CaseFacts,
    MemberFacts,
)
from lg_sotf.domain.case.model import (
    Case,
    CaseAction,
    CaseAlert,
    CaseClosedByCounts,
    CaseCounts,
    CaseDecision,
    CaseEntity,
    CaseOwner,
    NotAvailable,
)
from lg_sotf.domain.case.timeline import timeline
from lg_sotf.domain.digests import ENTITY_KINDS
from lg_sotf.domain.investigation.facts import EscalationFacts, bounded, strings
from lg_sotf.domain.investigation.outcome import decide_code, why
from lg_sotf.models.vocabulary import SEVERITY_RANK

__all__ = [
    "AuditFacts",
    "Case",
    "CaseEscalation",
    "CaseEvent",
    "CaseFacts",
    "MemberFacts",
    "assemble",
]

#: The statuses in which a case still waits for its decision (an expired one can still be decided).
ACTIVE_STATUSES = frozenset({"open", "claimed", "expired"})
#: The entity values of one alert that are counted (the normalizers keep at most 50 per kind).
MAX_VALUES_PER_KIND = 50


def entities(members: Sequence[MemberFacts]) -> List[CaseEntity]:
    """What the case touches: every value its alerts name with how many of them name it, most shared first
    (then in the order an analyst reads the kinds: who, where, what)."""
    seen: Counter[Tuple[int, str, str]] = Counter()
    for member in members:
        for order, (key, kind) in enumerate(ENTITY_KINDS):
            values = strings(member.entities.get(key), limit=MAX_VALUES_PER_KIND, chars=MAX_VALUE_CHARS)
            seen.update((order, kind, value) for value in dict.fromkeys(values))
    ranked = sorted(seen.items(), key=lambda item: (-item[1], item[0]))
    return [CaseEntity(kind=kind, value=value, alerts=count) for (_, kind, value), count in ranked[:MAX_ENTITIES]]


def _closer(alert: CaseAlert) -> Optional[str]:
    """The field of :class:`CaseClosedByCounts` a closed alert counts in."""
    if alert.closed_by is None:
        return None
    if alert.closed_by.kind != "ai":
        return alert.closed_by.kind
    return "ai_audit" if alert.category == "ai_closed_audit" else "ai_evidence"


def counts(alerts: Sequence[CaseAlert], actions: Sequence[CaseAction], total: int) -> CaseCounts:
    closers = Counter(closer for a in alerts if (closer := _closer(a)) is not None)
    states, roles = Counter(a.state for a in alerts), Counter(a.role for a in alerts)
    return CaseCounts(
        alerts=total,
        open=states["open"],
        processing=states["processing"],
        closed=states["closed"],
        linked=roles["linked"],
        reopened=roles["reopened"],
        flagged=sum(1 for a in alerts if a.flagged is not None),
        withheld=sum(1 for a in alerts if a.hidden_for_blind_audit),
        closed_by=CaseClosedByCounts(**closers),
        actions_awaiting_approval=sum(1 for a in actions if a.status == "awaiting_approval"),
    )


def _escalation(case: CaseEscalation) -> EscalationFacts:
    return EscalationFacts(
        id=case.id, alert_id=case.alert_id, status=case.status, summary=case.summary, decision=case.decision
    )


def _decision(facts: CaseFacts) -> Optional[CaseDecision]:
    case = facts.escalation
    if not case.decision:
        return None
    return CaseDecision(
        decision=case.decision,
        notes=bounded(case.decision_notes, MAX_NOTES_CHARS) if case.decision_notes else None,
        decided_by=person(case.decided_by, facts.emails),
        decided_at=case.decided_at,
    )


def assemble(facts: CaseFacts) -> Case:
    """The case view, from stored data only. ``facts.members`` must hold the case's primary alert."""
    case = facts.escalation
    escalation = _escalation(case)
    primary = next(m for m in facts.members if m.alert.id == case.alert_id)
    alerts = sorted(
        (case_alert(case, m, escalation if m is primary else None, facts.emails) for m in facts.members),
        key=lambda a: (a.occurred_at, a.id),
    )
    opened_for = next(a for a in alerts if a.id == case.alert_id)
    entries, cut = timeline(case, facts.members, facts.emails)
    return Case(
        id=case.id,
        tenant_id=case.tenant_id,
        generated_at=facts.now,
        alert_id=case.alert_id,
        title=bounded(primary.title, MAX_TITLE_CHARS),
        status=case.status,
        active=case.status in ACTIVE_STATUSES,
        severity=max((m.alert.severity for m in facts.members), key=lambda s: SEVERITY_RANK.get(s, -1)),
        category=opened_for.category if opened_for.category in ("needs_decision", "needs_review") else None,
        reason=None if primary.hidden else why(decide_code(primary.alert, escalation, primary.events)),
        opened_at=case.created_at,
        sla_deadline=case.sla_deadline,
        owner=(
            CaseOwner(user_id=case.assigned_to, email=facts.emails.get(case.assigned_to), since=case.claimed_at)
            if case.assigned_to
            else None
        ),
        version=case.version,
        decision=_decision(facts),
        counts=counts(alerts, facts.actions, facts.total_alerts),
        alerts=alerts,
        alerts_truncated=facts.total_alerts > len(alerts),
        entities=entities(facts.members),
        actions=list(facts.actions),
        timeline=entries,
        timeline_truncated=cut,
        not_available=[NotAvailable(field=m.field, reason=m.reason, issue=m.issue) for m in words.NOT_AVAILABLE],
    )
