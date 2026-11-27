"""One alert of a case: its state, how it joined the case, and who or what closed it and why.

Who closed it comes from the alert's close reason, as on the investigation
view (:func:`lg_sotf.domain.investigation.outcome.who_closed`). The case
adds what only the alert's timeline says: the analyst behind a decision,
the rule of the decision policy and the closure tier behind an AI close,
and who or what recorded a reopening.

An alert that waits for its blind-audit label shows what its source sent
and nothing else: not its disposition, not who closed it, not how it
joined the case.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Mapping, Optional, Sequence

from lg_sotf.domain import closure
from lg_sotf.domain.case import words
from lg_sotf.domain.case.facts import (
    MAX_NOTES_CHARS,
    MAX_REASON_CHARS,
    MAX_TITLE_CHARS,
    MAX_VALUE_CHARS,
    CaseEscalation,
    CaseEvent,
    MemberFacts,
)
from lg_sotf.domain.case.model import (
    AlertRole,
    AlertState,
    CaseAlert,
    CaseBlindAudit,
    CaseClosedBy,
    CaseEntityRef,
    CaseFlagged,
    CaseLink,
    CasePerson,
    CaseReopened,
    ConfirmedBy,
)
from lg_sotf.domain.digests import entities_preview
from lg_sotf.domain.investigation import words as investigation_words
from lg_sotf.domain.investigation.facts import MAX_CODE_CHARS, AlertFacts, EscalationFacts, bounded, mapping
from lg_sotf.domain.investigation.model import InvestigationReason, OutcomeCategory
from lg_sotf.domain.investigation.outcome import decide_code, outcome_category, who_closed, why

WAITING_STATUSES = frozenset({"waiting_human", "waiting_approval"})
REOPEN_MODES = ("folded", "requeued")
DECISION_EVENT = "analyst.decision"
REOPENED_EVENT = "alert.reopened"
#: A person's flag (``lg_sotf.core.reopen``): the timeline event and the alert-summary key.
FLAGGED_EVENT, FLAGGED = "alert.flagged", "flagged"
#: The close reasons of a close on the model's word start with this (``lg_sotf.domain.closure.MODEL_CLOSE_REASON``).
MODEL_CLOSE_PREFIX = "ai_closed:"


def state_of(status: str) -> AlertState:
    if status == "closed":
        return "closed"
    return "open" if status in WAITING_STATUSES else "processing"


def person(user_id: Optional[str], emails: Mapping[str, str]) -> Optional[CasePerson]:
    return CasePerson(user_id=bounded(user_id, MAX_CODE_CHARS), email=emails.get(user_id)) if user_id else None


def _text(value: Any) -> Optional[str]:
    return bounded(value, MAX_CODE_CHARS) if isinstance(value, str) and value else None


def _when(value: Any) -> Optional[datetime]:
    """A stored ISO timestamp; ``None`` for anything else."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _last(events: Sequence[CaseEvent], event_type: str, node: Optional[str] = None) -> Optional[CaseEvent]:
    for event in reversed(events):
        if event.event_type == event_type and (node is None or event.node == node):
            return event
    return None


def _links(summary: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    linked = summary.get("linked")
    return [m for m in linked if isinstance(m, Mapping)] if isinstance(linked, list) else []


def role_of(case: CaseEscalation, member: MemberFacts) -> AlertRole:
    """How the alert is in the case (see :class:`~lg_sotf.domain.case.model.CaseAlert`)."""
    if member.alert.id == case.alert_id:
        return "primary"
    if member.hidden:
        return "withheld"
    if isinstance(member.alert.summary.get(closure.REOPENED), Mapping):
        return "reopened"
    return "linked" if _links(member.alert.summary) else "attached"


def _link(case: CaseEscalation, summary: Mapping[str, Any]) -> CaseLink:
    """The link into this case, else the newest one (a later case of the same threat replaces the entry)."""
    links = _links(summary)
    entry = next((m for m in links if m.get("escalation_id") == case.id), links[-1])
    return CaseLink(
        reason=InvestigationReason(code=words.LINK_CODE, sentence=words.LINKED),
        threat_alert_id=_text(entry.get("threat_alert_id")),
        at=_when(entry.get("at")),
    )


def _note(event: Optional[CaseEvent]) -> Optional[str]:
    """The reason a person gave when they reopened or flagged the alert: data, cut to its stored length."""
    note = event.data.get("note") if event is not None else None
    return bounded(note, MAX_REASON_CHARS) if isinstance(note, str) and note else None


def _reopened(member: MemberFacts, emails: Mapping[str, str]) -> CaseReopened:
    marker = mapping(member.alert.summary.get(closure.REOPENED))
    event = _last(member.events, REOPENED_EVENT)
    by_person = event is not None and event.actor_type == "user"
    confirmed_by: Optional[ConfirmedBy] = None if event is None else ("person" if by_person else "workflow")
    mode = marker.get("mode")
    code = str(marker.get("reason"))
    own = words.REOPENED_BY_ANALYST.get(code)  # a person's own reopening; any other reason is the safety net's
    return CaseReopened(
        reason=InvestigationReason(code=code if own else words.LINK_CODE, sentence=own or words.REOPENED_BY[confirmed_by]),
        note=_note(event) if own else None,
        threat_alert_id=_text(marker.get("threat_alert_id")),
        mode=mode if mode in REOPEN_MODES else None,
        confirmed_by=confirmed_by,
        by=person(event.actor_id, emails) if event is not None and by_person else None,
        at=event.ts if event is not None else None,
    )


def _flagged(member: MemberFacts, emails: Mapping[str, str]) -> Optional[CaseFlagged]:
    """The flag on the alert (its summary's ``flagged``: who and when), with the reason from its timeline."""
    marker = member.alert.summary.get(FLAGGED)
    if not isinstance(marker, Mapping):
        return None
    return CaseFlagged(
        by=person(_text(marker.get("by")), emails), at=_when(marker.get("at")), note=_note(_last(member.events, FLAGGED_EVENT))
    )


def _can_reopen(alert: AlertFacts) -> bool:
    """The models closed it alone and the close stands (``lg_sotf.services.folded.closed_by_models``)."""
    reason = alert.summary.get("close_reason")
    return alert.status == "closed" and isinstance(reason, str) and reason.startswith(MODEL_CLOSE_PREFIX)


def _tier(events: Sequence[CaseEvent]) -> Optional[str]:
    """The tenant's model-led closure tier as the last ``decide`` step recorded it."""
    decided = _last(events, "node.completed", "decide")
    tier = decided.data.get("autonomy_tier") if decided is not None else None
    return str(tier) if tier in closure.AUTONOMY_TIERS else None


def _closed_by(
    case: CaseEscalation, member: MemberFacts, escalation: Optional[EscalationFacts], emails: Mapping[str, str]
) -> Optional[CaseClosedBy]:
    base = who_closed(member.alert)
    if base is None:
        return None
    out = CaseClosedBy(
        kind=base.kind, reason=base.reason, at=base.at, decision=base.decision, rule_id=base.rule_id,
        rule_name=base.rule_name, source_alert_id=base.source_alert_id,
    )
    if base.kind == "analyst":
        decided = _last(member.events, DECISION_EVENT)
        if decided is None:
            return out
        where = _text(decided.data.get("escalation_id"))
        here = where == case.id and bool(case.decision_notes)
        return out.model_copy(
            update={
                "analyst": person(decided.actor_id, emails) if decided.actor_type == "user" else None,
                "decided_in_case_id": where,
                "notes": bounded(case.decision_notes, MAX_NOTES_CHARS) if here else None,
            }
        )
    if base.kind == "ai":
        code = decide_code(member.alert, escalation, member.events)
        sentence = investigation_words.DECIDE_SENTENCES.get(code or "")
        policy = InvestigationReason(code=code, sentence=sentence) if code and sentence else None
        return out.model_copy(update={"policy": policy, "tier": _tier(member.events)})
    return out


def _audit(member: MemberFacts) -> CaseBlindAudit:
    audit = member.audit
    if member.hidden or (audit is not None and audit.label is None):
        return CaseBlindAudit(state="pending")
    if audit is None:
        return CaseBlindAudit(state="not_sampled")
    return CaseBlindAudit(state="labelled", label=audit.label, agrees=audit.agreement, labelled_at=audit.labelled_at)


def _entities(member: MemberFacts) -> List[CaseEntityRef]:
    preview = entities_preview(member.entities) or {}
    return [
        CaseEntityRef(kind=str(item["kind"]), value=bounded(item["value"], MAX_VALUE_CHARS))
        for item in preview.get("items", [])
    ]


def category_of(member: MemberFacts, escalation: Optional[EscalationFacts]) -> Optional[OutcomeCategory]:
    return None if member.hidden else outcome_category(member.alert, escalation, member.events)


def case_alert(
    case: CaseEscalation, member: MemberFacts, escalation: Optional[EscalationFacts], emails: Mapping[str, str]
) -> CaseAlert:
    """``escalation``: the case's escalation for its primary alert, ``None`` for every other alert (their decide
    code is their own, not the case's)."""
    alert = member.alert
    role, state = role_of(case, member), state_of(alert.status)
    shown = not member.hidden
    reason = None
    if shown and state == "open":
        waiting = alert.status == "waiting_approval" and escalation is None
        reason = why("awaiting_approval" if waiting else decide_code(alert, escalation, member.events))
    return CaseAlert(
        id=alert.id,
        title=bounded(member.title, MAX_TITLE_CHARS),
        severity=alert.severity,
        status=alert.status,
        state=state,
        role=role,
        occurred_at=member.occurred_at,
        closed_at=alert.closed_at,
        disposition=member.disposition if shown else None,
        entities=_entities(member),
        hidden_for_blind_audit=member.hidden,
        category=category_of(member, escalation),
        why=reason,
        closed_by=_closed_by(case, member, escalation, emails) if shown else None,
        blind_audit=_audit(member),
        link=_link(case, alert.summary) if role == "linked" else None,
        reopened=_reopened(member, emails) if role == "reopened" else None,
        flagged=_flagged(member, emails) if shown else None,
        can_reopen=shown and _can_reopen(alert),
    )
