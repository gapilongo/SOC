"""The timeline of a case: what happened to the case and to its alerts, merged, in plain words.

Each alert contributes its arrival and the steps that changed where it
stands (closed, sent to a person, linked, reopened, decided, a response
planned or run, notes and tickets). The workflow's inner steps (first
assessment, correlation, analysis, the policy's choice) are on the alert's
investigation view and are left out here. The case contributes its
opening, its claim and its decision; the decision is said once, for the
case, not again for every alert it applied to.

An alert that waits for its blind-audit label contributes its arrival and
its notes only, as on every other read.
"""

from __future__ import annotations

from typing import List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.blind_audit import shown_while_hidden
from lg_sotf.domain.case import words
from lg_sotf.domain.case.alerts import DECISION_EVENT, by_flag, person
from lg_sotf.domain.case.facts import MAX_TIMELINE, CaseEscalation, CaseEvent, MemberFacts
from lg_sotf.domain.case.model import CaseTimelineEntry
from lg_sotf.domain.investigation import words as investigation_words
from lg_sotf.domain.investigation.steps import INGESTED, plain_step
from lg_sotf.models.vocabulary import DECISIONS

#: Completed workflow steps a case does not show (the alert's investigation view has them).
INNER_NODES: Tuple[str, ...] = ("triage", "correlation", "analysis", "decide")
RECEIVED = "alert.received"


def _kind(event: CaseEvent) -> str:
    return f"step.{event.node}" if event.event_type == "node.completed" else event.event_type


def _left_out(case: CaseEscalation, event: CaseEvent) -> bool:
    if event.event_type == INGESTED:
        return True  # said once, from the alert's own arrival time
    if event.event_type == "node.completed":
        # The gate is a step of the case only when it closed the alert.
        return event.node in INNER_NODES or (event.node == "gate" and event.data.get("suppressed") is not True)
    # The decision on this case is one entry of the case, not one per alert it applied to.
    return event.event_type == DECISION_EVENT and case.decision is not None and event.data.get("escalation_id") == case.id


def _closes_after_decision(event: CaseEvent) -> bool:
    """The ``close`` step that carries out an analyst's decision."""
    reason = event.data.get("close_reason")
    return event.event_type == "node.completed" and event.node == "close" and isinstance(reason, str) and reason.startswith("analyst:")


def _entry(event: CaseEvent, alert_id: str, emails: Mapping[str, str]) -> Optional[CaseTimelineEntry]:
    step = plain_step(event)
    # The case's own sentence for the event, else the investigation's (which also says a person's own reopening).
    person_reopened = str(event.data.get("reason")) in investigation_words.REOPENED_STEPS
    own = None if person_reopened else words.EVENT_STEPS.get(event.event_type)
    if own is not None and by_flag(event):
        own = words.REOPENED_BY_FLAG_STEP
    said = own or (investigation_words.Step(step.actor, step.text) if step is not None else None)
    if said is None:
        return None
    return CaseTimelineEntry(
        ts=event.ts,
        kind=_kind(event),
        actor=said.actor,
        text=said.text,
        produced=step.produced if step is not None else None,
        alert_id=alert_id,
        by=person(event.actor_id, emails) if event.actor_type == "user" else None,
    )


def _of_alert(case: CaseEscalation, member: MemberFacts, emails: Mapping[str, str]) -> List[CaseTimelineEntry]:
    alert = member.alert
    out: List[CaseTimelineEntry] = []
    if alert.ingested_at is not None:
        received = investigation_words.EVENT_STEPS[INGESTED]
        out.append(
            CaseTimelineEntry(ts=alert.ingested_at, kind=RECEIVED, actor=received.actor, text=received.text, alert_id=alert.id)
        )
    for event in member.events:
        if _left_out(case, event) or (member.hidden and not shown_while_hidden(event.event_type)):
            continue
        if _closes_after_decision(event) and out and out[-1].kind == DECISION_EVENT:
            continue  # the decision is the line before: it names the analyst and what they decided
        entry = _entry(event, alert.id, emails)
        if entry is not None:
            out.append(entry)
    return out


def _of_case(case: CaseEscalation, emails: Mapping[str, str]) -> List[CaseTimelineEntry]:
    out = [CaseTimelineEntry(ts=case.created_at, kind="case.opened", actor=words.CASE_OPENED.actor, text=words.CASE_OPENED.text)]
    if case.assigned_to and case.claimed_at is not None:
        out.append(
            CaseTimelineEntry(
                ts=case.claimed_at, kind="case.claimed", actor=words.CASE_CLAIMED.actor, text=words.CASE_CLAIMED.text,
                by=person(case.assigned_to, emails),
            )
        )
    if case.decision and case.decided_at is not None:
        out.append(
            CaseTimelineEntry(
                ts=case.decided_at, kind="case.decided", actor=words.CASE_DECIDED.actor, text=words.CASE_DECIDED.text,
                produced=case.decision.replace("_", " ") if case.decision in DECISIONS else None,
                by=person(case.decided_by, emails),
            )
        )
    return out


def timeline(
    case: CaseEscalation, members: Sequence[MemberFacts], emails: Mapping[str, str]
) -> Tuple[List[CaseTimelineEntry], bool]:
    """The entries, oldest first, and whether older ones were left out (the newest :data:`MAX_TIMELINE` stay)."""
    entries = _of_case(case, emails)
    for member in members:
        entries.extend(_of_alert(case, member, emails))
    entries.sort(key=lambda e: e.ts)
    return entries[-MAX_TIMELINE:], len(entries) > MAX_TIMELINE
