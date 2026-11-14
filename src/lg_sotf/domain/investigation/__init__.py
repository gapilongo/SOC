"""The investigation read model (PRD-2.8a): one typed view of what the AI concluded about an alert and why.

:func:`assemble` is a pure function of stored data
(:class:`~lg_sotf.domain.investigation.facts.InvestigationFacts`): no model
call, no write, no I/O. The service
:mod:`lg_sotf.services.investigation` reads the rows; the shape is
:class:`~lg_sotf.domain.investigation.model.Investigation`.

* :mod:`.outcome`: the four outcome categories, the reason in plain words, who closed the alert;
* :mod:`.evidence`: observations with a typed outcome, claims, what is not established;
* :mod:`.steps`: what the investigation did, without engine node names;
* :mod:`.words`: every decide code, blocker, close reason and node name as a fixed sentence.
"""

from __future__ import annotations

from typing import Optional

from lg_sotf.domain.investigation import evidence, words
from lg_sotf.domain.investigation.facts import (
    AlertFacts,
    EscalationFacts,
    EventFacts,
    InvestigationFacts,
    Lookup,
    TraceRef,
    TrackCounts,
)
from lg_sotf.domain.investigation.model import (
    Investigation,
    InvestigationSummary,
    NotEstablished,
    OutcomeCategory,
    OutcomeTrackRecord,
    PendingHarnessField,
    ProposedResponse,
)
from lg_sotf.domain.investigation.outcome import outcome, outcome_category, summary
from lg_sotf.domain.investigation.steps import steps

__all__ = [
    "AlertFacts",
    "EscalationFacts",
    "EventFacts",
    "Investigation",
    "InvestigationFacts",
    "Lookup",
    "TraceRef",
    "TrackCounts",
    "assemble",
    "outcome_category",
    "track_record",
]


def track_record(category: Optional[OutcomeCategory], counts: Optional[TrackCounts]) -> Optional[OutcomeTrackRecord]:
    """The counts behind an outcome category, with a rate only from ``min_samples`` verdicts on."""
    if category is None or counts is None:
        return None
    enough = counts.total >= counts.min_samples and counts.total > 0
    return OutcomeTrackRecord(
        category=category,
        basis="blind_audit_labels" if category.startswith("ai_closed") else "analyst_decisions",
        window_days=counts.window_days,
        total=counts.total,
        confirmed=counts.confirmed,
        min_samples=counts.min_samples,
        rate=round(counts.confirmed / counts.total, 4) if enough else None,
    )


def _pending() -> list[PendingHarnessField]:
    return [PendingHarnessField(field=p.field, why=p.why, issue=p.issue) for p in words.PENDING_HARNESS]


def assemble(facts: InvestigationFacts) -> Investigation:
    """The investigation view of one alert, from stored data only."""
    alert = facts.alert
    if facts.hidden:
        return Investigation(
            alert_id=alert.id,
            tenant_id=alert.tenant_id,
            generated_at=facts.now,
            hidden_for_blind_audit=True,
            outcome=None,
            summary=InvestigationSummary(text=None, written_by=None),
            claims=[],
            observations=[],
            not_established=NotEstablished(),
            steps=steps(alert, facts.events, hidden=True),
            track_record=None,
            response=ProposedResponse(source="none"),
            pending_harness=_pending(),
        )
    found = evidence.observations(facts.lookups, facts.failed_tools)
    return Investigation(
        alert_id=alert.id,
        tenant_id=alert.tenant_id,
        generated_at=facts.now,
        outcome=outcome(alert, facts.escalation, facts.events, facts.tier),
        summary=summary(alert, facts.escalation),
        claims=evidence.claims(alert.summary, facts.lookups, found),
        observations=found,
        not_established=evidence.not_established(alert.summary, alert.view, facts.lookups, found),
        steps=steps(alert, facts.events),
        track_record=track_record(outcome_category(alert, facts.escalation, facts.events), facts.track),
        response=facts.response,
        pending_harness=_pending(),
    )
