"""The outcome of an investigation: one of four categories, the reason in plain words, and who closed the alert.

The category says what happens next:

* ``ai_closed_evidence``: the AI closed the alert on approved evidence (a low
  threat backed by approved benign signals, an obvious false positive at the
  first assessment, or a completed automatic response);
* ``ai_closed_audit``: the AI closed it on the model's word; it is sampled for audit;
* ``needs_decision``: with a person, likely malicious (the analysis verdict
  was ``malicious``, or the decide code is one of :data:`LIKELY_MALICIOUS_CODES`);
* ``needs_review``: with a person, not proven either way.

An alert an analyst closed keeps the category the AI gave it before the
person decided. An alert a suppression rule or a cached analyst verdict
closed at the gate has no category: the AI never looked at it.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain import closure
from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation.facts import (
    MAX_CODE_CHARS,
    MAX_NAME_CHARS,
    MAX_SIGNALS,
    MAX_TEXT,
    AlertFacts,
    EscalationFacts,
    EventFacts,
    bounded,
    mapping,
    strings,
)
from lg_sotf.domain.investigation.model import (
    InvestigationClosedBy,
    InvestigationOutcome,
    InvestigationReason,
    InvestigationSummary,
    OutcomeCategory,
)
from lg_sotf.domain.routing import benign_evidence

#: Decide codes that mean "likely malicious" whatever the analysis verdict says: the response policy chose a
#: response, an automatic response did not complete, or an analyst labelled the close malicious in a blind audit.
LIKELY_MALICIOUS_CODES: Tuple[str, ...] = ("high_risk", "response_review", "blind_audit")
#: Close reasons of the two AI categories (the alert's first ``close`` event carries one of them).
EVIDENCE_CLOSE_REASONS: Tuple[str, ...] = ("policy:close", "policy:response", "triage:false_positive")
AUDIT_CLOSE_REASONS: Tuple[str, ...] = (closure.MODEL_CLOSE_REASON,)
WAITING_STATUSES = frozenset({"waiting_human", "waiting_approval"})
ACTIVE_ESCALATION_STATUSES = frozenset({"open", "claimed"})
UNKNOWN_CODE = "unknown"


def _code(value: Any) -> Optional[str]:
    return bounded(value, MAX_CODE_CHARS) if isinstance(value, str) and value else None


def _own(alert: AlertFacts, escalation: Optional[EscalationFacts]) -> Optional[EscalationFacts]:
    """The escalation when it is the alert's own (not the one of a group the alert is attached to)."""
    return escalation if escalation is not None and escalation.alert_id == alert.id else None


def decide_code(
    alert: AlertFacts, escalation: Optional[EscalationFacts], events: Sequence[EventFacts]
) -> Optional[str]:
    """The code of the decision that routed the alert: its own escalation's, else the one stored at close, else
    the last ``decide`` step's. ``reopened`` while an alert the safety net reopened is open again."""
    if alert.status != "closed" and alert.summary.get(closure.REOPENED):
        return "reopened"
    own = _own(alert, escalation)
    stored = (
        _code(mapping(mapping(own.summary).get("routing")).get("code")) if own is not None else None
    ) or _code(mapping(alert.summary.get("decision")).get("code"))
    if stored is not None:
        return stored
    for event in reversed(events):
        if event.event_type == "node.completed" and event.node == "decide":
            return _code(event.data.get("code"))
    return None


def likely_malicious(verdict: Any, code: Optional[str]) -> bool:
    """Whether an alert that went to a person is "likely malicious" (else "not proven either way")."""
    return verdict == "malicious" or code in LIKELY_MALICIOUS_CODES


def _escalated(alert: AlertFacts, escalation: Optional[EscalationFacts], code: Optional[str]) -> OutcomeCategory:
    own = _own(alert, escalation)
    verdict = mapping(own.summary).get("verdict") if own is not None else None
    if verdict is None:
        verdict = mapping(alert.summary.get("analysis")).get("verdict")
    return "needs_decision" if likely_malicious(verdict, code) else "needs_review"


def _close_reason(alert: AlertFacts) -> Optional[str]:
    return _code(alert.summary.get("close_reason")) if alert.status == "closed" else None


def outcome_category(
    alert: AlertFacts, escalation: Optional[EscalationFacts], events: Sequence[EventFacts]
) -> Optional[OutcomeCategory]:
    """The alert's category (see the module docs); ``None`` at the gate, while it is processed, or when unknown."""
    code = decide_code(alert, escalation, events)
    if alert.status == "closed":
        reason = _close_reason(alert)
        entry = words.CLOSE_REASONS.get(reason or "")
        if entry is None or entry.closed_by in ("suppression_rule", "cached_verdict"):
            return None
        if entry.closed_by == "analyst":
            return _escalated(alert, escalation, code)
        return "ai_closed_audit" if reason in AUDIT_CLOSE_REASONS else "ai_closed_evidence"
    if alert.status == "waiting_approval":
        return "needs_decision"
    if alert.status in WAITING_STATUSES or (escalation is not None and escalation.status in ACTIVE_ESCALATION_STATUSES):
        return _escalated(alert, escalation, code)
    return None


def _reason(code: str, sentence: str) -> InvestigationReason:
    return InvestigationReason(code=code, sentence=sentence)


def blockers(alert: AlertFacts, tier: str) -> List[InvestigationReason]:
    """Why the AI may not close the alert on its own, recomputed from the stored digests with the closure policy
    (:mod:`lg_sotf.domain.closure`). Empty without a triage digest: the policy never ran on the alert."""
    triage = alert.summary.get("triage")
    if not isinstance(triage, Mapping):
        return []
    state = {
        "severity": alert.severity,
        "alert": alert.view,
        "triage": triage,
        "analysis": mapping(alert.summary.get("analysis")),
        "correlation": mapping(alert.summary.get("correlation")),
    }
    names = closure.model_close_blockers(state, tier=tier)
    if benign_evidence(triage):
        names += [name for name in closure.evidence_close_blockers(state) if name not in names]
    return [_reason(name, words.BLOCKER_SENTENCES.get(name, words.UNKNOWN_REASON)) for name in names]


def _closed_by(alert: AlertFacts, reason: str, entry: words.CloseReason) -> InvestigationClosedBy:
    by = mapping(alert.summary.get("suppressed_by"))
    decision = by.get("decision") if entry.closed_by == "cached_verdict" else alert.summary.get("analyst_decision")
    rule = entry.closed_by == "suppression_rule"
    return InvestigationClosedBy(
        kind=entry.closed_by,
        reason=_reason(reason, entry.sentence),
        at=alert.closed_at,
        rule_id=_code(by.get("rule_id")) if rule else None,
        rule_name=bounded(by["name"], MAX_NAME_CHARS) if rule and isinstance(by.get("name"), str) else None,
        source_alert_id=_code(by.get("source_alert_id")) if entry.closed_by == "cached_verdict" else None,
        decision=_code(decision) if entry.closed_by in ("cached_verdict", "analyst") else None,
    )


def _why(code: Optional[str]) -> InvestigationReason:
    return _reason(code or UNKNOWN_CODE, words.decide_sentence(code))


def outcome(
    alert: AlertFacts, escalation: Optional[EscalationFacts], events: Sequence[EventFacts], tier: str
) -> Optional[InvestigationOutcome]:
    """The outcome, or ``None`` while the alert is still being processed (no decision yet)."""
    category = outcome_category(alert, escalation, events)
    code = decide_code(alert, escalation, events)
    with_person = category in ("needs_decision", "needs_review")
    held = blockers(alert, tier) if with_person else []
    if alert.status != "closed":
        if category is None:
            return None
        waiting = alert.status == "waiting_approval" and _own(alert, escalation) is None
        return InvestigationOutcome(
            category=category, reason=_why("awaiting_approval" if waiting else code), blockers=held
        )
    close_reason = _close_reason(alert)
    entry = words.CLOSE_REASONS.get(close_reason or "")
    if close_reason is None or entry is None:
        return InvestigationOutcome(category=None, reason=None)
    closed_by = _closed_by(alert, close_reason, entry)
    evidence: List[str] = []
    if category == "ai_closed_evidence":
        evidence = strings(mapping(alert.summary.get("triage")).get("rule_fp"), limit=MAX_SIGNALS, chars=MAX_CODE_CHARS)
    return InvestigationOutcome(
        category=category,
        # An analyst's close keeps the reason the alert was with a person; the close itself is in closed_by.
        reason=_why(code) if with_person else closed_by.reason,
        blockers=held,
        evidence=evidence,
        closed_by=closed_by,
    )


def summary(alert: AlertFacts, escalation: Optional[EscalationFacts]) -> InvestigationSummary:
    """The conclusion as it was written, marked with who wrote it: the analysis conclusion (the model's when it
    was consulted, else the rules'), else the fast model's reasoning."""
    analysis, triage = mapping(alert.summary.get("analysis")), mapping(alert.summary.get("triage"))
    own = _own(alert, escalation)
    for source in (analysis, mapping(own.summary) if own is not None else {}):
        text = source.get("conclusion")
        if isinstance(text, str) and text.strip():
            used = source.get("llm_used")
            return InvestigationSummary(
                text=bounded(text.strip(), MAX_TEXT),
                written_by=("model" if used else "rules") if isinstance(used, bool) else None,
            )
    reasoning = triage.get("reasoning")
    if triage.get("llm_used") is True and isinstance(reasoning, str) and reasoning.strip():
        return InvestigationSummary(text=bounded(reasoning.strip(), MAX_TEXT), written_by="model")
    return InvestigationSummary(text=None, written_by=None)
