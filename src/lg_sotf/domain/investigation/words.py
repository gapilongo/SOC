"""The plain sentences of the investigation read model: one table per code family.

The investigation view explains a decision to an analyst, so it never shows a
decide code, a blocker name or an engine node name. Every code the workflow
can produce has a sentence here, and ``tests/unit/domain/test_investigation_words.py``
fails when the workflow gains a code, a blocker, a close reason or a node
that has none.

The sentences are fixed text. Nothing from an alert, a model or a provider is
ever formatted into one: such values travel next to the sentence as data.
"""

from __future__ import annotations

from typing import Final, Literal, Mapping, NamedTuple, Optional, Tuple

from lg_sotf.domain.investigation.model import ClosedByKind, Direction, StepActor

__all__ = [
    "BLOCKER_SENTENCES",
    "CLOSE_REASONS",
    "DECIDE_SENTENCES",
    "EVENT_STEPS",
    "LOOKUP_CLAIMS",
    "LOOKUP_STATUS_SENTENCES",
    "LOOKUP_TITLES",
    "NODE_STEPS",
    "NODE_STEP_VARIANTS",
    "NO_ANALYSIS",
    "NO_LOOKUP_WHY",
    "NO_TELEMETRY",
    "NOT_INVESTIGATED",
    "PENDING_HARNESS",
    "TOOL_ERROR_SENTENCE",
    "UNCHECKED_KINDS",
    "UNKNOWN_LOOKUP_TITLE",
    "UNKNOWN_REASON",
    "CloseReason",
    "PendingField",
    "Step",
    "decide_sentence",
]

#: Shown for a code written by a newer release than this table (a rolling deploy); the test keeps it unused.
UNKNOWN_REASON: Final = "The decision policy sent this alert to a person."

#: Decide codes (``lg_sotf.domain.routing.decide``, the ``escalate`` node, the escalation service) in plain words:
#: why the alert is with a person, or why the AI closed it.
DECIDE_SENTENCES: Final[Mapping[str, str]] = {
    "analyst_request": "An analyst asked for more information, so the alert came back to a person after the new analysis.",
    "model_refused": "A model declined to assess this alert, so a person has to.",
    "high_risk": "The assessed threat is high enough for the response policy, so a response was proposed.",
    "grey_zone": (
        "The assessment is not clear either way: the threat score is in the middle range or the analysis was "
        "inconclusive."
    ),
    "inconclusive": "No automatic rule applies to this alert, so a person decides.",
    "model_closed": (
        "The AI judged the alert benign and closed it on the model's word. No independent evidence backs the "
        "close, so it is sampled for audit."
    ),
    "false_positive_review": (
        "The alert looks like a false positive, but the AI may not close it without approved benign evidence, "
        "so a person confirms."
    ),
    "llm_normalized": (
        "A model read this alert's fields from unstructured text, so only a person may close it as benign."
    ),
    "rule_corroborated_benign": "The threat score is low and approved benign evidence backs it, so the AI closed the alert.",
    "response_review": "An automatic response did not complete, so a person reviews the threat.",
    "group_review": "A decision made on a similar alert does not fit this one, so it gets its own review.",
    "blind_audit": "An analyst labelled this AI-closed alert malicious in a blind audit, so it needs a decision.",
    "different_fingerprint": (
        "This alert is a different detection than the one that was reviewed, so the group decision was not "
        "applied to it."
    ),
    "higher_severity": (
        "This alert is more severe than the one that was reviewed, so the group decision was not applied to it."
    ),
    "complex_attack": "The alert is part of a complex attack, so a person decides.",
    "regulatory_compliance": "A compliance rule requires a person to decide this alert.",
    "conflicting_evidence": "The evidence points both ways, so a person decides.",
    "policy_exception": "A policy exception applies to this alert, so a person decides.",
    "reopened": "A related threat appeared after the AI closed this alert, so it was reopened for a person.",
    "awaiting_approval": "A response was proposed and waits for a person to approve it.",
}

#: Why the AI may not close an alert on its own (``lg_sotf.domain.closure``: the model-led close and the
#: evidence close), in plain words.
BLOCKER_SENTENCES: Final[Mapping[str, str]] = {
    "tier_off": "This customer has not allowed the AI to close alerts on the model's word.",
    "severity": "Alerts of this severity are never closed on the model's word.",
    "never_close_class": (
        "The detection belongs to a class that only a person may close, such as credential access, log clearing, "
        "security-tool tampering, ransomware behaviour or persistence the attacker names."
    ),
    "llm_normalized": "A model read this alert's fields from unstructured text, so its content is not trusted for a close.",
    "reopened": "The alert was reopened after a related threat appeared.",
    "steering_text": "The alert contains text that tries to steer the model.",
    "recent_true_positive": (
        "A confirmed threat involves the same entities: earlier alerts an analyst confirmed as malicious, a "
        "related alert closed as malicious, or rule evidence of a threat."
    ),
    "fast_tier_threat": "The first model assessment called it a likely or confirmed threat.",
    "deep_tier_not_benign": "The deeper analysis did not judge it benign.",
}


class CloseReason(NamedTuple):
    """Who or what closed the alert (``ai``, ``suppression_rule``, ``cached_verdict``, ``analyst``) and why."""

    closed_by: ClosedByKind
    sentence: str


#: Close reasons (``WorkflowNodes.outcome``, ``services.folded``) in plain words.
CLOSE_REASONS: Final[Mapping[str, CloseReason]] = {
    "analyst:true_positive": CloseReason("analyst", "An analyst confirmed a real threat."),
    "analyst:false_positive": CloseReason("analyst", "An analyst decided it is a false positive."),
    "analyst:benign_positive": CloseReason("analyst", "An analyst decided it is real activity that is expected here."),
    "suppression_rule": CloseReason(
        "suppression_rule", "A suppression rule of this customer matched the alert, so no investigation ran."
    ),
    "suppressed": CloseReason("suppression_rule", "The alert was closed before any investigation ran."),
    "verdict_cache": CloseReason(
        "cached_verdict",
        "An analyst had already decided that the same detection and behaviour is benign. That verdict was "
        "applied, so no new investigation ran.",
    ),
    "policy:close": CloseReason("ai", "The AI closed it: the threat score was low and approved benign evidence backed that."),
    "ai_closed:audit_required": CloseReason(
        "ai",
        "The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
    ),
    "policy:response": CloseReason("ai", "The AI closed it as malicious after the automatic response completed."),
    "triage:false_positive": CloseReason(
        "ai", "The AI closed it at the first assessment as an obvious false positive: rule signals marked it benign."
    ),
}


class Step(NamedTuple):
    """One line of "what the investigation did": who acted (``code``, ``model``, ``check``, ``policy``,
    ``person``) and the sentence."""

    actor: StepActor
    text: str


#: Engine node names (``lg_sotf.core.nodes.WorkflowNodes``) as plain steps. ``decide`` and ``close`` are the
#: fallbacks: the step shows the sentence of the decide code or the close reason when it is known.
NODE_STEPS: Final[Mapping[str, Step]] = {
    "gate": Step("policy", "Checked the suppression rules and earlier analyst verdicts. None applied."),
    "triage": Step("code", "First assessment of the alert by the rules."),
    "correlation": Step("code", "Looked for related alerts of this customer."),
    "analysis": Step("code", "Deeper analysis by the rules, with the customer's history for the same entities."),
    "decide": Step("policy", "The decision policy chose what happens next."),
    "escalate": Step("policy", "Sent to an analyst."),
    "await_analyst": Step("person", "An analyst recorded a decision."),
    "plan_response": Step("policy", "Proposed response actions. None runs without the customer's policy or an approval."),
    "await_approval": Step("person", "A person approved or rejected proposed response actions."),
    "execute_actions": Step("code", "Ran the response actions that were approved or allowed to run automatically."),
    "close": Step("policy", "The alert was closed."),
}

#: Variants of a node's step that depend on what the node recorded (never on alert text).
NODE_STEP_VARIANTS: Final[Mapping[str, Step]] = {
    "gate:suppression_rule": Step("policy", "A suppression rule matched the alert. No investigation ran."),
    "gate:verdict_cache": Step("policy", "An earlier analyst verdict for the same detection applied. No investigation ran."),
    "triage:model": Step("model", "First assessment of the alert by the fast model and the rules."),
    "correlation:model": Step("model", "Looked for related alerts of this customer and assessed them with the model."),
    "analysis:model": Step(
        "model", "Deeper analysis: the model read the alert, chose reputation lookups and wrote its conclusion."
    ),
}

#: Timeline events other than a completed node, as plain steps.
EVENT_STEPS: Final[Mapping[str, Step]] = {
    "ingested": Step("code", "Alert received."),
    "analyst.decision": NODE_STEPS["await_analyst"],
    "actions.approval": NODE_STEPS["await_approval"],
    "escalation.detached": Step("policy", DECIDE_SENTENCES["group_review"]),
    "alert.reopened": Step("policy", DECIDE_SENTENCES["reopened"]),
    "note": Step("person", "A person added a note."),
    "ticket.created": Step("code", "Opened a ticket in the connected ticketing system."),
    "ticket.linked": Step("code", "Linked the alert to an existing ticket."),
    "ticket.resolved_externally": Step("person", "The ticket was resolved in the ticketing system."),
    "action.verified": Step("check", "Verified that a response action took effect."),
    "action.verification_failed": Step("check", "Could not verify that a response action took effect."),
    "action.rollback_requested": Step("person", "A person asked to undo a response action."),
}

#: What a lookup tool does, by tool name (``lg_sotf.agents.analysis``): the title of its observations.
LOOKUP_TITLES: Final[Mapping[str, str]] = {
    "reputation": "Threat-intelligence reputation",
    "history": "Earlier alerts of this customer for the same entity",
}
UNKNOWN_LOOKUP_TITLE: Final = "Lookup"

#: Provider result statuses (``lg_sotf.tools.enrichment.base.Status``) that mean the lookup could not be made,
#: as ``(kind, sentence)``; ``kind`` is ``no_source`` or ``tool_failed``.
LOOKUP_STATUS_SENTENCES: Final[Mapping[str, Tuple[Literal["no_source", "tool_failed"], str]]] = {
    "not_configured": ("no_source", "No source is connected for this customer."),
    "unsupported": ("no_source", "The connected source does not answer for this kind of value."),
    "rate_limited": ("tool_failed", "The source refused the lookup: its rate limit was reached."),
    "error": ("tool_failed", "The source did not answer."),
    "skipped": ("tool_failed", "The lookup was skipped."),
}
TOOL_ERROR_SENTENCE: Final = "The lookup failed before it returned a result."

#: Rule evidence a lookup backs (``analysis.threat_indicators``), as ``(direction, sentence)``.
LOOKUP_CLAIMS: Final[Mapping[str, Tuple[Direction, str]]] = {
    "threat_intel_malicious": ("malicious", "A threat-intelligence source reports a value of this alert as malicious."),
    "threat_intel_suspicious": ("malicious", "A threat-intelligence source reports a value of this alert as suspicious."),
    "prior_malicious_history": (
        "malicious",
        "An analyst confirmed earlier alerts of this customer for the same entity as malicious.",
    ),
}

#: What is not checked today, by entity kind of the alert (``lg_sotf.domain.digests.ENTITY_KINDS``).
UNCHECKED_KINDS: Final[Mapping[str, str]] = {
    "ip": "Reputation of the alert's addresses",
    "domain": "Reputation of the alert's domains",
    "url": "Reputation of the alert's links",
    "hash": "Reputation of the alert's file hashes",
}
NO_LOOKUP_WHY: Final = (
    "No lookup ran for it. The model did not ask for one, the value is internal or private, or no "
    "threat-intelligence source is connected."
)
NO_TELEMETRY: Final[Tuple[str, str]] = (
    "What else happened on the host and for the user around the alert",
    "The investigation cannot query the source's own event data yet.",
)
NOT_INVESTIGATED: Final[Tuple[str, str]] = (
    "The alert itself",
    "No investigation ran: the alert was closed before any check.",
)
NO_ANALYSIS: Final[Tuple[str, str]] = (
    "Reputation and history of the alert's values",
    "No deeper analysis ran for this alert, so no lookup was made.",
)


class PendingField(NamedTuple):
    """A field today's data cannot fill: its path in the response, why it is empty and the issue that fills it."""

    field: str
    why: str
    issue: int


#: The fields that stay empty until the investigation harness lands (ADR-0014 Amendments 1 and 2).
PENDING_HARNESS: Final[Tuple[PendingField, ...]] = (
    PendingField(
        "claims[].observation_ids",
        "The model does not cite observations yet, so only claims the rules derive from a lookup name one.",
        201,
    ),
    PendingField(
        "claims[].check",
        "No checker compares claims with observations yet: a claim is supported only when a lookup backs it, "
        "and none is ever rejected.",
        207,
    ),
    PendingField(
        "observations[].excerpt[].marks",
        "Highlight ranges are set by typed query templates, which do not exist yet.",
        200,
    ),
    PendingField(
        "observations",
        "Only reputation and history lookups are recorded. Typed facts from the source's own event data come "
        "with the evidence tools.",
        200,
    ),
    PendingField(
        "not_established.not_checked",
        "Without a playbook the list names only the lookups today's analysis could have made.",
        205,
    ),
    PendingField(
        "steps",
        "The steps come from the workflow's timeline. Playbook selection, the lookups of a playbook and the "
        "checker's result are not recorded yet.",
        356,
    ),
)


def decide_sentence(code: Optional[str]) -> str:
    """The sentence of a decide code; :data:`UNKNOWN_REASON` for one this release does not know."""
    return DECIDE_SENTENCES.get(code or "", UNKNOWN_REASON)

