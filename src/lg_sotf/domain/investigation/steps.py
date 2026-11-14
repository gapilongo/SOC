"""What the investigation did, in plain words: the workflow's timeline without engine node names.

A log of actions, written by code. Each step says who acted (code, a model,
a check, the policy or a person), a fixed sentence
(:mod:`lg_sotf.domain.investigation.words`) and what the step produced:
counts and vocabulary values the workflow recorded, never text from the
alert. Events this release has no sentence for are left out (the raw
timeline stays at ``GET /alerts/{id}/events``).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.blind_audit import shown_while_hidden
from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation.facts import MAX_STEPS, AlertFacts, EventFacts
from lg_sotf.domain.investigation.model import PlainStep
from lg_sotf.models.vocabulary import ACTION_STATUSES, DECISIONS, DISPOSITIONS, ESCALATION_LEVELS

SEPARATOR = " · "
INGESTED = "ingested"


def _count(data: Mapping[str, Any], key: str) -> Optional[int]:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _word(data: Mapping[str, Any], key: str, vocabulary: Sequence[str]) -> Optional[str]:
    """A value of a closed vocabulary, with its underscores as spaces; anything else is dropped."""
    value = data.get(key)
    return value.replace("_", " ") if isinstance(value, str) and value in vocabulary else None


def _counted(data: Mapping[str, Any], parts: Sequence[Tuple[str, str]]) -> Optional[str]:
    """``"2 automatic · 1 blocked"`` for the keys of ``parts`` that hold a positive count."""
    found = [f"{count} {label}" for key, label in parts if (count := _count(data, key))]
    return SEPARATOR.join(found) or None


def _join(*parts: Optional[str]) -> Optional[str]:
    return SEPARATOR.join(p for p in parts if p) or None


def _triage(data: Mapping[str, Any]) -> Optional[str]:
    confidence = _count(data, "confidence")
    return _join(
        f"confidence {confidence}" if confidence is not None else None,
        _counted(data, (("rule_fp", "benign signals"), ("rule_tp", "threat signals"))),
    )


def _analysis(data: Mapping[str, Any]) -> Optional[str]:
    verdict = _word(data, "verdict", DISPOSITIONS)
    return _join(_counted(data, (("tool_steps", "lookups"),)), f"verdict {verdict}" if verdict else None)


def _escalate(data: Mapping[str, Any]) -> Optional[str]:
    level, priority = _word(data, "level", ESCALATION_LEVELS), _count(data, "priority")
    return _join(f"level {level}" if level else None, f"priority {priority}" if priority is not None else None)


def _executed(data: Mapping[str, Any]) -> Optional[str]:
    statuses = data.get("statuses")
    if not isinstance(statuses, Mapping):
        return None
    return _counted(statuses, [(status, status.replace("_", " ")) for status in ACTION_STATUSES])


#: What each node's step produced, from the digest the node recorded on its timeline event.
PRODUCED: Dict[str, Callable[[Mapping[str, Any]], Optional[str]]] = {
    "triage": _triage,
    "correlation": lambda d: _counted(d, (("related_count", "related alerts"),)),
    "analysis": _analysis,
    "escalate": _escalate,
    "plan_response": lambda d: _counted(
        d, (("auto", "automatic"), ("awaiting", "awaiting approval"), ("blocked", "blocked"), ("done", "already done"))
    ),
    "execute_actions": _executed,
    "close": lambda d: _word(d, "disposition", DISPOSITIONS),
    "analyst.decision": lambda d: _word(d, "decision", DECISIONS),
    "actions.approval": lambda d: _counted(d, (("approved", "approved"), ("rejected", "rejected"))),
}


def _node_step(node: str, data: Mapping[str, Any]) -> Optional[words.Step]:
    base = words.NODE_STEPS.get(node)
    if base is None:
        return None
    if node == "gate" and data.get("suppressed") is True:
        return words.NODE_STEP_VARIANTS["gate:verdict_cache" if data.get("verdict_cache") else "gate:suppression_rule"]
    if node == "decide":
        sentence = words.DECIDE_SENTENCES.get(str(data.get("code") or ""))
        return words.Step(base.actor, sentence) if sentence else base
    if node == "close":
        reason = words.CLOSE_REASONS.get(str(data.get("close_reason") or ""))
        if reason is None:
            return base
        return words.Step("person" if reason.closed_by == "analyst" else base.actor, reason.sentence)
    if data.get("llm_used") is True:
        return words.NODE_STEP_VARIANTS.get(f"{node}:model", base)
    return base


def _step(event: EventFacts) -> Optional[PlainStep]:
    if event.event_type == "node.completed":
        key = event.node or ""
        step = _node_step(key, event.data)
    else:
        key = event.event_type
        step = words.EVENT_STEPS.get(key)
    if step is None:
        return None
    produced = PRODUCED.get(key)
    return PlainStep(ts=event.ts, actor=step.actor, text=step.text, produced=produced(event.data) if produced else None)


def steps(alert: AlertFacts, events: Sequence[EventFacts], *, hidden: bool = False) -> List[PlainStep]:
    """The plain steps, oldest first, starting with the alert's arrival. ``hidden``: only what is shown while
    the alert waits for its blind-audit label (arrival and notes), since the workflow's path names the verdict."""
    shown = [e for e in events if not hidden or shown_while_hidden(e.event_type)]
    out: List[PlainStep] = []
    if alert.ingested_at is not None and not any(e.event_type == INGESTED for e in shown):
        received = words.EVENT_STEPS[INGESTED]
        out.append(PlainStep(ts=alert.ingested_at, actor=received.actor, text=received.text))
    for event in shown:
        step = _step(event)
        if step is not None:
            out.append(step)
    return out[:MAX_STEPS]
