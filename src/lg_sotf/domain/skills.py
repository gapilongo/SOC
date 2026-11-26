"""Skill rules that need no I/O: which skill an alert gets, what its queries are bound to, what its
indicators say (ADR 0014 sections 1.3 and 2.1, Amendment 1 points 3 and 4).

**Selection.** :func:`select_skill` reads only what the platform itself wrote on the alert: the format
whose normalizer built it. In this slice the catalogue holds the default skill, so a Wazuh alert gets
``wazuh.default`` and any other alert gets none (today's path). Family skills are ranked in front of it
when they exist.

**Bindings.** :func:`bind` turns a query's arguments into values: a field of the alert's typed view
(:mod:`lg_sotf.domain.skill_views`), the alert's own time, a whole number or a constant of the file. A
binding whose view field is ``None`` gives no arguments at all: the query is skipped. Nothing here reads a
model's output.

**Indicators.** :func:`evaluate` is Kleene three-valued: ``True``, ``False`` or ``None`` (unknown). A
predicate over evidence that was skipped, failed, or came back incomplete without showing the thing is
unknown: an empty or failed lookup never shows that nothing happened (Amendment 2). What an indicator
does to a close is decided by the checker and the decision policy (step 4), not here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.domain.ledger import LedgerEntry
from lg_sotf.models.skill import (
    AllOf,
    AnyGroupIn,
    AnyOf,
    AnyTechniqueIn,
    ArgValue,
    Const,
    MaxLevelGe,
    Maybe,
    Not,
    Predicate,
    SkillSpec,
)

__all__ = ["IndicatorState", "bind", "evaluate", "indicator_states", "select_skill", "state_name", "true_indicators",
           "unbound_reason"]

HOST_ACTIVITY = "host_activity"
IndicatorState = Optional[bool]


def select_skill(alert: Mapping[str, Any], catalog: Sequence[SkillSpec]) -> Optional[SkillSpec]:
    """The active skill for ``alert``, or ``None`` (today's path). Reads the alert's ``normalizer`` only."""
    source = alert.get("normalizer") if isinstance(alert, Mapping) else None
    if not isinstance(source, str):
        return None
    matches = [skill for skill in catalog if skill.status == "active" and source in skill.applies_to.source_types]
    return matches[0] if len(matches) == 1 else None  # a tie fails closed: no skill


def bind(args: Mapping[str, ArgValue], view: Any, occurred_at: datetime) -> Optional[Dict[str, Any]]:
    """The arguments of one query, or ``None`` when a binding has no value (the query is skipped)."""
    bound: Dict[str, Any] = {}
    for name, arg in args.items():
        optional = isinstance(arg, Maybe)
        source = arg.optional if isinstance(arg, Maybe) else arg
        if isinstance(source, Const):
            value: Any = source.const
        elif isinstance(source, int):
            value = source
        elif source == "alert.occurred_at":
            value = occurred_at
        else:
            value = getattr(view, source.removeprefix("view."), None)
        if value is None and optional:
            continue  # the query runs without it
        if value is None:
            return None
        bound[name] = value
    return bound


def unbound_reason(args: Mapping[str, ArgValue], view: Any, default: str) -> str:
    """Why :func:`bind` gave no arguments: the view's own reason for a field it left out on purpose (a common
    binary has no prevalence worth asking for), else ``default``."""
    for arg in args.values():
        if isinstance(arg, str) and arg.startswith("view."):
            why = getattr(view, "why_unbound", lambda name: None)(arg.removeprefix("view."))
            if why and getattr(view, arg.removeprefix("view."), None) is None:
                return str(why)
    return default


def _reads(predicate: Predicate) -> List[str]:
    if isinstance(predicate, (AllOf, AnyOf)):
        inner = predicate.all if isinstance(predicate, AllOf) else predicate.any
        return [fact for one in inner for fact in _reads(one)]
    return _reads(predicate.negated) if isinstance(predicate, Not) else [predicate.fact]


def true_indicators(skill: SkillSpec, ledger: Sequence[LedgerEntry]) -> Dict[str, List[str]]:
    """The malicious indicators of ``skill`` that are true over the run's ledger, each with the ids of the
    facts it read: what blocks a model-led close (ADR 0014 Amendment 1 point 1). An indicator that is
    unknown (the tool could not answer) is not in it."""
    held: Dict[str, List[str]] = {}
    for hypothesis in skill.hypotheses.malicious:
        if evaluate(hypothesis.indicator, ledger) is True:
            read = set(_reads(hypothesis.indicator))
            held[hypothesis.id] = [e.fact_id for e in ledger if e.evidence_id in read and e.fact is not None][:8]
    return held


def _known(entries: Sequence[LedgerEntry], shows: bool) -> IndicatorState:
    """Whether what was looked for is there: seen, or known absent only when every answer was whole."""
    if shows:
        return True
    whole = bool(entries) and all(entry.outcome != "failed" and entry.complete for entry in entries)
    return False if whole else None


def _values(entries: Sequence[LedgerEntry]) -> List[Mapping[str, Any]]:
    """The values of the ``host_activity`` facts among ``entries``."""
    found: List[Mapping[str, Any]] = []
    for entry in entries:
        fact = entry.fact if entry.outcome == "success" and isinstance(entry.fact, Mapping) else None
        value = fact.get("value") if fact is not None and fact.get("kind") == HOST_ACTIVITY else None
        if isinstance(value, Mapping):
            found.append(value)
    return found


def _strings(values: Sequence[Mapping[str, Any]], key: str) -> List[str]:
    return [item for value in values for item in (value.get(key) or []) if isinstance(item, str)]


def _fact_predicate(predicate: Any, entries: Sequence[LedgerEntry]) -> IndicatorState:
    values = _values(entries)
    if isinstance(predicate, AnyTechniqueIn):
        wanted = set(predicate.any_technique_in)
        seen = _strings(values, "techniques")
        return _known(entries, any(t in wanted or t.split(".", 1)[0] in wanted for t in seen))
    if isinstance(predicate, AnyGroupIn):
        groups = [g.get("group") for v in values for g in (v.get("by_group") or []) if isinstance(g, Mapping)]
        return _known(entries, bool(set(predicate.any_group_in) & {g for g in groups if isinstance(g, str)}))
    levels = [v.get("max_level") for v in values]
    return _known(entries, any(isinstance(n, int) and n >= predicate.max_level_ge for n in levels))


def evaluate(predicate: Predicate, ledger: Sequence[LedgerEntry]) -> IndicatorState:
    """``predicate`` over a run's ledger: ``True``, ``False`` or ``None`` when it cannot be known."""
    if isinstance(predicate, AllOf):
        states = [evaluate(inner, ledger) for inner in predicate.all]
        return False if False in states else None if None in states else True
    if isinstance(predicate, AnyOf):
        states = [evaluate(inner, ledger) for inner in predicate.any]
        return True if True in states else None if None in states else False
    if isinstance(predicate, Not):
        state = evaluate(predicate.negated, ledger)
        return None if state is None else not state
    if isinstance(predicate, (AnyTechniqueIn, AnyGroupIn, MaxLevelGe)):
        return _fact_predicate(predicate, [entry for entry in ledger if entry.evidence_id == predicate.fact])
    return None


def state_name(state: IndicatorState) -> str:
    return "unknown" if state is None else "true" if state else "false"


def indicator_states(skill: SkillSpec, ledger: Sequence[LedgerEntry]) -> Dict[str, str]:
    """Each malicious indicator of ``skill`` over the run's ledger: ``true``, ``false`` or ``unknown``."""
    return {h.id: state_name(evaluate(h.indicator, ledger)) for h in skill.hypotheses.malicious}
