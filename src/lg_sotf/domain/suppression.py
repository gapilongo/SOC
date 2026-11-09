"""Safe evaluation of suppression-rule predicates against an alert.

A rule's ``match`` maps a field path to a predicate; every entry must match.
Paths are dotted (``severity``, ``entities.ips``, ``normalized.user.name``)
and resolve against the alert view built by :func:`alert_match_view`.

Predicates:

* a scalar: equality (against any element when the field is a list);
* a list of scalars: membership;
* ``{"eq": v}``, ``{"in": [...]}``;
* ``{"cidr": "10.0.0.0/8"}`` or a list of networks: IP containment;
* ``{"regex": "..."}``: full match, pattern and subject length limited.

Regexes run on the ReDoS-safe subset and linear-time matcher of
:mod:`lg_sotf.security.safe_regex`, never on a backtracking engine; its
docstring lists the accepted subset and the cost limits. Every evaluation
carries a work budget (state-set steps): one subject may cost at most
``MAX_MATCH_WORK`` and one call of :func:`first_matching_rule` /
:func:`explain_rule` at most ``MAX_EVALUATION_WORK``. Running out counts as
*no match* (the alert is not suppressed) and is logged without the subject.
The engine raises ``InvalidPattern``; this module re-raises it as
:class:`InvalidRule` with the same message, which reaches API clients.

A malformed rule never matches: a broken rule must not suppress alerts.
:func:`validate_rule_match` is the check the API runs when a rule is created
and :func:`explain_rule` reports, predicate by predicate, why a rule does or
does not match an alert.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.observability.logging import get_logger
from lg_sotf.security import safe_regex
from lg_sotf.security.redaction import redact_text
from lg_sotf.security.safe_regex import InvalidPattern, SafePattern, WorkBudget, WorkBudgetExceeded

log = get_logger(__name__)

MAX_PATH_DEPTH = 6
MAX_SUBJECT_CHARS = 1_024
MAX_LIST_VALUES = 256
MAX_CANDIDATES = 256
EXPLAIN_VALUE_CHARS = 128

_SCALARS = (str, int, float, bool)
_MISSING = object()
_OPERATORS = ("eq", "in", "cidr", "regex")


class InvalidRule(ValueError):
    """A suppression predicate is malformed or unsafe."""


@dataclass(frozen=True)
class PredicateExplanation:
    """Outcome of one ``path -> predicate`` entry of a rule."""

    path: str
    operator: str
    matched: bool
    reason: str
    """``matched``, ``field_missing``, ``no_value_matched``, ``subject_too_long``, ``work_budget_exceeded`` or ``invalid``."""
    value: Optional[str] = None
    """The (redacted, truncated) field value that matched, when one did."""
    candidates: int = 0
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "path": self.path,
            "operator": self.operator,
            "matched": self.matched,
            "reason": self.reason,
            "candidates": self.candidates,
        }
        if self.value is not None:
            out["value"] = self.value
        if self.error is not None:
            out["error"] = self.error
        return out


@dataclass(frozen=True)
class RuleExplanation:
    matched: bool
    predicates: Tuple[PredicateExplanation, ...] = ()
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"matched": self.matched, "predicates": [p.as_dict() for p in self.predicates]}
        if self.error is not None:
            out["error"] = self.error
        return out


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str
    explanation: Optional[RuleExplanation] = field(default=None, compare=False)


def alert_match_view(
    *,
    title: str,
    severity: str,
    category: Optional[str],
    source_id: str,
    source_alert_id: str,
    fingerprint: str,
    normalized: Mapping[str, Any],
    verdict_key: Optional[str] = None,
) -> dict[str, Any]:
    """Fields a suppression rule may reference. Canonical-model keys are also exposed at the top level.

    ``verdict_key`` (:mod:`lg_sotf.domain.verdict_key`) is present only when the
    alert has one: a rule on it never matches an alert whose behaviour could
    not be read.
    """
    view: dict[str, Any] = {k: v for k, v in normalized.items() if k not in ("raw", "verdict_key")}
    view.update(
        {
            "title": title,
            "severity": severity,
            "category": category,
            "source_id": source_id,
            "source_alert_id": source_alert_id,
            "fingerprint": fingerprint,
            "normalized": {k: v for k, v in normalized.items() if k != "raw"},
        }
    )
    if verdict_key:
        view["verdict_key"] = verdict_key
    return view


def stored_alert_view(alert: Any) -> dict[str, Any]:
    """:func:`alert_match_view` of a stored alert (``lg_sotf.db.repos.Alert``), with its verdict key."""
    return alert_match_view(
        title=alert.title, severity=alert.severity, category=alert.category, source_id=alert.source_id,
        source_alert_id=alert.source_alert_id, fingerprint=alert.fingerprint, normalized=alert.normalized,
        verdict_key=verdict_key_of(alert),
    )


def _resolve(view: Mapping[str, Any], path: str) -> Any:
    parts = path.split(".")
    if not path or len(parts) > MAX_PATH_DEPTH or any(not p for p in parts):
        raise InvalidRule(f"invalid field path {path!r}")
    node: Any = view
    for part in parts:
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def _candidates(value: Any) -> List[Any]:
    """Scalar values to compare: the value itself, list elements, or ``{"value": ...}`` entries."""
    items: Iterable[Any] = value if isinstance(value, (list, tuple)) else [value]
    out: List[Any] = []
    for item in items:
        if isinstance(item, Mapping):
            item = item.get("value", item.get("name"))
        if isinstance(item, _SCALARS):
            out.append(item)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    return bool(a == b)


# --------------------------------------------------------------------------
# Regex predicates (engine: lg_sotf.security.safe_regex)
# --------------------------------------------------------------------------


def compile_pattern(pattern: Any) -> SafePattern:
    """Validate and compile ``pattern`` (cached); raises :class:`InvalidRule` outside the safe subset."""
    try:
        return safe_regex.compile_pattern(pattern)
    except InvalidPattern as exc:
        raise InvalidRule(str(exc)) from exc


def validate_regex(pattern: Any) -> str:
    """Raise :class:`InvalidRule` unless ``pattern`` is in the safe subset; returns it unchanged."""
    return compile_pattern(pattern).pattern


def _regex_outcome(pattern: SafePattern, candidates: Sequence[Any], budget: WorkBudget) -> _Outcome:
    """First candidate the pattern fully matches; a candidate that runs out of work counts as no match."""
    n = len(candidates)
    cut_short = False
    too_long = False
    for c in candidates:
        if not isinstance(c, str):
            continue
        if len(c) > MAX_SUBJECT_CHARS:
            too_long = True
            continue
        try:
            if pattern.fullmatch(c, budget):
                return _Outcome(True, "matched", c, n)
        except WorkBudgetExceeded:
            cut_short = True
            budget.overruns += 1
            if budget.exceeded:
                break
    if cut_short:
        return _Outcome(False, "work_budget_exceeded", None, n)
    return _Outcome(False, "subject_too_long" if too_long else "no_value_matched", None, n)


# --------------------------------------------------------------------------
# Predicates
# --------------------------------------------------------------------------


@lru_cache(maxsize=512)
def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise InvalidRule(f"invalid CIDR {value!r}") from exc


def _as_ip(value: Any) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _scalar_list(value: Any, what: str) -> Sequence[Any]:
    items = value if isinstance(value, (list, tuple)) else [value]
    if len(items) > MAX_LIST_VALUES or not all(isinstance(i, _SCALARS) for i in items):
        raise InvalidRule(f"{what} must be a scalar or a list of at most {MAX_LIST_VALUES} scalars")
    return items


def _operator_name(predicate: Any) -> str:
    if isinstance(predicate, Mapping):
        return str(next(iter(predicate), "?"))[:16]
    if isinstance(predicate, (list, tuple)):
        return "in"
    return "eq"


@dataclass(frozen=True)
class _Outcome:
    matched: bool
    reason: str
    value: Any = None
    candidates: int = 0


def _evaluate(predicate: Any, value: Any, budget: Optional[WorkBudget] = None) -> _Outcome:
    """Raises :class:`InvalidRule` for malformed predicates."""
    if value is _MISSING or value is None:
        if isinstance(predicate, Mapping):
            _validate_operator(predicate)
        return _Outcome(False, "field_missing")
    candidates = _candidates(value)
    n = len(candidates)

    def first(test: Callable[[Any], bool]) -> _Outcome:
        for c in candidates:
            if test(c):
                return _Outcome(True, "matched", c, n)
        return _Outcome(False, "no_value_matched", None, n)

    if isinstance(predicate, _SCALARS):
        return first(lambda c: _eq(c, predicate))
    if isinstance(predicate, (list, tuple)):
        allowed = _scalar_list(predicate, "list predicate")
        return first(lambda c: any(_eq(c, a) for a in allowed))
    if isinstance(predicate, Mapping):
        op, arg = _validate_operator(predicate)
        if op == "eq":
            return first(lambda c: _eq(c, arg))
        if op == "in":
            allowed = _scalar_list(arg, "'in'")
            return first(lambda c: any(_eq(c, a) for a in allowed))
        if op == "cidr":
            networks = [_network(n) for n in _scalar_list(arg, "'cidr'") if isinstance(n, str)]
            if not networks:
                raise InvalidRule("'cidr' needs at least one network")

            def in_networks(c: Any) -> bool:
                ip = _as_ip(c)
                return ip is not None and any(ip.version == net.version and ip in net for net in networks)

            return first(in_networks)
        return _regex_outcome(compile_pattern(arg), candidates, budget if budget is not None else WorkBudget())
    raise InvalidRule(f"unsupported predicate type {type(predicate).__name__}")


def evaluate_predicate(predicate: Any, value: Any, budget: Optional[WorkBudget] = None) -> bool:
    """Raises :class:`InvalidRule` for malformed predicates. Running out of ``budget`` is no match."""
    return _evaluate(predicate, value, budget).matched


def _validate_operator(predicate: Mapping[str, Any]) -> tuple[str, Any]:
    if len(predicate) != 1:
        raise InvalidRule("an operator predicate must have exactly one key")
    op, arg = next(iter(predicate.items()))
    if op not in _OPERATORS:
        raise InvalidRule(f"unknown operator {op!r}")
    if op == "regex":
        compile_pattern(arg)
    return op, arg


def validate_rule_match(match: Any) -> None:
    """Raise :class:`InvalidRule` unless ``match`` is a well-formed, safe rule (used on rule creation)."""
    if not isinstance(match, Mapping) or not match:
        raise InvalidRule("a rule needs at least one predicate")
    for path, predicate in match.items():
        _resolve({}, str(path))
        if isinstance(predicate, Mapping):
            op, arg = _validate_operator(predicate)
            if op == "in":
                _scalar_list(arg, "'in'")
            elif op == "cidr":
                if not [_network(n) for n in _scalar_list(arg, "'cidr'") if isinstance(n, str)]:
                    raise InvalidRule("'cidr' needs at least one network")
            elif op == "eq" and not isinstance(arg, _SCALARS):
                raise InvalidRule("'eq' needs a scalar")
        elif isinstance(predicate, (list, tuple)):
            _scalar_list(predicate, "list predicate")
        elif not isinstance(predicate, _SCALARS):
            raise InvalidRule(f"unsupported predicate type {type(predicate).__name__}")


def rule_matches(match: Mapping[str, Any], view: Mapping[str, Any], budget: Optional[WorkBudget] = None) -> bool:
    """All predicates must match. Raises :class:`InvalidRule` for malformed rules."""
    if not isinstance(match, Mapping) or not match:
        raise InvalidRule("a rule needs at least one predicate")
    budget = budget if budget is not None else WorkBudget()
    for path, predicate in match.items():
        if not evaluate_predicate(predicate, _resolve(view, str(path)), budget):
            return False
    return True


def _log_overruns(budget: WorkBudget, rules: int) -> None:
    if budget.overruns:
        # Never the subject or the pattern text: both may carry alert data.
        log.warning(
            "suppression.work_budget_exceeded", overruns=budget.overruns, exhausted=budget.exceeded, rules=rules
        )


def _display(value: Any) -> Optional[str]:
    if value is None:
        return None
    text, _ = redact_text(str(value))
    return text if len(text) <= EXPLAIN_VALUE_CHARS else text[: EXPLAIN_VALUE_CHARS - 3] + "..."


def explain_rule(match: Any, view: Mapping[str, Any], budget: Optional[WorkBudget] = None) -> RuleExplanation:
    """Evaluate every predicate of ``match`` (no short-circuit) and say why each did or did not match.

    Never raises: a malformed rule is reported with ``error`` set and
    ``matched=False``, which is also how :func:`first_matching_rule` treats
    it. Matched values are shown redacted and truncated. A regex that ran out
    of work is reported as ``work_budget_exceeded`` (not matched).
    """
    if not isinstance(match, Mapping) or not match:
        return RuleExplanation(False, (), "a rule needs at least one predicate")
    own_budget = budget is None
    budget = budget if budget is not None else WorkBudget()
    results: List[PredicateExplanation] = []
    error: Optional[str] = None
    for path, predicate in match.items():
        path_text = str(path)[:200]
        operator = _operator_name(predicate)
        try:
            outcome = _evaluate(predicate, _resolve(view, str(path)), budget)
        except InvalidRule as exc:
            error = error or str(exc)
            results.append(PredicateExplanation(path_text, operator, False, "invalid", error=str(exc)))
            continue
        results.append(
            PredicateExplanation(
                path_text, operator, outcome.matched, outcome.reason, _display(outcome.value), outcome.candidates
            )
        )
    matched = error is None and all(r.matched for r in results)
    if own_budget:
        _log_overruns(budget, 1)
    return RuleExplanation(matched, tuple(results), error)


#: The ``match`` keys of a suggestion written before verdict keys (one false positive, or a bulk proposal).
FINGERPRINT_SUGGESTION_KEYS = frozenset({"fingerprint", "source_id", "severity"})


def fingerprint_suggestion(rule: Any) -> bool:
    """A suggested rule that matches a fingerprint alone: written before verdict keys, never applied at the gate.

    A fingerprint is the detection and its entities, not what ran, so such a
    rule closed a malicious service or command next to a benign one (#343).
    It is a suggestion when it came from an analyst's false positive
    (``source_feedback_id``) or has exactly the suggestions' shape.
    """
    match = getattr(rule, "match", None)
    if not isinstance(match, Mapping) or "fingerprint" not in match:
        return False
    return bool(getattr(rule, "source_feedback_id", None)) or set(match) == FINGERPRINT_SUGGESTION_KEYS


def matching_rules(rules: Iterable[Any], views: Sequence[Mapping[str, Any]]) -> List[Any]:
    """Every valid rule that matches any of ``views`` (each rule with its own work budget per view)."""
    out: List[Any] = []
    for rule in rules:
        for view in views:
            try:
                if rule_matches(rule.match, view, WorkBudget()):
                    out.append(rule)
                    break
            except InvalidRule:
                break
    return out


def first_matching_rule(
    rules: Iterable[Any], view: Mapping[str, Any], budget: Optional[WorkBudget] = None
) -> Optional[RuleMatch]:
    """First rule (``SuppressionRule``-like: ``id``, ``name``, ``match``) that matches; invalid rules are skipped.

    All rules share one work budget (default :data:`MAX_EVALUATION_WORK`), so
    the cost of the gate is bounded however many rules a tenant has; regex
    predicates evaluated after it runs out do not match. The returned
    :class:`RuleMatch` carries the explanation of the match (computed with
    its own budget, at most the cost of the successful evaluation again).
    """
    budget = budget if budget is not None else WorkBudget()
    evaluated = 0
    try:
        for rule in rules:
            evaluated += 1
            try:
                if rule_matches(rule.match, view, budget):
                    explanation = explain_rule(rule.match, view, WorkBudget())
                    return RuleMatch(rule_id=str(rule.id), name=str(rule.name), explanation=explanation)
            except InvalidRule as exc:
                log.warning("suppression.rule_invalid", rule_id=str(rule.id), reason=str(exc))
        return None
    finally:
        _log_overruns(budget, evaluated)
