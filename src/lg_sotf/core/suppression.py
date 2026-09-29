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

Regexes are restricted to a subset without catastrophic backtracking: no
backreferences, lookarounds or conditionals, no quantifier nested in an
unbounded one (or the reverse), no quantified alternation, at most one
unbounded quantifier and at most two wide ones (unbounded or a range over
:data:`MAX_NARROW_RANGE`). Matching also runs under a hard per-match timeout
in the ``regex`` engine; a timeout counts as no match.

A malformed rule never matches: a broken rule must not suppress alerts.
:func:`validate_rule_match` is the check the API runs when a rule is created.
"""

from __future__ import annotations

import ipaddress
import re
import re._constants as sre_constants
import re._parser as sre_parser
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable, List, Mapping, Optional, Sequence

import regex

from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

MAX_PATH_DEPTH = 6
MAX_PATTERN_CHARS = 256
MAX_SUBJECT_CHARS = 1_024
MAX_LIST_VALUES = 256
MAX_CANDIDATES = 256

MAX_BOUNDED_REPEAT = 256
MAX_NARROW_RANGE = 16
MAX_UNBOUNDED_QUANTIFIERS = 1
MAX_WIDE_QUANTIFIERS = 2
MATCH_TIMEOUT_S = 0.05

_SCALARS = (str, int, float, bool)
_MISSING = object()
_REPEATS = frozenset(
    {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT}
)
_FORBIDDEN = {
    sre_constants.GROUPREF: "backreferences",
    sre_constants.GROUPREF_EXISTS: "conditionals",
    sre_constants.ASSERT: "lookarounds",
    sre_constants.ASSERT_NOT: "lookarounds",
}


class InvalidRule(ValueError):
    """A suppression predicate is malformed or unsafe."""


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str


def alert_match_view(
    *,
    title: str,
    severity: str,
    category: Optional[str],
    source_id: str,
    source_alert_id: str,
    fingerprint: str,
    normalized: Mapping[str, Any],
) -> dict[str, Any]:
    """Fields a suppression rule may reference. Canonical-model keys are also exposed at the top level."""
    view: dict[str, Any] = {k: v for k, v in normalized.items() if k != "raw"}
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
    return view


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
    return a == b


def _children(op: Any, av: Any) -> List[Any]:
    if op in _REPEATS:
        return [av[2]]
    if op is sre_constants.SUBPATTERN:
        return [av[3]]
    if op is sre_constants.BRANCH:
        return list(av[1])
    if op is sre_constants.ATOMIC_GROUP:
        return [av]
    return []


def _has(items: Any, wanted: frozenset[Any]) -> bool:
    for op, av in items:
        if op in wanted or any(_has(child, wanted) for child in _children(op, av)):
            return True
    return False


def _check_safe(items: Any, outer: Optional[str], counts: dict[str, int]) -> None:
    """``outer`` is the kind of the enclosing repeating quantifier: None, "bounded" or "unbounded"."""
    for op, av in items:
        if op in _FORBIDDEN:
            raise InvalidRule(f"regex uses {_FORBIDDEN[op]}")
        if op in _REPEATS:
            low, high, body = av
            unbounded = high == sre_constants.MAXREPEAT
            if not unbounded and high > MAX_BOUNDED_REPEAT:
                raise InvalidRule(f"regex repeat bound above {MAX_BOUNDED_REPEAT}")
            repeats = high > 1
            if outer == "unbounded" or (outer == "bounded" and unbounded):
                raise InvalidRule("regex uses nested quantifiers")
            if repeats and _has(body, frozenset({sre_constants.BRANCH})):
                raise InvalidRule("regex quantifies an alternation")
            counts["unbounded"] += int(unbounded)
            counts["wide"] += int(unbounded or high - low > MAX_NARROW_RANGE)
            inner = outer
            if repeats:
                inner = "unbounded" if unbounded or outer == "unbounded" else "bounded"
            _check_safe(body, inner, counts)
            continue
        for child in _children(op, av):
            _check_safe(child, outer, counts)


def validate_regex(pattern: Any) -> str:
    """Raise :class:`InvalidRule` unless ``pattern`` is in the safe subset; returns it unchanged."""
    if not isinstance(pattern, str) or not pattern:
        raise InvalidRule("regex must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise InvalidRule(f"regex longer than {MAX_PATTERN_CHARS} characters")
    try:
        parsed = sre_parser.parse(pattern)
    except re.error as exc:
        raise InvalidRule(f"invalid regex: {exc.msg}") from exc
    except RecursionError as exc:
        raise InvalidRule("regex nests too deeply") from exc
    counts = {"unbounded": 0, "wide": 0}
    _check_safe(list(parsed), None, counts)
    if counts["unbounded"] > MAX_UNBOUNDED_QUANTIFIERS:
        raise InvalidRule(f"regex uses more than {MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifier")
    if counts["wide"] > MAX_WIDE_QUANTIFIERS:
        raise InvalidRule(f"regex uses more than {MAX_WIDE_QUANTIFIERS} wide quantifiers")
    return pattern


@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> regex.Pattern[str]:
    validate_regex(pattern)
    try:
        return regex.compile(pattern, regex.V0)
    except regex.error as exc:
        raise InvalidRule(f"invalid regex: {exc}") from exc


def _regex_fullmatch(pattern: regex.Pattern[str], subject: str) -> bool:
    try:
        return pattern.fullmatch(subject, timeout=MATCH_TIMEOUT_S) is not None
    except TimeoutError:
        log.warning("suppression.regex_timeout", pattern_chars=len(pattern.pattern))
        return False


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


def evaluate_predicate(predicate: Any, value: Any) -> bool:
    """Raises :class:`InvalidRule` for malformed predicates."""
    if value is _MISSING or value is None:
        if isinstance(predicate, Mapping):
            _validate_operator(predicate)
        return False
    candidates = _candidates(value)
    if isinstance(predicate, _SCALARS):
        return any(_eq(c, predicate) for c in candidates)
    if isinstance(predicate, (list, tuple)):
        allowed = _scalar_list(predicate, "list predicate")
        return any(_eq(c, a) for c in candidates for a in allowed)
    if isinstance(predicate, Mapping):
        op, arg = _validate_operator(predicate)
        if op == "eq":
            return any(_eq(c, arg) for c in candidates)
        if op == "in":
            allowed = _scalar_list(arg, "'in'")
            return any(_eq(c, a) for c in candidates for a in allowed)
        if op == "cidr":
            networks = [_network(n) for n in _scalar_list(arg, "'cidr'") if isinstance(n, str)]
            if not networks:
                raise InvalidRule("'cidr' needs at least one network")
            for c in candidates:
                ip = _as_ip(c)
                if ip is not None and any(ip.version == n.version and ip in n for n in networks):
                    return True
            return False
        pattern = compile_pattern(arg)
        return any(
            isinstance(c, str) and len(c) <= MAX_SUBJECT_CHARS and _regex_fullmatch(pattern, c) for c in candidates
        )
    raise InvalidRule(f"unsupported predicate type {type(predicate).__name__}")


def _validate_operator(predicate: Mapping[str, Any]) -> tuple[str, Any]:
    if len(predicate) != 1:
        raise InvalidRule("an operator predicate must have exactly one key")
    op, arg = next(iter(predicate.items()))
    if op not in ("eq", "in", "cidr", "regex"):
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


def rule_matches(match: Mapping[str, Any], view: Mapping[str, Any]) -> bool:
    """All predicates must match. Raises :class:`InvalidRule` for malformed rules."""
    if not isinstance(match, Mapping) or not match:
        raise InvalidRule("a rule needs at least one predicate")
    for path, predicate in match.items():
        if not evaluate_predicate(predicate, _resolve(view, str(path))):
            return False
    return True


def first_matching_rule(rules: Iterable[Any], view: Mapping[str, Any]) -> Optional[RuleMatch]:
    """First rule (``SuppressionRule``-like: ``id``, ``name``, ``match``) that matches; invalid rules are skipped."""
    for rule in rules:
        try:
            if rule_matches(rule.match, view):
                return RuleMatch(rule_id=str(rule.id), name=str(rule.name))
        except InvalidRule as exc:
            log.warning("suppression.rule_invalid", rule_id=str(rule.id), reason=str(exc))
    return None
