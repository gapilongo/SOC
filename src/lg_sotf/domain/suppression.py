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

Regexes run on a built-in linear-time matcher (a Thompson NFA simulated with
a lazily built, bounded DFA cache, the approach RE2 uses), never on a
backtracking engine, so matching cost is at most proportional to
``len(subject) * active states`` and no timeout is needed. The accepted
subset is: literals, ``.``, character classes and ``\\d \\w \\s`` (and
negations), groups, alternation, ``* + ? {m,n}``, ``^``/``$`` at the ends
of the pattern and the ``i``/``s`` flags. Backreferences, lookarounds,
conditionals, word boundaries, possessive quantifiers and atomic groups are
rejected. Patterns are also kept readable: no quantifier nested in an
unbounded one (or the reverse), no quantified alternation, at most two
unbounded quantifiers over something other than ``.`` and at most two wide
ones (unbounded or a range over :data:`MAX_NARROW_RANGE`). Unbounded
wildcards (``.*``, ``.+``) are exempt from both counts, so the common
analyst pattern ``.*foo.*`` is accepted; a bounded wildcard range such as
``.{0,200}`` is not exempt (it expands to one matcher state per position).

Cost is bounded three ways, because "linear" is only cheap when the active
state set is small:

* a pattern expands to at most :data:`MAX_NFA_STATES` matcher states;
* the per-pattern DFA cache is bounded by the total size of the cached state
  sets (:data:`MAX_DFA_CACHE_STATES`), not only by the number of entries, and
  large state sets are never cached;
* every evaluation carries a work budget (state-set steps): one subject may
  cost at most :data:`MAX_MATCH_WORK` and one call of
  :func:`first_matching_rule` / :func:`explain_rule` at most
  :data:`MAX_EVALUATION_WORK`. Running out counts as *no match* (the alert is
  not suppressed) and is logged without the subject.

A malformed rule never matches: a broken rule must not suppress alerts.
:func:`validate_rule_match` is the check the API runs when a rule is created
and :func:`explain_rule` reports, predicate by predicate, why a rule does or
does not match an alert.
"""

from __future__ import annotations

import ipaddress
import re
import re._constants as sre_constants
import re._parser as sre_parser
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact_text

log = get_logger(__name__)

MAX_PATH_DEPTH = 6
MAX_PATTERN_CHARS = 256
MAX_SUBJECT_CHARS = 1_024
MAX_LIST_VALUES = 256
MAX_CANDIDATES = 256

MAX_BOUNDED_REPEAT = 256
MAX_NARROW_RANGE = 16
MAX_UNBOUNDED_QUANTIFIERS = 2
MAX_WIDE_QUANTIFIERS = 2
MAX_NFA_STATES = 512
# DFA cache per compiled pattern: at most this many entries, holding at most this many
# state ids in total; state sets larger than MAX_CACHED_SET are recomputed, never cached.
MAX_DFA_CACHE = 4_096
MAX_DFA_CACHE_STATES = 8_192
MAX_CACHED_SET = 128
MAX_COMPILED_PATTERNS = 128
# Work budgets in state-set steps (a cache hit costs 1, a miss the size of the sets involved).
MAX_MATCH_WORK = 200_000
MAX_EVALUATION_WORK = 1_000_000
EXPLAIN_VALUE_CHARS = 128

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
_OPERATORS = ("eq", "in", "cidr", "regex")


class InvalidRule(ValueError):
    """A suppression predicate is malformed or unsafe."""


class WorkBudgetExceeded(Exception):
    """A regex evaluation ran out of its work budget; callers treat it as no match."""


class WorkBudget:
    """Remaining regex work (state-set steps) for one evaluation, shared across subjects and rules."""

    __slots__ = ("remaining", "exceeded", "overruns")

    def __init__(self, total: int = MAX_EVALUATION_WORK) -> None:
        if total < 1:
            raise ValueError("work budget must be >= 1")
        self.remaining = total
        self.exceeded = False
        self.overruns = 0
        """Regex evaluations cut short (per-subject limit or this budget), counted as no match."""

    def spend(self, units: int) -> None:
        self.remaining -= units
        if self.remaining < 0:
            self.exceeded = True
            raise WorkBudgetExceeded()


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
    return bool(a == b)


# --------------------------------------------------------------------------
# Regex subset: validation
# --------------------------------------------------------------------------


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


def _is_wildcard(body: Any) -> bool:
    """``.`` alone (the body of ``.*``, ``.+`` and ``.{m,n}``)."""
    items = list(body)
    return len(items) == 1 and items[0][0] is sre_constants.ANY


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
            # Only ``.*``/``.+`` are exempt: they are one looping state. A bounded ``.{m,n}``
            # expands to one state per position and counts like any other wide range.
            if not (unbounded and _is_wildcard(body)):
                counts["unbounded"] += int(unbounded)
                counts["wide"] += int(unbounded or high - low > MAX_NARROW_RANGE)
            inner = outer
            if repeats:
                inner = "unbounded" if unbounded or outer == "unbounded" else "bounded"
            _check_safe(body, inner, counts)
            continue
        for child in _children(op, av):
            _check_safe(child, outer, counts)


def _parse(pattern: Any) -> Any:
    if not isinstance(pattern, str) or not pattern:
        raise InvalidRule("regex must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise InvalidRule(f"regex longer than {MAX_PATTERN_CHARS} characters")
    try:
        return sre_parser.parse(pattern)
    except re.error as exc:
        raise InvalidRule(f"invalid regex: {exc.msg}") from exc
    except RecursionError as exc:
        raise InvalidRule("regex nests too deeply") from exc


def validate_regex(pattern: Any) -> str:
    """Raise :class:`InvalidRule` unless ``pattern`` is in the safe subset; returns it unchanged."""
    return compile_pattern(pattern).pattern


# --------------------------------------------------------------------------
# Regex subset: linear-time matcher
# --------------------------------------------------------------------------

_CharTest = Callable[[str], bool]
_CHAR, _SPLIT, _MATCH = 0, 1, 2
_BEGIN_ANCHORS = frozenset({sre_constants.AT_BEGINNING, sre_constants.AT_BEGINNING_STRING})
_END_ANCHORS = frozenset({sre_constants.AT_END, sre_constants.AT_END_STRING})


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


_CATEGORIES: Dict[Any, _CharTest] = {
    sre_constants.CATEGORY_DIGIT: str.isdecimal,
    sre_constants.CATEGORY_NOT_DIGIT: lambda c: not c.isdecimal(),
    sre_constants.CATEGORY_SPACE: str.isspace,
    sre_constants.CATEGORY_NOT_SPACE: lambda c: not c.isspace(),
    sre_constants.CATEGORY_WORD: _is_word,
    sre_constants.CATEGORY_NOT_WORD: lambda c: not _is_word(c),
}


def _variants(ch: str, ignore_case: bool) -> Tuple[str, ...]:
    return (ch, ch.lower(), ch.upper(), ch.casefold()) if ignore_case else (ch,)


def _literal_test(code: int, ignore_case: bool, negate: bool = False) -> _CharTest:
    target = chr(code)
    if ignore_case:
        folded = target.casefold()

        def test(c: str) -> bool:
            return (c.casefold() == folded) != negate

        return test
    return (lambda c: c != target) if negate else (lambda c: c == target)


def _class_test(items: Sequence[Tuple[Any, Any]], ignore_case: bool) -> _CharTest:
    negate = False
    literals: set[str] = set()
    ranges: List[Tuple[int, int]] = []
    categories: List[_CharTest] = []
    for op, av in items:
        if op is sre_constants.NEGATE:
            negate = True
        elif op is sre_constants.LITERAL:
            literals.add(chr(av))
        elif op is sre_constants.RANGE:
            ranges.append((av[0], av[1]))
        elif op is sre_constants.CATEGORY and av in _CATEGORIES:
            categories.append(_CATEGORIES[av])
        else:
            raise InvalidRule("regex uses an unsupported character class item")
    if ignore_case:
        literals = {v for lit in literals for v in _variants(lit, True)}

    def member(c: str) -> bool:
        for v in _variants(c, ignore_case):
            if v in literals or any(lo <= ord(v) <= hi for lo, hi in ranges if len(v) == 1):
                return True
        return any(test(c) for test in categories)

    return (lambda c: not member(c)) if negate else member


class _Builder:
    """Builds a Thompson NFA back to front (each fragment is compiled against its continuation)."""

    def __init__(self) -> None:
        self.kind: List[int] = []
        self.test: List[Optional[_CharTest]] = []
        self.out1: List[int] = []
        self.out2: List[int] = []

    def _new(self, kind: int, test: Optional[_CharTest] = None, out1: int = -1, out2: int = -1) -> int:
        if len(self.kind) >= MAX_NFA_STATES:
            raise InvalidRule(f"regex expands to more than {MAX_NFA_STATES} matcher states")
        self.kind.append(kind)
        self.test.append(test)
        self.out1.append(out1)
        self.out2.append(out2)
        return len(self.kind) - 1

    def match_state(self) -> int:
        return self._new(_MATCH)

    def sequence(self, items: Sequence[Tuple[Any, Any]], nxt: int, flags: int) -> int:
        for op, av in reversed(list(items)):
            nxt = self.node(op, av, nxt, flags)
        return nxt

    def node(self, op: Any, av: Any, nxt: int, flags: int) -> int:
        ignore_case = bool(flags & re.IGNORECASE)
        if op is sre_constants.LITERAL:
            return self._new(_CHAR, _literal_test(av, ignore_case), nxt)
        if op is sre_constants.NOT_LITERAL:
            return self._new(_CHAR, _literal_test(av, ignore_case, negate=True), nxt)
        if op is sre_constants.ANY:
            dotall = bool(flags & re.DOTALL)
            return self._new(_CHAR, (lambda c: True) if dotall else (lambda c: c != "\n"), nxt)
        if op is sre_constants.IN:
            return self._new(_CHAR, _class_test(av, ignore_case), nxt)
        if op is sre_constants.BRANCH:
            starts = [self.sequence(alt, nxt, flags) for alt in av[1]]
            head = starts[-1]
            for start in reversed(starts[:-1]):
                head = self._new(_SPLIT, None, start, head)
            return head
        if op is sre_constants.SUBPATTERN:
            _group, add_flags, del_flags, body = av
            unsupported = (add_flags | del_flags) & ~(re.IGNORECASE | re.DOTALL | re.UNICODE)
            if unsupported:
                raise InvalidRule("regex uses unsupported inline flags")
            return self.sequence(body, nxt, (flags | add_flags) & ~del_flags)
        if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
            low, high, body = av
            if high == sre_constants.MAXREPEAT:
                loop = self._new(_SPLIT, None, -1, nxt)
                self.out1[loop] = self.sequence(body, loop, flags)
                tail = loop
            else:
                tail = nxt
                for _ in range(high - low):
                    tail = self._new(_SPLIT, None, self.sequence(body, tail, flags), nxt)
            for _ in range(low):
                tail = self.sequence(body, tail, flags)
            return tail
        if op is sre_constants.POSSESSIVE_REPEAT or op is sre_constants.ATOMIC_GROUP:
            raise InvalidRule("regex uses possessive quantifiers or atomic groups")
        if op is sre_constants.AT:
            raise InvalidRule("regex anchors and word boundaries are only supported as ^ and $ at the ends")
        raise InvalidRule(f"regex uses an unsupported construct ({op})")


class SafePattern:
    """A compiled suppression regex. :meth:`fullmatch` runs in time linear in the subject length."""

    def __init__(self, pattern: str) -> None:
        parsed = _parse(pattern)
        counts = {"unbounded": 0, "wide": 0}
        _check_safe(list(parsed), None, counts)
        if counts["unbounded"] > MAX_UNBOUNDED_QUANTIFIERS:
            raise InvalidRule(f"regex uses more than {MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifiers")
        if counts["wide"] > MAX_WIDE_QUANTIFIERS:
            raise InvalidRule(f"regex uses more than {MAX_WIDE_QUANTIFIERS} wide quantifiers")
        flags = parsed.state.flags
        if flags & ~(re.IGNORECASE | re.DOTALL | re.UNICODE | re.VERBOSE | re.MULTILINE):
            raise InvalidRule("regex uses unsupported flags")
        items = list(parsed)
        # Matching is always a full match, so anchors at the two ends are redundant.
        while items and items[0][0] is sre_constants.AT and items[0][1] in _BEGIN_ANCHORS:
            items.pop(0)
        while items and items[-1][0] is sre_constants.AT and items[-1][1] in _END_ANCHORS:
            items.pop()
        builder = _Builder()
        self.pattern = pattern
        self._kind = builder.kind
        self._test = builder.test
        self._out1 = builder.out1
        self._out2 = builder.out2
        match = builder.match_state()
        self._match = match
        self._start = self._closure((builder.sequence(items, match, flags),))
        self._dfa: Dict[Tuple[FrozenSet[int], str], FrozenSet[int]] = {}
        self._dfa_states = 0

    @property
    def state_count(self) -> int:
        return len(self._kind)

    @property
    def cache_size(self) -> Tuple[int, int]:
        """(entries, state ids held) of the DFA cache."""
        return len(self._dfa), self._dfa_states

    def _closure(self, states: Iterable[int]) -> FrozenSet[int]:
        seen: set[int] = set()
        stack = list(states)
        while stack:
            s = stack.pop()
            if s in seen:
                continue
            seen.add(s)
            if self._kind[s] == _SPLIT:
                stack.append(self._out1[s])
                stack.append(self._out2[s])
        return frozenset(seen)

    def _step(self, current: FrozenSet[int], ch: str, budget: WorkBudget) -> FrozenSet[int]:
        key = (current, ch)
        cached = self._dfa.get(key)
        if cached is not None:
            budget.spend(1)
            return cached
        # Charge before doing the work, so an exhausted budget never pays for one more step.
        budget.spend(len(current) + 1)
        moved = [
            self._out1[s]
            for s in current
            if self._kind[s] == _CHAR and self._test[s](ch)  # type: ignore[misc]
        ]
        nxt = self._closure(moved)
        budget.spend(len(nxt))
        size = len(current) + len(nxt)
        if len(current) <= MAX_CACHED_SET and len(nxt) <= MAX_CACHED_SET:
            if len(self._dfa) >= MAX_DFA_CACHE or self._dfa_states + size > MAX_DFA_CACHE_STATES:
                self._dfa.clear()
                self._dfa_states = 0
            self._dfa[key] = nxt
            self._dfa_states += size
        return nxt

    def fullmatch(self, subject: str, budget: Optional[WorkBudget] = None) -> bool:
        """Full match of ``subject``; raises :class:`WorkBudgetExceeded` when ``budget`` (or the
        per-subject limit :data:`MAX_MATCH_WORK`) runs out."""
        local = WorkBudget(MAX_MATCH_WORK)
        current = self._start
        for ch in subject:
            before = local.remaining
            current = self._step(current, ch, local)
            if budget is not None:
                budget.spend(before - local.remaining)
            if not current:
                return False
        return self._match in current


@lru_cache(maxsize=MAX_COMPILED_PATTERNS)
def _compile_cached(pattern: str) -> SafePattern:
    return SafePattern(pattern)


def compile_pattern(pattern: Any) -> SafePattern:
    """Validate and compile ``pattern`` (cached); raises :class:`InvalidRule` outside the safe subset."""
    if not isinstance(pattern, str) or not pattern:
        raise InvalidRule("regex must be a non-empty string")
    return _compile_cached(pattern)


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
