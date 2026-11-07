"""A ReDoS-safe regex subset with a linear-time matcher.

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
* every match carries a work budget (state-set steps): one subject may cost
  at most :data:`MAX_MATCH_WORK`, and a caller may share one
  :class:`WorkBudget` (default :data:`MAX_EVALUATION_WORK`) across many
  matches. Running out raises :class:`WorkBudgetExceeded`.

Patterns are parsed with CPython's private ``re._parser`` and
``re._constants``; ``tests/unit/security/test_safe_regex_parser_guard.py``
fails loudly if a Python upgrade changes their shape. This module imports
only the standard library: it is a leaf (import-linter contract
``safe-regex-is-leaf``).
"""

from __future__ import annotations

import re
import re._constants as sre_constants
import re._parser as sre_parser
from functools import lru_cache
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

MAX_PATTERN_CHARS = 256

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

_REPEATS = frozenset(
    {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT}
)
_FORBIDDEN = {
    sre_constants.GROUPREF: "backreferences",
    sre_constants.GROUPREF_EXISTS: "conditionals",
    sre_constants.ASSERT: "lookarounds",
    sre_constants.ASSERT_NOT: "lookarounds",
}


class InvalidPattern(ValueError):
    """A regex is malformed or outside the safe subset. The message is safe to show to API clients."""


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
            raise InvalidPattern(f"regex uses {_FORBIDDEN[op]}")
        if op in _REPEATS:
            low, high, body = av
            unbounded = high == sre_constants.MAXREPEAT
            if not unbounded and high > MAX_BOUNDED_REPEAT:
                raise InvalidPattern(f"regex repeat bound above {MAX_BOUNDED_REPEAT}")
            repeats = high > 1
            if outer == "unbounded" or (outer == "bounded" and unbounded):
                raise InvalidPattern("regex uses nested quantifiers")
            if repeats and _has(body, frozenset({sre_constants.BRANCH})):
                raise InvalidPattern("regex quantifies an alternation")
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
        raise InvalidPattern("regex must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise InvalidPattern(f"regex longer than {MAX_PATTERN_CHARS} characters")
    try:
        return sre_parser.parse(pattern)
    except re.error as exc:
        raise InvalidPattern(f"invalid regex: {exc.msg}") from exc
    except RecursionError as exc:
        raise InvalidPattern("regex nests too deeply") from exc


def validate_regex(pattern: Any) -> str:
    """Raise :class:`InvalidPattern` unless ``pattern`` is in the safe subset; returns it unchanged."""
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
            raise InvalidPattern("regex uses an unsupported character class item")
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
            raise InvalidPattern(f"regex expands to more than {MAX_NFA_STATES} matcher states")
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
                raise InvalidPattern("regex uses unsupported inline flags")
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
            raise InvalidPattern("regex uses possessive quantifiers or atomic groups")
        if op is sre_constants.AT:
            raise InvalidPattern("regex anchors and word boundaries are only supported as ^ and $ at the ends")
        raise InvalidPattern(f"regex uses an unsupported construct ({op})")


class SafePattern:
    """A compiled safe-subset regex. :meth:`fullmatch` runs in time linear in the subject length."""

    def __init__(self, pattern: str) -> None:
        parsed = _parse(pattern)
        counts = {"unbounded": 0, "wide": 0}
        _check_safe(list(parsed), None, counts)
        if counts["unbounded"] > MAX_UNBOUNDED_QUANTIFIERS:
            raise InvalidPattern(f"regex uses more than {MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifiers")
        if counts["wide"] > MAX_WIDE_QUANTIFIERS:
            raise InvalidPattern(f"regex uses more than {MAX_WIDE_QUANTIFIERS} wide quantifiers")
        flags = parsed.state.flags
        if flags & ~(re.IGNORECASE | re.DOTALL | re.UNICODE | re.VERBOSE | re.MULTILINE):
            raise InvalidPattern("regex uses unsupported flags")
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
    """Validate and compile ``pattern`` (cached); raises :class:`InvalidPattern` outside the safe subset."""
    if not isinstance(pattern, str) or not pattern:
        raise InvalidPattern("regex must be a non-empty string")
    return _compile_cached(pattern)
