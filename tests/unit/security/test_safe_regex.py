"""Safe regex engine: the accepted subset agrees with ``re``, unsafe constructs are rejected, cost is bounded."""

from __future__ import annotations

import random
import re
import time
from typing import Any

import pytest

from lg_sotf.security.safe_regex import (
    MAX_DFA_CACHE,
    MAX_DFA_CACHE_STATES,
    MAX_MATCH_WORK,
    InvalidPattern,
    SafePattern,
    WorkBudget,
    WorkBudgetExceeded,
    compile_pattern,
    validate_regex,
)


@pytest.mark.parametrize(
    ("pattern", "subject", "expected"),
    [
        (".*scanner.*", "Known scanner sweep", True),
        (".*scanner.*", "Known sweep", False),
        (".*qualys.*", "Known scanner sweep from Qualys", False),
        ("(?i).*qualys.*", "Known scanner sweep from Qualys", True),
        (".*\\.exe", "C:\\Windows\\svchost.exe", True),
        (".*a.*b.*c.*", "xaxbxcx", True),
        (".*a.*b.*c.*", "xcxbxax", False),
        ("^svc-[a-z]+$", "svc-scan", True),
        ("svc-.+", "svc-", False),
        (".+", "", False),
        ("host-[0-9]{2,4}", "host-12345", False),
        ("host-[0-9]{2,4}", "host-123", True),
        ("[^0-9]*", "abc", True),
        ("[^0-9]*", "ab1", False),
        (r"\d{1,3}(\.\d{1,3}){3}", "10.1.2.3", True),
        (r"\w+@\w+\.com", "a_b@corp.com", True),
        (r"\s*x\s*", "  x  ", True),
        ("(ab|cd)?x", "cdx", True),
        ("(ab|cd)?x", "abcdx", False),
        ("(?s)a.b", "a\nb", True),
        ("a.b", "a\nb", False),
        ("(?i:ab)c", "ABc", True),
        ("(?i:ab)c", "ABC", False),
        ("[a-f]+", "DEAD", False),
        ("(?i)[a-f]+", "DEAD", True),
    ],
)
def test_matches_agree_with_python_regex(pattern: str, subject: str, expected: bool) -> None:
    assert compile_pattern(pattern).fullmatch(subject) is expected
    assert (re.fullmatch(pattern, subject) is not None) is expected


def test_randomised_agreement_with_python_regex() -> None:
    rng = random.Random(20260929)
    patterns = [
        ".*ab.*", "a*b", "(ab|a)c", "[a-c]+d?", "a{1,3}b{0,2}", ".*b.*a", "(?i)A.*B", "x?y?z?", "[^a]*a",
        r"\d+-\w*", "(a|b|c)d", "a.{0,5}b", "(?:ab)?(?:cd)?", ".+c", "a*",
    ]
    alphabet = "abcdxyz-1 "
    for pattern in patterns:
        compiled = compile_pattern(pattern)
        for _ in range(300):
            subject = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            assert compiled.fullmatch(subject) == (re.fullmatch(pattern, subject) is not None), (pattern, subject)


def test_wildcards_are_accepted_but_other_unbounded_quantifiers_are_limited() -> None:
    for pattern in (".*scanner.*", ".*a.*b.*c.*d.*", ".+foo.+", "prefix.*"):
        assert validate_regex(pattern) == pattern
    for pattern in ("[a-z]*[a-z]*[a-z]*!", "(a+)+$", "(x*)*y", "a{0,256}a{0,256}a{0,256}!"):
        with pytest.raises(InvalidPattern):
            validate_regex(pattern)


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("(a)\\1", "backreferences"),
        ("(?=a)a", "lookarounds"),
        ("\\bfoo\\b", "anchors and word boundaries"),
        ("a$b", "anchors"),
        ("a*+b", "possessive"),
        ("(?>a)b", "possessive quantifiers or atomic groups"),
        ("(?a)\\w+", "unsupported flags"),
        ("x" * 300, "longer than"),
        ("[", "invalid regex"),
    ],
)
def test_constructs_outside_the_subset_are_rejected_with_a_reason(pattern: str, reason: str) -> None:
    with pytest.raises(InvalidPattern, match=reason.split(" or ")[0]):
        validate_regex(pattern)


@pytest.mark.parametrize("bad", [None, 3, "", ["a"], {"x": 1}])
def test_non_string_patterns_are_invalid(bad: Any) -> None:
    with pytest.raises(InvalidPattern, match="regex must be a non-empty string"):
        compile_pattern(bad)


def test_invalid_pattern_is_a_value_error_and_keeps_the_parser_cause() -> None:
    with pytest.raises(InvalidPattern) as raised:
        compile_pattern("[")
    assert isinstance(raised.value, ValueError)
    assert isinstance(raised.value.__cause__, re.error)


def test_compiled_patterns_are_cached() -> None:
    assert compile_pattern("A+") is compile_pattern("A+")


def test_state_budget_is_enforced() -> None:
    assert compile_pattern("a{0,16}b{0,16}c").state_count < 100
    with pytest.raises(InvalidPattern, match="matcher states"):
        SafePattern("((x{0,16}){0,16}){0,16}")


# The most expensive accepted shapes: a leading .* keeps every position of the wide ranges active.
WORST_ACCEPTED = [".*a.{0,120}.{0,120}b", ".*.{0,250}!", ".*[a-m].{0,120}[a-m].{0,120}!"]


@pytest.mark.parametrize("pattern", WORST_ACCEPTED)
def test_one_subject_costs_a_bounded_amount_of_work(pattern: str) -> None:
    compiled = compile_pattern(pattern)
    rng = random.Random(7)
    subject = "".join(rng.choice("ab") for _ in range(1_024))
    started = time.perf_counter()
    with pytest.raises(WorkBudgetExceeded):
        compiled.fullmatch(subject)
    assert time.perf_counter() - started < 0.5
    entries, states = compiled.cache_size
    assert entries <= MAX_DFA_CACHE and states <= MAX_DFA_CACHE_STATES


def test_a_shared_budget_is_charged_and_stops_matching() -> None:
    compiled = compile_pattern("[a-z ]*")
    budget = WorkBudget(MAX_MATCH_WORK)
    assert compiled.fullmatch("abc", budget)
    assert 0 < MAX_MATCH_WORK - budget.remaining and not budget.exceeded
    small = WorkBudget(5)
    with pytest.raises(WorkBudgetExceeded):
        compiled.fullmatch("x" * 200, small)
    assert small.exceeded


def test_work_budget_validates_its_size() -> None:
    with pytest.raises(ValueError):
        WorkBudget(0)
