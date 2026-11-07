"""Suppression matcher: supported predicates, and malformed or unsafe rules never match."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from lg_sotf.domain.suppression import (
    MAX_SUBJECT_CHARS,
    InvalidRule,
    WorkBudget,
    alert_match_view,
    compile_pattern,
    evaluate_predicate,
    explain_rule,
    first_matching_rule,
    rule_matches,
    validate_regex,
    validate_rule_match,
)

VIEW = alert_match_view(
    title="Known scanner sweep",
    severity="low",
    category="recon",
    source_id="splunk-prod",
    source_alert_id="abc",
    fingerprint="fp-1",
    normalized={
        "entities": {"ips": ["10.1.2.3", "2001:db8::1"], "users": [{"value": "svc-scan"}]},
        "raw": {"secret": "never matched"},
    },
)


@pytest.mark.parametrize(
    "match",
    [
        {"severity": "low"},
        {"severity": ["low", "info"]},
        {"severity": {"in": ["low", "info"]}},
        {"severity": {"eq": "low"}},
        {"entities.ips": "10.1.2.3"},
        {"entities.ips": {"cidr": "10.0.0.0/8"}},
        {"entities.ips": {"cidr": ["192.168.0.0/16", "2001:db8::/32"]}},
        {"entities.users": "svc-scan"},
        {"title": {"regex": "Known scanner .*"}},
        {"normalized.entities.ips": {"cidr": "10.1.2.0/24"}, "source_id": "splunk-prod"},
    ],
)
def test_matching_predicates(match: Dict[str, Any]) -> None:
    assert rule_matches(match, VIEW)


@pytest.mark.parametrize(
    "match",
    [
        {"severity": "high"},
        {"title": {"regex": "scanner"}},
        {"entities.ips": {"cidr": "172.16.0.0/12"}},
        {"severity": "low", "category": "malware"},
        {"missing.field": "x"},
        {"raw.secret": "never matched"},
    ],
)
def test_non_matching_predicates(match: Dict[str, Any]) -> None:
    assert not rule_matches(match, VIEW)


@pytest.mark.parametrize(
    "match",
    [
        {},
        {"title": {"regex": "(a+)+$"}},
        {"title": {"regex": "(x*)*y"}},
        {"title": {"regex": "(a)\\1"}},
        {"title": {"regex": "a" * 300}},
        {"title": {"regex": "["}},
        {"title": {"like": "x"}},
        {"title": {"eq": "a", "in": ["b"]}},
        {"entities.ips": {"cidr": "not-a-network"}},
        {"a..b": "x"},
        {"title": [{"nested": 1}]},
    ],
)
def test_invalid_rules_raise(match: Dict[str, Any]) -> None:
    with pytest.raises(InvalidRule):
        rule_matches(match, VIEW)


@pytest.mark.parametrize(
    "pattern",
    [
        "[a-z]*[a-z]*[a-z]*[a-z]*[a-z]*!",
        "(a|aa)*b",
        "(?:a|ab)+c",
        "(a+){1,200}b",
        "(?:a?a?)*b",
        "(?=a)a",
        "a{0,256}a{0,256}a{0,256}!",
        "x{1000}",
        ".{0,200}.{0,200}.{0,200}!",
    ],
)
def test_regex_outside_the_safe_subset_is_rejected(pattern: str) -> None:
    with pytest.raises(InvalidRule):
        validate_regex(pattern)
    with pytest.raises(InvalidRule):
        validate_rule_match({"title": {"regex": pattern}})


@pytest.mark.parametrize(
    "pattern",
    [
        "Known scanner .{0,40}",
        r"\d{1,3}(\.\d{1,3}){3}",
        r"[a-z]+\.example\.com",
        "(ab|cd)?x",
        "host-[0-9]+",
        # Unbounded wildcards are exempt from the quantifier limits: the common analyst pattern.
        ".*scanner.*",
    ],
)
def test_common_patterns_are_accepted(pattern: str) -> None:
    assert validate_regex(pattern) == pattern


def test_accepted_patterns_match_long_subjects_quickly() -> None:
    started = time.perf_counter()
    for pattern in ("[a-z]*!", ".*x.{0,200}!", "(ab|cd)?a+!"):
        assert not evaluate_predicate({"regex": pattern}, "a" * MAX_SUBJECT_CHARS)
    assert time.perf_counter() - started < 1.0


EXPENSIVE = ".*a.{0,120}.{0,120}b"


def test_running_out_of_work_counts_as_no_match() -> None:
    # Accepted (two wide ranges), matches a short subject, but a long one exceeds the per-subject budget.
    assert validate_regex(EXPENSIVE) == EXPENSIVE
    assert evaluate_predicate({"regex": EXPENSIVE}, "ab" * 20)
    assert not evaluate_predicate({"regex": EXPENSIVE}, "ab" * 512)
    explained = explain_rule({"title": {"regex": EXPENSIVE}}, {"title": "ab" * 512})
    assert not explained.matched and explained.error is None
    assert [p.reason for p in explained.predicates] == ["work_budget_exceeded"]


def test_an_exhausted_shared_budget_stops_suppressing() -> None:
    budget = WorkBudget(5)
    assert not evaluate_predicate({"regex": "[a-z ]*"}, "x" * 200, budget)
    assert budget.exceeded and budget.overruns == 1
    rules = [Rule("r1", "wide", {"title": {"regex": ".*scanner.*"}})]
    assert first_matching_rule(rules, VIEW, WorkBudget(1)) is None
    hit = first_matching_rule(rules, VIEW)
    assert hit is not None and hit.rule_id == "r1"
    assert hit.explanation is not None and hit.explanation.matched


@pytest.mark.parametrize(
    "match",
    [
        {},
        {"a..b": "x"},
        {"title": {"eq": ["list"]}},
        {"title": {"in": [{"x": 1}]}},
        {"entities.ips": {"cidr": []}},
        {"title": {"like": "x"}},
        {"title": object()},
    ],
)
def test_validate_rule_match_rejects_malformed_rules(match: Any) -> None:
    with pytest.raises(InvalidRule):
        validate_rule_match(match)


def test_validate_rule_match_accepts_valid_rules() -> None:
    validate_rule_match(
        {"title": {"regex": "Known scanner .{0,40}"}, "entities.ips": {"cidr": ["10.0.0.0/8"]}, "severity": ["low", "medium"]}
    )


def test_regex_subject_length_is_limited() -> None:
    view = dict(VIEW, title="A" * 5_000)
    assert not rule_matches({"title": {"regex": "A+"}}, view)
    assert compile_pattern("A+") is compile_pattern("A+")


@dataclass
class Rule:
    id: str
    name: str
    match: Dict[str, Any]


def test_first_matching_rule_skips_invalid_rules() -> None:
    rules = [
        Rule("r1", "broken", {"title": {"regex": "(a+)+"}}),
        Rule("r2", "no", {"severity": "critical"}),
        Rule("r3", "yes", {"severity": "low"}),
    ]
    hit = first_matching_rule(rules, VIEW)
    assert hit is not None and hit.rule_id == "r3"
    assert first_matching_rule(rules[:2], VIEW) is None


# Exact rejection messages: they reach API clients (422 invalid_rule, the explain endpoint), so a
# refactor of the regex engine must keep them byte-identical.
REGEX_REJECTIONS = [
    (None, "regex must be a non-empty string"),
    ("", "regex must be a non-empty string"),
    (3, "regex must be a non-empty string"),
    ("x" * 257, "regex longer than 256 characters"),
    ("[", "invalid regex: unterminated character set"),
    ("a{3}{2}", "invalid regex: multiple repeat"),
    ("(a)\\1", "regex uses backreferences"),
    ("(a)?(?(1)b|c)", "regex uses conditionals"),
    ("(?<=a)b", "regex uses lookarounds"),
    ("x{257}", "regex repeat bound above 256"),
    ("(a+)+", "regex uses nested quantifiers"),
    ("(ab|cd)+", "regex quantifies an alternation"),
    ("[a-z]*[0-9]*[A-Z]*!", "regex uses more than 2 unbounded quantifiers"),
    ("a{0,20}b{0,20}c{0,20}!", "regex uses more than 2 wide quantifiers"),
    ("((x{0,16}){0,16}){0,16}", "regex expands to more than 512 matcher states"),
    ("(?a)\\w+", "regex uses unsupported flags"),
    ("(?i:a(?m:b))", "regex uses unsupported inline flags"),
    ("a*+b", "regex uses possessive quantifiers or atomic groups"),
    ("\\bfoo", "regex anchors and word boundaries are only supported as ^ and $ at the ends"),
]


@pytest.mark.parametrize(("pattern", "message"), REGEX_REJECTIONS)
def test_regex_rejection_messages_are_stable(pattern: Any, message: str) -> None:
    with pytest.raises(InvalidRule) as raised:
        validate_regex(pattern)
    assert str(raised.value) == message
    with pytest.raises(InvalidRule) as raised:
        validate_rule_match({"title": {"regex": pattern}})
    assert str(raised.value) == message
    with pytest.raises(InvalidRule) as raised:
        rule_matches({"title": {"regex": pattern}}, VIEW)
    assert str(raised.value) == message
    explained = explain_rule({"title": {"regex": pattern}}, VIEW)
    assert explained.error == message and explained.predicates[0].error == message
