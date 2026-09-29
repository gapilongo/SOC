"""Suppression matcher: supported predicates, and malformed or unsafe rules never match."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from lg_sotf.core import suppression
from lg_sotf.core.suppression import (
    MAX_SUBJECT_CHARS,
    InvalidRule,
    alert_match_view,
    compile_pattern,
    evaluate_predicate,
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
        ".*scanner.*",
    ],
)
def test_regex_outside_the_safe_subset_is_rejected(pattern: str) -> None:
    with pytest.raises(InvalidRule):
        validate_regex(pattern)
    with pytest.raises(InvalidRule):
        validate_rule_match({"title": {"regex": pattern}})


@pytest.mark.parametrize(
    "pattern",
    ["Known scanner .{0,40}", r"\d{1,3}(\.\d{1,3}){3}", r"[a-z]+\.example\.com", "(ab|cd)?x", "host-[0-9]+"],
)
def test_common_patterns_are_accepted(pattern: str) -> None:
    assert validate_regex(pattern) == pattern


def test_accepted_patterns_match_long_subjects_quickly() -> None:
    started = time.perf_counter()
    for pattern in ("[a-z]*!", ".*x.{0,200}!", "(ab|cd)?a+!"):
        assert not evaluate_predicate({"regex": pattern}, "a" * MAX_SUBJECT_CHARS)
    assert time.perf_counter() - started < 1.0


def test_regex_timeout_counts_as_no_match(monkeypatch: pytest.MonkeyPatch) -> None:
    class Slow:
        pattern = "x"

        def fullmatch(self, subject: str, timeout: float) -> None:
            raise TimeoutError("regex timed out")

    assert suppression._regex_fullmatch(Slow(), "x") is False  # type: ignore[arg-type]


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
