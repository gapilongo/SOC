"""Gate suppression matcher: analyst wildcard patterns, linear-time matching, explain output."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from lg_sotf.domain.suppression import (
    MAX_SUBJECT_CHARS,
    InvalidRule,
    alert_match_view,
    compile_pattern,
    evaluate_predicate,
    explain_rule,
    first_matching_rule,
    validate_rule_match,
)
from lg_sotf.security.safe_regex import MAX_EVALUATION_WORK, WorkBudget

VIEW = alert_match_view(
    title="Known scanner sweep from Qualys",
    severity="low",
    category="recon",
    source_id="splunk-prod",
    source_alert_id="abc",
    fingerprint="fp-1",
    normalized={
        "entities": {
            "ips": ["10.1.2.3"],
            "users": [{"value": "svc-scan"}],
            "processes": ["C:\\Windows\\System32\\svchost.exe"],
        },
        "description": "password=hunter2 in the command line",
        "raw": {"secret": "never matched"},
    },
)


def test_matching_is_linear_on_adversarial_subjects() -> None:
    """Patterns that are catastrophic for a backtracking engine stay fast (no timeouts involved)."""
    subject = "a" * MAX_SUBJECT_CHARS
    started = time.perf_counter()
    for pattern in (".*a.*a.*a.*a.*b", ".*.*.*.*!", "(a|a)?a{0,16}.*b", ".*x.{0,200}!"):
        assert not evaluate_predicate({"regex": pattern}, subject)
    assert time.perf_counter() - started < 1.0
    rng = random.Random(1)
    varied = "".join(rng.choice("abcdefgh") for _ in range(MAX_SUBJECT_CHARS))
    assert len(set(varied)) == 8
    started = time.perf_counter()
    assert not compile_pattern(".*h.*g.*f.*e.*d.*zz").fullmatch(varied)
    assert time.perf_counter() - started < 1.0


def test_subjects_over_the_limit_never_match() -> None:
    assert not evaluate_predicate({"regex": ".*"}, "a" * (MAX_SUBJECT_CHARS + 1))
    assert evaluate_predicate({"regex": ".*"}, "a" * MAX_SUBJECT_CHARS)


def test_explain_reports_each_predicate() -> None:
    rule = {
        "title": {"regex": ".*scanner.*"},
        "entities.ips": {"cidr": "10.0.0.0/8"},
        "severity": ["low", "info"],
        "entities.users": "svc-scan",
    }
    explanation = explain_rule(rule, VIEW)
    assert explanation.matched and explanation.error is None
    data = explanation.as_dict()
    assert [p["path"] for p in data["predicates"]] == list(rule)
    assert data["predicates"][0] == {
        "path": "title",
        "operator": "regex",
        "matched": True,
        "reason": "matched",
        "candidates": 1,
        "value": "Known scanner sweep from Qualys",
    }
    assert data["predicates"][1]["value"] == "10.1.2.3" and data["predicates"][2]["operator"] == "in"
    assert data["predicates"][3]["operator"] == "eq" and data["predicates"][3]["value"] == "svc-scan"


def test_explain_says_why_a_rule_does_not_match_without_short_circuiting() -> None:
    explanation = explain_rule(
        {"severity": "high", "missing.field": "x", "title": {"regex": ".*nothing.*"}, "entities.ips": {"cidr": "10.0.0.0/8"}},
        VIEW,
    )
    reasons = [(p.path, p.matched, p.reason) for p in explanation.predicates]
    assert not explanation.matched
    assert reasons == [
        ("severity", False, "no_value_matched"),
        ("missing.field", False, "field_missing"),
        ("title", False, "no_value_matched"),
        ("entities.ips", True, "matched"),
    ]
    long_title = dict(VIEW, title="x" * (MAX_SUBJECT_CHARS + 5))
    assert explain_rule({"title": {"regex": "x+"}}, long_title).predicates[0].reason == "subject_too_long"


def test_explain_never_raises_and_redacts_values() -> None:
    bad = explain_rule({"title": {"regex": "(a+)+"}}, VIEW)
    assert not bad.matched and bad.error and bad.predicates[0].reason == "invalid"
    assert explain_rule({}, VIEW).error == "a rule needs at least one predicate"
    shown = explain_rule({"description": {"regex": ".*password.*"}}, VIEW).predicates[0]
    assert shown.matched and "hunter2" not in (shown.value or "") and "[REDACTED]" in (shown.value or "")


@dataclass
class Rule:
    id: str
    name: str
    match: Dict[str, Any]


def test_first_matching_rule_carries_its_explanation() -> None:
    rules = [
        Rule("r1", "broken", {"title": {"regex": "(a+)+"}}),
        Rule("r2", "no", {"severity": "critical"}),
        Rule("r3", "scanner noise", {"title": {"regex": ".*scanner.*"}, "source_id": "splunk-prod"}),
    ]
    hit = first_matching_rule(rules, VIEW)
    assert hit is not None and hit.rule_id == "r3"
    assert hit.explanation is not None and hit.explanation.matched
    assert [p.path for p in hit.explanation.predicates] == ["title", "source_id"]
    assert first_matching_rule(rules[:2], VIEW) is None


# ------------------------------------------------------------ bounded cost (no CPU/memory denial of service)


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        (".{0,256}" * 7 + "x", "more than 2 wide quantifiers"),
        (".{0,64}.{0,64}.{0,64}x", "more than 2 wide quantifiers"),
        (".{0,256}x", "matcher states"),
        ("[a-z]{0,200}[0-9]{0,200}x", "matcher states"),
    ],
)
def test_bounded_wildcard_ranges_are_not_exempt_from_the_limits(pattern: str, reason: str) -> None:
    with pytest.raises(InvalidRule, match=reason):
        validate_rule_match({"entities.command_lines": {"regex": pattern}})


def test_unbounded_wildcards_stay_exempt() -> None:
    for pattern in (".*foo.*", ".+bar.+", ".*a.*b.*c.*d.*", "(?i).*scanner.*sweep.*", ".*x.{0,200}!", "prefix.*"):
        validate_rule_match({"title": {"regex": pattern}})


# The most expensive accepted shapes: a leading .* keeps every position of the wide ranges active.
WORST_ACCEPTED = [".*a.{0,120}.{0,120}b", ".*.{0,250}!", ".*[a-m].{0,120}[a-m].{0,120}!"]


@pytest.mark.parametrize("pattern", WORST_ACCEPTED)
def test_running_out_of_work_on_one_subject_is_no_match(pattern: str) -> None:
    rng = random.Random(7)
    subject = "".join(rng.choice("ab") for _ in range(MAX_SUBJECT_CHARS))
    # The engine raises WorkBudgetExceeded (tests/unit/security/test_safe_regex.py); as a predicate,
    # running out of work is simply "no match".
    assert not evaluate_predicate({"regex": pattern}, subject)
    explained = explain_rule({"title": {"regex": pattern}}, dict(VIEW, title=subject)).predicates[0]
    assert (explained.matched, explained.reason) == (False, "work_budget_exceeded")


def test_the_gate_is_bounded_however_many_rules_and_values(caplog: pytest.LogCaptureFixture) -> None:
    """Reviewer's probe: 20 rules x 50 command lines of 1,000 characters took ~20 s per alert before."""
    rng = random.Random(3)
    commands = ["".join(rng.choice("ab") for _ in range(1_000)) for _ in range(50)]
    view = alert_match_view(
        title="t", severity="low", category=None, source_id="s", source_alert_id="1", fingerprint="f",
        normalized={"entities": {"command_lines": commands}},
    )
    rules = [Rule(f"r{i}", "slow", {"entities.command_lines": {"regex": WORST_ACCEPTED[i % 3]}}) for i in range(20)]
    # A cheap rule after the expensive ones still gets evaluated (and matches).
    rules.append(Rule("cheap", "severity", {"severity": "low"}))
    budget = WorkBudget(MAX_EVALUATION_WORK)
    started = time.perf_counter()
    hit = first_matching_rule(rules, view, budget)
    assert time.perf_counter() - started < 2.0
    assert hit is not None and hit.rule_id == "cheap"
    assert budget.exceeded and budget.overruns > 0


def test_a_legitimate_wildcard_rule_still_matches_long_values() -> None:
    subject = "powershell.exe -nop -w hidden " + "a" * 900 + " qualys-scanner"
    assert len(subject) <= MAX_SUBJECT_CHARS
    started = time.perf_counter()
    for _ in range(50):
        assert evaluate_predicate({"regex": "(?i).*qualys.*"}, subject)
    assert time.perf_counter() - started < 1.0

