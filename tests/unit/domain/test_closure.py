"""Model-led closure (FIX-1, decision policy v2): the tenant's autonomy tier and every condition of a model close."""

from __future__ import annotations

import copy
import itertools
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.domain import closure, routing
from lg_sotf.domain.closure import (
    AUTONOMY_TIERS,
    MODEL_CLOSED,
    autonomy_tier,
    model_close_blockers,
    never_close_class,
    validate_ai_closure_settings,
)
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.models.vocabulary import SEVERITIES

T = RoutingThresholds()
AUTO = "auto_full_audit"
INJECTION = "prompt_injection_suspected"


def benign_state(**changes: Any) -> Dict[str, Any]:
    """A low alert both model tiers call benign within the default thresholds, without rule evidence.

    ``changes`` maps dotted paths (``triage.threat_likelihood``) to new values.
    """
    state: Dict[str, Any] = {
        "severity": "low",
        "confidence": 25,
        "alert": {"title": "Successful logon", "mitre": {"tactics": ["Initial Access"], "techniques": ["T1078"]}},
        "triage": {
            "confidence": 25, "rule_confidence": 40, "rule_fp": [], "rule_tp": [], "llm_fp": ["routine logon"],
            "llm_tp": [], "llm_used": True, "threat_assessment": "benign", "threat_likelihood": 5,
        },
        "correlation": {"related_count": 0, "related_dispositions": {}},
        "analysis": {
            "threat_score": 10, "certainty": 90, "verdict": "benign", "rule_threat_score": 45, "rule_evidence": [],
            "rule_corroborated": False, "llm_used": True,
        },
    }
    for path, value in changes.items():
        *parents, leaf = path.split(".")
        target = state
        for key in parents:
            target = target[key]
        target[leaf] = value
    return state


def test_a_model_led_close_needs_the_tier_and_is_marked_for_audit() -> None:
    decision = routing.decide(benign_state(), T, AUTO)
    assert (decision.route, decision.disposition, decision.code) == ("close", "benign", MODEL_CLOSED)
    assert decision.reason.startswith("AI-closed, audit required")
    assert closure.MODEL_CLOSE_REASON == "ai_closed:audit_required"
    for decided in (routing.decide(benign_state(), T, "off"), routing.decide(benign_state(), T)):
        assert (decided.route, decided.code) == ("escalate", "false_positive_review")


@pytest.mark.parametrize(
    ("path", "value", "blocker"),
    [
        ("severity", "high", "severity"),
        ("severity", "critical", "severity"),
        ("severity", "unknown", "severity"),
        ("alert.mitre.tactics", ["Credential Access"], "never_close_class"),
        ("alert.mitre.techniques", ["T1070.001"], "never_close_class"),
        ("triage.rule_tp", [INJECTION], "steering_text"),
        ("triage.rule_tp", None, "steering_text"),
        ("analysis.rule_evidence", ["prior_malicious_history"], "recent_true_positive"),
        ("analysis.rule_corroborated", True, "recent_true_positive"),
        ("correlation.related_dispositions", {"malicious": 1, "benign": 4}, "recent_true_positive"),
        ("triage.threat_assessment", "suspicious", "fast_tier_not_benign"),
        ("triage.threat_likelihood", 9, "fast_tier_not_benign"),
        ("triage.threat_likelihood", None, "fast_tier_not_benign"),
        ("triage.threat_likelihood", True, "fast_tier_not_benign"),
        ("triage.llm_used", False, "fast_tier_not_benign"),
        ("analysis.verdict", "inconclusive", "deep_tier_not_benign"),
        ("analysis.certainty", 84, "deep_tier_not_benign"),
        ("analysis.certainty", None, "deep_tier_not_benign"),
        ("analysis.llm_used", False, "deep_tier_not_benign"),
    ],
)
def test_each_condition_alone_blocks_a_model_led_close(path: str, value: Any, blocker: str) -> None:
    state = benign_state(**{path: value})
    blockers = model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85)
    assert blockers == [blocker]
    assert routing.decide(state, T, AUTO).route != "close"


def test_model_normalised_alerts_and_refusals_never_close_on_the_models_word() -> None:
    normalised = benign_state(**{"alert.flags": ["llm_normalized"]})
    assert routing.decide(normalised, T, AUTO).code == "llm_normalized"
    refused = benign_state(**{"analysis.llm_refusal": {"reason": "model_refused"}})
    assert routing.decide(refused, T, AUTO).code == "model_refused"
    asked = benign_state(more_info_loops=1)
    assert routing.decide(asked, T, AUTO).code == "analyst_request"


def test_the_thresholds_are_inclusive_and_install_settings() -> None:
    assert (T.model_close_max_likelihood, T.model_close_min_certainty) == (8, 85)
    edge = benign_state(**{"triage.threat_likelihood": 8, "analysis.certainty": 85})
    assert routing.decide(edge, T, AUTO).code == MODEL_CLOSED
    stricter = RoutingThresholds.from_settings({"model_close_max_likelihood": 4, "model_close_min_certainty": 95})
    assert routing.decide(benign_state(), stricter, AUTO).route == "escalate"
    assert routing.decide(benign_state(**{"triage.threat_likelihood": 4, "analysis.certainty": 95}), stricter, AUTO).code == MODEL_CLOSED


def test_a_model_led_close_still_needs_a_low_threat_outside_the_grey_zone() -> None:
    for threat, code in ((29, MODEL_CLOSED), (30, "grey_zone"), (75, "inconclusive"), (85, "high_risk")):
        assert routing.decide(benign_state(**{"analysis.threat_score": threat}), T, AUTO).code == code


def _grid(severities: List[str], evidence: bool) -> List[Dict[str, Any]]:
    states = []
    values = itertools.product(
        severities,
        (0, 8, 60),  # fast likelihood
        ("benign", "suspicious"),
        (0, 85, 100),  # deep certainty
        ("benign", "malicious", "inconclusive"),
        (0, 10, 50, 95),  # analysis threat score
        (0, 25, 90),  # triage confidence
        ([], [INJECTION]),
        ([], ["Credential Access"]),
    )
    for severity, likelihood, assessment, certainty, verdict, threat, confidence, rule_tp, tactics in values:
        state = benign_state(
            severity=severity,
            confidence=confidence,
            **{
                "triage.threat_likelihood": likelihood, "triage.threat_assessment": assessment,
                "triage.confidence": confidence, "triage.rule_tp": list(rule_tp),
                "triage.rule_fp": ["known_scanner"] if evidence else [],
                "analysis.certainty": certainty, "analysis.verdict": verdict, "analysis.threat_score": threat,
                "alert.mitre.tactics": list(tactics),
            },
        )
        states.append(state)
    return states


def test_with_the_tier_off_a_model_never_closes_alone() -> None:
    """INV-03: without approved benign evidence nothing closes at tier off, whatever both models say; nor at any
    value that is not exactly ``auto_full_audit``."""
    for tier in ("off", "", "AUTO_FULL_AUDIT", "auto_sampled", "auto"):
        for state in _grid(list(SEVERITIES), evidence=False):
            decision = routing.decide(state, T, tier)
            assert decision.route != "close" and decision.code != MODEL_CLOSED, (tier, state)
            assert routing.route_after_triage(state, T) != "close"


def test_high_and_critical_never_close_at_any_tier() -> None:
    """INV-03: with or without benign evidence, at every tier, a high or critical alert never closes."""
    for tier, evidence in itertools.product(AUTONOMY_TIERS, (False, True)):
        for state in _grid(["high", "critical"], evidence=evidence):
            assert routing.decide(state, T, tier).route != "close", (tier, state)
            assert routing.route_after_triage(state, T) != "close"
            assert "severity" in model_close_blockers(state, tier=tier, max_likelihood=100, min_certainty=0)


@pytest.mark.parametrize(
    ("tactics", "techniques", "expected"),
    [
        (["Credential Access"], [], "credential_access"),
        (["credential-access"], [], "credential_access"),
        (["TA0006"], [], "credential_access"),
        ([], ["T1003.001"], "credential_access"),
        ([], ["t1110.003"], "credential_access"),
        ([], ["T1558.003"], "credential_access"),
        ([], ["T1070.001"], "log_clearing"),
        ([], ["T1562.001"], "tampering"),
        ([], ["T1486"], "ransomware"),
        ([], ["T1490"], "ransomware"),
        (["Persistence"], ["T1053.005"], "named_persistence"),
        ([], ["T1543.003"], "named_persistence"),
        ([], ["T1547.001"], "named_persistence"),
        ([], ["T1136.001"], "named_persistence"),
        (["Discovery", "Execution"], ["T1059.001", "T1083"], None),
        (["Persistence", "Initial Access"], ["T1078"], None),
        (["Defense Evasion"], [], None),
        ([], [], "unmapped"),
    ],
)
def test_never_close_classes_never_close_on_the_models_word(
    tactics: List[str], techniques: List[str], expected: Optional[str]
) -> None:
    alert = {"mitre": {"tactics": tactics, "techniques": techniques}}
    assert never_close_class(alert) == expected
    state = benign_state(**{"alert.mitre": copy.deepcopy(alert["mitre"])})
    decision = routing.decide(state, T, AUTO)
    assert (decision.code == MODEL_CLOSED) is (expected is None)


def test_an_alert_without_a_readable_attack_mapping_is_a_never_close_class() -> None:
    """Fail closed: nothing shows an unmapped alert is outside the never-close classes."""
    for alert in (None, {}, {"mitre": "T1003"}, {"mitre": {"tactics": [], "techniques": []}},
                  {"mitre": {"tactics": [" "], "techniques": [1003, None]}}, {"category": "authentication_success"}):
        assert never_close_class(alert) == "unmapped", alert
    assert never_close_class({"mitre": {"tactics": "Credential Access"}}) == "credential_access"
    assert never_close_class({"mitre": {"techniques": [1003, None, "T1486"]}}) == "ransomware"
    unmapped = benign_state(**{"alert.mitre": {"tactics": [], "techniques": []}})
    assert model_close_blockers(unmapped, tier=AUTO, max_likelihood=8, min_certainty=85) == ["never_close_class"]


def test_the_autonomy_tier_fails_closed() -> None:
    assert autonomy_tier({"ai_closure": {"tier": "auto_full_audit"}}) == AUTO
    for settings in (None, {}, {"ai_closure": None}, {"ai_closure": "auto_full_audit"},
                     {"ai_closure": {"tier": "AUTO_FULL_AUDIT"}}, {"ai_closure": {"tier": ["auto_full_audit"]}},
                     {"ai_closure": {"tier": "off"}}, {"triage": {"tier": "auto_full_audit"}}):
        assert autonomy_tier(settings) == "off", settings


def test_the_setting_is_validated() -> None:
    assert validate_ai_closure_settings({"tier": AUTO}) == {"tier": AUTO}
    assert validate_ai_closure_settings({}) == {"tier": "off"}
    for bad in ({"tier": "auto_sampled"}, {"tier": "off", "max_likelihood": 50}, {"tier": None}, "off", []):
        with pytest.raises(ValueError, match="ai_closure"):
            validate_ai_closure_settings(bad)
