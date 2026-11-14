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
        ("severity", "critical", "severity"),
        ("severity", "unknown", "severity"),
        ("alert.mitre.tactics", ["Credential Access"], "never_close_class"),
        ("alert.mitre.techniques", ["T1070.001"], "never_close_class"),
        ("alert.mitre.techniques", ["T1531"], "never_close_class"),
        ("alert.flags", ["llm_normalized"], "llm_normalized"),
        ("alert.reopened", {"reason": "related_threat"}, "reopened"),
        ("triage.rule_tp", [INJECTION], "steering_text"),
        ("triage.rule_tp", None, "steering_text"),
        ("analysis.rule_evidence", ["prior_malicious_history"], "recent_true_positive"),
        ("analysis.rule_corroborated", True, "recent_true_positive"),
        ("correlation.related_dispositions", {"malicious": 1, "benign": 4}, "recent_true_positive"),
        ("triage.threat_assessment", "likely_threat", "fast_tier_threat"),
        ("triage.threat_assessment", "confirmed_threat", "fast_tier_threat"),
        ("analysis.verdict", "inconclusive", "deep_tier_not_benign"),
        ("analysis.verdict", "malicious", "deep_tier_not_benign"),
        ("analysis.verdict", None, "deep_tier_not_benign"),
        ("analysis.llm_used", False, "deep_tier_not_benign"),
    ],
)
def test_each_condition_alone_blocks_a_model_led_close(path: str, value: Any, blocker: str) -> None:
    state = benign_state(**{path: value})
    assert model_close_blockers(state, tier=AUTO) == [blocker]
    assert routing.decide(state, T, AUTO).route != "close"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("severity", "high"),  # high closes on the models' word at the tier (v3)
        ("triage.threat_assessment", "suspicious"),  # only likely_threat and confirmed_threat block
        ("triage.threat_likelihood", 60),  # the install thresholds are gone
        ("triage.llm_used", False),
        ("analysis.certainty", 5),  # any certainty
        ("analysis.threat_score", 50),  # the grey zone does not hold a benign verdict back
        ("alert.mitre", {"tactics": [], "techniques": []}),  # unmapped no longer blocks
        ("correlation", {"related_count": 9, "burst": True, "related_threats": 3, "related_open_reviews": 9,
                         "related_dispositions": {"undecided": 9}}),  # no campaign check: retro-reopen instead
    ],
)
def test_v3_removed_the_forward_gates(path: str, value: Any) -> None:
    """FIX-3: the thresholds, the grey zone for a benign verdict, the campaign check and the unmapped block are
    gone; the safety net reopens a close when a related threat appears (lg_sotf.core.retro_reopen)."""
    state = benign_state(**{path: value})
    assert model_close_blockers(state, tier=AUTO) == []
    assert routing.decide(state, T, AUTO).code == MODEL_CLOSED


def test_model_normalised_alerts_and_refusals_never_close_on_the_models_word() -> None:
    normalised = benign_state(**{"alert.flags": ["llm_normalized"]})
    assert routing.decide(normalised, T, AUTO).code == "llm_normalized"
    refused = benign_state(**{"analysis.llm_refusal": {"reason": "model_refused"}})
    assert routing.decide(refused, T, AUTO).code == "model_refused"
    asked = benign_state(more_info_loops=1)
    assert routing.decide(asked, T, AUTO).code == "analyst_request"


def test_a_benign_verdict_closes_below_the_response_policy_and_evidence_closes_first() -> None:
    for threat, code in ((5, MODEL_CLOSED), (30, MODEL_CLOSED), (75, MODEL_CLOSED), (85, "high_risk")):
        assert routing.decide(benign_state(**{"analysis.threat_score": threat}), T, AUTO).code == code
    evidence = benign_state(**{"triage.rule_fp": ["test_detected"]})
    assert routing.decide(evidence, T, AUTO).code == "rule_corroborated_benign"


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


def test_critical_never_closes_at_any_tier_and_high_only_on_the_models_word_at_the_tier() -> None:
    """INV-03 (v3): with or without benign evidence, at every tier, a critical alert never closes; a high alert never
    closes on evidence or at tier off, and on the models' word only at auto_full_audit."""
    for tier, evidence in itertools.product(AUTONOMY_TIERS, (False, True)):
        for state in _grid(["critical"], evidence=evidence):
            assert routing.decide(state, T, tier).route != "close", (tier, state)
            assert routing.route_after_triage(state, T) != "close"
            assert "severity" in model_close_blockers(state, tier=tier)
        for state in _grid(["high"], evidence=evidence):
            decision = routing.decide(state, T, tier)
            assert decision.route != "close" or (tier == AUTO and decision.code == MODEL_CLOSED), (tier, state)
            assert routing.route_after_triage(state, T) != "close"


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
        ([], ["T1531"], "credential_access"),
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


def test_an_unmapped_alert_closes_on_the_models_word_but_an_unreadable_wazuh_rule_does_not() -> None:
    """v3: nothing shows an unmapped alert is outside the never-close classes, but the safety net now reopens it on
    a related threat, so it closes; a Wazuh alert whose rule cannot be read (vendor_unknown) still never does."""
    for alert in (None, {}, {"mitre": "T1003"}, {"mitre": {"tactics": [], "techniques": []}},
                  {"mitre": {"tactics": [" "], "techniques": [1003, None]}}, {"category": "authentication_success"}):
        assert never_close_class(alert) == "unmapped", alert
        assert closure.model_close_class(alert) is None
    assert never_close_class({"mitre": {"tactics": "Credential Access"}}) == "credential_access"
    assert never_close_class({"mitre": {"techniques": [1003, None, "T1486"]}}) == "ransomware"
    unmapped = benign_state(**{"alert.mitre": {"tactics": [], "techniques": []}})
    assert model_close_blockers(unmapped, tier=AUTO) == []
    unreadable = benign_state(**{"alert.mitre": {"tactics": [], "techniques": []}, "alert.normalizer": "wazuh"})
    assert model_close_blockers(unreadable, tier=AUTO) == ["never_close_class"]


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


# --------------------------------------------------------------------------- independent review of #341 (adopted)
# The reviewer's proofs (scratchpad rev341/test_rev341_findings.py), each asserting the safe behaviour.


def _review_state(**changes: Any) -> Dict[str, Any]:
    """The reviewer's base: a medium alert both tiers call benign (likelihood 2, certainty 95), no evidence."""
    return benign_state(severity="medium", **{"triage.threat_likelihood": 2, "analysis.certainty": 95,
                                               "analysis.threat_score": 5}, **changes)


def test_review_f1_evidence_never_closes_past_threat_intel_history_related_malicious_and_steering() -> None:
    state = _review_state(**{
        "alert.mitre": {"tactics": ["Credential Access"], "techniques": ["T1110.003"]},
        "triage.rule_fp": ["known_scanner"], "triage.rule_tp": [INJECTION],
        "analysis.rule_threat_score": 95, "analysis.rule_corroborated": True,
        "analysis.rule_evidence": ["threat_intel_malicious", "prior_malicious_history"],
        "correlation": {"related_count": 6, "burst": True, "related_dispositions": {"malicious": 3}},
    })
    for tier in AUTONOMY_TIERS:
        decision = routing.decide(state, T, tier)
        assert (decision.route, decision.code) == ("escalate", "false_positive_review"), decision
    assert set(closure.evidence_close_blockers(state)) == {"steering_text", "recent_true_positive", "never_close_class"}


def test_review_f2_sentinel_credential_access_is_a_never_close_class() -> None:
    from datetime import UTC, datetime

    from lg_sotf.ingestion.normalizers import NormalizeContext, get_normalizer

    ctx = NormalizeContext(source_id="src-1", source_type="sentinel", now=datetime(2024, 3, 5, 12, tzinfo=UTC))
    for tactics in ("CredentialAccess", "Credential Access", "credential_access", "TA0006"):
        event = {"SystemAlertId": "a1", "AlertName": "Password spray", "AlertSeverity": "Medium", "Tactics": tactics,
                 "TimeGenerated": "2024-03-05T11:00:00Z", "ProductName": "Azure Sentinel"}
        alert = get_normalizer("sentinel").normalize(event, ctx).model_dump(mode="json")
        assert never_close_class(alert) == "credential_access", (tactics, alert.get("mitre"))
        assert routing.decide(_review_state(alert=alert), T, AUTO).route != "close"


def test_review_f2b_pascal_case_tactics_are_never_closed_on_the_models_word() -> None:
    state = _review_state(**{"alert.mitre": {"tactics": ["CredentialAccess"], "techniques": []}})
    assert routing.decide(state, T, AUTO).route != "close"


# --------------------------------------------------------------------------- F1: the evidence gate's hard checks

EVIDENCE = ("known_scanner", "test_environment", "eicar_test_file", "test_detected",
            "email_internal_sender_authenticated")
HARD_FLAGS: Dict[str, Dict[str, Any]] = {
    "steering_text": {"triage.rule_tp": [INJECTION]},
    "rule_corroborated": {"analysis.rule_corroborated": True},
    "threat_intel_and_history": {"analysis.rule_evidence": ["prior_malicious_history"]},
    "related_malicious": {"correlation.related_dispositions": {"malicious": 1}},
}


def test_approved_benign_evidence_still_closes_without_a_flag() -> None:
    for signal in EVIDENCE:
        decision = routing.decide(benign_state(**{"triage.rule_fp": [signal]}), T, "off")
        assert (decision.route, decision.code) == ("close", "rule_corroborated_benign"), signal


def test_approved_benign_evidence_never_closes_past_a_hard_flag() -> None:
    """F1: whatever the evidence, steering text or a recent true positive escalates, at every tier and severity."""
    for signal, (flag, change), severity, tier in itertools.product(
        EVIDENCE, HARD_FLAGS.items(), ("info", "low", "medium"), AUTONOMY_TIERS
    ):
        state = benign_state(severity=severity, **{"triage.rule_fp": [signal], **change})
        decision = routing.decide(state, T, tier)
        assert (decision.route, decision.code) == ("escalate", "false_positive_review"), (signal, flag, tier)


@pytest.mark.parametrize(
    "mitre",
    [
        {"tactics": ["Credential Access"], "techniques": []},
        {"tactics": ["CredentialAccess"], "techniques": []},
        {"tactics": [], "techniques": ["T1003.001"]},
        {"tactics": [], "techniques": ["T1070.001"]},
        {"tactics": [], "techniques": ["T1562.001"]},
        {"tactics": [], "techniques": ["T1486"]},
        {"tactics": [], "techniques": ["T1053.005"]},
    ],
)
def test_a_scanner_or_test_source_never_closes_a_never_close_class(mitre: Dict[str, Any]) -> None:
    """F1: where the activity came from (a declared scanner, a test source) is context an attacker borrows by acting
    from there; it never closes a mapped never-close class. The rule's own test intent and EICAR are exempt."""
    for signal in ("known_scanner", "test_environment"):
        state = benign_state(**{"triage.rule_fp": [signal], "alert.mitre": copy.deepcopy(mitre)})
        assert closure.evidence_close_blockers(state) == ["never_close_class"]
        assert routing.decide(state, T, "off").route == "escalate"
    for signal in ("eicar_test_file", "test_detected"):
        state = benign_state(**{"triage.rule_fp": [signal], "alert.mitre": copy.deepcopy(mitre)})
        assert routing.decide(state, T, "off").code == "rule_corroborated_benign"
    unmapped = benign_state(**{"triage.rule_fp": ["known_scanner"], "alert.mitre": {"tactics": [], "techniques": []}})
    assert routing.decide(unmapped, T, "off").code == "rule_corroborated_benign"
