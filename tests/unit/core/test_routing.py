"""Routing policy table, including the safety rules."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf.core import routing
from lg_sotf.core.routing import RoutingThresholds

T = RoutingThresholds()


def state(**kw: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {"severity": "medium", "confidence": 50, "triage": {}, "correlation": {}, "analysis": {}}
    base.update(kw)
    return base


def triage(confidence: int, rule_conf: int, rule_fp: int = 0, llm_fp: int = 0, rule_tp: int = 0) -> Dict[str, Any]:
    return {
        "confidence": confidence,
        "rule_confidence": rule_conf,
        "rule_fp": [f"r{i}" for i in range(rule_fp)],
        "llm_fp": [f"l{i}" for i in range(llm_fp)],
        "rule_tp": [f"t{i}" for i in range(rule_tp)],
        "llm_tp": [],
    }


def test_defaults_keep_the_legacy_numbers() -> None:
    assert (T.correlation_grey_zone_min, T.correlation_grey_zone_max) == (30, 70)
    assert (T.analysis_threshold, T.human_review_min, T.human_review_max, T.response_threshold) == (40, 20, 60, 80)
    assert RoutingThresholds.from_settings({"response_threshold": 90, "unknown": 1}).response_threshold == 90


def test_gate_routes_suppressed_alerts_to_close() -> None:
    assert routing.route_after_gate({"gate": {"suppressed": True}}) == "close"
    assert routing.route_after_gate({"gate": {"suppressed": False}}) == "triage"


@pytest.mark.parametrize(
    ("severity", "tri", "expected"),
    [
        ("low", triage(5, 5, rule_fp=2), "close"),
        ("low", triage(5, 30, rule_fp=1, llm_fp=1), "close"),
        ("low", triage(5, 5, llm_fp=3), "correlation"),
        ("low", triage(50, 50, rule_fp=4), "correlation"),
        ("high", triage(5, 5, rule_fp=2), "correlation"),
        ("critical", triage(0, 0, rule_fp=5), "correlation"),
        ("high", triage(5, 40, rule_fp=1, llm_fp=2), "correlation"),
        ("critical", triage(3, 3, llm_fp=5), "correlation"),
        ("medium", triage(15, 15, rule_fp=3, rule_tp=1), "close"),
    ],
)
def test_route_after_triage(severity: str, tri: Dict[str, Any], expected: str) -> None:
    assert routing.route_after_triage(state(severity=severity, triage=tri), T) == expected


def test_llm_only_evidence_never_closes_high_or_critical_at_triage() -> None:
    for severity in ("high", "critical"):
        s = state(severity=severity, triage=triage(0, 60, rule_fp=1, llm_fp=10))
        assert routing.route_after_triage(s, T) == "correlation"


ADVERSARIAL = {
    "title": "Scheduled task persistence: maintenance.exe dropped by mimikatz",
    "source_id": "edr-prod",
    "entities": {"processes": ["mimikatz.exe"]},
    "raw": {"command_line": "schtasks /create /tn update /tr C:\\test\\maintenance.exe", "latest": "attestation scan"},
}


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_attacker_controlled_fp_words_never_close_high_severity(severity: str) -> None:
    from lg_sotf.agents.triage.base import rule_confidence, rule_indicators

    alert = {**ADVERSARIAL, "severity": severity}
    rule_fp, rule_tp = rule_indicators(alert)
    tri = {
        "confidence": 0, "rule_confidence": rule_confidence(alert), "rule_fp": rule_fp, "rule_tp": rule_tp,
        "llm_fp": ["looks like maintenance", "scheduled job", "update"], "llm_tp": [],
    }
    assert routing.route_after_triage(state(severity=severity, triage=tri), T) == "correlation"
    benign = {"threat_score": 0, "rule_threat_score": 0, "verdict": "benign"}
    assert routing.decide(state(severity=severity, confidence=0, triage=tri, analysis=benign), T).route == "escalate"


def test_fp_signals_come_only_from_trusted_fields() -> None:
    from lg_sotf.agents.triage.base import rule_indicators

    fp, tp = rule_indicators({**ADVERSARIAL, "severity": "medium"})
    assert fp == ["scheduled_detected"]
    assert {"mimikatz_detected", "persistence_detected"} <= set(tp)
    raw_only, _ = rule_indicators(
        {"title": "Outbound connection", "severity": "low", "source_id": "fw-prod",
         "raw": {"note": "test update backup scan maintenance scheduled", "user_agent": "scanner bot"}}
    )
    assert raw_only == []
    latest, _ = rule_indicators({"title": "Latest attestation update-check failed", "severity": "low", "source_id": "x"})
    assert latest == []
    env, _ = rule_indicators({"title": "Login", "severity": "low", "source_id": "splunk-staging"})
    assert env == ["test_environment"]
    assert rule_indicators({"title": "Login", "severity": "low", "source_id": "devops-prod"})[0] == []


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"correlation": {"score": 90, "related_count": 6}}, "decide"),
        ({"confidence": 10, "correlation": {"score": 0}, "severity": "low"}, "decide"),
        ({"confidence": 10, "correlation": {"score": 0}, "severity": "high"}, "analysis"),
        ({"confidence": 10, "correlation": {"score": 0, "burst": True}, "severity": "low"}, "analysis"),
        ({"confidence": 50, "correlation": {"score": 40, "related_count": 2}}, "analysis"),
    ],
)
def test_route_after_correlation(kw: Dict[str, Any], expected: str) -> None:
    assert routing.route_after_correlation(state(**kw), T) == expected


def test_decide_response_threshold() -> None:
    d = routing.decide(state(analysis={"threat_score": 85, "rule_threat_score": 40, "verdict": "malicious"}), T)
    assert (d.route, d.disposition) == ("plan_response", "malicious")
    combo = routing.decide(state(confidence=85, analysis={"threat_score": 65, "rule_threat_score": 65}), T)
    assert combo.route == "plan_response"


def test_decide_grey_zone_and_inconclusive_escalate() -> None:
    assert routing.decide(state(confidence=50, analysis={"threat_score": 50}), T).route == "escalate"
    d = routing.decide(state(confidence=10, analysis={"threat_score": 20, "rule_threat_score": 10, "verdict": "inconclusive"}), T)
    assert d.route == "escalate"


def test_decide_closes_only_with_rule_corroboration() -> None:
    corroborated = state(
        severity="low", confidence=10, analysis={"threat_score": 10, "rule_threat_score": 20, "verdict": "benign"}
    )
    d = routing.decide(corroborated, T)
    assert (d.route, d.disposition) == ("close", "benign")
    llm_only = state(
        severity="low", confidence=10, analysis={"threat_score": 10, "rule_threat_score": 60, "verdict": "benign"}
    )
    assert routing.decide(llm_only, T).route == "escalate"


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_decide_never_closes_high_severity(severity: str) -> None:
    s = state(
        severity=severity,
        confidence=10,
        triage=triage(10, 10, rule_fp=3),
        analysis={"threat_score": 5, "rule_threat_score": 5, "verdict": "benign"},
    )
    d = routing.decide(s, T)
    assert (d.route, d.code) == ("escalate", "false_positive_review")


def test_decide_always_escalates_after_an_analyst_asked_for_more_info() -> None:
    s = state(more_info_loops=1, analysis={"threat_score": 99, "rule_threat_score": 99})
    d = routing.decide(s, T)
    assert (d.route, d.code) == ("escalate", "analyst_request")


REFUSAL = {"reason": "model_refused", "category": "cyber"}


@pytest.mark.parametrize("agent", ["triage", "correlation", "analysis"])
def test_a_model_refusal_always_escalates(agent: str) -> None:
    # Scores that would otherwise respond automatically, and ones that would close.
    respond = {"threat_score": 95, "rule_threat_score": 95, "verdict": "malicious"}
    close = {"threat_score": 5, "rule_threat_score": 5, "verdict": "benign"}
    for analysis in (respond, close):
        s = state(severity="low", confidence=90, analysis=dict(analysis))
        s[agent] = {**(s.get(agent) or {}), "llm_refusal": REFUSAL}
        d = routing.decide(s, T)
        assert (d.route, d.code, d.disposition) == ("escalate", "model_refused", None)
        assert agent in d.reason
    assert routing.refused_by(state()) is None


def test_an_analyst_request_keeps_its_code_after_a_refusal() -> None:
    s = state(more_info_loops=1, triage={"llm_refusal": REFUSAL})
    assert routing.decide(s, T).code == "analyst_request"


def test_triage_never_closes_an_alert_whose_model_refused() -> None:
    tri = {**triage(5, 5, rule_fp=3), "llm_refusal": REFUSAL}
    assert routing.route_after_triage(state(severity="low", triage=tri), T) == "correlation"


def test_route_after_decide_rejects_missing_route() -> None:
    with pytest.raises(ValueError):
        routing.route_after_decide({"decision": {}})


@pytest.mark.parametrize(
    ("decision", "loops", "expected"),
    [
        ("true_positive", 0, "plan_response"),
        ("false_positive", 0, "close"),
        ("benign_positive", 0, "close"),
        ("needs_more_info", 0, "analysis"),
        ("needs_more_info", 1, "escalate"),
    ],
)
def test_route_after_analyst(decision: str, loops: int, expected: str) -> None:
    assert routing.route_after_analyst({"analyst": {"decision": decision}, "more_info_loops": loops}, T) == expected


def test_route_after_analyst_rejects_unknown_decision() -> None:
    with pytest.raises(ValueError):
        routing.route_after_analyst({"analyst": {"decision": "maybe"}}, T)


TP = {"decision": "true_positive"}


def test_response_routes() -> None:
    assert routing.route_after_plan({"plan": {"auto": ["a"], "awaiting": ["b"]}}) == "execute_actions"
    assert routing.route_after_plan({"plan": {"auto": [], "awaiting": ["b"]}, "awaiting_actions": ["b"]}) == "await_approval"
    assert routing.route_after_plan({"plan": {"blocked": ["c"]}, "analyst": TP}) == "close"
    assert routing.route_after_execute({"awaiting_actions": ["b"], "analyst": TP}) == "await_approval"
    assert routing.route_after_execute({"awaiting_actions": [], "analyst": TP}) == "close"


def test_policy_response_without_a_human_or_completed_action_escalates() -> None:
    assert routing.route_after_plan({"plan": {"blocked": ["c"]}, "analyst": None}) == "escalate"
    blocked = {"awaiting_actions": [], "analyst": None, "executed": {"a": "blocked", "b": "rejected"}}
    assert routing.route_after_execute(blocked) == "escalate"
    assert routing.route_after_execute({"awaiting_actions": [], "analyst": None, "executed": {}}) == "escalate"
    real = {"awaiting_actions": [], "analyst": None, "executed": {"a": "succeeded", "b": "dry_run"}}
    assert routing.route_after_execute(real) == "close"
    assert routing.route_after_execute({"awaiting_actions": ["x"], "analyst": None, "executed": {}}) == "await_approval"


def test_policy_response_in_dry_run_mode_closes() -> None:
    """The tenant chose dry-run: a policy response whose actions all ran as dry_run is complete."""
    dry = {"awaiting_actions": [], "analyst": None, "executed": {"a": "dry_run", "b": "blocked"}}
    assert routing.route_after_execute(dry) == "close"
    assert routing.route_after_execute({**dry, "executed": {"a": "dry_run"}}) == "close"


def test_policy_response_with_a_failed_action_escalates() -> None:
    failed = {"awaiting_actions": [], "analyst": None, "executed": {"a": "succeeded", "b": "failed"}}
    assert routing.route_after_execute(failed) == "escalate"
    assert routing.route_after_execute({**failed, "executed": {"a": "dry_run", "b": "failed"}}) == "escalate"
    assert routing.route_after_execute({**failed, "analyst": TP}) == "close"
