"""The offline policy simulator (AI-E1.9) against scorecard v2's recorded DeepSeek V4 decisions.

The simulator calls the real ``routing.decide``; these tests pin that it
reproduces every decision the run made, what each policy does on known items,
and the numbers ``docs/scorecards/v2/deepseek-v4/CALIBRATION.md`` reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

import pytest

from lg_sotf.domain.benign_evidence import SCANNER_SIGNAL
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.eval import calibration
from lg_sotf.eval.calibration import POLICIES, decide_state, decision_inputs, policy_thresholds, simulate

pytestmark = pytest.mark.unit

V2 = Path(__file__).resolve().parents[3] / "docs" / "scorecards" / "v2" / "deepseek-v4"
SHIPPED = policy_thresholds(POLICIES["P3+P4+P5"])


@pytest.fixture(scope="module")
def report() -> Dict[str, Any]:
    data: Dict[str, Any] = json.loads((V2 / "corpus_v1.json").read_text(encoding="utf-8"))
    return data


@pytest.fixture(scope="module")
def inputs(report: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return calibration.load_inputs(report, json.loads((V2 / "decision_inputs.json").read_text(encoding="utf-8")))


def _all(outcomes: Any, policy: str) -> calibration.PolicyOutcome:
    return next(o for o in outcomes if o.policy == policy and o.group == "all")


def test_the_simulator_reproduces_every_recorded_decision(report: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
    assert len(inputs) == 520
    assert calibration.mismatches(report, inputs) == []


@pytest.mark.parametrize(
    ("item_id", "old", "new"),
    [
        # Benign, verdict benign (threat 5), Defender noise: the band held it; its rules' score (42) still does.
        ("cv1-0045", "grey_zone", "false_positive_review"),
        # Malicious: password spray (T1110.003) and file discovery (T1083) with a benign verdict stay with a human.
        ("cv1-0021", "grey_zone", "false_positive_review"),
        ("cv1-0358", "grey_zone", "false_positive_review"),
        # Critical Windows patching look-alike with a benign verdict: never closed by automation.
        ("cv1-0237", "false_positive_review", "false_positive_review"),
        # Benign scan look-alike decided without analysis at confidence 80+: no response plan under the cap.
        ("cv1-0418", "high_risk", "inconclusive"),
    ],
)
def test_known_items(inputs: Mapping[str, Mapping[str, Any]], item_id: str, old: str, new: str) -> None:
    assert simulate(inputs[item_id], policy_thresholds(())).code == old
    assert simulate(inputs[item_id], SHIPPED).code == new


def test_on_the_recorded_outputs_no_policy_closes_and_the_cap_removes_the_benign_plans(
    report: Mapping[str, Any], inputs: Mapping[str, Mapping[str, Any]]
) -> None:
    outcomes = calibration.run_policies(report, inputs)
    for policy in POLICIES:
        o = _all(outcomes, policy)
        assert (o.benign_auto_close.successes, o.malicious_auto_close.successes) == (0, 0)
        assert (o.benign_auto_close.n, o.malicious_auto_close.n) == (312, 208)
    assert _all(outcomes, "1.2 policy").benign_response_plan.successes == 33
    assert _all(outcomes, "P5 correlation cap").benign_response_plan.successes == 0
    assert _all(outcomes, "P5 correlation cap").malicious_response_plan.successes == 16
    assert all(o.malicious_auto_close.successes == 0 for o in outcomes)


def _counterfactual(inputs: Mapping[str, Mapping[str, Any]], **change: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item_id, i in inputs.items():
        triage = dict(i["triage"])
        if change.get("fp_as_context"):
            triage["rule_fp"] = [SCANNER_SIGNAL for _ in triage["rule_fp"]]
        analysis = dict(i["analysis"]) if i["analysis"] else None
        if analysis and change.get("no_rule_test"):
            analysis["rule_threat_score"] = 0.0
        out[item_id] = {**i, "triage": triage, "analysis": analysis}
    return out


def test_why_the_corroboration_must_be_the_tenants(report: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
    """Two counterfactuals CALIBRATION.md reports, both on the recorded verdicts."""
    p3p4 = {"P3+P4": POLICIES["P3+P4"]}
    # Every recorded rule false-positive signal (detector words in 17 benign rule names) taken as context: 8 closes.
    as_context = _all(calibration.run_policies(report, _counterfactual(inputs, fp_as_context=True), p3p4), "P3+P4")
    assert (as_context.benign_auto_close.successes, as_context.malicious_auto_close.successes) == (8, 0)
    # No rule test at all (a model-only close): 73 benign, and both malicious alerts with a benign verdict.
    model_only = _all(calibration.run_policies(report, _counterfactual(inputs, no_rule_test=True), p3p4), "P3+P4")
    assert (model_only.benign_auto_close.successes, model_only.malicious_auto_close.successes) == (73, 2)
    assert {"cv1-0021", "cv1-0358"} <= set(model_only.closed_ids)


def test_decision_inputs_round_trip_through_decide() -> None:
    thresholds = RoutingThresholds(benign_verdict_precedence=True, context_corroboration=True)
    full = {
        "severity": "low",
        "confidence": 55.0,
        "more_info_loops": 0,
        "alert": {"title": "x", "flags": ["llm_normalized"]},
        "triage": {"confidence": 30, "rule_confidence": 45, "rule_fp": [SCANNER_SIGNAL], "llm_fp": ["l"], "notes": ["n"]},
        "correlation": {"score": 40, "related_count": 2, "burst": False, "related_alert_ids": ["a"]},
        "analysis": {"verdict": "benign", "threat_score": 10, "rule_threat_score": 60, "conclusion": "c"},
    }
    recorded = decision_inputs(full)
    assert recorded["llm_normalized"] and recorded["triage"]["rule_fp"] == [SCANNER_SIGNAL]
    assert simulate(recorded, thresholds) == calibration.decide(full, thresholds)
    for variant in ({**full, "alert": {}}, {**full, "correlation": {"llm_refusal": {"reason": "r"}}}, {**full, "analysis": {}}):
        assert simulate(decision_inputs(variant), thresholds) == calibration.decide(variant, thresholds)
    assert json.loads(json.dumps(recorded)) == recorded
    assert decide_state({"triage": {"confidence": None}}, thresholds) == {
        "severity": None, "more_info_loops": 0, "triage": {}, "correlation": {},
    }


def test_policy_thresholds_pin_every_switch() -> None:
    assert policy_thresholds(()).benign_verdict_precedence is False
    on = policy_thresholds(calibration.POLICY_KNOBS, {"response_threshold": 90})
    assert on.cap_correlated_confidence and on.response_threshold == 90
    with pytest.raises(ValueError, match="unknown policy switches"):
        policy_thresholds(["lower_the_bar"])


def test_main_prints_the_tables(capsys: pytest.CaptureFixture[str]) -> None:
    code = calibration.main([str(V2 / "corpus_v1.json"), "--inputs", str(V2 / "decision_inputs.json")])
    out = capsys.readouterr().out
    assert code == 0 and "the 1.2 policy reproduces 520 decisions" in out
    assert "### sysmon" in out and "| P3+P4+P5 |" in out
