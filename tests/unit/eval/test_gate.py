"""Thresholds validation and the regression gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.eval.gate import ThresholdsError, evaluate_gate, load_thresholds, resolve_metric, validate_thresholds

pytestmark = pytest.mark.unit

SMOKE_THRESHOLDS = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "smoke_thresholds.yaml"


def report(**metrics: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "scored": 10,
        "error_rate": 0.0,
        "malicious_false_negative_rate": 0.0,
        "benign_auto_close_rate": 0.5,
        "escalation_rate": 0.5,
        "per_class": {"malicious": {"recall": 0.9}},
        "latency_s": {"p95": 2.0},
    }
    base.update(metrics)
    return {"metrics": base, "splits": {"adversarial": {"metrics": {**base, "malicious_false_negative_rate": 0.25}}}}


def gate(thresholds: Dict[str, Any], rep: Dict[str, Any], baseline: Any = None) -> Any:
    return evaluate_gate(rep, validate_thresholds(thresholds), baseline=baseline)


def test_passes_when_every_bound_holds() -> None:
    result = gate(
        {"min_items": 10, "metrics": {"error_rate": {"max": 0}, "benign_auto_close_rate": {"min": 0.5}}}, report()
    )
    assert result.passed and result.checked == 3 and result.violations == []


def test_max_and_min_violations() -> None:
    result = gate(
        {"metrics": {"malicious_false_negative_rate": {"max": 0.05}, "benign_auto_close_rate": {"min": 0.6}}},
        report(malicious_false_negative_rate=0.1),
    )
    assert not result.passed
    kinds = {(v.metric, v.kind) for v in result.violations}
    assert kinds == {("malicious_false_negative_rate", "above_max"), ("benign_auto_close_rate", "below_min")}
    over = next(v for v in result.violations if v.kind == "above_max")
    assert over.actual == 0.1 and over.limit == 0.05 and "> max" in over.message


def test_nested_and_split_paths() -> None:
    thresholds = {
        "metrics": {
            "per_class.malicious.recall": {"min": 0.95},
            "latency_s.p95": {"max": 5},
            "splits.adversarial.malicious_false_negative_rate": {"max": 0},
        }
    }
    result = gate(thresholds, report())
    assert {v.metric for v in result.violations} == {
        "per_class.malicious.recall",
        "splits.adversarial.malicious_false_negative_rate",
    }
    assert resolve_metric(report(), "latency_s.p95") == 2.0
    with pytest.raises(KeyError):
        resolve_metric(report(), "splits.adversarial")


def test_missing_or_undefined_metric_fails_unless_allowed() -> None:
    thresholds = {"metrics": {"nope": {"max": 1}, "escalation_rate": {"max": 1}}}
    result = gate(thresholds, report(escalation_rate=None))
    assert {(v.metric, v.kind) for v in result.violations} == {("nope", "missing"), ("escalation_rate", "missing")}
    allowed = gate({"metrics": {"nope": {"max": 1, "allow_missing": True}}}, report())
    assert allowed.passed


def test_min_items() -> None:
    result = gate({"min_items": 11}, report())
    assert [v.kind for v in result.violations] == ["too_few_items"]


def test_regressions_need_a_baseline() -> None:
    thresholds = {
        "regressions": {
            "malicious_false_negative_rate": {"max_increase": 0},
            "benign_auto_close_rate": {"max_decrease": 0.05},
        }
    }
    current = report(malicious_false_negative_rate=0.02, benign_auto_close_rate=0.40)
    assert gate(thresholds, current).passed  # without a baseline nothing is compared
    result = gate(thresholds, current, baseline=report())
    assert {(v.metric, v.kind) for v in result.violations} == {
        ("malicious_false_negative_rate", "regressed"),
        ("benign_auto_close_rate", "regressed"),
    }
    within = gate(thresholds, report(benign_auto_close_rate=0.46), baseline=report())
    assert within.passed
    improved = gate(thresholds, report(benign_auto_close_rate=0.9), baseline=report())
    assert improved.passed


def test_regression_missing_in_baseline() -> None:
    thresholds = {"regressions": {"escalation_rate": {"max_increase": 0.1}}}
    result = gate(thresholds, report(), baseline={"metrics": {}, "splits": {}})
    assert [v.kind for v in result.violations] == ["missing"]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "must be a mapping"),
        ({"version": 2}, "unsupported thresholds version"),
        ({"surprise": 1}, "unknown top-level keys"),
        ({"min_items": -1}, "min_items"),
        ({"metrics": {"x": 1}}, "must be a mapping such as"),
        ({"metrics": {"x": {"maximum": 1}}}, "unknown keys"),
        ({"metrics": {"x": {"max": "a"}}}, "finite number"),
        ({"metrics": {"x": {"max": float("nan")}}}, "finite number"),
        ({"metrics": {"x": {"min": 2, "max": 1}}}, "min is greater than max"),
        ({"metrics": {"x": {"allow_missing": True}}}, "sets no bound"),
        ({"regressions": {"x": {"max_increase": -1}}}, "must not be negative"),
        ({"regressions": {"x": {"max": 1}}}, "unknown keys"),
    ],
)
def test_invalid_thresholds(data: Any, message: str) -> None:
    with pytest.raises(ThresholdsError, match=message):
        validate_thresholds(data)


def test_load_thresholds_from_yaml_and_json(tmp_path: Path) -> None:
    y = tmp_path / "t.yaml"
    y.write_text("version: 1\nmetrics:\n  error_rate: {max: 0}\n")
    assert load_thresholds(y)["metrics"] == {"error_rate": {"max": 0.0}}
    j = tmp_path / "t.json"
    j.write_text('{"min_items": 3}')
    assert load_thresholds(j)["min_items"] == 3
    bad = tmp_path / "bad.yaml"
    bad.write_text("metrics: [unclosed")
    with pytest.raises(ThresholdsError, match="not valid YAML"):
        load_thresholds(bad)
    with pytest.raises(ThresholdsError, match="cannot read"):
        load_thresholds(tmp_path / "missing.yaml")


def test_shipped_smoke_thresholds_are_valid_and_gate_the_headline() -> None:
    thresholds = load_thresholds(SMOKE_THRESHOLDS)
    assert thresholds["metrics"]["malicious_false_negative_rate"] == {"max": 0.0}
    assert thresholds["metrics"]["splits.adversarial.malicious_false_negative_rate"] == {"max": 0.0}
    assert thresholds["min_items"] >= 60
