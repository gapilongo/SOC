"""Metric math: confusion matrix, precision/recall/F1, kappa, percentiles and the safety rates."""

from __future__ import annotations

import math

import pytest

from lg_sotf.eval.metrics import (
    cohen_kappa,
    compute_metrics,
    confusion_matrix,
    inter_annotator_kappa,
    macro_f1,
    metrics_by_split,
    per_class_scores,
    percentile,
    ratio,
)
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit


def test_ratio_is_undefined_for_an_empty_denominator() -> None:
    assert ratio(0, 0) is None
    assert ratio(1, 4) == 0.25


def test_confusion_matrix_counts_expected_rows_and_predicted_columns() -> None:
    pairs = [("malicious", "malicious"), ("malicious", "benign"), ("benign", "benign"), ("benign", "inconclusive")]
    m = confusion_matrix(pairs)
    assert m["malicious"] == {"malicious": 1, "benign": 1, "inconclusive": 0}
    assert m["benign"] == {"malicious": 0, "benign": 1, "inconclusive": 1}
    assert m["inconclusive"] == {"malicious": 0, "benign": 0, "inconclusive": 0}


def test_confusion_matrix_adds_unknown_labels() -> None:
    m = confusion_matrix([("malicious", "other")])
    assert m["malicious"]["other"] == 1 and "other" in m


def test_per_class_scores_match_hand_computation() -> None:
    # malicious: tp=2 fp=1 fn=1 -> p=2/3 r=2/3 f1=2/3 ; benign: tp=1 fp=1 fn=1 -> 0.5/0.5/0.5
    pairs = [
        ("malicious", "malicious"),
        ("malicious", "malicious"),
        ("malicious", "benign"),
        ("benign", "benign"),
        ("benign", "malicious"),
    ]
    s = per_class_scores(pairs)
    assert s["malicious"]["precision"] == pytest.approx(2 / 3)
    assert s["malicious"]["recall"] == pytest.approx(2 / 3)
    assert s["malicious"]["f1"] == pytest.approx(2 / 3)
    assert s["malicious"]["support"] == 3 and s["malicious"]["predicted"] == 3
    assert s["benign"]["precision"] == pytest.approx(0.5)
    assert s["benign"]["f1"] == pytest.approx(0.5)
    # A class that is never expected nor predicted has undefined scores, not zeros.
    assert s["inconclusive"] == {"precision": None, "recall": None, "f1": None, "support": 0, "predicted": 0}
    assert macro_f1(s) == pytest.approx((2 / 3 + 0.5) / 2)


def test_f1_is_zero_when_a_class_is_predicted_but_never_right() -> None:
    s = per_class_scores([("benign", "malicious"), ("malicious", "benign")])
    assert s["malicious"]["precision"] == 0.0 and s["malicious"]["recall"] == 0.0
    assert s["malicious"]["f1"] == 0.0


def test_macro_f1_counts_undefined_f1_as_zero_for_present_classes() -> None:
    # inconclusive is expected once but never predicted: precision undefined -> F1 counts as 0.
    s = per_class_scores([("malicious", "malicious"), ("inconclusive", "malicious")])
    assert s["inconclusive"]["f1"] is None
    assert macro_f1(s) == pytest.approx((2 * 0.5 * 1.0 / 1.5 + 0.0) / 2)
    assert macro_f1(per_class_scores([])) is None


def test_cohen_kappa_known_value() -> None:
    # Classic 2x2 example: p_o = 0.7, p_e = 0.5 -> kappa = 0.4
    a = ["y"] * 20 + ["y"] * 5 + ["n"] * 10 + ["n"] * 15
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    assert cohen_kappa(a, b) == pytest.approx(0.4)


def test_cohen_kappa_edges() -> None:
    assert cohen_kappa(["a", "b", "a"], ["a", "b", "a"]) == pytest.approx(1.0)
    assert cohen_kappa(["a", "a"], ["a", "a"]) == 1.0  # both raters constant and identical
    assert cohen_kappa(["a"], ["a"]) is None
    # Systematic disagreement is worse than chance.
    kappa = cohen_kappa(["a", "b", "a", "b"], ["b", "a", "b", "a"])
    assert kappa is not None and kappa < 0
    with pytest.raises(ValueError):
        cohen_kappa(["a"], ["a", "b"])


def test_inter_annotator_kappa_only_for_pairs_sharing_two_items() -> None:
    results = [
        result("1", "malicious", labels={"ann1": "malicious", "ann2": "malicious"}),
        result("2", "benign", labels={"ann1": "benign", "ann2": "malicious", "ann3": "benign"}),
        result("3", "benign", labels={"ann1": "benign", "ann2": "benign"}),
    ]
    iak = inter_annotator_kappa(results)
    assert set(iak["pairs"]) == {"ann1|ann2"}  # ann3 labelled one item only
    pair = iak["pairs"]["ann1|ann2"]
    assert pair["items"] == 3
    expected = cohen_kappa(["malicious", "benign", "benign"], ["malicious", "malicious", "benign"])
    assert pair["kappa"] == pytest.approx(expected)
    assert iak["mean"] == pytest.approx(expected)
    assert inter_annotator_kappa([result("1", "benign")]) == {"pairs": {}, "mean": None}


def test_percentile_interpolates_linearly() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile(values, 0) == 1.0
    assert percentile(values, 50) == pytest.approx(2.5)
    assert percentile(values, 95) == pytest.approx(3.85)
    assert percentile(values, 100) == 4.0
    assert percentile([7.0], 95) == 7.0
    assert percentile([], 50) is None
    with pytest.raises(ValueError):
        percentile(values, 101)


def test_headline_rates() -> None:
    results = [
        # malicious: one missed (closed benign), one escalated, one waiting approval
        result("m1", "malicious", "closed", disposition="benign", severity="medium"),
        result("m2", "malicious", "waiting_human", predicted="malicious"),
        result("m3", "malicious", "waiting_approval"),
        # benign: two auto-closed, one escalated, one routed to response
        result("b1", "benign", "closed", disposition="benign", severity="low"),
        result("b2", "benign", "closed", disposition="benign", severity="high"),
        result("b3", "benign", "waiting_human", predicted="benign"),
        result("b4", "benign", "waiting_approval"),
        # inconclusive: escalated
        result("i1", "inconclusive", "waiting_human"),
        # errored item: excluded from every rate except error_rate
        result("e1", "malicious", "error"),
    ]
    m = compute_metrics(results)
    assert m["items"] == 9 and m["scored"] == 8 and m["errors"] == 1
    assert m["error_rate"] == pytest.approx(1 / 9)
    assert m["malicious_items"] == 3 and m["benign_items"] == 4
    assert m["malicious_false_negatives"] == 1
    assert m["malicious_false_negative_rate"] == pytest.approx(1 / 3)
    assert m["missed_malicious_ids"] == ["m1"]
    assert m["benign_auto_close_rate"] == pytest.approx(2 / 4)
    assert m["benign_auto_response_rate"] == pytest.approx(1 / 4)
    assert m["high_severity_auto_closed_benign"] == 1  # b2: high severity closed as benign
    assert m["high_severity_auto_closed_malicious"] == 0
    assert m["auto_close_rate"] == pytest.approx(3 / 8)
    assert m["escalation_rate"] == pytest.approx(3 / 8)
    assert m["approval_request_rate"] == pytest.approx(2 / 8)
    assert m["inconclusive_rate"] == pytest.approx(1 / 8)  # only i1 predicts inconclusive
    # predicted: m1 benign, m2 malicious, m3 malicious, b1 benign, b2 benign, b3 benign, b4 malicious, i1 inconclusive
    assert m["accuracy"] == pytest.approx(6 / 8)
    assert m["confusion_matrix"]["benign"]["malicious"] == 1
    assert m["per_class"]["malicious"]["recall"] == pytest.approx(2 / 3)


def test_escalated_malicious_is_not_a_false_negative() -> None:
    m = compute_metrics([result("m", "malicious", "waiting_human", predicted="benign")])
    assert m["malicious_false_negative_rate"] == 0.0
    assert m["per_class"]["malicious"]["recall"] == 0.0  # the verdict was still wrong


def test_rates_without_items_in_the_denominator_are_undefined() -> None:
    m = compute_metrics([result("b", "benign", "closed")])
    assert m["malicious_false_negative_rate"] is None
    assert m["route_accuracy"] is None and m["escalation_accuracy"] is None
    empty = compute_metrics([])
    assert empty["error_rate"] is None and empty["cost_per_alert_usd"] is None
    assert empty["latency_s"] == {"mean": None, "p50": None, "p95": None, "max": None}


def test_route_and_escalation_accuracy_use_labelled_items_only() -> None:
    results = [
        result("a", "benign", "closed", expected_route="close", expected_escalation=False),
        result("b", "benign", "waiting_human", expected_route="close", expected_escalation=False),
        result("c", "malicious", "waiting_approval", expected_escalation=True),  # approval counts as a human
        result("d", "malicious", "waiting_human"),
    ]
    m = compute_metrics(results)
    assert m["route_labelled_items"] == 2 and m["route_accuracy"] == pytest.approx(0.5)
    assert m["escalation_labelled_items"] == 3 and m["escalation_accuracy"] == pytest.approx(2 / 3)


def test_high_severity_closes_split_by_disposition() -> None:
    """A policy response that completed closes a critical alert as malicious: reported, not a safety breach."""
    results = [
        result("r", "malicious", "closed", disposition="malicious", severity="critical", route="plan_response"),
        result("h", "benign", "closed", disposition="benign", severity="high"),
        result("x", "benign", "closed", disposition="inconclusive", severity="critical"),
        result("l", "benign", "closed", disposition="benign", severity="low"),
        result("w", "malicious", "waiting_human", severity="critical"),
    ]
    m = compute_metrics(results)
    assert m["high_severity_auto_closed_malicious"] == 1
    assert m["high_severity_auto_closed_benign"] == 2  # anything but malicious counts
    assert "high_severity_auto_closed" not in m  # the old, ambiguous metric fails a gate loudly as missing


def test_cost_tokens_and_latency_aggregate_scored_items() -> None:
    results = [
        result("a", "benign", "closed", cost_usd=0.01, total_tokens=100, llm_calls=1, latency_s=1.0),
        result("b", "malicious", "waiting_human", cost_usd=0.03, total_tokens=300, llm_calls=3, latency_s=3.0),
        result("e", "malicious", "error", cost_usd=5.0, total_tokens=900, latency_s=100.0),
    ]
    m = compute_metrics(results)
    # Totals include what errored items spent (it is billed); per-alert means cover scored items.
    assert m["total_cost_usd"] == pytest.approx(5.04)
    assert m["errored_cost_usd"] == pytest.approx(5.0)
    assert m["total_tokens"] == 1300
    assert m["cost_per_alert_usd"] == pytest.approx(0.02)
    assert m["tokens_per_alert"] == pytest.approx(200)
    assert m["llm_calls_per_alert"] == pytest.approx(2)
    assert m["latency_s"]["mean"] == pytest.approx(2.0)
    assert m["latency_s"]["max"] == 3.0
    assert math.isclose(m["latency_s"]["p95"], 2.9)


def test_kappa_vs_expected_and_metrics_by_split() -> None:
    results = [
        result("a", "benign", "closed", split="standard"),
        result("b", "malicious", "waiting_approval", split="standard"),
        result("c", "malicious", "closed", split="adversarial", disposition="benign"),
        result("d", "benign", "closed", split="adversarial"),
    ]
    m = compute_metrics(results)
    assert m["kappa_vs_expected"] == pytest.approx(
        cohen_kappa(["benign", "malicious", "malicious", "benign"], ["benign", "malicious", "benign", "benign"])
    )
    splits = metrics_by_split(results)
    assert list(splits) == ["adversarial", "standard"]
    assert splits["adversarial"]["malicious_false_negative_rate"] == 1.0
    assert splits["standard"]["malicious_false_negative_rate"] == 0.0
