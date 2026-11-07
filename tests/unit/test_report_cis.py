"""AI-E1.7 acceptance: every rate in the eval and reporting outputs renders n and a 95% Wilson interval.

``test_report_cis`` runs once per surface: the eval report (JSON and
Markdown), the scorecard, the ``/reports/*`` response models (where the PoV
report will add its own), the monthly HTML report and the CSV exports. The
structural checks find rates by name (``*_rate``, ``accuracy``), so a rate
added later without an interval fails here.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Callable, Dict, Iterator, List, Mapping, Tuple

import pytest
from pydantic import BaseModel

from lg_sotf.db.repos.feedback import FeedbackStats
from lg_sotf.db.repos.reports import AccuracyGroupRow, DetectionRow, ValueDayRow
from lg_sotf.domain.rates import RateInterval, wilson_interval
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.gate import resolve_metric
from lg_sotf.eval.metrics import RATE_KEYS, rate_counts
from lg_sotf.eval.report import HEADLINE_ROWS, build_report, render_markdown
from lg_sotf.eval.scorecard import ScorecardOptions, build_scorecard, render_scorecard
from lg_sotf.services import reporting
from lg_sotf.services.report_render import detections_csv, monthly_html, value_csv
from lg_sotf.services.reporting import (
    FeedbackRate,
    MonthlyReport,
    build_accuracy_report,
    build_detections_report,
    build_value_report,
    month_window,
)
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 1, tzinfo=UTC)
# A rendered rate: "93.3% (14 of 15; 95% CI 70.2% to 98.8%)", or the shared small-sample wording.
RATE = r"(?:\d+\.\d%|\d+%) \((?:\d+) of (?P<n>\d+); 95% CI \d+\.\d% to \d+\.\d%\)|Not enough data \(n=0\)"


def _is_rate_key(key: str) -> bool:
    return key.endswith("_rate") or key.endswith("accuracy")


def _check_interval(interval: Mapping[str, Any], k: int, n: int) -> None:
    """``interval`` is ``{rate, n, ci_low, ci_high}`` for ``k`` of ``n`` with the 95% Wilson bounds."""
    assert set(interval) == {"rate", "n", "ci_low", "ci_high"}
    assert interval["n"] == n
    bounds = wilson_interval(k, n)
    if bounds is None:
        assert interval["rate"] is None and interval["ci_low"] is None and interval["ci_high"] is None
    else:
        assert interval["rate"] == pytest.approx(k / n)
        assert (interval["ci_low"], interval["ci_high"]) == (pytest.approx(bounds[0], abs=1e-6),
                                                             pytest.approx(bounds[1], abs=1e-6))


# ------------------------------------------------------------------- eval

def _eval_report() -> Dict[str, Any]:
    rows = [{"id": f"i{n}", "source_type": "canonical", "alert": {"title": "t"}, "expected": {"disposition": "benign"}}
            for n in range(8)]
    dataset = parse_dataset('{"_meta": {"synthetic": true}}\n' + "\n".join(json.dumps(r) for r in rows), path="x.jsonl")
    results = [
        result("m1", "malicious", "closed", disposition="benign"),
        result("m2", "malicious", "waiting_human", split="adversarial", expected_route="escalate"),
        result("m3", "malicious", "closed", disposition="malicious", expected_escalation=False),
        result("m4", "malicious", "waiting_approval"),
        result("b1", "benign", "closed", disposition="benign"),
        result("b2", "benign", "closed", disposition="benign", expected_route="close"),
        result("b3", "benign", "waiting_human", split="adversarial"),
        result("e1", "benign", "error"),
    ]
    return build_report(results, dataset=dataset, run_info={"llm_provider": "ollama", "fast_model": "m",
                                                            "deep_model": "m"})


def _check_eval_json() -> None:
    report = _eval_report()
    blocks = [report["metrics"], *(s["metrics"] for s in report["splits"].values())]
    for metrics in blocks:
        rates = {key for key, value in metrics.items() if _is_rate_key(key)}
        assert rates == set(RATE_KEYS), "a rate without an interval: add it to eval.metrics.rate_counts"
        for key in RATE_KEYS:
            n = metrics["intervals"][key]["n"]
            k = round((metrics[key] or 0) * n)
            _check_interval(metrics["intervals"][key], k, n)
        for cls, scores in metrics["per_class"].items():
            intervals = metrics["per_class_intervals"][cls]
            _check_interval(intervals["precision"], round((scores["precision"] or 0) * scores["predicted"]),
                            scores["predicted"])
            _check_interval(intervals["recall"], round((scores["recall"] or 0) * scores["support"]), scores["support"])
    # The denominators are the ones the metric definitions use.
    assert rate_counts([]) == {key: (0, 0) for key in RATE_KEYS}
    assert report["metrics"]["intervals"]["malicious_false_negative_rate"]["n"] == 4
    assert report["metrics"]["intervals"]["error_rate"]["n"] == 8
    # The gate can bound the interval, not just the point estimate.
    assert resolve_metric(report, "intervals.malicious_false_negative_rate.ci_high") == pytest.approx(0.699, abs=1e-3)


def _table_rows(md: str, heading: str) -> List[List[str]]:
    section = md.split(heading, 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ") and not line.startswith("|---")]
    return [[cell.strip() for cell in row.strip("|").split(" | ")] for row in rows[1:]]


def _check_eval_markdown() -> None:
    report = _eval_report()
    rows = {row[0]: row[1:] for row in _table_rows(render_markdown(report), "## Headline metrics")}
    rate_labels = [label for label, key, _ in HEADLINE_ROWS if key in RATE_KEYS]
    assert len(rate_labels) == len(RATE_KEYS)
    for label in rate_labels:
        for cell in rows[label]:
            assert re.fullmatch(RATE, cell), f"{label}: {cell!r}"
    for row in _table_rows(render_markdown(report), "## Per class"):
        assert re.fullmatch(RATE, row[1]) and re.fullmatch(RATE, row[2]), row
    fnr = rows["Malicious false-negative rate (auto-closed as benign)"][0]
    assert fnr == "25.0% (1 of 4; 95% CI 4.6% to 69.9%)"


def _check_scorecard() -> None:
    card = build_scorecard([_eval_report()], ScorecardOptions())
    md = render_scorecard(card)
    for row in _table_rows(md, "## Automation"):
        assert all(re.fullmatch(RATE, cell) for cell in row[1:]), row
    for row in _table_rows(md, "## Per class"):
        if row[1] != "macro F1":
            assert re.fullmatch(RATE, row[2]) and re.fullmatch(RATE, row[3]), row
    for row in _table_rows(md, "## Malicious false-negative rate"):
        assert row[2].isdigit() and "%" in row[4], row  # n and the Wilson interval have their own columns


# ---------------------------------------------------------------- reports

def _monthly() -> MonthlyReport:
    window = month_window("2026-09")
    value = build_value_report(
        window, value_rows=[ValueDayRow(day=date(2026, 9, 1), ingested=5, handled_without_human=3, needed_human=1)],
        escalation_rows=[], sla_by_day={}, escalations_breached=0, cost_by_day={date(2026, 9, 1): Decimal("0.1")},
        minutes_per_alert=15, generated_at=NOW,
    )
    group = dict(verdict=None, score_band=None, analysis_provider="ollama", analysis_model="m", triage_provider=None,
                 triage_model=None, llm_used=True)
    groups = [
        AccuracyGroupRow(decision="true_positive", **group, n=4),  # type: ignore[arg-type]
        AccuracyGroupRow(decision="true_positive", **{**group, "verdict": "benign"}, n=1),  # type: ignore[arg-type]
        AccuracyGroupRow(decision="false_positive", **{**group, "verdict": "benign"}, n=6),  # type: ignore[arg-type]
        AccuracyGroupRow(decision="false_positive", **{**group, "verdict": "malicious"}, n=2),  # type: ignore[arg-type]
    ]
    feedback = FeedbackStats(total=12, by_decision={"true_positive": 5}, triage_accuracy=0.75, analysis_accuracy=None,
                             correlation_helpful_rate=0.5, avg_review_duration_s=30.0, triage_rated=12,
                             correlation_rated=4, analysis_rated=0)
    accuracy = build_accuracy_report(window, groups=groups, feedback=feedback, thresholds=RoutingThresholds(),
                                     generated_at=NOW)
    detection = DetectionRow(
        source_id="splunk", rule_field="rule_name", rule="R", volume=20, decided=16, benign=15, malicious=1,
        auto_closed=10, analyst_false_positive=5, analyst_benign_positive=0, analyst_true_positive=1,
        median_severity_rank=1, max_severity_rank=2, max_confirmed_benign_rank=2,
    )
    detections = build_detections_report(window, [detection], limit=200, generated_at=NOW)
    return MonthlyReport(tenant_id="acme", tenant_name="Acme", month="2026-09", generated_at=NOW, value=value,
                         accuracy=accuracy, detections=detections)


def _models(obj: Any) -> Iterator[BaseModel]:
    if isinstance(obj, BaseModel):
        yield obj
        for name in type(obj).model_fields:
            yield from _models(getattr(obj, name))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _models(item)


def _response_models() -> List[type[BaseModel]]:
    return [cls for cls in vars(reporting).values()
            if isinstance(cls, type) and issubclass(cls, BaseModel) and cls.__module__ == reporting.__name__]


def _check_reports_api() -> None:
    # Structure: every *_rate field of every report model has a *_rate_ci sibling; FeedbackRate is one itself.
    for cls in _response_models():
        for name in cls.model_fields:
            if name.endswith("_rate"):
                assert f"{name}_ci" in cls.model_fields, f"{cls.__name__}.{name} has no {name}_ci"
                assert not cls.model_fields[f"{name}_ci"].is_required(), "new response fields stay optional"
    assert {"rate", "n", "ci_low", "ci_high"} <= set(FeedbackRate.model_fields)
    # Values: each interval matches its rate, with the Wilson bounds of its own counts.
    checked = 0
    for model in _models(_monthly()):
        for name in type(model).model_fields:
            if name.endswith("_rate"):
                ci = getattr(model, f"{name}_ci")
                assert isinstance(ci, RateInterval) and ci.rate == getattr(model, name)
                _check_interval(ci.model_dump(), ci.successes, ci.n)
                checked += 1
        if isinstance(model, FeedbackRate):
            assert model.n == model.samples
            _check_interval(model.model_dump(include={"rate", "n", "ci_low", "ci_high"}),
                            round((model.rate or 0) * model.samples), model.samples)
            checked += 1
    # handled (totals + 30 days), accuracy (4 rates x overall + 1 model), 3 feedback rates, 1 detection.
    assert checked == 31 + 8 + 3 + 1
    block = _monthly().accuracy.overall
    assert block.false_negative_rate_ci is not None and block.false_negative_rate_ci.n == 5
    assert block.false_negative_ci95 == block.false_negative_rate_ci.bounds  # the older field is unchanged


def _check_monthly_html() -> None:
    html = monthly_html(_monthly())
    for expected in (
        "3 of 4 finished alerts. 95% CI",  # handled without a human
        "1 of 5 alerts an analyst confirmed as malicious",  # headline false-negative rate ...
        "Agreement 46.2% (6 of 13; 95% CI",
        "false-positive rate (of benign) 25.0% (2 of 8; 95% CI",
        "AI inconclusive 30.8% (4 of 13; 95% CI",
        "75.0% (9 of 12; 95% CI",  # feedback: triage correct
        "Not enough data (n=0)",  # feedback: analysis accurate, never answered
        "93.8% (15 of 16; 95% CI",  # detection benign rate
    ):
        assert expected in html, expected
    fn = html.split("1 of 5 alerts an analyst confirmed as malicious", 1)[1][:80]
    assert "95% CI" in fn


def _check_csv() -> None:
    monthly = _monthly()
    value = list(csv.DictReader(io.StringIO(value_csv(monthly.value))))
    first = value[0]
    assert first["handled_without_human_rate"] == "0.75" and first["handled_without_human_rate_n"] == "4"
    assert 0 < float(first["handled_without_human_rate_ci_low"]) < 0.75 < float(first["handled_without_human_rate_ci_high"])
    assert value[1]["handled_without_human_rate_n"] == "0" and value[1]["handled_without_human_rate_ci_low"] == ""
    assert "handled_without_human_rate_ci" not in first
    # Appended after the existing columns, which keep their positions.
    assert list(first)[-3:] == ["handled_without_human_rate_n", "handled_without_human_rate_ci_low",
                                "handled_without_human_rate_ci_high"]
    detections = list(csv.DictReader(io.StringIO(detections_csv(monthly.detections))))
    assert detections[0]["benign_rate_n"] == "16" and float(detections[0]["benign_rate_ci_low"]) > 0.6


SURFACES: Dict[str, Callable[[], None]] = {
    "eval-json": _check_eval_json,
    "eval-markdown": _check_eval_markdown,
    "scorecard": _check_scorecard,
    "reports-api": _check_reports_api,
    "monthly-html": _check_monthly_html,
    "csv-exports": _check_csv,
}


@pytest.mark.parametrize("surface", list(SURFACES))
def test_report_cis(surface: str) -> None:
    """Every rate renders n and a 95% Wilson interval (AI-E1.7)."""
    SURFACES[surface]()


def test_report_cis_cover_every_reporting_rate_model() -> None:
    names: List[Tuple[str, str]] = [
        (cls.__name__, name) for cls in _response_models() for name in cls.model_fields if name.endswith("_rate")
    ]
    assert sorted(names) == [
        ("AccuracyBlock", "agreement_rate"),
        ("AccuracyBlock", "ai_inconclusive_rate"),
        ("AccuracyBlock", "false_negative_rate"),
        ("AccuracyBlock", "false_positive_rate"),
        ("Detection", "benign_rate"),
        ("ValueDay", "handled_without_human_rate"),
        ("ValueMetrics", "handled_without_human_rate"),
    ]
