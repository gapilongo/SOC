"""Report metric math (lg_sotf.services.reporting) and exports (lg_sotf.services.report_render)."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pytest

from lg_sotf.core.routing import RoutingThresholds
from lg_sotf.db.repos.feedback import FeedbackStats
from lg_sotf.db.repos.reports import AccuracyGroupRow, DetectionRow, EscalationDayRow, ValueDayRow
from lg_sotf.services.report_render import (
    REPORT_CSP,
    REPORT_CSS,
    csv_cell,
    detections_csv,
    monthly_html,
    value_csv,
)
from lg_sotf.services.reporting import (
    MIN_ACCURACY_SAMPLES,
    MonthlyReport,
    ReportingPolicy,
    ReportWindowError,
    ValueSums,
    accuracy_block,
    ai_class,
    analyst_class,
    build_accuracy_report,
    build_detections_report,
    build_value_report,
    detection_suggestion,
    hours_saved,
    model_key,
    month_window,
    ratio,
    resolve_reporting_policy,
    resolve_window,
    suppression_match,
    value_metrics,
    wilson_interval,
)

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


# ------------------------------------------------------------------ basics


def test_ratio_and_hours_saved_edges() -> None:
    assert ratio(1, 0) is None and ratio(0, 0) is None
    assert ratio(0, 4) == 0.0 and ratio(3, 4) == 0.75
    assert hours_saved(0, 15) == 0.0 and hours_saved(-3, 15) == 0.0 and hours_saved(10, 0) == 0.0
    assert hours_saved(10, 15) == 2.5 and hours_saved(7, 20) == pytest.approx(2.33)


def test_wilson_interval() -> None:
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(0, 10)  # type: ignore[misc]
    assert lo == 0.0 and 0.25 < hi < 0.35
    lo, hi = wilson_interval(10, 10)  # type: ignore[misc]
    assert 0.65 < lo < 0.75 and hi == 1.0
    lo, hi = wilson_interval(50, 100)  # type: ignore[misc]
    assert lo == pytest.approx(0.4038, abs=1e-3) and hi == pytest.approx(0.5962, abs=1e-3)
    with pytest.raises(ValueError):
        wilson_interval(3, 2)


def test_reporting_policy_defaults_and_validation() -> None:
    assert resolve_reporting_policy(None).minutes_per_alert == 15
    assert resolve_reporting_policy({"reporting": {"minutes_per_alert": 40}}).minutes_per_alert == 40
    for broken in ({"reporting": {"minutes_per_alert": 0}}, {"reporting": "x"}, {"reporting": {"minutes_per_alert": True}}):
        assert resolve_reporting_policy(broken).minutes_per_alert == 15
    with pytest.raises(ValueError):
        ReportingPolicy.model_validate({"minutes_per_alert": 481})
    with pytest.raises(ValueError):
        ReportingPolicy.model_validate({"minutes_per_alert": 15, "extra": 1})


def test_windows() -> None:
    w = resolve_window(None, None, today=date(2026, 9, 30))
    assert (w.start, w.end, w.days) == (date(2026, 9, 1), date(2026, 9, 30), 30)
    assert w.since == datetime(2026, 9, 1, tzinfo=UTC) and w.until == datetime(2026, 10, 1, tzinfo=UTC)
    assert resolve_window(date(2025, 10, 1), date(2026, 10, 1)).days == 366
    with pytest.raises(ReportWindowError):
        resolve_window(date(2025, 9, 30), date(2026, 10, 1))
    with pytest.raises(ReportWindowError):
        resolve_window(date(2026, 9, 2), date(2026, 9, 1))
    assert month_window("2026-02") == resolve_window(date(2026, 2, 1), date(2026, 2, 28))
    december = month_window("2026-12")
    assert december.end == date(2026, 12, 31) and december.until == datetime(2027, 1, 1, tzinfo=UTC)
    for bad in ("2026-13", "2026", "1999-01", "x"):
        with pytest.raises(ReportWindowError):
            month_window(bad)


# ------------------------------------------------------------------- value


def test_value_metrics_without_data_never_divides_by_zero() -> None:
    m = value_metrics(ValueSums(), 15)
    assert m.alerts_ingested == 0 and m.in_progress == 0
    assert m.handled_without_human_rate is None and m.analyst_hours_saved == 0.0
    assert m.mean_time_to_verdict_s is None and m.mtta_s is None and m.mttr_s is None
    assert m.mttr_auto_s is None and m.mttr_human_s is None and m.llm_cost_per_alert_usd is None
    assert m.llm_cost_usd == 0.0


def test_value_metrics_math() -> None:
    s = ValueSums(
        ingested=10, handled_without_human=6, needed_human=3, resolved=4, resolve_seconds=400, verdicts=5,
        verdict_seconds=50, acknowledged=2, ack_seconds=30, llm_cost_usd=Decimal("1.5"),
    )
    m = value_metrics(s, 20)
    assert m.in_progress == 1 and m.handled_without_human_rate == pytest.approx(6 / 9)
    assert m.analyst_hours_saved == 2.0 and m.mttr_s == 100 and m.mean_time_to_verdict_s == 10
    assert m.mtta_s == 15 and m.llm_cost_per_alert_usd == 0.15


def test_value_report_fills_days_and_totals_are_weighted() -> None:
    window = resolve_window(date(2026, 9, 1), date(2026, 9, 3))
    rows = [
        ValueDayRow(day=date(2026, 9, 1), ingested=1, handled_without_human=1, resolved=1, resolve_seconds=10),
        ValueDayRow(day=date(2026, 9, 3), ingested=3, needed_human=3, resolved=3, resolve_seconds=90),
    ]
    report = build_value_report(
        window,
        value_rows=rows,
        escalation_rows=[EscalationDayRow(day=date(2026, 9, 3), escalations=2, acknowledged=1, ack_seconds=40)],
        sla_by_day={date(2026, 9, 2): 2},
        escalations_breached=1,
        cost_by_day={date(2026, 9, 1): Decimal("0.4")},
        minutes_per_alert=15,
        generated_at=NOW,
    )
    assert [d.day for d in report.days] == [date(2026, 9, 1), date(2026, 9, 2), date(2026, 9, 3)]
    empty = report.days[1]
    assert empty.alerts_ingested == 0 and empty.sla_breaches == 2 and empty.mttr_s is None
    t = report.totals
    # Mean of all resolutions (100 s / 4), not the mean of the daily means ((10 + 30) / 2).
    assert t.mttr_s == 25 and t.resolved == 4
    assert t.handled_without_human_rate == 0.25 and t.analyst_hours_saved == 0.25
    assert t.mtta_s == 40 and t.sla_breaches == 2 and t.llm_cost_per_alert_usd == pytest.approx(0.1)
    dumped = report.model_dump(mode="json", by_alias=True)
    assert dumped["from"] == "2026-09-01" and dumped["to"] == "2026-09-03"


# ---------------------------------------------------------------- accuracy


def test_class_mappings() -> None:
    assert analyst_class("true_positive") == "malicious"
    assert analyst_class("false_positive") == analyst_class("benign_positive") == "benign"
    assert analyst_class("needs_more_info") is None
    assert ai_class("benign", "high") == "benign"  # the verdict wins over the score
    assert ai_class(None, "high") == "malicious" and ai_class(None, "low") == "benign"
    assert ai_class(None, "mid") == ai_class(None, None) == ai_class("weird", None) == "inconclusive"


def _group(**kwargs: Any) -> AccuracyGroupRow:
    base = dict(
        decision="true_positive", verdict=None, score_band=None, analysis_provider=None, analysis_model=None,
        triage_provider=None, triage_model=None, llm_used=False, n=1,
    )
    base.update(kwargs)
    return AccuracyGroupRow(**base)


def test_model_key() -> None:
    assert model_key(_group(analysis_provider="openai", analysis_model="gpt-x", triage_model="t")) == "openai/gpt-x"
    assert model_key(_group(triage_provider="gemini", triage_model="flash")) == "gemini/flash"
    assert model_key(_group(analysis_model="bare")) == "bare"
    assert model_key(_group(llm_used=True)) == "unrecorded"
    assert model_key(_group()) == "rules only"


def test_accuracy_block_empty_and_counts() -> None:
    empty = accuracy_block({})
    assert empty.samples == 0 and empty.status == "insufficient_data"
    assert empty.agreement_rate is None and empty.false_negative_rate is None and empty.false_positive_rate is None
    assert empty.agreement_ci95 is None and empty.ai_inconclusive_rate is None
    block = accuracy_block(
        {("malicious", "malicious"): 18, ("malicious", "benign"): 2, ("benign", "benign"): 9, ("benign", "inconclusive"): 1,
         ("other", "benign"): 5, ("benign", "other"): 5, ("malicious", "inconclusive"): 0},
        min_samples=30,
    )
    assert block.samples == 30 and block.status == "ok"
    assert block.agreement == 27 and block.agreement_rate == pytest.approx(0.9)
    assert block.false_negatives == 2 and block.false_negative_rate == pytest.approx(0.1)
    assert block.false_positive_rate == 0.0 and block.ai_inconclusive == 1
    assert accuracy_block({("malicious", "malicious"): 29}).status == "insufficient_data"


def test_build_accuracy_report_groups_by_model_and_skips_needs_more_info() -> None:
    window = resolve_window(date(2026, 9, 1), date(2026, 9, 30))
    groups = [
        _group(decision="true_positive", verdict="benign", analysis_provider="anthropic", analysis_model="m", n=2),
        _group(decision="false_positive", score_band="low", n=3),
        _group(decision="needs_more_info", verdict="benign", n=7),
    ]
    feedback = FeedbackStats(
        total=12, by_decision={"true_positive": 2}, triage_accuracy=0.5, correlation_helpful_rate=None,
        analysis_accuracy=1.0, avg_review_duration_s=30.0, triage_rated=12, correlation_rated=0, analysis_rated=3,
    )
    report = build_accuracy_report(
        window, groups=groups, feedback=feedback, thresholds=RoutingThresholds(), generated_at=NOW
    )
    assert report.overall.samples == 5 and report.overall.false_negative_rate == 1.0
    assert [(m.model, m.accuracy.samples) for m in report.by_model] == [("rules only", 3), ("anthropic/m", 2)]
    assert report.min_samples == MIN_ACCURACY_SAMPLES
    assert report.feedback.triage_correct.status == "ok" and report.feedback.analysis_accurate.status == "insufficient_data"
    assert report.feedback.correlation_helpful.rate is None


# -------------------------------------------------------------- detections


def _detection(**kwargs: Any) -> DetectionRow:
    base = dict(
        source_id="splunk", rule_field="rule_name", rule="R", volume=20, decided=20, benign=20, malicious=0,
        auto_closed=10, analyst_false_positive=5, analyst_benign_positive=0, analyst_true_positive=0,
        median_severity_rank=1, max_severity_rank=2, max_confirmed_benign_rank=2,
    )
    base.update(kwargs)
    return DetectionRow(**base)


def test_detection_suggestions() -> None:
    suggestion, reason = detection_suggestion(_detection())
    assert suggestion == "candidate_suppression" and "severity up to medium" in reason
    assert detection_suggestion(_detection(decided=9, benign=9))[0] is None
    assert detection_suggestion(_detection(decided=0, benign=0))[0] is None  # no division by zero
    assert detection_suggestion(_detection(benign=15, malicious=5))[0] is None  # 75 % benign
    tune, why = detection_suggestion(_detection(benign=19, malicious=1, analyst_true_positive=1))
    assert tune == "tune_rule" and "hide real threats" in why
    tune, why = detection_suggestion(_detection(analyst_false_positive=2))
    assert tune == "tune_rule" and "only 2 were confirmed" in why
    tune, why = detection_suggestion(_detection(median_severity_rank=3))
    assert tune == "tune_rule" and "median severity is high" in why
    tune, why = detection_suggestion(_detection(benign=18))
    assert tune == "tune_rule" and "95%" in why


def test_suppression_match_is_bounded_by_confirmed_severity() -> None:
    assert suppression_match(_detection()) == {
        "source_id": "splunk", "rule_name": "R", "severity": {"in": ["info", "low", "medium"]}
    }
    assert suppression_match(_detection(rule_field="title", max_confirmed_benign_rank=0))["title"] == "R"
    with pytest.raises(ValueError):
        suppression_match(_detection(max_confirmed_benign_rank=None))


# ----------------------------------------------------------------- exports


def test_csv_cells_are_formula_safe() -> None:
    assert csv_cell("=1+1") == "'=1+1" and csv_cell("  @SUM(A1)") == "'  @SUM(A1)" and csv_cell("-2") == "'-2"
    assert csv_cell(-2) == -2 and csv_cell(0.5) == 0.5 and csv_cell(None) == "" and csv_cell(True) == "true"
    assert csv_cell(date(2026, 9, 1)) == "2026-09-01" and csv_cell("plain") == "plain"


def _monthly(**detection: Any) -> MonthlyReport:
    window = month_window("2026-09")
    value = build_value_report(
        window, value_rows=[ValueDayRow(day=date(2026, 9, 1), ingested=2, handled_without_human=1)],
        escalation_rows=[], sla_by_day={}, escalations_breached=0, cost_by_day={}, minutes_per_alert=15,
        generated_at=NOW,
    )
    accuracy = build_accuracy_report(
        window, groups=[], feedback=FeedbackStats(total=0, by_decision={}, triage_accuracy=None,
                                                  correlation_helpful_rate=None, analysis_accuracy=None,
                                                  avg_review_duration_s=None),
        thresholds=RoutingThresholds(), generated_at=NOW,
    )
    detections = build_detections_report(window, [_detection(**detection)], limit=200, generated_at=NOW)
    return MonthlyReport(tenant_id="acme", tenant_name='Acme "<b>" & Co', month="2026-09", generated_at=NOW,
                         value=value, accuracy=accuracy, detections=detections)


def test_value_and_detection_csv() -> None:
    monthly = _monthly(rule="=cmd|' /C calc'!A0")
    rows = list(csv.reader(io.StringIO(value_csv(monthly.value))))
    assert rows[0][:3] == ["day", "alerts_ingested", "handled_without_human"] and len(rows) == 31
    assert rows[1][:3] == ["2026-09-01", "2", "1"]
    exported = list(csv.DictReader(io.StringIO(detections_csv(monthly.detections))))
    assert exported[0]["rule"] == "'=cmd|' /C calc'!A0" and exported[0]["volume"] == "20"


def test_monthly_html_is_self_contained_and_escaped() -> None:
    html = monthly_html(_monthly(rule="<img src=x onerror=alert(1)>"), version="1.0.0")
    assert html.startswith("<!doctype html>") and "</html>" in html
    assert "<script" not in html and "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "Acme &quot;&lt;b&gt;&quot; &amp; Co" in html
    assert "insufficient data" in html.lower() and "September 2026" in html
    assert ' style="' not in html and "http" not in html.replace("http-equiv", "")
    digest = base64.b64encode(hashlib.sha256(REPORT_CSS.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in REPORT_CSP and "default-src 'none'" in REPORT_CSP
    assert html.count("<style>") == 1 and f"<style>{REPORT_CSS}</style>" in html
