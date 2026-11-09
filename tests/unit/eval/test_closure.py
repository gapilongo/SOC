"""Closure attribution, the two headline numbers and event-time ordering (fatigue step 1)."""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from lg_sotf.eval.closure import (
    close_mechanism,
    closure_summary,
    event_time,
    event_time_order,
    headline_lines,
    malicious_cell,
    mechanism_of,
    render_closure,
)
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.report import build_report, render_markdown, summary_lines
from lg_sotf.eval.results import ItemResult

pytestmark = pytest.mark.unit


def _result(item_id: str, expected: str, status: str = "waiting_human", **fields: Any) -> ItemResult:
    return ItemResult(item_id=item_id, split="standard", tags=[], source_type="canonical", expected=expected,
                      status=status, **fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("reason", "state", "mechanism"),
    [
        ("suppression_rule", {}, "suppression"),
        ("verdict_cache", {}, "cache"),
        ("triage:false_positive", {}, "rules"),
        ("policy:response", {}, "response"),
        ("ai_closed:audit_required", {"analysis": {"verdict": "benign"}}, "model"),
        ("policy:close", {}, "rules"),
        ("policy:close", {"analysis": {"verdict": "benign", "history": [{"verdict": "unknown"}]}}, "model"),
        ("policy:close", {"analysis": {"verdict": "benign", "history": [{"verdict": "harmless"}]}}, "history"),
        ("analyst:false_positive", {}, None),
        (None, {}, None),
    ],
)
def test_each_close_is_attributed_to_one_mechanism(reason: Any, state: Dict[str, Any], mechanism: Any) -> None:
    assert close_mechanism(reason, state) == mechanism


def test_reports_without_attribution_read_what_they_recorded() -> None:
    closed = dict(status="closed", disposition="benign")
    assert mechanism_of(_result("a", "benign", close_reason="verdict_cache", **closed)) == "cache"
    assert mechanism_of(_result("b", "benign", close_reason="policy:close", **closed)) == "unattributed"
    assert mechanism_of(_result("c", "benign", close_reason="policy:close", decision_inputs={"analysis": {"x": 1}},
                                **closed)) == "model"
    assert mechanism_of(_result("d", "benign", close_reason="policy:close", decision_inputs={"triage": {}},
                                **closed)) == "rules"
    assert mechanism_of(_result("e", "benign", close_reason="odd", **closed)) == "unattributed"
    assert mechanism_of(_result("f", "benign")) is None


def test_the_headline_counts_closes_with_an_interval_and_an_upper_bound() -> None:
    results = [
        _result("b1", "benign", "closed", disposition="benign", close_reason="verdict_cache", close_mechanism="cache"),
        _result("b2", "benign"),
        _result("b3", "benign", "closed", disposition="benign", close_reason="policy:close", close_mechanism="model"),
        _result("m1", "malicious", "closed", disposition="benign", close_reason="verdict_cache",
                close_mechanism="cache", severity="medium", family="audit"),
        _result("m2", "malicious"),
        _result("i1", "inconclusive", "closed", disposition="benign", close_mechanism="rules"),
        _result("e1", "benign", "error"),
    ]
    summary = closure_summary(results, has_context=True)
    h = summary["headline"]
    assert (h["benign_closure"]["k"], h["benign_closure"]["n"]) == (2, 3)
    assert h["benign_closure"]["ci_low"] < 2 / 3 < h["benign_closure"]["ci_high"]
    m = h["malicious_auto_close"]
    assert (m["k"], m["n"], m["rate"]) == (1, 2, 0.5) and 0.5 < m["upper_95"] < 1
    rows = {r["mechanism"]: r for r in summary["by_mechanism"]}
    assert rows["cache"]["benign"]["k"] == 1 and rows["cache"]["malicious"] == 1
    assert rows["model"]["benign"]["k"] == 1 and rows["rules"]["other"] == 1
    assert summary["malicious_closed"] == [{"item_id": "m1", "mechanism": "cache", "close_reason": "verdict_cache",
                                            "disposition": "benign", "severity": "medium", "family": "audit"}]
    text = "\n".join(render_closure(summary))
    assert "**Benign closure rate:** 66.7% (2 of 3" in text and "1 of 2 (50.0%; 95% upper bound" in text
    assert "`m1`: cache (verdict_cache)" in text and "### Declared tenant context" in text
    assert malicious_cell({"k": 0, "n": 0}) == "Not enough data (n=0)"


def test_every_report_leads_with_the_two_numbers() -> None:
    meta = {"synthetic": True, "tenant_context": {"automation_hosts": ["build-01"]}}
    item = {"id": "c-1", "source_type": "canonical", "expected": {"disposition": "benign"},
            "alert": {"title": "Job ran", "severity": "low", "entities": {"hosts": ["build-01"]}}}
    dataset = parse_dataset(json.dumps({"_meta": meta}) + "\n" + json.dumps(item))
    report = build_report([_result("c-1", "benign", "closed", disposition="benign", close_mechanism="rules")],
                          dataset=dataset, run_info={"oracle": {"accept_suppressions": False}})
    assert report["closure"]["context"]["benign_closable_with_context"]["k"] == 1
    assert report["items"][0]["context"] == ["automation_host"]
    assert report["dataset"]["tenant_context"] == {"automation_host": 1}
    assert report["notes"][-1].startswith("Analyst oracle")
    markdown = render_markdown(report)
    assert markdown.index("## Closure") < markdown.index("## Headline metrics")
    assert "| analyst oracle | propose; 0 suppressions enabled |" in markdown
    assert summary_lines(report)[:2] == [line.replace("**", "")[2:] for line in headline_lines(report["closure"])]


def _item(item_id: str, ts: Any) -> Dict[str, Any]:
    alert: Dict[str, Any] = {"title": "t", "severity": "low"}
    if ts is not None:
        alert["occurred_at"] = ts
    return {"id": item_id, "source_type": "canonical", "alert": alert, "expected": {"disposition": "benign"}}


def test_items_run_in_event_time_order_and_untimed_items_keep_their_place() -> None:
    rows = [_item("late", "2026-10-20T10:00:00Z"), _item("early", "2026-10-20T08:00:00Z"),
            _item("untimed", None), _item("tie", "2026-10-20T08:00:00Z")]
    items = parse_dataset("\n".join(json.dumps(r) for r in rows)).items
    assert event_time(items[2]) is None
    # "untimed" follows its predecessor in the dataset ("early").
    assert [i.id for i in event_time_order(items)] == ["early", "untimed", "tie", "late"]
    email = parse_dataset(json.dumps({"id": "m", "source_type": "email", "alert": {"mime": "Subject: x\n\nbody"},
                                      "expected": {"disposition": "benign"}})).items[0]
    assert event_time(email) is None
