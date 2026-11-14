"""What a proof-of-value run stores of its backtest's report (PRD-11.1): the aggregates, no per-alert row."""

from __future__ import annotations

import pytest

from lg_sotf.eval.dataset import Dataset
from lg_sotf.eval.pov import RESULT_KEYS, backtest_result
from lg_sotf.eval.report import build_report
from lg_sotf.eval.results import ItemResult

pytestmark = pytest.mark.unit


def test_the_stored_result_keeps_every_aggregate_and_drops_the_per_alert_rows() -> None:
    results = [
        ItemResult(
            item_id="a-1", split="history", tags=[], source_type="canonical", expected="benign", status="closed",
            alert_id="a-1", severity="low", predicted="benign", disposition="benign", route="close",
        )
    ]
    dataset = Dataset(items=[], meta={"synthetic": False}, path="history:acme:30d", sha256="0" * 64)
    report = build_report(results, dataset=dataset, run_info={"mode": "history", "tenant_id": "acme"})

    stored = backtest_result(report)

    assert set(stored) == set(RESULT_KEYS)
    assert {"items", "splits"} <= set(report) - set(stored)
    assert (stored["metrics"]["items"], stored["run"]["mode"]) == (1, "history")
    assert backtest_result({"metrics": {}, "items": [{"alert_id": "a-1"}]}) == {"metrics": {}}
