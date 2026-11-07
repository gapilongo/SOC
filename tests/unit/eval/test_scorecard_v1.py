"""Scorecard v1 (AI-E1.1): committed, from a real local model run on the synthetic and phishing sets.

The scorecard in ``docs/scorecards/v1/`` must be exactly what ``lg-sotf
eval-scorecard`` produces from the committed reports, so its numbers cannot
drift from the per-item results, and it must describe a real model (not the
fake provider, not DeepSeek) on both shipped datasets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.eval.scorecard import ScorecardOptions, build_scorecard, load_reports, render_scorecard

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
V1 = ROOT / "docs" / "scorecards" / "v1" / "qwen2.5-7b"
FIXTURES = ROOT / "tests" / "fixtures" / "eval"
REPORTS = [V1 / "synthetic.json", V1 / "phishing.json"]


@pytest.fixture(scope="module")
def committed() -> Dict[str, Any]:
    card: Dict[str, Any] = json.loads((V1 / "scorecard.json").read_text(encoding="utf-8"))
    return card


def test_scorecard_v1_regenerates_from_its_committed_reports(committed: Dict[str, Any]) -> None:
    options = ScorecardOptions(
        title=committed["title"],
        prompt_version=committed["prompt_version"],
        notes=tuple(committed["notes"]),
        internal=committed["internal_only"],
    )
    card = build_scorecard(load_reports(REPORTS), options)
    assert card == committed
    assert (V1 / "scorecard.md").read_text(encoding="utf-8") == render_scorecard(card)


def test_scorecard_v1_is_a_real_local_model_on_both_shipped_datasets(committed: Dict[str, Any]) -> None:
    assert committed["model"]["llm_provider"] not in ("fake", "disabled")
    assert committed["internal_only"] is False
    assert "deepseek" not in json.dumps(committed["model"]).lower()
    shipped = {
        f"tests/fixtures/eval/{name}": hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        for name in ("synthetic_v1.jsonl", "phishing_v1.jsonl")
    }
    assert {d["dataset"]["path"]: d["dataset"]["sha256"] for d in committed["datasets"]} == shipped
    for dataset in committed["datasets"]:
        assert dataset["scored"] > 0 and dataset["malicious_false_negative"]["n"] > 0
        assert dataset["malicious_false_negative"]["ci95"] is not None
