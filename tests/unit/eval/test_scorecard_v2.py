"""Scorecard v2: DeepSeek V4 (open weights) on the 520-alert attack-emulation corpus.

The scorecard in ``docs/scorecards/v2/`` must be exactly what ``lg-sotf
eval-scorecard`` produces from the committed report, and it must describe a
real model (not the fake provider or a cassette replay) on the committed
``corpus_v1`` with every item scored. A DeepSeek scorecard is publishable
only because every dataset is synthetic; the test pins that too.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.scorecard import ScorecardOptions, build_scorecard, load_reports, render_scorecard

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
V2 = ROOT / "docs" / "scorecards" / "v2" / "deepseek-v4"
CORPUS = ROOT / "tests" / "fixtures" / "eval" / "corpus_v1.jsonl.gz"


def corpus_sha256_without_tenant_settings() -> str:
    """The corpus v2 ran on: today's alerts, before AI-E1.9 and fatigue step 1 declared the estate in ``_meta``."""
    first, rest = gzip.decompress(CORPUS.read_bytes()).decode("utf-8").split("\n", 1)
    header = json.loads(first)
    assert header["_meta"].pop("tenant_settings") == {"triage": {"known_scanners": ["10.20.5.10"]}}
    header["_meta"].pop("tenant_context")  # fatigue step 1: the declared estate facts, measured only
    text = json.dumps(header, ensure_ascii=False, separators=(",", ":")) + "\n" + rest
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def committed() -> Dict[str, Any]:
    card: Dict[str, Any] = json.loads((V2 / "scorecard.json").read_text(encoding="utf-8"))
    return card


def test_scorecard_v2_regenerates_from_its_committed_report(committed: Dict[str, Any]) -> None:
    options = ScorecardOptions(
        title=committed["title"],
        prompt_version=committed["prompt_version"],
        notes=tuple(committed["notes"]),
        internal=False,
    )
    card = build_scorecard(load_reports([V2 / "corpus_v1.json"]), options)
    assert card == committed
    assert (V2 / "scorecard.md").read_text(encoding="utf-8") == render_scorecard(card)


def test_scorecard_v2_is_a_real_model_on_the_whole_synthetic_corpus(committed: Dict[str, Any]) -> None:
    assert committed["model"] == {
        "llm_provider": "openai",
        "fast_model": "deepseek-flash",
        "deep_model": "deepseek-v4-pro",
    }
    # Publishable only because the data is synthetic: no customer data went to the hosted API.
    assert committed["internal_only"] is False
    corpus = load_dataset(CORPUS)
    (dataset,) = committed["datasets"]
    assert dataset["dataset"]["synthetic"] is True
    assert dataset["dataset"]["sha256"] == corpus_sha256_without_tenant_settings()
    assert dataset["dataset"]["items"] == len(corpus.items) >= 500
    assert dataset["scored"] == len(corpus.items) and dataset["errors"] == 0
    miss = dataset["malicious_false_negative"]
    assert miss["n"] >= 200 and miss["ci95"] is not None
