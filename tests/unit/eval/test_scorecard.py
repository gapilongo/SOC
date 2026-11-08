"""The evaluation scorecard: Wilson intervals, the card built from reports, its Markdown and the CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.domain.rates import wilson_interval
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.report import build_report
from lg_sotf.eval.scorecard import (
    ScorecardError,
    ScorecardOptions,
    build_scorecard,
    load_reports,
    proportion,
    render_scorecard,
)
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit


def report(provider: str = "ollama", model: str = "qwen2.5:7b", **run: Any) -> Dict[str, Any]:
    rows = [{"id": f"i{n}", "source_type": "canonical", "alert": {"title": "t"}, "expected": {"disposition": "benign"}}
            for n in range(6)]
    dataset = parse_dataset('{"_meta": {"synthetic": true}}\n' + "\n".join(json.dumps(r) for r in rows), path="x.jsonl")
    results = [
        result("m1", "malicious", "closed", disposition="benign"),  # a miss
        result("m2", "malicious", "waiting_human", split="adversarial"),
        result("m3", "malicious", "closed", disposition="malicious"),
        result("b1", "benign", "closed", disposition="benign"),
        result("b2", "benign", "closed", disposition="benign"),
        result("e1", "benign", "error"),
    ]
    info = {"llm_provider": provider, "fast_model": model, "deep_model": model,
            "selection": {"splits": [], "tags": [], "limit": None, "isolation": "splits"}, **run}
    return build_report(results, dataset=dataset, run_info=info)


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [(0, 35, 0.0, 0.0990), (5, 10, 0.2366, 0.7634), (14, 15, 0.7018, 0.9881), (3, 3, 0.4385, 1.0)],
)
def test_wilson_interval_matches_reference_values(k: int, n: int, low: float, high: float) -> None:
    interval = wilson_interval(k, n)
    assert interval is not None
    assert interval == (pytest.approx(low, abs=1e-4), pytest.approx(high, abs=1e-4))


def test_wilson_interval_of_an_empty_sample_is_undefined() -> None:
    assert wilson_interval(0, 0) is None
    assert proportion(0, 0) == {"k": 0, "n": 0, "rate": None, "ci95": None}
    with pytest.raises(ValueError):
        wilson_interval(4, 3)


def test_card_counts_misses_auto_close_precision_and_escalations() -> None:
    card = build_scorecard([report()], ScorecardOptions())
    ds = card["datasets"][0]
    assert ds["malicious_false_negative"]["k"] == 1 and ds["malicious_false_negative"]["n"] == 3
    assert ds["missed_malicious_ids"] == ["m1"]
    # Four auto-closes, three with the expected disposition (m1 closed as benign is wrong).
    assert (ds["auto_close_precision"]["k"], ds["auto_close_precision"]["n"]) == (3, 4)
    assert (ds["escalation"]["k"], ds["escalation"]["n"]) == (1, 5)
    assert (ds["error"]["k"], ds["error"]["n"]) == (1, 6) and ds["errors"] == 1
    assert ds["splits"]["adversarial"]["malicious_false_negative"]["n"] == 1
    assert card["model"] == {"llm_provider": "ollama", "fast_model": "qwen2.5:7b", "deep_model": "qwen2.5:7b"}
    assert card["internal_only"] is False and card["prompt_version"] is None
    assert any("synthetic" in note for note in card["limitations"])
    assert any("1 items errored" in note for note in card["limitations"])


def test_markdown_leads_with_the_false_negative_rate_and_lists_limitations() -> None:
    text = render_scorecard(build_scorecard([report()], ScorecardOptions(notes=("CPU only",))))
    headline = text.index("## Malicious false-negative rate")
    assert headline < text.index("## Automation") < text.index("## Per class") < text.index("## Cost and latency")
    assert "| `x` | 1 | 3 | 33.3% |" in text
    assert "Missed in `x`: `m1`." in text
    assert "75.0% (3 of 4; 95% CI" in text
    assert "not recorded in the report (prompt hashes arrive with AI-E1.2)" in text
    assert text.rstrip().endswith("- CPU only")
    assert "INTERNAL" not in text


def test_prompt_versions_come_from_the_report_or_the_option() -> None:
    hashes = {"triage": "sha256:abc"}
    assert build_scorecard([report(prompt_hashes=hashes)], ScorecardOptions())["prompt_version"] == hashes
    card = build_scorecard([report(prompt_hashes=hashes)], ScorecardOptions(prompt_version="commit 1234"))
    assert card["prompt_version"] == "commit 1234"
    assert "| Prompt version | commit 1234 |" in render_scorecard(card)


def test_deepseek_scorecards_are_marked_internal_only() -> None:
    card = build_scorecard([report(provider="openai", model="deepseek-chat")], ScorecardOptions())
    assert card["internal_only"] is True
    assert "INTERNAL ONLY: not for publication" in render_scorecard(card)
    assert build_scorecard([report()], ScorecardOptions(internal=True))["internal_only"] is True


def test_reports_from_different_models_do_not_make_one_scorecard() -> None:
    with pytest.raises(ScorecardError, match="different models"):
        build_scorecard([report(), report(model="mistral:7b")], ScorecardOptions())
    with pytest.raises(ScorecardError, match="at least one"):
        build_scorecard([], ScorecardOptions())


def test_a_subset_run_is_listed_as_a_limitation() -> None:
    subset = report(selection={"splits": ["standard"], "tags": [], "limit": 20, "isolation": "splits"})
    limitations = build_scorecard([subset], ScorecardOptions())["limitations"]
    assert "x.jsonl: a subset was evaluated (splits standard; first 20 items)." in limitations


def test_load_reports_rejects_files_that_are_not_eval_reports(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"metrics": {}}', encoding="utf-8")
    with pytest.raises(ScorecardError, match="not an lg-sotf eval report"):
        load_reports([bad])
    with pytest.raises(ScorecardError, match="cannot read"):
        load_reports([tmp_path / "missing.json"])


def test_cli_writes_markdown_and_json(tmp_path: Path) -> None:
    paths: List[str] = []
    for name in ("a", "b"):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(report()), encoding="utf-8")
        paths.append(str(path))
    out, js = tmp_path / "card.md", tmp_path / "card.json"
    res = CliRunner().invoke(
        cli, ["eval-scorecard", *paths, "--output", str(out), "--json", str(js), "--note", "GPU: test-only"]
    )
    assert res.exit_code == 0, res.output
    assert "malicious false negatives 1 of 3" in res.output
    card = json.loads(js.read_text(encoding="utf-8"))
    assert len(card["datasets"]) == 2 and card["notes"] == ["GPU: test-only"]
    assert out.read_text(encoding="utf-8") == render_scorecard(card)


def test_cli_reports_unusable_input_as_an_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    res = CliRunner().invoke(cli, ["eval-scorecard", str(bad), "--output", str(tmp_path / "x.md")])
    assert res.exit_code == 1 and "not an lg-sotf eval report" in res.output


def test_a_generated_corpus_is_not_called_hand_written() -> None:
    small = build_scorecard([report()], ScorecardOptions())
    assert any("hand-written" in note for note in small["limitations"])
    big = report()
    big["dataset"]["items"] = 520  # corpus_v1 size: a generated set, not a hand-written one
    card = build_scorecard([big], ScorecardOptions())
    assert not any("hand-written" in note for note in card["limitations"])
    assert any("generated alerts" in note for note in card["limitations"])
