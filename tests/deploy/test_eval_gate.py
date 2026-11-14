"""ARCH-E2.1: the evaluation gate in CI.

``scripts/ci/eval_gate.py`` behind the ``eval-gate`` job of ci.yml (fake model, committed baselines)
and the ``real-model-eval`` job of nightly.yml (a pinned EU or local model, scorecard as an artifact).
Nothing here needs a database or a model: the runs themselves are stubbed. The gate against real
services, with a deliberate regression, is tests/integration/eval/test_ci_gate.py.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterator, List, Sequence, Tuple

import pytest
import yaml

from lg_sotf.eval.dataset import Dataset, load_dataset, parse_dataset
from lg_sotf.eval.gate import evaluate_gate, load_thresholds, resolve_metric
from lg_sotf.eval.report import build_report
from lg_sotf.settings import get_settings
from tests.deploy._support import REPO_ROOT
from tests.unit.eval._support import result

SCRIPT = REPO_ROOT / "scripts" / "ci" / "eval_gate.py"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
V1_REPORTS = REPO_ROOT / "docs" / "scorecards" / "v1" / "qwen2.5-7b"
PINNED = {"EVAL_LLM_FAST_MODEL": "mistral-small-2506", "EVAL_LLM_DEEP_MODEL": "mistral-medium-2508"}
MISTRAL_EU = {
    "EVAL_LLM_PROVIDER": "openai",
    "EVAL_LLM_BASE_URL": "https://api.mistral.ai/v1",
    "EVAL_LLM_API_KEY": "test-only-model-key",
    **PINNED,
}
PROVIDER_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY")  # the settings fall back to these
OLLAMA_LOCAL = {
    "EVAL_LLM_PROVIDER": "ollama",
    "EVAL_LLM_BASE_URL": "http://127.0.0.1:11434/v1",
    "EVAL_LLM_FAST_MODEL": "qwen3:8b",
    "EVAL_LLM_DEEP_MODEL": "qwen3:14b",
}


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_eval_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _restore_environ() -> Iterator[None]:
    """The script writes the settings' environment variables; put the process back as it was."""
    saved = dict(os.environ)
    for name in list(os.environ):
        if name.startswith(("LG_SOTF_LLM__", "LG_SOTF_SECURITY__", "EVAL_LLM_")) or name in PROVIDER_KEYS:
            del os.environ[name]
    yield
    os.environ.clear()
    os.environ.update(saved)


class Runs:
    """Stands in for ``lg-sotf``: records each command with the model settings it would have run under."""

    def __init__(self, codes: Sequence[int] = (), reports: bool = False) -> None:
        self.codes = list(codes)
        self.reports = reports
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, args: Sequence[str]) -> int:
        llm = get_settings().llm
        self.calls.append({
            "args": list(args), "provider": llm.provider, "base_url": llm.base_url, "fast": llm.fast.model,
            "deep": llm.deep.model, "prompt_caching": llm.prompt_caching,
            "api_key": llm.api_key.get_secret_value() if llm.api_key else None,
        })
        code = self.codes.pop(0) if self.codes else 0
        if self.reports and code == 0:
            name = "synthetic.json" if "synthetic_v1" in args[args.index("--dataset") + 1] else "phishing.json"
            shutil.copy(V1_REPORTS / name, args[args.index("--report") + 1])
        return code


def _jobs(workflow: str) -> Dict[str, Any]:
    jobs = yaml.safe_load((WORKFLOWS / workflow).read_text())["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _runs(job: Dict[str, Any]) -> List[str]:
    return [step.get("run", "").strip() for step in job["steps"]]


# --------------------------------------------------------------------------- the workflows


def test_every_pull_request_runs_the_gate_with_the_fake_model_and_no_secret() -> None:
    job = _jobs("ci.yml")["eval-gate"]
    assert "continue-on-error" not in job and "if" not in job, "the gate blocks, on every run"
    assert not any("continue-on-error" in step for step in job["steps"])
    assert job["env"]["LG_SOTF_LLM__PROVIDER"] == "fake"
    runs = _runs(job)
    gate_step = runs.index("python scripts/ci/eval_gate.py pr --out eval-gate")
    assert runs.index("lg-sotf migrate") < gate_step
    assert "if" not in job["steps"][gate_step]
    # No real model can be reached from this job: it holds no secret, no key and no model variable.
    text = json.dumps(job)
    assert "secrets." not in text and "vars." not in text and "EVAL_LLM" not in text and "API_KEY" not in text
    upload = job["steps"][-1]
    assert upload["uses"].startswith("actions/upload-artifact@") and upload["if"] == "always()"
    assert upload["with"]["path"] == "eval-gate/"
    assert os.access(SCRIPT, os.X_OK)


def test_the_nightly_run_is_skipped_without_a_model_and_keeps_the_scorecard(gate: ModuleType) -> None:
    job = _jobs("nightly.yml")["real-model-eval"]
    assert job["if"] == "${{ vars.EVAL_LLM_PROVIDER != '' }}", "no model configured: skipped, not failed"
    assert not any(key.startswith("LG_SOTF_LLM__") for key in job["env"]), "the script sets and checks the model"
    runs = _runs(job)
    step = job["steps"][runs.index("python scripts/ci/eval_gate.py nightly --out eval-nightly")]
    assert set(step["env"]) == set(gate.MODEL_ENV)
    from_secrets = {key for key, value in step["env"].items() if "secrets." in value}
    assert from_secrets == {"EVAL_LLM_API_KEY"}
    assert all(value == f"${{{{ vars.{key} }}}}" for key, value in step["env"].items() if key not in from_secrets)
    assert json.dumps(job).count("secrets.") == 1, "the key reaches one step only"
    upload = job["steps"][-1]
    assert upload["uses"].startswith("actions/upload-artifact@") and upload["if"] == "always()"
    assert upload["with"]["name"] == "eval-scorecard" and upload["with"]["path"] == "eval-nightly/"
    assert upload["with"]["retention-days"] == 90
    for workflow in ("ci.yml", "nightly.yml"):  # no DeepSeek endpoint or model in either
        text = (WORKFLOWS / workflow).read_text().lower()
        assert "deepseek.com" not in text and "deepseek-" not in text, workflow


def test_make_runs_the_same_gate_and_records_the_baselines() -> None:
    make = (REPO_ROOT / "Makefile").read_text()
    assert "eval-gate:" in make and "scripts/ci/eval_gate.py pr\n" in make
    assert "eval-baselines:" in make and "scripts/ci/eval_gate.py pr --update-baselines\n" in make


# --------------------------------------------------------------------------- the committed baselines


def test_the_committed_baselines_describe_the_committed_sets(gate: ModuleType) -> None:
    assert [gated.name for gated in gate.SETS] == ["synthetic_v1", "phishing_v1"]
    for gated in gate.SETS:
        dataset = load_dataset(REPO_ROOT / gated.dataset)
        baseline = json.loads((REPO_ROOT / gated.baseline).read_text())
        # An edited dataset needs its baseline recorded again (`lg-sotf eval` refuses the comparison otherwise).
        assert baseline["dataset"]["sha256"] == dataset.sha256, f"{gated.name}: run make eval-baselines"
        assert baseline["dataset"]["items"] == len(dataset.items) == len(baseline["outcomes"])
        assert set(baseline["outcomes"]) == {item.id for item in dataset.items}
        assert baseline["run"]["llm_provider"] == "fake"
        assert baseline["metrics"]["malicious_false_negatives"] == 0 and baseline["metrics"]["errors"] == 0
        # Nothing that changes from run to run: the file moves only when behaviour does.
        text = json.dumps(baseline)
        assert not any(word in text for word in ("latency", "generated_at", "alert_id", "duration", "tenant"))
        thresholds = load_thresholds(REPO_ROOT / gated.thresholds)
        assert thresholds["regressions"]["malicious_false_negative_rate"] == {"max_increase": 0.0}
        assert thresholds["regressions"]["benign_auto_close_rate"] == {"max_decrease": 0.0}
        for path in thresholds["regressions"]:
            assert isinstance(resolve_metric(baseline, path), (int, float)), f"{gated.name}: {path}"


def _small_run() -> Tuple[Dataset, Dict[str, Any]]:
    """Three items: both benign ones closed, the attack with an analyst."""
    dataset = parse_dataset("\n".join(
        json.dumps({"id": item_id, "source_type": "canonical", "alert": {"title": item_id},
                    "expected": {"disposition": expected}})
        for item_id, expected in (("b-1", "benign"), ("b-2", "benign"), ("m-1", "malicious"))
    ))
    results = [result("b-1", "benign", "closed"), result("b-2", "benign", "closed"), result("m-1", "malicious")]
    return dataset, build_report(results, dataset=dataset, run_info={"llm_provider": "fake", "selection": {"limit": None}})


def test_a_baseline_keeps_the_gated_numbers_and_each_item_outcome(gate: ModuleType) -> None:
    dataset, report = _small_run()
    baseline = gate.baseline_from_report(report, gate.SETS[0])
    assert baseline["metrics"]["benign_auto_close_rate"] == 1.0 and baseline["metrics"]["malicious_false_negatives"] == 0
    assert baseline["outcomes"] == {"b-1": "closed:benign", "b-2": "closed:benign", "m-1": "waiting_human"}
    assert baseline["dataset"] == {"path": "tests/fixtures/eval/synthetic_v1.jsonl", "sha256": dataset.sha256, "items": 3}
    assert baseline["run"] == {"llm_provider": "fake", "selection": {"limit": None}}
    assert gate.changed_outcomes(report, baseline) == []

    # One benign item no longer closes and the attack does: both show as regressions against the baseline.
    after = [result("b-1", "benign", "closed"), result("b-2", "benign"), result("m-1", "malicious", "closed")]
    regressed = build_report(after, dataset=dataset, run_info={"llm_provider": "fake"})
    assert gate.changed_outcomes(regressed, baseline) == [
        "b-2: closed:benign -> waiting_human", "m-1: waiting_human -> closed:benign",
    ]
    thresholds = load_thresholds(REPO_ROOT / gate.SETS[0].thresholds)
    verdict = evaluate_gate(regressed, {**thresholds, "metrics": {}, "min_items": None}, baseline=baseline)
    assert {(v.metric, v.kind) for v in verdict.violations} >= {
        ("malicious_false_negative_rate", "regressed"), ("benign_auto_close_rate", "regressed"),
    }


# --------------------------------------------------------------------------- pr mode


def test_the_pull_request_gate_forces_the_fake_model_and_fails_when_a_set_fails(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    os.environ.update({"LG_SOTF_LLM__PROVIDER": "openai", "LG_SOTF_LLM__API_KEY": "test-only-model-key"})
    runs = Runs(codes=[0, 1])
    monkeypatch.setattr(gate, "lg_sotf", runs)
    assert gate.main(["pr", "--out", str(tmp_path)]) == 1
    assert [call["provider"] for call in runs.calls] == ["fake", "fake"]
    for call, gated in zip(runs.calls, gate.SETS, strict=True):
        assert call["args"] == [
            "eval", "--dataset", str(gated.dataset), "--thresholds", str(gated.thresholds),
            "--report", str(tmp_path / f"{gated.name}.json"), "--baseline", str(gated.baseline),
        ]
    assert "::error::Evaluation gate failed on phishing_v1" in capsys.readouterr().out

    # A set that could not run outranks a failed gate; --set runs one set only.
    monkeypatch.setattr(gate, "lg_sotf", Runs(codes=[2, 1]))
    assert gate.main(["pr", "--out", str(tmp_path)]) == 2
    one = Runs()
    monkeypatch.setattr(gate, "lg_sotf", one)
    assert gate.main(["pr", "--out", str(tmp_path), "--set", "phishing_v1"]) == 0
    assert len(one.calls) == 1 and "tests/fixtures/eval/phishing_v1.jsonl" in one.calls[0]["args"]


def test_baselines_are_written_only_from_a_run_that_passed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "FIXTURES", tmp_path / "fixtures")  # where the baselines go
    monkeypatch.setattr(gate, "lg_sotf", Runs(codes=[1, 2]))
    assert gate.main(["pr", "--out", str(tmp_path / "out"), "--update-baselines"]) == 2
    assert not (tmp_path / "fixtures").exists()

    def passing_run(args: Sequence[str]) -> int:
        assert "--baseline" not in args, "recording compares with nothing"
        Path(args[args.index("--report") + 1]).write_text(json.dumps(_small_run()[1], default=str))
        return 0

    monkeypatch.setattr(gate, "lg_sotf", passing_run)
    assert gate.main(["pr", "--out", str(tmp_path / "out"), "--update-baselines"]) == 0
    for name in ("synthetic_v1", "phishing_v1"):
        written = json.loads((tmp_path / "fixtures" / "baselines" / f"{name}.json").read_text())
        assert written["dataset"]["items"] == 3 and written["outcomes"]["m-1"] == "waiting_human"


# --------------------------------------------------------------------------- nightly mode


def test_nightly_does_nothing_and_succeeds_when_no_model_is_configured(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = Runs()
    monkeypatch.setattr(gate, "lg_sotf", runs)
    for env in ({}, {"EVAL_LLM_PROVIDER": "  ", "EVAL_LLM_API_KEY": "test-only-model-key"}):
        assert gate.main(["nightly", "--out", str(tmp_path)], env=env) == 0
    assert runs.calls == [] and list(tmp_path.iterdir()) == []
    assert "::notice::No evaluation model is configured" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("env", "error"),
    [
        # The DeepSeek API is hosted in China: never from CI, whatever the data.
        ({**MISTRAL_EU, "EVAL_LLM_BASE_URL": "https://api.deepseek.com/v1"}, "classified 'cn'"),
        ({"EVAL_LLM_PROVIDER": "anthropic", "EVAL_LLM_API_KEY": "test-only-model-key", **PINNED}, "classified 'us'"),
        ({**MISTRAL_EU, "EVAL_LLM_BASE_URL": "https://llm-gateway.example.com/v1"}, "classified 'unknown'"),
        ({**OLLAMA_LOCAL, "EVAL_LLM_BASE_URL": "https://models.example.com/v1"}, "classified 'unknown'"),
        ({"EVAL_LLM_PROVIDER": "fake", **PINNED}, "classified 'offline'"),
        ({**MISTRAL_EU, "EVAL_LLM_FAST_MODEL": "mistral-small-latest"}, "moving alias"),
        ({**OLLAMA_LOCAL, "EVAL_LLM_DEEP_MODEL": "qwen3:latest"}, "moving alias"),
        ({**MISTRAL_EU, "EVAL_LLM_DEEP_MODEL": ""}, "EVAL_LLM_DEEP_MODEL is not set"),
        ({**MISTRAL_EU, "EVAL_LLM_API_KEY": ""}, "EVAL_LLM_API_KEY (a repository secret) is not set"),
    ],
)
def test_nightly_refuses_a_model_that_is_not_a_pinned_eu_or_local_one(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    env: Dict[str, str], error: str,
) -> None:
    runs = Runs()
    monkeypatch.setattr(gate, "lg_sotf", runs)
    assert gate.main(["nightly", "--out", str(tmp_path)], env=env) == 2
    out = capsys.readouterr().out
    assert "::error::" in out and error in out
    assert runs.calls == [], "refused before anything is sent to the model"
    assert "test-only-model-key" not in out


@pytest.mark.parametrize(("env", "residency"), [(MISTRAL_EU, "eu"), (OLLAMA_LOCAL, "local")])
def test_nightly_runs_both_sets_on_the_configured_model_and_writes_the_scorecard(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    env: Dict[str, str], residency: str,
) -> None:
    os.environ["LG_SOTF_LLM__STRUCTURED_OUTPUT"] = "json_mode"  # not passed for this run: must not leak in
    runs = Runs(reports=True)
    monkeypatch.setattr(gate, "lg_sotf", runs)
    summary = tmp_path / "summary.md"
    out = tmp_path / "eval-nightly"
    full_env = {**env, "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_SHA": "0123456789abcdef0123"}
    assert gate.main(["nightly", "--out", str(out)], env=full_env) == 0
    assert [call["args"] for call in runs.calls] == [
        ["eval", "--dataset", str(gated.dataset), "--report", str(out / f"{gated.name}.json")] for gated in gate.SETS
    ], "no thresholds: the nightly run records, the pull-request job gates"
    for call in runs.calls:
        assert (call["provider"], call["base_url"]) == (env["EVAL_LLM_PROVIDER"], env["EVAL_LLM_BASE_URL"])
        assert (call["fast"], call["deep"]) == (env["EVAL_LLM_FAST_MODEL"], env["EVAL_LLM_DEEP_MODEL"])
        assert call["api_key"] == env.get("EVAL_LLM_API_KEY") and call["prompt_caching"] is False
    assert "LG_SOTF_LLM__STRUCTURED_OUTPUT" not in os.environ
    card = (out / "scorecard.md").read_text()
    assert f"({residency})" in card.splitlines()[0] and env["EVAL_LLM_FAST_MODEL"] in card.splitlines()[0]
    assert "at commit 0123456789ab" in card and f"hosted: {residency}" in card
    assert json.loads((out / "scorecard.json").read_text())["datasets"]
    assert summary.read_text().startswith(card)
    assert "test-only-model-key" not in capsys.readouterr().out + card


def test_nightly_fails_when_a_set_could_not_run_but_keeps_the_other_scorecard(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "lg_sotf", Runs(codes=[0, 2], reports=True))
    assert gate.main(["nightly", "--out", str(tmp_path)], env=MISTRAL_EU) == 2
    assert len(json.loads((tmp_path / "scorecard.json").read_text())["datasets"]) == 1
