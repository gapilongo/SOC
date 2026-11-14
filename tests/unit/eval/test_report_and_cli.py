"""Reports (JSON + Markdown) and the ``lg-sotf eval`` command without a database."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.eval import command as eval_command
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.report import (
    FAKE_MODEL_NOTE,
    SYNTHETIC_NOTE,
    UNREVIEWED_NOTE,
    build_report,
    load_report,
    render_markdown,
    write_json,
)
from lg_sotf.eval.runner import EvalRun, EvalSetupError, new_eval_tenant_id
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "synthetic_v1.jsonl"
SMOKE = FIXTURES / "smoke_thresholds.yaml"


def small_dataset(synthetic: bool = True) -> Any:
    meta = '{"_meta": {"synthetic": true}}\n' if synthetic else ""
    rows = [
        {"id": "m1", "source_type": "canonical", "alert": {"title": "a"}, "expected": {"disposition": "malicious"}},
        {"id": "b1", "source_type": "canonical", "alert": {"title": "b"}, "expected": {"disposition": "benign"},
         "split": "adversarial"},
    ]
    return parse_dataset(meta + "\n".join(json.dumps(r) for r in rows), path="small.jsonl")


def results() -> List[Any]:
    return [
        result("m1", "malicious", "closed", disposition="benign", severity="low"),
        result("b1", "benign", "waiting_human", split="adversarial", predicted="benign"),
        result("e1", "benign", "error", error="ingest rejected: a|b"),
    ]


def test_build_report_structure_and_notices() -> None:
    rep = build_report(results(), dataset=small_dataset(), run_info={"llm_provider": "fake", "tenant_id": "eval-x"})
    assert rep["schema_version"] == 1
    assert rep["dataset"]["synthetic"] is True and rep["dataset"]["items"] == 2
    assert rep["metrics"]["items"] == 3 and rep["metrics"]["errors"] == 1
    assert rep["notes"] == [SYNTHETIC_NOTE, FAKE_MODEL_NOTE, UNREVIEWED_NOTE]
    assert rep["metrics"]["malicious_false_negative_rate"] == 1.0
    assert set(rep["splits"]) == {"standard", "adversarial"}
    assert rep["splits"]["adversarial"]["metrics"]["escalation_rate"] == 1.0
    assert [i["item_id"] for i in rep["items"]] == ["m1", "b1", "e1"]
    real = build_report(results(), dataset=small_dataset(synthetic=False), run_info={"llm_provider": "anthropic"})
    assert real["notes"] == [UNREVIEWED_NOTE]


def test_markdown_marks_missed_items_escapes_cells_and_shows_the_gate() -> None:
    rep = build_report(results(), dataset=small_dataset(), run_info={"llm_provider": "fake"})
    gate = {"passed": False, "checked": 2, "violations": [{"message": "malicious_false_negative_rate = 1 > max 0"}]}
    md = render_markdown(rep, gate)
    assert md.startswith("# LG-SOTF evaluation report")
    assert "**FAILED** (2 checks)" in md and "- malicious_false_negative_rate = 1 > max 0" in md
    assert "| Malicious false-negative rate (auto-closed as benign) | 100.0% (1 of 1; 95% CI 20.7% to 100.0%) |" in md
    row = next(line for line in md.splitlines() if line.startswith("| `m1`"))
    assert row.rstrip().endswith("| MISSED |")
    error_row = next(line for line in md.splitlines() if line.startswith("| `e1`"))
    assert error_row.rstrip().endswith("| ingest rejected: a\\|b |")
    assert "Not computed: no two annotators" in md
    for line in md.splitlines():
        if line.startswith("| Latency"):
            assert line.count("|") == 5  # label + all + two splits


def test_json_report_round_trip(tmp_path: Path) -> None:
    rep = build_report(results(), dataset=small_dataset())
    path = tmp_path / "nested" / "r.json"
    write_json(rep, path)
    assert load_report(path)["metrics"]["items"] == 3
    (tmp_path / "x.json").write_text("[]")
    with pytest.raises(ValueError):
        load_report(tmp_path / "x.json")


def test_eval_tenant_ids_are_valid_and_unique() -> None:
    from lg_sotf.db.tenancy import is_valid_tenant_id

    ids = {new_eval_tenant_id() for _ in range(20)}
    assert len(ids) == 20 and all(is_valid_tenant_id(i) and i.startswith("eval-") for i in ids)


# ------------------------------------------------------------------------ CLI


@pytest.fixture
def env(settings_env: Any) -> Any:
    return settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL="postgresql://nobody:x@127.0.0.1:1/none_test",
    )


def test_help_lists_eval() -> None:
    out = CliRunner().invoke(cli, ["--help"]).output
    assert "eval" in out


def test_validate_only_checks_dataset_and_thresholds(env: Any) -> None:
    res = CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), "--thresholds", str(SMOKE), "--validate-only"])
    assert res.exit_code == 0, res.output
    assert "dataset ok: 64 items" in res.output and "thresholds ok" in res.output


def test_bad_inputs_exit_2(env: Any, tmp_path: Path) -> None:
    runner = CliRunner()
    missing = runner.invoke(cli, ["eval", "--dataset", str(tmp_path / "none.jsonl"), "--validate-only"])
    assert missing.exit_code == 2 and "cannot read dataset" in missing.output
    bad = tmp_path / "t.yaml"
    bad.write_text("metrics: {x: {max: -}}")
    res = runner.invoke(cli, ["eval", "--dataset", str(DATASET), "--thresholds", str(bad), "--validate-only"])
    assert res.exit_code == 2 and "Error:" in res.output
    empty = runner.invoke(cli, ["eval", "--dataset", str(DATASET), "--split", "nope", "--validate-only"])
    assert empty.exit_code == 2 and "no dataset items match" in empty.output
    baseline = tmp_path / "b.json"
    baseline.write_text("{}")
    res = runner.invoke(cli, ["eval", "--dataset", str(DATASET), "--baseline", str(baseline), "--validate-only"])
    assert res.exit_code == 2 and "baseline" in res.output


def _fake_run(outcomes: List[Any]) -> Any:
    async def run(settings: Any, dataset: Any, **kwargs: Any) -> EvalRun:
        assert kwargs["concurrency"] == 1
        for i, r in enumerate(outcomes):
            kwargs["progress"](i + 1, len(outcomes), r)
        return EvalRun(results=outcomes, info={"llm_provider": "fake", "tenant_id": "eval-test"})

    return run


def test_run_writes_reports_and_fails_the_gate_with_exit_1(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = [result("syn-001", "malicious", "closed", disposition="benign", severity="medium")]
    monkeypatch.setattr(eval_command, "run_evaluation", _fake_run(outcomes))
    report = tmp_path / "out" / "report.json"
    res = CliRunner().invoke(
        cli,
        ["eval", "--dataset", str(DATASET), "--limit", "1", "--report", str(report), "--thresholds", str(SMOKE)],
    )
    assert res.exit_code == 1, res.output
    assert "[1/1] syn-001: closed, predicted benign" in res.output
    assert "gate FAILED" in res.output
    data = json.loads(report.read_text())
    assert data["gate"]["passed"] is False
    assert {v["metric"] for v in data["gate"]["violations"]} >= {"malicious_false_negative_rate", "scored"}
    md = report.with_suffix(".md").read_text()
    assert "**FAILED**" in md and "MISSED" in md


def test_run_passes_without_thresholds_and_honours_markdown_path(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = [result("syn-030", "benign", "closed")]
    monkeypatch.setattr(eval_command, "run_evaluation", _fake_run(outcomes))
    md = tmp_path / "custom.md"
    res = CliRunner().invoke(
        cli,
        ["eval", "--dataset", str(DATASET), "--limit", "1", "--report", str(tmp_path / "r.json"), "--markdown", str(md)],
    )
    assert res.exit_code == 0, res.output
    assert md.exists() and "gate" not in json.loads((tmp_path / "r.json").read_text())


def test_setup_errors_exit_2(env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*args: Any, **kwargs: Any) -> EvalRun:
        raise EvalSetupError("tenant 'eval-x' already exists")

    monkeypatch.setattr(eval_command, "run_evaluation", fail)
    res = CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), "--report", str(tmp_path / "r.json")])
    assert res.exit_code == 2 and "already exists" in res.output
    assert not (tmp_path / "r.json").exists()


def test_production_environment_is_refused(settings_env: Any) -> None:
    import asyncio

    from lg_sotf.eval.runner import run_evaluation

    settings = settings_env(LG_SOTF_ENVIRONMENT="production")
    with pytest.raises(EvalSetupError, match="production"):
        asyncio.run(run_evaluation(settings, small_dataset()))


def test_cassettes_reach_the_runner_and_a_missing_replay_directory_exits_2(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: List[Any] = []

    async def run(settings: Any, dataset: Any, **kwargs: Any) -> EvalRun:
        seen.append(kwargs["cassettes"])
        return EvalRun(results=[result("syn-001", "malicious", "waiting_human")], info={"llm_provider": "cassette"})

    monkeypatch.setattr(eval_command, "run_evaluation", run)
    runner = CliRunner()
    base = ["eval", "--dataset", str(DATASET), "--limit", "1", "--report", str(tmp_path / "r.json")]
    missing = runner.invoke(cli, [*base, "--cassettes", str(tmp_path / "none")])
    assert missing.exit_code == 2 and "no cassette directory" in missing.output and seen == []
    recorded = runner.invoke(cli, [*base, "--cassettes", str(tmp_path / "rec"), "--cassette-mode", "record"])
    assert recorded.exit_code == 0, recorded.output
    (tmp_path / "rec").mkdir()
    replayed = runner.invoke(cli, [*base, "--cassettes", str(tmp_path / "rec")])
    assert replayed.exit_code == 0, replayed.output
    assert [(c.mode, c.directory, c.dataset_sha256 is not None) for c in seen] == [
        ("record", tmp_path / "rec", True), ("replay", tmp_path / "rec", True)
    ]
    history = runner.invoke(cli, ["eval", "--from-history", "--tenant", "t1", "--cassettes", str(tmp_path / "rec")])
    assert history.exit_code == 2 and "not to --from-history" in history.output


def test_the_oracle_reaches_the_runner_and_needs_one_item_at_a_time(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: List[Any] = []

    async def run(settings: Any, dataset: Any, **kwargs: Any) -> EvalRun:
        seen.append((kwargs["oracle"], kwargs["accept_suppressions"]))
        return EvalRun(results=[result("syn-001", "malicious", "waiting_human")], info={"llm_provider": "fake"})

    monkeypatch.setattr(eval_command, "run_evaluation", run)
    runner = CliRunner()
    report = tmp_path / "r.json"
    base = ["eval", "--dataset", str(DATASET), "--limit", "1", "--report", str(report)]
    assert runner.invoke(cli, [*base, "--oracle", "propose"]).exit_code == 0
    assert json.loads(report.read_text())["run"]["selection"]["oracle"] == "propose"
    assert runner.invoke(cli, [*base, "--oracle", "accept"]).exit_code == 0
    assert runner.invoke(cli, base).exit_code == 0
    assert "oracle" not in json.loads(report.read_text())["run"]["selection"]
    assert seen == [(True, False), (True, True), (False, False)]
    parallel = runner.invoke(cli, [*base, "--oracle", "propose", "--concurrency", "2"])
    assert parallel.exit_code == 2 and "--concurrency 1" in parallel.output
    history = runner.invoke(cli, ["eval", "--from-history", "--tenant", "t1", "--oracle", "propose"])
    assert history.exit_code == 2 and "not to --from-history" in history.output
    with pytest.raises(eval_command.EvalCommandError, match="--oracle must be one of"):
        eval_command.check_run_options(eval_command.EvalOptions(dataset="d", report="r", oracle="always"))
