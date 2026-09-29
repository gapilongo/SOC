"""``lg-sotf eval`` failure handling: setup errors exit 2 before any work, baselines must match, usage is kept."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.eval import command as eval_command
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.runner import (
    EvalRun,
    EvalRunner,
    EvalSetupError,
    check_services,
    group_by_split,
    split_tenant_ids,
)
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "synthetic_v1.jsonl"
SMOKE = FIXTURES / "smoke_thresholds.yaml"


@pytest.fixture
def env(settings_env: Any) -> Any:
    return settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL="postgresql://nobody:x@127.0.0.1:1/none_test",
    )


class Recorder:
    """A stand-in for ``run_evaluation`` that returns fixed outcomes and records its calls."""

    def __init__(self, outcomes: List[Any]) -> None:
        self.outcomes = outcomes
        self.calls: List[Dict[str, Any]] = []

    async def __call__(self, settings: Any, dataset: Any, **kwargs: Any) -> EvalRun:
        self.calls.append(kwargs)
        for i, r in enumerate(self.outcomes):
            kwargs["progress"](i + 1, len(self.outcomes), r)
        return EvalRun(results=self.outcomes, info={"llm_provider": "fake", "isolation": kwargs["isolate"]})


def invoke(*args: str) -> Any:
    return CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), *args])


# ------------------------------------------------------------ report path (EV-1)


def test_unwritable_report_path_exits_2_before_anything_runs(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Recorder([result("syn-001", "malicious")])
    monkeypatch.setattr(eval_command, "run_evaluation", run)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    res = invoke("--limit", "1", "--report", str(blocker / "report.json"))
    assert res.exit_code == 2, res.output
    assert "cannot write the report" in res.output and "Nothing was evaluated" in res.output
    assert "Traceback" not in res.output
    assert run.calls == []


def test_unwritable_markdown_path_exits_2_before_anything_runs(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Recorder([result("syn-001", "malicious")])
    monkeypatch.setattr(eval_command, "run_evaluation", run)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    res = invoke("--limit", "1", "--report", str(tmp_path / "r.json"), "--markdown", str(blocker / "r.md"))
    assert res.exit_code == 2 and run.calls == []
    assert not (tmp_path / "r.json").exists()


def test_writability_probe_leaves_no_files(tmp_path: Path) -> None:
    target = tmp_path / "new" / "report.json"
    eval_command.check_writable(target)
    assert target.parent.is_dir() and list(target.parent.iterdir()) == []
    existing = tmp_path / "old.json"
    existing.write_text("keep")
    eval_command.check_writable(existing)
    assert existing.read_text() == "keep"
    with pytest.raises(eval_command.EvalCommandError):
        eval_command.check_writable(tmp_path)  # a directory is not a report file


def test_results_survive_a_failed_final_write(env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eval_command, "run_evaluation", Recorder([result("syn-001", "malicious")]))
    real_write = eval_command.write_json
    calls: List[str] = []

    def flaky(report: Any, path: Any) -> None:
        calls.append(str(path))
        if len(calls) == 1:
            raise OSError(28, "No space left on device")
        real_write(report, path)

    monkeypatch.setattr(eval_command, "write_json", flaky)
    res = invoke("--limit", "1", "--report", str(tmp_path / "r.json"))
    assert res.exit_code == 2
    assert "results were saved to" in res.output
    fallback = Path(calls[1])
    try:
        assert json.loads(fallback.read_text())["metrics"]["items"] == 1
    finally:
        fallback.unlink()


# ------------------------------------------------ nothing scored, setup errors (EV-2, EV-3)


def test_a_run_where_every_item_errored_exits_2_even_without_thresholds(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errored = [result("syn-001", "malicious", "error", error="ConnectionError: redis"),
               result("syn-002", "malicious", "error", error="ConnectionError: redis")]
    monkeypatch.setattr(eval_command, "run_evaluation", Recorder(errored))
    report = tmp_path / "r.json"
    res = invoke("--limit", "2", "--report", str(report))
    assert res.exit_code == 2, res.output
    assert "every one of the 2 items errored" in res.output
    assert json.loads(report.read_text())["metrics"]["errors"] == 2  # the report still explains why


@pytest.mark.parametrize(
    "error",
    [
        "DatabaseError",
        "UndefinedTableError",
        "OperationError",
        "RedisConnectionError",
    ],
)
def test_database_and_redis_errors_exit_2_without_a_traceback(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    import asyncpg
    from redis.exceptions import ConnectionError as RedisConnectionError

    from lg_sotf.db.errors import DatabaseError
    from lg_sotf.runtime.ops import OperationError

    exc = {
        "DatabaseError": DatabaseError("database schema is not migrated; run `lg-sotf migrate`"),
        "UndefinedTableError": asyncpg.UndefinedTableError('relation "alerts" does not exist'),
        "OperationError": OperationError("tenant 'x' already exists"),
        "RedisConnectionError": RedisConnectionError("Error 111"),
    }[error]

    async def fail(*args: Any, **kwargs: Any) -> EvalRun:
        raise exc

    monkeypatch.setattr(eval_command, "run_evaluation", fail)
    res = invoke("--limit", "1", "--report", str(tmp_path / "r.json"))
    assert res.exit_code == 2, (res.exit_code, res.output, res.exception)
    assert res.output.startswith("Error:") and "Traceback" not in res.output
    assert not (tmp_path / "r.json").exists()


class _Conn:
    def __init__(self, missing: List[str]) -> None:
        self.missing = missing

    async def fetchval(self, sql: str) -> List[str]:
        return self.missing


class _Ctx:
    def __init__(self, conn: _Conn) -> None:
        self.conn = conn

    async def __aenter__(self) -> _Conn:
        return self.conn

    async def __aexit__(self, *exc: object) -> None:
        return None


class _Db:
    def __init__(self, missing: Optional[List[str]] = None, down: bool = False) -> None:
        self.missing = missing or []
        self.down = down

    async def ping(self, acquire_timeout_s: float = 1.0) -> float:
        from lg_sotf.db.errors import DatabaseUnavailable

        if self.down:
            raise DatabaseUnavailable("database ping failed: ConnectionRefusedError")
        return 0.001

    def connection(self) -> _Ctx:
        return _Ctx(_Conn(self.missing))


class _Redis:
    def __init__(self, up: bool = True) -> None:
        self.up = up

    async def ping(self) -> bool:
        from redis.exceptions import ConnectionError as RedisConnectionError

        if not self.up:
            raise RedisConnectionError("Error 111 connecting to 127.0.0.1:6999")
        return True


def test_check_services_accepts_a_ready_environment() -> None:
    asyncio.run(check_services(_Db(), _Redis()))


def test_check_services_names_what_is_wrong() -> None:
    with pytest.raises(EvalSetupError, match="database unavailable"):
        asyncio.run(check_services(_Db(down=True), _Redis()))
    with pytest.raises(EvalSetupError, match=r"not migrated \(missing alerts, checkpoints\).*lg-sotf migrate"):
        asyncio.run(check_services(_Db(missing=["alerts", "checkpoints"]), _Redis()))
    with pytest.raises(EvalSetupError, match="redis unavailable: ConnectionError"):
        asyncio.run(check_services(_Db(), _Redis(up=False)))


# ------------------------------------------------------------ split isolation (EV-6)


def test_split_tenants_are_valid_distinct_and_bounded() -> None:
    from lg_sotf.db.tenancy import is_valid_tenant_id

    tenants = split_tenant_ids("eval-20260929-120000-abcdef", ["standard", "adversarial", "Adv.Ersarial", "x" * 128])
    assert tenants["standard"] == "eval-20260929-120000-abcdef-0-standard"
    assert tenants["adversarial"] == "eval-20260929-120000-abcdef-1-adversarial"
    assert len(set(tenants.values())) == 4
    assert all(is_valid_tenant_id(t) and len(t) <= 63 for t in tenants.values())
    with pytest.raises(EvalSetupError, match="too long"):
        split_tenant_ids("t" * 61, ["standard"])


def test_group_by_split_keeps_dataset_order_within_each_split() -> None:
    rows = [
        {"id": i, "source_type": "canonical", "alert": {"title": i}, "expected": {"disposition": "benign"}, "split": s}
        for i, s in (("a", "standard"), ("b", "adversarial"), ("c", "standard"), ("d", "adversarial"))
    ]
    dataset = parse_dataset("\n".join(json.dumps(r) for r in rows))
    groups = [(name, [i.id for i in items]) for name, items in group_by_split(dataset.items)]
    assert groups == [("standard", ["a", "c"]), ("adversarial", ["b", "d"])]


def test_isolation_is_passed_through_and_recorded(env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = Recorder([result("syn-001", "malicious")])
    monkeypatch.setattr(eval_command, "run_evaluation", run)
    report = tmp_path / "r.json"
    assert invoke("--limit", "1", "--report", str(report)).exit_code == 0
    assert run.calls[-1]["isolate"] == "splits"
    assert invoke("--limit", "1", "--report", str(report), "--isolate", "none").exit_code == 0
    assert run.calls[-1]["isolate"] == "none"
    data = json.loads(report.read_text())
    assert data["run"]["selection"] == {"splits": [], "tags": [], "limit": 1, "isolation": "none"}
    assert invoke("--limit", "1", "--isolate", "items").exit_code == 2


# ------------------------------------------------------------ baseline compatibility (EV-9)


def test_baseline_from_another_dataset_or_selection_is_refused(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Recorder([result("syn-001", "malicious")])
    monkeypatch.setattr(eval_command, "run_evaluation", run)
    baseline = tmp_path / "baseline.json"
    assert invoke("--limit", "1", "--report", str(baseline)).exit_code == 0

    same = invoke("--limit", "1", "--report", str(tmp_path / "r.json"), "--thresholds", str(SMOKE),
                  "--baseline", str(baseline))
    assert "baseline is not comparable" not in same.output
    assert json.loads((tmp_path / "r.json").read_text())["gate"]["checked"] == 12  # min_items + 8 bounds + 3 regressions

    calls_before = len(run.calls)
    other = invoke("--limit", "1", "--split", "standard", "--report", str(tmp_path / "r2.json"),
                   "--baseline", str(baseline))
    assert other.exit_code == 2 and "baseline is not comparable" in other.output and "selection" in other.output
    assert len(run.calls) == calls_before

    data = json.loads(baseline.read_text())
    data["dataset"]["sha256"] = "0" * 64
    baseline.write_text(json.dumps(data))
    res = invoke("--limit", "1", "--report", str(tmp_path / "r3.json"), "--baseline", str(baseline))
    assert res.exit_code == 2 and "different dataset file" in res.output
    forced = invoke("--limit", "1", "--report", str(tmp_path / "r3.json"), "--baseline", str(baseline),
                    "--allow-baseline-mismatch")
    assert forced.exit_code == 0 and "Warning: baseline is not comparable" in forced.output

    data["schema_version"] = 99
    baseline.write_text(json.dumps(data))
    assert "schema version 99" in invoke("--limit", "1", "--baseline", str(baseline), "--validate-only").output


# ------------------------------------------------------------ customer data near git (EV-7)


def _non_synthetic_dataset(directory: Path) -> Path:
    path = directory / "feedback.jsonl"
    path.write_text(json.dumps({
        "id": "fb-1", "source_type": "canonical", "alert": {"title": "x"}, "expected": {"disposition": "benign"},
    }) + "\n")
    return path


def test_warns_when_real_labelled_data_sits_in_a_git_work_tree(env: Any, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    data = _non_synthetic_dataset(repo)
    res = CliRunner().invoke(cli, ["eval", "--dataset", str(data), "--report", str(repo / "out" / "r.json"),
                                   "--validate-only"])
    assert res.exit_code == 0
    assert "the dataset" in res.output and "the report" in res.output and "out of version control" in res.output

    outside = tmp_path / "private"
    outside.mkdir()
    clean = CliRunner().invoke(cli, ["eval", "--dataset", str(_non_synthetic_dataset(outside)),
                                     "--report", str(outside / "r.json"), "--validate-only"])
    assert clean.exit_code == 0 and "version control" not in clean.output
    synthetic = CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), "--validate-only"])
    assert "version control" not in synthetic.output


# ------------------------------------------------------------ usage of failed items (EV-8)


class _Alerts:
    def __init__(self, summary: Dict[str, Any], fail: bool = False) -> None:
        self.summary = summary
        self.fail = fail

    async def get(self, tenant_id: str, alert_id: str) -> Any:
        if self.fail:
            raise RuntimeError("database gone")
        return SimpleNamespace(summary=self.summary)


class _Ingestion:
    async def ingest(self, tenant_id: str, source_id: str, events: List[Any]) -> Any:
        return SimpleNamespace(items=[SimpleNamespace(status="inserted", alert_id="a-1", reason=None)])


class _Engine:
    async def run(self, tenant_id: str, alert_id: str) -> Any:
        raise RuntimeError("analysis node crashed")


def _item() -> Any:
    return parse_dataset(json.dumps({
        "id": "x", "source_type": "canonical", "alert": {"title": "t"}, "expected": {"disposition": "malicious"},
    })).items[0]


def test_an_item_that_fails_after_model_calls_keeps_its_usage() -> None:
    usage = {"llm_usage": {"calls": 2, "input_tokens": 900, "output_tokens": 100, "total_tokens": 1000,
                           "cost_usd": 0.012}}
    runner = EvalRunner(tenant_id="t", repos=SimpleNamespace(alerts=_Alerts(usage)),  # type: ignore[arg-type]
                        ingestion=_Ingestion(), engine=_Engine())  # type: ignore[arg-type]
    r = asyncio.run(runner.evaluate(_item()))
    assert r.status == "error" and r.error.startswith("RuntimeError: analysis node crashed")
    assert (r.llm_calls, r.total_tokens, r.cost_usd) == (2, 1000, pytest.approx(0.012))


def test_usage_lookup_failure_does_not_mask_the_item_error() -> None:
    runner = EvalRunner(tenant_id="t", repos=SimpleNamespace(alerts=_Alerts({}, fail=True)),  # type: ignore[arg-type]
                        ingestion=_Ingestion(), engine=_Engine())  # type: ignore[arg-type]
    r = asyncio.run(runner.evaluate(_item()))
    assert r.status == "error" and "analysis node crashed" in r.error and r.cost_usd == 0.0
