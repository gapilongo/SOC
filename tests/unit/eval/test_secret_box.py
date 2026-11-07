"""``lg-sotf eval`` builds the process's SecretBox in cli.py and passes it to every evaluation path (D7, ADR-0006).

Enrichment reads tenant-encrypted tool keys with it, in the dataset
evaluation and in the history backtest alike.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
from click.testing import CliRunner

from lg_sotf.agents.registry import AgentSet
from lg_sotf.cli import cli
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.eval import command as eval_command
from lg_sotf.eval import history as history_module
from lg_sotf.eval import runner as runner_module
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.history import HistoryBacktestError, run_history_backtest
from lg_sotf.eval.runner import EvalSetupError, run_evaluation
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "synthetic_v1.jsonl"


class Stop(Exception):
    pass


@pytest.fixture
def env(settings_env: Any) -> Any:
    def apply(keys: str) -> Settings:
        return settings_env(
            LG_SOTF_ENVIRONMENT="test",
            LG_SOTF_LLM__PROVIDER="fake",
            LG_SOTF_DATABASE__URL="postgresql://nobody:x@127.0.0.1:1/none_test",
            LG_SOTF_SECURITY__ENCRYPTION_KEYS=keys,
        )

    return apply


def _recording(calls: List[Dict[str, Any]], error: Exception) -> Any:
    async def run(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        raise error

    return run


def test_the_dataset_evaluation_gets_the_box_built_by_the_cli(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env(generate_key())
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(eval_command, "run_evaluation", _recording(calls, EvalSetupError("stop here")))
    res = CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), "--report", str(tmp_path / "r.json")])
    assert res.exit_code == 2 and "stop here" in res.output
    assert isinstance(calls[0]["secret_box"], SecretBox)


def test_the_history_backtest_gets_the_box_built_by_the_cli(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env(generate_key())
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(history_module, "run_history_backtest", _recording(calls, HistoryBacktestError("stop here")))
    res = CliRunner().invoke(
        cli, ["eval", "--from-history", "--tenant", "t1", "--days", "7", "--report", str(tmp_path / "r.json")]
    )
    assert res.exit_code == 2 and "stop here" in res.output
    assert isinstance(calls[0]["secret_box"], SecretBox)


def test_invalid_keys_stop_the_evaluation_before_it_runs(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env("test-only-not-a-fernet-key")
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(eval_command, "run_evaluation", _recording(calls, EvalSetupError("unreachable")))
    res = CliRunner().invoke(cli, ["eval", "--dataset", str(DATASET), "--report", str(tmp_path / "r.json")])
    assert res.exit_code == 2 and "not a valid Fernet key" in res.output
    assert calls == []


async def test_the_backtest_agents_decrypt_with_the_box(
    make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = SecretBox([generate_key()])
    seen: Dict[str, Any] = {}

    def build(settings: Settings, **kwargs: Any) -> Any:
        seen.update(kwargs)
        raise Stop

    monkeypatch.setattr(AgentSet, "build", build)
    with pytest.raises(Stop):
        await run_history_backtest(make_settings(), tenant_id="t1", days=7, secret_box=box)
    assert seen["secret_box"] is box


async def test_the_evaluation_engine_and_ingestion_decrypt_with_the_box(
    make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = SecretBox([generate_key()])
    seen: Dict[str, Any] = {}

    async def nothing(*args: Any, **kwargs: Any) -> None:
        return None

    class NoRedis:
        aclose = nothing

    class Ingestion:
        def __init__(self, db: Any, settings: Settings, **kwargs: Any) -> None:
            seen["ingestion"] = kwargs.get("secret_box")

        close = nothing

    async def create(**kwargs: Any) -> Any:
        seen["engine"] = kwargs.get("secret_box")
        raise Stop

    monkeypatch.setattr(Database, "open", nothing)
    monkeypatch.setattr(Database, "close", nothing)
    monkeypatch.setattr("redis.asyncio.Redis.from_url", lambda *a, **k: NoRedis())
    monkeypatch.setattr(runner_module, "check_services", nothing)
    monkeypatch.setattr(runner_module, "IngestionService", Ingestion)
    monkeypatch.setattr(WorkflowEngine, "create", create)
    dataset = parse_dataset(DATASET.read_text(encoding="utf-8"))
    with pytest.raises(Stop):
        await run_evaluation(make_settings(), dataset, secret_box=box)
    assert seen == {"ingestion": box, "engine": box}
