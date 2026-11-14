"""ARCH-E2.1 acceptance: a deliberate regression on an evaluation set fails the CI gate.

Each test runs the command of the ``eval-gate`` job in ci.yml (``scripts/ci/eval_gate.py pr``) in this
process: `lg-sotf eval` with the fake model on the test PostgreSQL and Redis, against the committed
thresholds and baseline of the phishing set. The regressions are patches of the routing policy
(``lg_sotf.domain.routing``), as a careless change to it would be.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterator, List, Mapping, Set, Tuple

import pytest

from lg_sotf.domain import routing
from lg_sotf.domain.routing import Decision, RoutingThresholds
from lg_sotf.settings import Settings
from tests.integration.db._support import db_settings, truncate_all

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "ci" / "eval_gate.py"
SET = "phishing_v1"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_eval_gate_it", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


async def _truncate(url: str) -> None:
    from lg_sotf.db.pool import Database

    db = Database(db_settings(url), application_name="lg-sotf-tests")
    await db.open()
    try:
        await truncate_all(db)
    finally:
        await db.close()


@pytest.fixture
def ci_environment(
    settings_env: Callable[..., Settings], checkpointed_database_url: str, redis_url: str, unique_prefix: str
) -> Iterator[None]:
    """What the CI job gives the command: a migrated database and a Redis. The script adds the rest."""
    saved = dict(os.environ)
    asyncio.run(_truncate(checkpointed_database_url))
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_DATABASE__URL=checkpointed_database_url,
        LG_SOTF_REDIS__URL=redis_url,
        LG_SOTF_REDIS__KEY_PREFIX=unique_prefix,
        LG_SOTF_LLM__PROVIDER=None,  # the script forces the fake model itself
    )
    yield
    asyncio.run(_truncate(checkpointed_database_url))
    os.environ.clear()  # the script wrote LG_SOTF_LLM__PROVIDER and throwaway security keys
    os.environ.update(saved)


def run_gate(gate: ModuleType, out: Path) -> Tuple[int, Set[Tuple[str, str]], Dict[str, Any]]:
    """The gate's exit code, its ``(metric, kind)`` violations and the report's metrics."""
    code = gate.main(["pr", "--set", SET, "--out", str(out)])
    report = json.loads((out / f"{SET}.json").read_text())
    return code, {(v["metric"], v["kind"]) for v in report["gate"]["violations"]}, report["metrics"]


def test_the_gate_passes_on_the_committed_baseline(
    gate: ModuleType, ci_environment: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, violations, metrics = run_gate(gate, tmp_path)
    assert (code, violations) == (0, set()), capsys.readouterr().out[-2000:]
    baseline = json.loads((SCRIPT.parents[2] / "tests/fixtures/eval/baselines" / f"{SET}.json").read_text())
    for key, value in baseline["metrics"].items():
        assert metrics[key] == pytest.approx(value), key
    assert "ended differently than in the baseline" not in capsys.readouterr().out


def test_one_benign_close_fewer_than_the_baseline_fails_the_gate(
    gate: ModuleType, ci_environment: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Benign handling below the baseline: the policy stops closing one alert it used to close."""
    real = routing.decide
    dropped: List[str] = []

    def regressed(state: Mapping[str, Any], t: RoutingThresholds, tier: str = "off") -> Decision:
        decision = real(state, t, tier)
        if decision.route == "close" and not dropped:
            dropped.append(decision.code)
            return Decision("escalate", "deliberate regression", None, "false_positive_review")
        return decision

    monkeypatch.setattr(routing, "decide", regressed)
    code, violations, metrics = run_gate(gate, tmp_path)
    out = capsys.readouterr().out
    assert code == 1 and dropped == ["rule_corroborated_benign"], out[-2000:]
    # 2 of 11 still clears the absolute floor (0.1): only the comparison with the baseline (3 of 11) fails.
    assert violations == {("benign_auto_close_rate", "regressed")}
    assert metrics["benign_auto_close_rate"] == pytest.approx(2 / 11)
    assert "benign_auto_close_rate fell from 0.2727 to 0.1818" in out
    assert "phish-019: closed:benign -> waiting_human" in out
    assert f"::error::Evaluation gate failed on {SET}" in out


def test_a_missed_attack_fails_the_gate(
    gate: ModuleType, ci_environment: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missed attacks above the baseline: the policy takes any alert as carrying approved benign evidence."""
    monkeypatch.setattr(routing, "benign_evidence", lambda triage: True)
    code, violations, metrics = run_gate(gate, tmp_path)
    out = capsys.readouterr().out
    assert code == 1, out[-2000:]
    assert ("malicious_false_negative_rate", "regressed") in violations
    assert ("malicious_false_negative_rate", "above_max") in violations
    assert metrics["malicious_false_negatives"] >= 1 and metrics["missed_malicious_ids"]
    missed = metrics["missed_malicious_ids"][0]
    assert f"{missed}: waiting_human -> closed:benign" in out
    assert f"::error::Evaluation gate failed on {SET}" in out
