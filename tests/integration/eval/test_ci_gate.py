"""ARCH-E2.1 acceptance: a deliberate regression on an evaluation set fails the CI gate.

Each test runs the command of the ``eval-gate`` job in ci.yml (``scripts/ci/eval_gate.py pr``) as a
process of its own: `lg-sotf eval` with the fake model on the test PostgreSQL and Redis, against the
committed thresholds and baseline of the phishing set. The regressions are patches of the routing
policy (``lg_sotf.domain.routing``), as a careless change to it would be; the child process applies
them (``_ci_gate_child.py``, which also says why the gate never runs inside the pytest process).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, Set, Tuple

import pytest

from tests.integration.db._support import db_settings, truncate_all

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

REPO_ROOT = Path(__file__).resolve().parents[3]
CHILD = Path(__file__).with_name("_ci_gate_child.py")
SET = "phishing_v1"


async def _truncate(url: str) -> None:
    from lg_sotf.db.pool import Database

    db = Database(db_settings(url), application_name="lg-sotf-tests")
    await db.open()
    try:
        await truncate_all(db)
    finally:
        await db.close()


@pytest.fixture
def ci_environment(checkpointed_database_url: str, redis_url: str, unique_prefix: str) -> Iterator[Dict[str, str]]:
    """What the CI job gives the command: a migrated database and a Redis. The script adds the rest."""
    asyncio.run(_truncate(checkpointed_database_url))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LG_SOTF_", "EVAL_LLM_"))}
    yield {
        **env,
        "LG_SOTF_ENVIRONMENT": "test",
        "LG_SOTF_DATABASE__URL": checkpointed_database_url,
        "LG_SOTF_REDIS__URL": redis_url,
        "LG_SOTF_REDIS__KEY_PREFIX": unique_prefix,
    }
    asyncio.run(_truncate(checkpointed_database_url))


def run_gate(regression: str, env: Dict[str, str], out: Path) -> Tuple[int, str, Set[Tuple[str, str]], Dict[str, Any]]:
    """The gate's exit code and output, its ``(metric, kind)`` violations and the report's metrics."""
    proc = subprocess.run(
        [sys.executable, str(CHILD), regression, "pr", "--set", SET, "--out", str(out)],
        env=env, cwd=out, capture_output=True, text=True, timeout=240, stdin=subprocess.DEVNULL,
    )
    output = proc.stdout + proc.stderr[-2000:]
    report_path = out / f"{SET}.json"
    assert report_path.is_file(), f"the gate wrote no report (exit code {proc.returncode}):\n{output[-3000:]}"
    report = json.loads(report_path.read_text())
    violations = {(v["metric"], v["kind"]) for v in report["gate"]["violations"]}
    return proc.returncode, output, violations, report["metrics"]


def test_the_gate_passes_on_the_committed_baseline(ci_environment: Dict[str, str], tmp_path: Path) -> None:
    code, output, violations, metrics = run_gate("none", ci_environment, tmp_path)
    assert (code, violations) == (0, set()), output[-3000:]
    baseline = json.loads((REPO_ROOT / "tests/fixtures/eval/baselines" / f"{SET}.json").read_text())
    for key, value in baseline["metrics"].items():
        assert metrics[key] == pytest.approx(value), key
    assert "ended differently than in the baseline" not in output


def test_one_benign_close_fewer_than_the_baseline_fails_the_gate(
    ci_environment: Dict[str, str], tmp_path: Path
) -> None:
    """Benign handling below the baseline: the policy stops closing one alert it used to close."""
    code, output, violations, metrics = run_gate("one_benign_close_fewer", ci_environment, tmp_path)
    assert code == 1, output[-3000:]
    # 2 of 11 still clears the absolute floor (0.1): only the comparison with the baseline (3 of 11) fails.
    assert violations == {("benign_auto_close_rate", "regressed")}
    assert metrics["benign_auto_close_rate"] == pytest.approx(2 / 11)
    assert "benign_auto_close_rate fell from 0.2727 to 0.1818" in output
    assert "phish-019: closed:benign -> waiting_human" in output
    assert f"::error::Evaluation gate failed on {SET}" in output


def test_a_missed_attack_fails_the_gate(ci_environment: Dict[str, str], tmp_path: Path) -> None:
    """Missed attacks above the baseline: the policy takes any alert as carrying approved benign evidence."""
    code, output, violations, metrics = run_gate("missed_attack", ci_environment, tmp_path)
    assert code == 1, output[-3000:]
    assert ("malicious_false_negative_rate", "regressed") in violations
    assert ("malicious_false_negative_rate", "above_max") in violations
    assert metrics["malicious_false_negatives"] >= 1 and metrics["missed_malicious_ids"]
    missed = metrics["missed_malicious_ids"][0]
    assert f"{missed}: waiting_human -> closed:benign" in output
    assert f"::error::Evaluation gate failed on {SET}" in output
