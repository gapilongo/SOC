"""corpus_skills_v1 (AI-E1.10) through the real pipeline with the fake model: every item runs, nothing malicious closes.

The dataset has no gate of its own yet: the per-skill scorecards and their
thresholds are AI-E3.8b, once the skills exist. This test keeps the dataset
usable until then: all 196 alerts ingest as Wazuh alerts and reach a decision
offline, the report is cut per skill family, and automation closes no attack
at the tier ``auto_full_audit`` (model-led closure on, the riskier setting).
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.report import build_report
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.settings import Settings
from tests.integration.eval._support import NetworkGuard, at_tier, closures, v3_closures

pytestmark = [pytest.mark.integration, pytest.mark.timeout(900)]

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_skills_v1.jsonl.gz"
FAMILIES = {"windows.logon_failure", "windows.service_install"}


async def test_corpus_skills_v1_runs_offline_and_closes_no_attack(
    eval_settings: Settings, monkeypatch: pytest.MonkeyPatch, repos: Repositories
) -> None:
    dataset = load_dataset(DATASET)
    assert set(dataset.families()) == FAMILIES and dataset.tenant_context is not None
    net = NetworkGuard(eval_settings)
    net.install(monkeypatch)
    run = await run_evaluation(eval_settings, at_tier(dataset, "auto_full_audit"),
                               tenant_id=f"play-csk1-{secrets.token_hex(3)}")
    assert [(r.item_id, r.error) for r in run.results if r.status == "error"] == [] and net.attempts == []
    report = build_report(run.results, dataset=dataset, run_info=run.info)
    metrics = report["metrics"]
    assert metrics["scored"] == len(dataset.items) == 196 and metrics["errors"] == 0
    assert set(report["families"]) == FAMILIES
    for family in FAMILIES:
        assert report["families"][family]["metrics"]["malicious_auto_closed"] == 0, family
    assert closures(run.results)["malicious_closed"] == 0
    counts = await v3_closures(repos, run)
    assert counts["malicious_still_closed"] == [] and counts["forbidden"] == [], counts
