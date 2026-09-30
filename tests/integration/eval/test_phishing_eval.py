"""The phishing evaluation set through the real ingestion service and workflow engine (fake LLM)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.gate import evaluate_gate, load_thresholds
from lg_sotf.eval.report import build_report
from lg_sotf.eval.runner import EMAIL_EVAL_SOURCE, EvalRunner, apply_tenant_settings, run_evaluation
from lg_sotf.settings import Settings
from tests.integration.eval.conftest import EVAL_TENANT

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "phishing_v1.jsonl"
THRESHOLDS = FIXTURES / "phishing_smoke_thresholds.yaml"


async def test_phishing_smoke_evaluation_passes_its_gate(eval_runner: EvalRunner, repos: Repositories) -> None:
    dataset = load_dataset(DATASET)
    await apply_tenant_settings(repos, EVAL_TENANT, dataset.tenant_settings)
    results = await eval_runner.run(dataset.items)
    report = build_report(results, dataset=dataset, run_info={"llm_provider": "fake"})
    gate = evaluate_gate(report, load_thresholds(THRESHOLDS))
    metrics = report["metrics"]
    assert gate.passed, ([v.message for v in gate.violations], metrics)
    assert metrics["errors"] == 0 and metrics["malicious_false_negative_rate"] == 0.0
    assert report["splits"]["adversarial"]["metrics"]["malicious_false_negative_rate"] == 0.0
    by_id: Dict[str, Any] = {r.item_id: r for r in results}

    # A fully authenticated internal notice closes as benign on rules plus the model.
    closed = by_id["phish-019"]
    assert (closed.status, closed.disposition) == ("closed", "benign")
    # Injection in the body and forged authentication never close.
    for item_id in ("phish-033", "phish-034", "phish-035", "phish-036", "phish-037"):
        assert by_id[item_id].disposition != "benign", item_id

    alert = await repos.alerts.get(EVAL_TENANT, by_id["phish-001"].alert_id)
    assert alert.source_id == EMAIL_EVAL_SOURCE and alert.category == "phishing"
    assert alert.normalized["email"]["reporter"] == "alice@example.com"
    assert "email_lookalike_domain" in alert.summary["triage"]["rule_tp"]
    assert alert.summary["triage"]["phishing"]["lookalike_hosts"] == ["examp1e.test"]


async def test_run_evaluation_applies_the_dataset_tenant_settings(eval_settings: Settings, repos: Repositories) -> None:
    dataset = load_dataset(DATASET).select(limit=2)
    run = await run_evaluation(eval_settings, dataset, tenant_id="eval-phish-1", isolate="none")
    assert all(r.status != "error" for r in run.results), [r.error for r in run.results]
    tenant = await repos.tenants.get("eval-phish-1")
    assert tenant.settings["tools"]["internal_domains"] == ["example.com"]
    assert tenant.settings["phishing"]["executives"] == ["Jane Doe", "John Smith"]
