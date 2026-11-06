"""The evaluation runner against real PostgreSQL, Redis, ingestion and workflow engine (fake LLM)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pydantic import SecretStr

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset, parse_dataset
from lg_sotf.eval.gate import evaluate_gate, load_thresholds
from lg_sotf.eval.report import build_report, render_markdown
from lg_sotf.eval.runner import EvalRunner, EvalSetupError, run_evaluation
from lg_sotf.settings import Settings
from tests.integration.eval._support import EVAL_TENANT

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "synthetic_v1.jsonl"
SMOKE_THRESHOLDS = FIXTURES / "smoke_thresholds.yaml"
SUBSET = ("syn-001", "syn-031", "syn-015", "syn-007", "syn-009", "syn-011", "syn-013", "adv-003")
# Enough threat evidence for the fake model that the policy plans a response and waits for approval.
RESPONSE_ITEM = {
    "id": "it-response",
    "source_type": "canonical",
    "alert": {
        "source_alert_id": "it-response-1",
        "title": "Ransomware with mimikatz credential dumping and cobalt strike beacon",
        "severity": "critical",
        "description": "Lateral movement via psexec, lsass credential dump, exfiltration to 203.0.113.9 and a ransom note.",
        "entities": {"hosts": ["fs-09"], "ips": ["203.0.113.9"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"]},
    },
    "expected": {"disposition": "malicious", "escalation": True},
}


def by_id(results: List[Any]) -> Dict[str, Any]:
    return {r.item_id: r for r in results}


async def test_subset_runs_through_every_source_format_without_inventing_decisions(
    eval_runner: EvalRunner, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    resumes: List[Any] = []

    async def no_resume(*args: Any, **kwargs: Any) -> Any:
        resumes.append(args)
        raise AssertionError("the evaluation must never resume a run")

    monkeypatch.setattr(eval_runner.engine, "resume", no_resume)
    dataset = load_dataset(DATASET)
    items = [i for i in dataset.items if i.id in SUBSET]
    items.append(parse_dataset(json.dumps(RESPONSE_ITEM)).items[0])
    progress: List[str] = []
    results = await eval_runner.run(items, progress=lambda done, total, r: progress.append(f"{done}/{total}"))
    assert progress[-1] == f"{len(SUBSET) + 1}/{len(SUBSET) + 1}"
    got = by_id(results)
    assert set(got) == {*SUBSET, "it-response"}
    assert all(r.status != "error" for r in results), [(r.item_id, r.error) for r in results]
    assert resumes == []

    # Obvious operational noise closes automatically.
    closed = got["syn-031"]
    assert (closed.status, closed.disposition, closed.predicted, closed.route) == ("closed", "benign", "benign", "close")
    assert closed.review is None and not closed.escalated
    alert = await repos.alerts.get(EVAL_TENANT, closed.alert_id)
    assert alert.status == "closed" and alert.disposition == "benign"

    # A critical credential-dumping detection waits for an analyst; the harness records it unreviewed.
    escalated = got["syn-001"]
    assert escalated.status == "waiting_human" and escalated.escalated and escalated.review == "unreviewed"
    assert escalated.severity == "critical" and escalated.route == "escalate"
    assert escalated.llm_calls > 0 and escalated.total_tokens > 0 and escalated.latency_s > 0
    esc = await repos.escalations.get_active_for_alert(EVAL_TENANT, escalated.alert_id)
    assert esc is not None and esc.status == "open" and esc.decision is None and esc.decided_by is None
    alert = await repos.alerts.get(EVAL_TENANT, escalated.alert_id)
    assert alert.status == "waiting_human" and alert.disposition is None
    events = (await repos.alert_events.list_for_alert(EVAL_TENANT, escalated.alert_id)).items
    marker = [e for e in events if e.event_type == "eval.review_not_performed"]
    assert len(marker) == 1 and marker[0].data["waiting_for"] == "waiting_human"
    assert marker[0].data["item_id"] == "syn-001"

    # A policy-chosen response waits for approval; nothing is approved or executed.
    approval = got["it-response"]
    assert approval.status == "waiting_approval" and approval.approval_requested and approval.review == "unreviewed"
    assert approval.predicted == "malicious" and approval.route == "plan_response"
    ledger = (await repos.actions.list(EVAL_TENANT, alert_id=approval.alert_id, limit=50)).items
    assert ledger and all(a.status in ("awaiting_approval", "blocked") for a in ledger)
    assert all(a.approved_by is None for a in ledger)

    # Vendor items went through push sources of their own format.
    sources = {s.id: s for s in (await repos.sources.list(EVAL_TENANT))}
    formats = {s.config.get("format") for s in sources.values()}
    assert {"crowdstrike", "sentinel", "wazuh", "guardduty", "qradar", "splunk", "generic"} <= formats
    assert all(s.type == "webhook" for s in sources.values())

    # The prompt-injection item is not closed.
    injected = got["adv-003"]
    assert injected.status in ("waiting_human", "waiting_approval")


async def test_rejected_and_duplicate_events_are_errors_not_crashes(eval_runner: EvalRunner) -> None:
    dataset = parse_dataset(
        '{"id": "bad", "source_type": "canonical", "alert": {"severity": "low"}, "expected": {"disposition": "benign"}}\n'
        '{"id": "ok", "source_type": "canonical", "alert": {"source_alert_id": "d-1", "title": "Scheduled backup test",'
        ' "severity": "low"}, "expected": {"disposition": "benign"}}\n'
        '{"id": "dup", "source_type": "canonical", "alert": {"source_alert_id": "d-1", "title": "Scheduled backup test",'
        ' "severity": "low"}, "expected": {"disposition": "benign"}}\n'
    )
    results = by_id(await eval_runner.run(dataset.items))
    assert results["bad"].status == "error" and results["bad"].error.startswith("ingest rejected")
    assert results["ok"].status == "closed"
    assert results["dup"].status == "error" and results["dup"].error.startswith("ingest duplicate")


async def test_smoke_evaluation_of_the_synthetic_dataset_passes_the_ci_gate(eval_runner: EvalRunner) -> None:
    """The CI smoke eval: all synthetic items, fake LLM, smoke thresholds (plumbing and safety, not quality)."""
    dataset = load_dataset(DATASET)
    results = await eval_runner.run(dataset.items)
    report = build_report(results, dataset=dataset, run_info={"llm_provider": "fake"})
    gate = evaluate_gate(report, load_thresholds(SMOKE_THRESHOLDS))
    assert gate.passed, [v.message for v in gate.violations]
    metrics = report["metrics"]
    assert metrics["items"] == len(dataset.items) and metrics["errors"] == 0
    assert metrics["malicious_false_negative_rate"] == 0.0
    assert metrics["high_severity_auto_closed_benign"] == 0
    assert report["splits"]["adversarial"]["metrics"]["auto_close_rate"] == 0.0
    assert any("fake LLM" in note for note in report["notes"])
    assert "## Headline metrics" in render_markdown(report, gate.as_dict())


async def test_run_evaluation_owns_its_resources_and_a_fresh_tenant(
    eval_settings: Settings, repos: Repositories
) -> None:
    dataset = load_dataset(DATASET).select(limit=3)
    run = await run_evaluation(eval_settings, dataset, tenant_id="eval-owned-1", isolate="none")
    assert [r.item_id for r in run.results] == [i.id for i in dataset.items]
    assert all(r.status != "error" for r in run.results)
    assert run.info["tenant_id"] == "eval-owned-1" and run.info["llm_provider"] == "fake"
    assert run.info["isolation"] == "none" and run.info["fast_model"] == "fake"
    tenant = await repos.tenants.get("eval-owned-1")
    assert tenant.name == "Evaluation eval-owned-1"
    page = await repos.alerts.list("eval-owned-1", limit=10)
    assert len(page.items) == 3
    with pytest.raises(EvalSetupError, match="already exists"):
        await run_evaluation(eval_settings, dataset, tenant_id="eval-owned-1", isolate="none")


async def test_each_split_runs_in_its_own_tenant_and_matches_a_split_only_run(
    eval_settings: Settings, repos: Repositories
) -> None:
    """Split metrics are independent: the adversarial split alone gives the same outcomes as inside a full run."""
    full = load_dataset(DATASET)
    run = await run_evaluation(eval_settings, full, tenant_id="eval-iso-full")
    assert [r.item_id for r in run.results] == [i.id for i in full.items]  # dataset order is kept
    assert run.info["isolation"] == "splits"
    assert run.info["tenants"] == {"standard": "eval-iso-full-0-standard", "adversarial": "eval-iso-full-1-adversarial"}
    adversarial_ids = {i.id for i in full.items if i.split == "adversarial"}
    page = await repos.alerts.list("eval-iso-full-1-adversarial", limit=100)
    assert len(page.items) == len(adversarial_ids)

    alone = await run_evaluation(eval_settings, full.select(splits=["adversarial"]), tenant_id="eval-iso-adv")
    assert run.info["tenants"]["adversarial"] != alone.info["tenants"]["adversarial"]

    def outcome(r: Any) -> Any:
        return (r.status, r.predicted, r.route, r.decision_code, r.disposition)

    in_full = {r.item_id: outcome(r) for r in run.results if r.item_id in adversarial_ids}
    by_itself = {r.item_id: outcome(r) for r in alone.results}
    assert in_full == by_itself


async def test_unreachable_redis_is_a_setup_error_and_creates_no_tenant(
    eval_settings: Settings, repos: Repositories
) -> None:
    from lg_sotf.db.errors import NotFound

    down = eval_settings.model_copy(
        update={"redis": eval_settings.redis.model_copy(update={"url": SecretStr("redis://127.0.0.1:6999/7")})}
    )
    with pytest.raises(EvalSetupError, match="redis unavailable"):
        await run_evaluation(down, load_dataset(DATASET).select(limit=1), tenant_id="eval-no-redis", isolate="none")
    with pytest.raises(NotFound):
        await repos.tenants.get("eval-no-redis")


async def test_a_completed_policy_response_closes_a_critical_alert_as_malicious_not_benign(
    eval_settings: Settings, repos: Repositories
) -> None:
    """Autonomy ``auto`` for low risk lets non-containment actions run; the critical alert then closes as malicious.

    That is correct behaviour and must not trip the safety metric, which counts high/critical alerts closed as
    anything but malicious.
    """
    auto_low = eval_settings.model_copy(
        update={
            "response": eval_settings.response.model_copy(
                update={"default_autonomy": {"low": "auto", "medium": "approval", "high": "approval",
                                             "critical": "disabled"}}
            )
        }
    )
    item = {
        "id": "crit-no-entities",
        "source_type": "canonical",
        "alert": {
            "source_alert_id": "crit-no-entities-1",
            "title": "Ransomware with mimikatz credential dumping and cobalt strike beacon",
            "severity": "critical",
            "description": "lsass credential dump, lateral movement via psexec, exfiltration and a ransom note.",
        },
        "expected": {"disposition": "malicious"},
    }
    dataset = parse_dataset(json.dumps(item))
    run = await run_evaluation(auto_low, dataset, tenant_id="eval-auto-low", isolate="none")
    [r] = run.results
    assert (r.status, r.disposition, r.route, r.severity) == ("closed", "malicious", "plan_response", "critical")
    metrics = build_report(run.results, dataset=dataset, run_info=run.info)["metrics"]
    assert metrics["high_severity_auto_closed_malicious"] == 1
    assert metrics["high_severity_auto_closed_benign"] == 0
    gate = evaluate_gate({"metrics": metrics, "splits": {}}, load_thresholds(SMOKE_THRESHOLDS))
    assert "high_severity_auto_closed_benign" not in {v.metric for v in gate.violations}
