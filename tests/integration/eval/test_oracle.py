"""The analyst oracle against the real database, Redis, ingestion and workflow engine (fake LLM).

A repeated benign pattern: the first two alerts are escalated, the oracle
decides each ``false_positive`` through ``ReviewService.decide`` and the runs
resume, so the close node writes two analyst decisions to the verdict cache;
the repeat (same detection, entities and behaviour, later in event time) then
closes at the gate on the cache. A malicious alert with the same fingerprint
but another command line is not the same verdict key: the cache leaves it to
the workflow, and the oracle decides it ``true_positive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.closure import closure_summary
from lg_sotf.eval.dataset import EvalItem, parse_dataset
from lg_sotf.eval.oracle import ORACLE_EMAIL, AnalystOracle
from lg_sotf.eval.runner import EvalRunner
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.eval._support import EVAL_TENANT

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def _item(item_id: str, at: str, disposition: str, command: str = "report.exe --nightly") -> Dict[str, Any]:
    return {
        "id": item_id,
        "source_type": "canonical",
        "alert": {
            "source_alert_id": f"src-{item_id}",
            "title": "Unusual sign-in pattern for a service account",
            "rule_name": "identity-unusual-signin",
            "severity": "medium",
            "occurred_at": at,
            "description": "A sign-in from a host this account rarely uses.",
            "entities": {"hosts": ["srv-app-7"], "users": ["svc_report"], "command_lines": [command]},
        },
        "expected": {"disposition": disposition},
    }


def _items(*rows: Dict[str, Any]) -> List[EvalItem]:
    return parse_dataset("\n".join(json.dumps(r) for r in rows)).items


def _oracle(runner: EvalRunner, repos: Repositories, settings: Settings, accept: bool = False) -> AnalystOracle:
    return AnalystOracle(repos, runner.engine, ReviewService(repos, settings), accept_suppressions=accept)


async def test_the_oracle_decides_through_the_real_path_and_the_cache_closes_the_repeat(
    eval_runner: EvalRunner, repos: Repositories, eval_settings: Settings
) -> None:
    eval_runner.oracle = _oracle(eval_runner, repos, eval_settings)
    # Dataset order puts the repeat first: the oracle runs in event-time order.
    items = _items(
        _item("repeat", "2026-10-20T09:00:00Z", "benign"),
        _item("first", "2026-10-20T08:00:00Z", "benign"),
        _item("second", "2026-10-20T08:30:00Z", "benign"),
        _item("attack", "2026-10-20T10:00:00Z", "malicious", command="report.exe -enc SQBFAFgA"),
    )
    order: List[str] = []
    results = {r.item_id: r for r in await eval_runner.run(items, progress=lambda d, t, r: order.append(r.item_id))}
    assert order == ["first", "second", "repeat", "attack"]
    assert all(r.error is None for r in results.values()), [r.error for r in results.values()]

    first = results["first"]
    assert first.status == "waiting_human" and first.escalated, "automation's own outcome is kept"
    assert first.review == "oracle" and first.oracle_decisions == ["false_positive"]
    assert first.final_status == "closed"
    assert first.alert_id is not None
    escalation_id = await repos.escalations.latest_id_for_alert(EVAL_TENANT, first.alert_id)
    assert escalation_id is not None
    decided = await repos.escalations.get(EVAL_TENANT, escalation_id)
    oracle_user = await repos.users.get_by_email(EVAL_TENANT, ORACLE_EMAIL)
    assert decided.decision == "false_positive" and decided.status == "decided"
    assert oracle_user is not None and decided.decided_by == oracle_user.id
    alert = await repos.alerts.get(EVAL_TENANT, first.alert_id)
    assert alert.status == "closed" and (alert.summary or {}).get("close_reason") == "analyst:false_positive"
    # Each false positive suggested a suppression rule, disabled until an admin enables it.
    rules = await repos.suppressions.list(EVAL_TENANT)
    assert len(rules) == 2 and not any(r.enabled for r in rules)

    repeat = results["repeat"]
    assert (repeat.status, repeat.close_reason, repeat.close_mechanism) == ("closed", "verdict_cache", "cache")
    assert repeat.oracle_decisions == [] and repeat.llm_calls == 0

    # One analyst decision is not enough for the cache: the second alert went to the oracle too.
    assert results["second"].oracle_decisions == ["false_positive"] and results["second"].final_status == "closed"

    # Same fingerprint, another command line: the cache does not close the attack.
    attack = results["attack"]
    assert attack.close_mechanism != "cache" and attack.oracle_decisions[:1] == ["true_positive"]
    summary = closure_summary(list(results.values()))
    assert summary["headline"]["benign_closure"]["k"] == 1 and summary["headline"]["benign_closure"]["n"] == 3
    assert summary["headline"]["malicious_auto_close"]["k"] == 0 and summary["malicious_closed"] == []
    cache = next(row for row in summary["by_mechanism"] if row["mechanism"] == "cache")
    assert cache["benign"]["k"] == 1 and cache["malicious"] == 0


async def test_accepted_suppressions_close_the_repeat_and_a_true_positive_clears_the_cache(
    eval_runner: EvalRunner, repos: Repositories, eval_settings: Settings
) -> None:
    eval_runner.oracle = _oracle(eval_runner, repos, eval_settings, accept=True)
    first = _item("first", "2026-10-21T08:00:00Z", "benign")
    other = _item("other", "2026-10-21T08:30:00Z", "malicious")
    other["alert"]["entities"] = {"hosts": ["srv-app-8"], "users": ["svc_report"]}
    results = {r.item_id: r for r in await eval_runner.run(_items(first, other, {
        **_item("repeat", "2026-10-21T09:00:00Z", "benign")}))}
    assert results["first"].oracle_decisions == ["false_positive"]
    assert eval_runner.oracle.suppressions_enabled == 1
    rules = await repos.suppressions.list(EVAL_TENANT)
    assert len(rules) == 1 and rules[0].enabled is True
    repeat = results["repeat"]
    assert (repeat.status, repeat.close_mechanism) == ("closed", "suppression")
    # The malicious alert on another host was escalated and decided true_positive, never closed by automation.
    malicious = results["other"]
    assert malicious.status != "closed" and malicious.oracle_decisions[0] == "true_positive"
    assert malicious.final_status in ("closed", "waiting_approval", "waiting_human")
