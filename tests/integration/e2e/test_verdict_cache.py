"""Analyst-benign verdict cache: severity-bound (LLM-W6-02) and invalidated by later threats (LLM-W6-04)."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

import pytest

from tests.integration.db._support import TENANT_A
from tests.integration.e2e._support import analyst_decides, eventually, running

pytestmark = pytest.mark.integration

BASE: Dict[str, Any] = {
    "title": "Suspicious PowerShell execution",
    "entities": {"hosts": ["ws-042"], "users": ["jdoe"]},
    "occurred_at": "2026-09-01T10:00:00Z",
}


async def _status_is(repos: Any, alert_id: str, *statuses: str) -> bool:
    return (await repos.alerts.get(TENANT_A, alert_id)).status in statuses


async def _ingest_settled(stack: Any, source_alert_id: str, severity: str, extra: Optional[Dict[str, Any]] = None) -> str:
    result = await stack.ingest(TENANT_A, "api", [{**BASE, "source_alert_id": source_alert_id, "severity": severity, **(extra or {})}])
    await stack.dispatch(TENANT_A, result)
    alert_id = result.inserted[0].alert_id
    await eventually(lambda: stack.all_settled(TENANT_A, [alert_id]), within=60)
    return alert_id


async def test_benign_verdict_does_not_close_a_higher_severity_repeat(stack_factory: Any, repos: Any) -> None:
    stack = stack_factory()
    engine = await stack.engine()
    analyst = str((await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id)
    async with running(stack.worker(engine)):
        medium = await _ingest_settled(stack, "c1", "medium", {"command_lines": ["powershell -File C:\\it\\inventory.ps1"]})
        await analyst_decides(stack, TENANT_A, medium, "false_positive", analyst)
        await eventually(lambda: _status_is(repos, medium, "closed"), within=30)
        same = await _ingest_settled(stack, "c2", "medium")
        high = await _ingest_settled(
            stack, "c3", "high", {"command_lines": ["powershell -nop -w hidden -enc SQBFAFgA"]}
        )
    same_row, high_row = await repos.alerts.get(TENANT_A, same), await repos.alerts.get(TENANT_A, high)
    assert same_row.fingerprint == high_row.fingerprint
    assert same_row.summary.get("close_reason") == "verdict_cache"  # the cache still works at the decided severity
    assert high_row.summary.get("close_reason") != "verdict_cache"
    assert high_row.status != "closed" or high_row.disposition != "benign"


async def test_true_positive_decision_invalidates_the_cached_benign_verdict(stack_factory: Any, repos: Any) -> None:
    stack = stack_factory()
    engine = await stack.engine()
    analyst = str((await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id)
    async with running(stack.worker(engine)):
        first = await _ingest_settled(stack, "s1", "high")
        await analyst_decides(stack, TENANT_A, first, "false_positive", analyst)
        await eventually(lambda: _status_is(repos, first, "closed"), within=30)
        critical = await _ingest_settled(stack, "s2", "critical", {"description": "PowerShell run by jdoe"})
        await analyst_decides(stack, TENANT_A, critical, "true_positive", analyst)
        await eventually(lambda: _status_is(repos, critical, "waiting_approval", "closed"), within=30)
        repeat = await _ingest_settled(stack, "s3", "medium", {"description": "Invoke-Mimikatz again"})
    row = await repos.alerts.get(TENANT_A, repeat)
    assert row.summary.get("close_reason") != "verdict_cache", row.summary
