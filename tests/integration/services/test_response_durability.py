"""Ledger durability: transitions and audit entries are atomic (M2); caps use the database clock (L2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, List

import asyncpg
import httpx
import pytest

import lg_sotf.services.response.execution as execution_module
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.services.connectors import WebhookConnector, WebhookTarget
from lg_sotf.services.response import ResponseService
from tests.integration.db._support import TENANT_A
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration


async def test_a_failed_audit_append_rolls_the_transition_back(repos: Any, make_settings: Any) -> None:
    alert_id = await add_alert(repos, TENANT_A)
    action, _ = await repos.actions.propose(TENANT_A, alert_id, "create_ticket", f"alert:{alert_id}", "low", status="approved")
    service = ResponseService(repos, make_settings(), None)
    real_append = repos.audit.append
    failed: List[str] = []

    async def flaky_append(tenant_id: str, actor_type: str, actor_id: Any, name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "response_action.dry_run" and not failed:
            failed.append(name)
            raise asyncpg.exceptions.ConnectionDoesNotExistError("connection was closed in the middle of operation")
        return await real_append(tenant_id, actor_type, actor_id, name, *args, **kwargs)

    repos.audit.append = flaky_append
    with pytest.raises(asyncpg.exceptions.ConnectionDoesNotExistError):
        await service.execute(TENANT_A, alert_id, [str(action.id)])
    assert (await repos.actions.get(TENANT_A, action.id)).status == "executing"  # the dry_run write rolled back
    assert await service.execute(TENANT_A, alert_id, [str(action.id)]) == {str(action.id): "dry_run"}
    entries = await repos.audit.list(TENANT_A, resource_type="response_action", resource_id=str(action.id), limit=50)
    actions = [e.action for e in entries.items]
    assert "response_action.executing" in actions and "response_action.dry_run" in actions


class _FastClock(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> _FastClock:  # type: ignore[override]
        return datetime.now(tz) + timedelta(minutes=6)  # type: ignore[return-value]


async def _resolve(host: str, port: int) -> List[str]:
    return ["93.184.216.34"]


async def test_hourly_cap_window_uses_the_database_clock(
    repos: Any, db: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(response={"dry_run": False})
    await repos.tenants.update_settings(TENANT_A, {"response": {"connector": "webhook", "max_actions_per_hour": 2}})
    sent: List[int] = []
    hook = WebhookConnector(
        WebhookTarget(url="https://soar.example.com/h", secret=b"x" * 32),
        policy=DestinationPolicy(require_https=True),
        target_kinds={"create_ticket": "alert"},
        transport=httpx.MockTransport(lambda r: sent.append(1) or httpx.Response(200, json={"status": "succeeded"})),
        resolver=_resolve,
    )
    service = ResponseService(repos, settings, None, connectors={"webhook": hook})
    ids = []
    for _ in range(3):
        alert_id = await add_alert(repos, TENANT_A)
        action, _ = await repos.actions.propose(TENANT_A, alert_id, "create_ticket", f"alert:{alert_id}", "low", status="approved")
        ids.append((alert_id, action.id))
    for alert_id, action_id in ids[:2]:
        await service.execute(TENANT_A, alert_id, [str(action_id)])
    async with db.system_tx() as conn:  # both ran 55 minutes ago on the database clock
        await conn.execute("UPDATE response_actions SET executed_at = now() - interval '55 minutes' WHERE status = 'succeeded'")
    monkeypatch.setattr(execution_module, "datetime", _FastClock)  # the worker's clock runs 6 minutes fast
    alert_id, action_id = ids[2]
    await service.execute(TENANT_A, alert_id, [str(action_id)])
    third = await repos.actions.get(TENANT_A, action_id)
    assert (third.status, third.blocked_reason) == ("blocked", "hourly_cap_reached")
    assert len(sent) == 2
    assert datetime.now(UTC)  # (module datetime restored by monkeypatch)
