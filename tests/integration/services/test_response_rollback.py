"""Rollback against Postgres: request, approval rules, background execution, verification, lineage, races."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, Dict, Iterator, List
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.repos import Repositories, ResponseAction
from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.connectors.webhook import build_payload
from lg_sotf.services.response import ActionRequestError, ResponseService
from lg_sotf.services.review import ReviewService
from lg_sotf.services.rollback import RollbackService
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft._support import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft._support import FAKE_SPECS, script_isolation

pytestmark = pytest.mark.integration

ISO = {"defender.fake_isolation": {}}


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


async def user(repos: Repositories, role: str) -> UUID:
    return (await repos.users.create(TENANT_A, f"{role}-{uuid4().hex[:8]}@example.com", role)).id


async def audit_actions(repos: Repositories, resource_id: Any) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(resource_id), limit=100)
    return [e.action for e in reversed(page.items)]


async def isolated(env: MicrosoftEnv) -> ResponseAction:
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "succeeded"
    return await env.get(action)


async def test_rollback_end_to_end(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    original = await isolated(env)
    rollbacks = RollbackService(env.service)
    eligibility = await rollbacks.eligibility_of(TENANT_A, original)
    assert eligibility.available and eligibility.action_type == "release_host" and eligibility.until is not None
    admin = await user(env.repos, "admin")
    rollback, current, created = await rollbacks.request(TENANT_A, original.id, user=admin, role="admin", reason="false alarm")
    assert created and current.id == original.id
    assert (rollback.action_type, rollback.status, rollback.execution_owner) == ("release_host", "approved", "scheduler")
    assert rollback.connector == "microsoft" and rollback.integration_id == env.integration.id
    assert rollback.rollback_of == original.id and rollback.approved_by == f"user:{admin}"
    assert rollback.params["rollback"] == {"of": str(original.id), "reason": "false alarm", "requested_by": f"user:{admin}"}
    assert await audit_actions(env.repos, rollback.id) == ["response_action.proposed", "response_action.approved"]
    assert "response_action.rollback_requested" in await audit_actions(env.repos, original.id)

    assert await env.run_background() == 1
    done = await env.get(rollback)
    assert done.status == "succeeded" and done.verification == "verified" and done.verified_at is not None
    unisolate = [r for r in env.fake.writes() if r.url.path.endswith("/unisolate")]
    assert len(unisolate) == 1 and json.loads(unisolate[0].content)["Comment"] == f"LG-SOTF action {rollback.id}"
    assert "response_action.verified" in await audit_actions(env.repos, rollback.id)
    timeline = [e.event_type for e in (await env.repos.alert_events.list_for_alert(TENANT_A, original.alert_id)).items]
    assert "action.rollback_requested" in timeline and "action.verified" in timeline

    again, _, created_again = await rollbacks.request(TENANT_A, original.id, user=admin, role="admin", reason="again")
    assert again.id == rollback.id and created_again is False
    assert (await rollbacks.eligibility_of(TENANT_A, await env.get(original))).reason == "rollback_exists"
    with pytest.raises(ActionRequestError) as exc:
        await rollbacks.request(TENANT_A, rollback.id, user=admin, role="admin", reason="undo the undo")
    assert exc.value.code == "rollback_unavailable" and exc.value.reason == "is_rollback"


async def test_analyst_rollback_waits_for_an_admin(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    original = await isolated(env)
    await env.repos.integrations.create(
        TENANT_A, "webhook", "soar-hook", config={"url": "https://soar.example.com/hook"},
        events=["action.awaiting_approval"], min_severity="info",
    )
    analyst, admin = await user(env.repos, "analyst"), await user(env.repos, "admin")
    rollback, _, _ = await RollbackService(env.service).request(
        TENANT_A, original.id, user=analyst, role="analyst", reason="host is clean"
    )
    assert rollback.status == "awaiting_approval" and rollback.params["approval_reason"] == "admin_approval_required"
    async with env.repos.db.tenant_tx(TENANT_A) as conn:
        events = await conn.fetch("SELECT event_type, payload FROM notification_outbox WHERE tenant_id = $1", TENANT_A)
    assert [e["event_type"] for e in events] == ["action.awaiting_approval"]
    assert events[0]["payload"]["action"]["rollback_of"] == str(original.id)
    assert await env.run_background() == 0  # nothing runs before the approval
    review = ReviewService(env.repos, env.settings, responses=env.service)
    assert await review.approve_actions(TENANT_A, [rollback.id], admin, "admin") == []  # no workflow resume
    assert await env.run_background() == 1
    assert (await env.get(rollback)).status == "succeeded"


async def test_rollback_works_after_the_asset_became_protected(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    original = await isolated(env)
    settings = (await env.repos.tenants.get(TENANT_A)).settings
    await env.repos.tenants.update_settings(TENANT_A, {**settings, "protected_assets": {"hosts": ["ws-042"]}})
    admin = await user(env.repos, "admin")
    rollback, _, _ = await RollbackService(env.service).request(TENANT_A, original.id, user=admin, role="admin", reason="r")
    assert rollback.status == "approved"
    await env.run_background()
    assert (await env.get(rollback)).status == "succeeded"
    # The protection still stops new containment of that host.
    again = await env.propose("isolate_host", "ws-042.corp")
    assert await env.execute(again) == "blocked"


async def test_concurrent_requests_create_one_rollback(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    original = await isolated(env)
    admin = await user(env.repos, "admin")
    service = RollbackService(env.service)
    results = await asyncio.gather(
        *(service.request(TENANT_A, original.id, user=admin, role="admin", reason=f"r{i}") for i in range(4))
    )
    assert len({r[0].id for r in results}) == 1 and sum(1 for r in results if r[2]) == 1
    rows = (await env.repos.actions.list(TENANT_A, rollback_of=original.id)).items
    assert len(rows) == 1


async def test_rollback_of_a_rejected_rollback_uses_a_new_generation(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    original = await isolated(env)
    analyst, admin = await user(env.repos, "analyst"), await user(env.repos, "admin")
    first, _, _ = await RollbackService(env.service).request(TENANT_A, original.id, user=analyst, role="analyst", reason="a")
    review = ReviewService(env.repos, env.settings, responses=env.service)
    await review.reject_actions(TENANT_A, [first.id], admin, "admin")
    second, _, created = await RollbackService(env.service).request(TENANT_A, original.id, user=admin, role="admin", reason="b")
    assert created and second.id != first.id and second.idempotency_key != first.idempotency_key


async def test_ineligible_actions(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO, live=False)
    script_isolation(env.fake)
    rehearsed = await env.propose("isolate_host", "ws-042")
    assert await env.execute(rehearsed) == "dry_run"
    admin = await user(env.repos, "admin")
    with pytest.raises(ActionRequestError) as exc:
        await RollbackService(env.service).request(TENANT_A, rehearsed.id, user=admin, role="admin", reason="x")
    assert (exc.value.status, exc.value.code, exc.value.reason) == (409, "rollback_unavailable", "not_executed")


class Captured:
    name = "webhook"

    def __init__(self) -> None:
        self.payloads: List[Dict[str, Any]] = []

    async def execute(self, action: Any) -> ConnectorResult:
        self.payloads.append(build_payload(action, target_type="ip", sent_at=datetime.now(UTC)))
        return ConnectorResult("succeeded", {"connector": "webhook"})


async def test_webhook_rollback_carries_rollback_of(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({}, tenant_settings={"response": {"dry_run": False, "connector": "webhook"},
                                                   "autonomy": {"medium": "approval"}})
    receiver = Captured()
    service = ResponseService(env.repos, env.settings, connectors={"webhook": receiver}, microsoft=env.service.microsoft)
    env.service = service
    env.background = type(env.background)(service)
    original = await env.propose("block_ip", "185.220.101.44")
    assert await env.execute(original) == "succeeded"
    assert receiver.payloads[0]["rollback_of"] is None
    admin = await user(env.repos, "admin")
    rollback, _, _ = await RollbackService(service).request(TENANT_A, original.id, user=admin, role="admin", reason="fp")
    assert rollback.action_type == "unblock_ip" and rollback.connector == "webhook"
    await env.run_background()
    assert (await env.get(rollback)).status == "succeeded"
    payload = receiver.payloads[-1]
    assert payload["rollback_of"] == str(original.id) and payload["action"]["type"] == "unblock_ip"
    assert payload["action"]["params"]["rollback"]["of"] == str(original.id)
