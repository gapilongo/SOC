"""Defender for Endpoint flows against the real ledger: isolate and verify, roll back, block inline, kill switches."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, List
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.services.rollback import RollbackService
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft._support import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft.defender._support import FakeDefender

pytestmark = pytest.mark.integration

ISOLATION = {"defender.isolation": {}}
IP = "185.220.101.44"


async def audit_actions(repos: Repositories, resource_id: Any) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(resource_id), limit=100)
    return [e.action for e in reversed(page.items)]


async def admin(repos: Repositories) -> UUID:
    return (await repos.users.create(TENANT_A, f"admin-{uuid4().hex[:8]}@example.com", "admin")).id


async def verify_until(env: MicrosoftEnv, action: Any) -> Any:
    await env.make_verifications_due()
    await env.run_verify()
    return await env.get(action)


async def isolated(env: MicrosoftEnv, defender: FakeDefender) -> Any:
    await env.alert(title="Ransomware beacon on ws-042")
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "succeeded"
    return await env.get(action)


async def test_isolate_then_background_verification(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISOLATION)
    defender = FakeDefender(env.fake)
    mid = defender.machine("ws-042.corp.contoso.example")
    row = await isolated(env, defender)
    assert row.connector == "microsoft" and row.integration_id == env.integration.id
    assert row.result is not None and row.result["capability"] == "defender.isolation"
    assert row.result["changed"] is True and row.result["live"] is True
    ref = row.external_ref or {}
    assert ref["machine_id"] == mid and ref["reversible"] is True and ref["capability"] == "defender.isolation"
    (post,) = defender.posts("/isolate")
    assert json.loads(post.content) == {"Comment": f"LG-SOTF action {row.id}: Ransomware beacon on ws-042",
                                        "IsolationType": "Full"}
    assert row.verification == "pending" and row.verify_deadline is not None
    assert row.verify_deadline - (row.executed_at or datetime.now(UTC)) <= timedelta(hours=76, seconds=5)

    still = await verify_until(env, row)
    assert still.verification == "pending" and still.verify_attempts == 1
    defender.set_status(ref["machine_action_id"], "Succeeded")
    done = await verify_until(env, row)
    assert done.verification == "verified" and done.verified_at is not None
    assert done.verification_detail is not None and done.verification_detail["status"] == "Succeeded"
    assert "response_action.verified" in await audit_actions(env.repos, row.id)
    assert [r.method for r in env.fake.api_requests() if "/machineactions/" in r.url.path] == ["GET", "GET"]


async def test_rollback_releases_the_device_and_verifies(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISOLATION)
    defender = FakeDefender(env.fake)
    defender.machine("ws-042")
    original = await isolated(env, defender)
    defender.set_status((original.external_ref or {})["machine_action_id"], "Succeeded")
    user = await admin(env.repos)
    rollbacks = RollbackService(env.service)
    eligibility = await rollbacks.eligibility_of(TENANT_A, original)
    assert eligibility.available and eligibility.action_type == "release_host" and eligibility.until is not None

    rollback, _, created = await rollbacks.request(TENANT_A, original.id, user=user, role="admin", reason="clean host")
    assert created and rollback.status == "approved" and rollback.execution_owner == "scheduler"
    assert await env.run_background() == 1
    released = await env.get(rollback)
    assert released.status == "succeeded" and released.result is not None and released.result["mode"] == "unisolate"
    (post,) = defender.posts("/unisolate")
    assert json.loads(post.content) == {"Comment": f"LG-SOTF action {rollback.id}: rollback"}
    assert released.verification == "pending"
    defender.set_status((released.external_ref or {})["machine_action_id"], "Succeeded")
    done = await verify_until(env, released)
    assert done.verification == "verified"
    assert "response_action.verified" in await audit_actions(env.repos, rollback.id)
    assert (await rollbacks.eligibility_of(TENANT_A, await env.get(original))).reason == "rollback_exists"


async def test_block_ip_is_verified_inline(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"defender.indicators": {"options": {"expiration_days": 14}}})
    defender = FakeDefender(env.fake)
    action = await env.propose("block_ip", IP)
    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert row.verification == "verified" and row.verified_at is not None
    assert row.verification_detail == {
        "enforcement": "configured; takes effect in up to 48 h",
        "indicator_id": (row.external_ref or {})["indicator_id"],
        "action": "Block",
    }
    (post,) = defender.writes()
    body = json.loads(post.content)
    assert (body["indicatorType"], body["action"], body["indicatorValue"]) == ("IpAddress", "Block", IP)
    assert body["description"] == f"LG-SOTF action {row.id}; alert {row.alert_id}"
    until = datetime.fromisoformat((row.external_ref or {})["rollback_until"])
    assert timedelta(days=13, hours=23) < until - datetime.now(UTC) <= timedelta(days=14)
    assert "response_action.verified" in await audit_actions(env.repos, row.id)
    eligibility = await RollbackService(env.service).eligibility_of(TENANT_A, row)
    assert eligibility.available and eligibility.action_type == "unblock_ip"


@pytest.mark.parametrize(
    "switch",
    [{"settings": {"response": {"dry_run": True}}},
     {"tenant_settings": {"response": {"dry_run": True}, "autonomy": {"high": "approval"}}}],
    ids=["install", "tenant"],
)
async def test_kill_switch_forces_dry_run_without_any_defender_request(
    microsoft_env: MicrosoftEnvFactory, switch: Any
) -> None:
    env = await microsoft_env(ISOLATION, **switch)
    defender = FakeDefender(env.fake)
    defender.machine("ws-042")
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "dry_run"
    row = await env.get(action)
    assert row.connector == "dry_run" and row.verification is None
    assert env.fake.requests == []
