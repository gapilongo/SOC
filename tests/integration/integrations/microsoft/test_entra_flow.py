"""Entra ID direct response against Postgres: approval, execution, verification, rollback, refusals, secret hygiene."""

from __future__ import annotations

import json
import logging
from typing import Any, List
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.services.review import ReviewService
from lg_sotf.services.rollback import RollbackService
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft.conftest import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft.entra._support import Directory

pytestmark = pytest.mark.integration

UPN = "alice@contoso.example"


async def user(repos: Repositories, role: str) -> UUID:
    return (await repos.users.create(TENANT_A, f"{role}-{uuid4().hex[:8]}@example.com", role)).id


async def audit_actions(repos: Repositories, resource_id: Any) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(resource_id), limit=100)
    return [e.action for e in reversed(page.items)]


async def subscribe(env: MicrosoftEnv) -> None:
    await env.repos.integrations.create(
        TENANT_A, "webhook", "soar-hook", config={"url": "https://soar.example.com/hook"},
        events=["action.awaiting_approval", "action.executed", "action.failed", "action.verification_failed"],
        min_severity="info",
    )


async def test_disable_approved_by_an_admin_is_executed_verified_and_rolled_back(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env({"entra.account": {}})
    directory = Directory(env.fake)
    alice = directory.add(UPN)
    action = await env.propose("disable_user", UPN, status="awaiting_approval")
    admin = await user(env.repos, "admin")
    review = ReviewService(env.repos, env.settings, responses=env.service)
    assert len(await review.approve_actions(TENANT_A, [action.id], admin, "admin")) == 1  # the run resumes it
    assert await env.execute(action) == "succeeded"

    done = await env.get(action)
    assert done.connector == "microsoft" and done.integration_id == env.integration.id and done.attempts == 1
    assert done.verification == "verified" and done.verified_at is not None
    assert done.result is not None and done.result["capability"] == "entra.account" and done.result["changed"] is True
    assert done.external_ref is not None and done.external_ref["reversible"] is True
    assert done.external_ref["user_id"] == alice.id and done.external_ref["capability"] == "entra.account"
    assert alice.enabled is False and directory.patches() == [{"accountEnabled": False}]
    trail = await audit_actions(env.repos, action.id)
    assert trail[-4:] == ["response_action.approved", "response_action.executing", "response_action.succeeded",
                          "response_action.verified"]

    rollbacks = RollbackService(env.service)
    eligibility = await rollbacks.eligibility_of(TENANT_A, done)
    assert eligibility.available and eligibility.action_type == "enable_user" and eligibility.risk == "critical"
    rollback, _, created = await rollbacks.request(TENANT_A, action.id, user=admin, role="admin", reason="false positive")
    assert created and rollback.status == "approved" and rollback.execution_owner == "scheduler"
    assert await env.run_background() == 1
    undone = await env.get(rollback)
    assert undone.status == "succeeded" and undone.verification == "verified"
    assert undone.result is not None and undone.result["changed"] is True
    assert alice.enabled is True and directory.patches() == [{"accountEnabled": False}, {"accountEnabled": True}]
    enable_reads = [r for r in env.fake.api_requests() if r.method == "GET" and r.url.path == f"/v1.0/users/{alice.id}"]
    assert enable_reads  # the rollback addressed the recorded object id
    assert (await rollbacks.eligibility_of(TENANT_A, await env.get(action))).reason == "rollback_exists"
    timeline = [e.event_type for e in (await env.repos.alert_events.list_for_alert(TENANT_A, action.alert_id)).items]
    assert "action.rollback_requested" in timeline and timeline.count("action.verified") == 2


async def test_a_synced_user_stays_pending_and_fails_when_sync_reverts(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"entra.account": {}})
    await subscribe(env)
    alice = Directory(env.fake).add(UPN, synced=True)
    action = await env.propose("disable_user", UPN)
    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert row.verification == "pending" and row.verify_deadline is not None and row.verify_after is not None
    assert (row.verify_after - row.executed_at).total_seconds() >= 2_300  # first check after about 40 minutes
    alice.enabled = True  # Entra Connect re-enabled it
    await env.make_verifications_due()
    assert await env.run_verify() == 1
    row = await env.get(action)
    assert row.verification == "failed" and row.verification_detail is not None
    assert row.verification_detail["reason"] == "reverted_by_sync"
    async with env.repos.db.tenant_tx(TENANT_A) as conn:
        events = [r["event_type"] for r in await conn.fetch("SELECT event_type FROM notification_outbox")]
    assert "action.verification_failed" in events


async def test_a_privileged_user_is_refused_without_a_write(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"entra.account": {}, "entra.sessions": {}})
    Directory(env.fake).add(UPN, member_of=[{"@odata.type": "#microsoft.graph.group", "id": "g",
                                              "isAssignableToRole": True}])
    for action_type in ("disable_user", "revoke_sessions"):
        action = await env.propose(action_type, UPN)
        assert await env.execute(action) == "failed"
        row = await env.get(action)
        assert row.result is not None and row.result["error"] == "privileged_target_refused"
        assert row.result["reason"] == "role_assignable_group" and row.result["retryable"] is False
        assert row.verification is None and "response_action.failed" in await audit_actions(env.repos, action.id)
    assert env.fake.writes() == []


async def test_reset_password_leaves_no_password_anywhere(
    microsoft_env: MicrosoftEnvFactory, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    env = await microsoft_env({"entra.password": {"options": {"require_mfa_on_change": True}}})
    await subscribe(env)
    directory = Directory(env.fake)
    directory.add(UPN)
    action = await env.propose("reset_password", UPN)
    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert row.verification == "verified" and row.external_ref is not None
    assert row.external_ref["reversible"] is False
    (body,) = directory.patches()
    secret = body["passwordProfile"]["password"]
    assert len(secret) >= 32 and body["passwordProfile"]["forceChangePasswordNextSignInWithMfa"] is True

    dumps: List[str] = []
    async with env.repos.db.system_tx() as conn:
        tables = [r["table_name"] for r in await conn.fetch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' "
            "AND table_type = 'BASE TABLE'"
        )]
        for table in tables:
            rows = await conn.fetch(f'SELECT row_to_json(t)::text AS j FROM "{table}" t')  # noqa: S608
            dumps.extend(r["j"] for r in rows)
    everything = "\n".join(dumps)
    assert '"action.executed"' in everything and '"response_action.succeeded"' in everything  # the scan saw them
    assert secret not in everything
    assert secret not in json.dumps(env.events.events, default=str) and secret not in caplog.text
    # The password appears in exactly one request: the PATCH to Microsoft.
    carrying = [r for r in env.fake.requests if secret.encode() in r.content or secret in str(r.url)]
    assert len(carrying) == 1 and carrying[0].method == "PATCH"


async def test_rehearsal_records_a_dry_run_without_writing(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"entra.risk": {}}, live=False)
    alice = Directory(env.fake).add(UPN)
    action = await env.propose("confirm_compromised", UPN)
    assert await env.execute(action) == "dry_run"
    row = await env.get(action)
    assert row.result is not None and row.result["rehearsal"] is True
    assert row.result["resolved"]["user"]["id"] == alice.id and row.result["resolved"]["guard"] == "passed"
    assert env.fake.writes() == [] and row.verification is None
