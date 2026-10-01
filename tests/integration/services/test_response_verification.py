"""Verification against Postgres: schedule, outcomes, events, re-check; evidence and export carry it, never secrets."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any, Dict, Iterator, List
from uuid import UUID, uuid4

import httpx
import pytest

from lg_sotf.compliance.evidence import build_evidence_pack, render_evidence_html
from lg_sotf.compliance.tenant_data import export_tenant_zip
from lg_sotf.db.repos import Repositories, ResponseAction
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.response import ActionRequestError
from lg_sotf.services.rollback import RollbackService
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft.conftest import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft._support import FAKE_SPECS, OPERATION_ID, script_isolation

pytestmark = pytest.mark.integration

ISO = {"defender.fake_isolation": {}}


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


def machine_action(env: MicrosoftEnv, status: str) -> None:
    env.fake.route("GET", "defender", f"/api/machineactions/{OPERATION_ID}",
                   httpx.Response(200, json={"id": OPERATION_ID, "status": status}), times=1)
    env.fake._routes.insert(0, env.fake._routes.pop())


async def executed(env: MicrosoftEnv) -> ResponseAction:
    script_isolation(env.fake, action_status="InProgress")
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert row.verification == "pending" and row.verify_after is not None and row.verify_deadline is not None
    assert row.verification_detail is not None and row.verification_detail["first_check_s"] == 5.0
    return row


async def audit_actions(repos: Repositories, resource_id: Any) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(resource_id), limit=100)
    return [e.action for e in reversed(page.items)]


async def outbox(env: MicrosoftEnv) -> List[Dict[str, Any]]:
    async with env.repos.db.tenant_tx(TENANT_A) as conn:
        rows = await conn.fetch("SELECT event_type, dedupe_key, payload FROM notification_outbox ORDER BY created_at")
    return [dict(r) for r in rows]


async def subscribe(env: MicrosoftEnv) -> None:
    await env.repos.integrations.create(
        TENANT_A, "webhook", "soar-hook", config={"url": "https://soar.example.com/hook"},
        events=["action.verification_failed"], min_severity="info",
    )


async def test_pending_then_verified(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await executed(env)
    assert await env.run_verify() == 0  # not due yet
    await env.make_verifications_due()
    assert await env.run_verify() == 1
    still = await env.get(action)
    assert still.verification == "pending" and still.verify_attempts == 1 and still.verified_at is None
    machine_action(env, "Succeeded")
    await env.make_verifications_due()
    await env.run_verify()
    done = await env.get(action)
    assert done.verification == "verified" and done.verified_at is not None and done.verify_attempts == 2
    assert "response_action.verified" in await audit_actions(env.repos, action.id)
    timeline = [e.event_type for e in (await env.repos.alert_events.list_for_alert(TENANT_A, action.alert_id)).items]
    assert "action.verified" in timeline
    assert all(r.method == "GET" for r in env.fake.api_requests() if "/machineactions/" in r.url.path)


async def test_failed_and_inconclusive_raise_the_event(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    await subscribe(env)
    action = await executed(env)
    machine_action(env, "Failed")
    await env.make_verifications_due()
    await env.run_verify()
    failed = await env.get(action)
    assert failed.verification == "failed" and failed.verification_detail is not None
    assert failed.verification_detail["reason"] == "machine_action_failed"
    assert "response_action.verification_failed" in await audit_actions(env.repos, action.id)
    events = await outbox(env)
    assert [e["event_type"] for e in events] == ["action.verification_failed"]
    assert events[0]["dedupe_key"] == f"action.verification_failed:{action.id}:1"
    assert events[0]["payload"]["action"]["verification"] == {"outcome": "failed", "reason": "machine_action_failed"}

    second = await env.propose("isolate_host", "ws-043")
    assert await env.execute(second) == "succeeded"
    await env.repos.integrations.update(TENANT_A, env.integration.id, enabled=False)
    await env.make_verifications_due()
    await env.run_verify()
    unavailable = await env.get(second)
    assert unavailable.verification == "inconclusive"
    assert unavailable.verification_detail == {"reason": "integration_unavailable"}
    assert "response_action.verification_inconclusive" in await audit_actions(env.repos, second.id)
    assert len(await outbox(env)) == 2


async def test_a_rollback_ends_the_originals_verification_without_a_false_alarm(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env(ISO)
    await subscribe(env)
    action = await executed(env)
    admin = (await env.repos.users.create(TENANT_A, f"admin-{uuid4().hex[:6]}@example.com", "admin")).id
    rollback, _, _ = await RollbackService(env.service).request(
        TENANT_A, action.id, user=admin, role="admin", reason="false positive",
    )
    assert rollback.status == "approved"
    assert await env.run_background() == 1
    assert (await env.get(rollback)).status == "succeeded"
    machine_action(env, "Cancelled")  # what the release did to the pending isolation
    await env.make_verifications_due()
    await env.run_verify()
    original = await env.get(action)
    assert original.verification == "inconclusive"
    assert original.verification_detail == {"reason": "rolled_back", "rollback_id": str(rollback.id)}
    assert "response_action.verification_inconclusive" in await audit_actions(env.repos, action.id)
    assert [e["event_type"] for e in await outbox(env) if e["event_type"] == "action.verification_failed"] == []
    timeline = [e.event_type for e in (await env.repos.alert_events.list_for_alert(TENANT_A, action.alert_id)).items]
    assert "action.verification_failed" not in timeline
    assert not [r for r in env.fake.api_requests() if r.url.path == f"/api/machineactions/{OPERATION_ID}"]


async def test_a_rollback_still_awaiting_approval_does_not_stop_verification(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env(ISO)
    action = await executed(env)
    admin = (await env.repos.users.create(TENANT_A, f"admin-{uuid4().hex[:6]}@example.com", "admin")).id
    rollback, _, _ = await RollbackService(env.service).request(
        TENANT_A, action.id, user=admin, role="admin", reason="false positive", approve=False,
    )
    assert rollback.status == "awaiting_approval"
    machine_action(env, "Succeeded")
    await env.make_verifications_due()
    await env.run_verify()
    assert (await env.get(action)).verification == "verified"


async def test_a_suspended_tenants_verifications_wait(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await executed(env)
    reads = len(env.fake.api_requests())
    await env.repos.tenants.set_status(TENANT_A, "suspended")
    try:
        await env.make_verifications_due()
        assert await env.run_verify() == 0
        row = await env.get(action)
        assert row.verification == "pending" and row.verify_attempts == 0 and len(env.fake.api_requests()) == reads
    finally:
        await env.repos.tenants.set_status(TENANT_A, "active")
    machine_action(env, "Succeeded")
    assert await env.run_verify() == 1
    assert (await env.get(action)).verification == "verified"


async def test_deadline_makes_it_inconclusive(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await executed(env)
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET verify_deadline = now() - interval '1 second', "
                           "verify_after = now() - interval '2 seconds' WHERE id = $1", action.id)
    await env.run_verify()
    row = await env.get(action)
    assert row.verification == "inconclusive" and row.verification_detail is not None
    assert row.verification_detail["reason"] == "deadline"


async def test_recheck(microsoft_env: MicrosoftEnvFactory) -> None:
    from lg_sotf.services.verification import VerificationService

    env = await microsoft_env(ISO)
    action = await executed(env)
    service = VerificationService(env.service)
    user = (await env.repos.users.create(TENANT_A, f"a-{uuid4().hex[:6]}@example.com", "analyst")).id
    with pytest.raises(ActionRequestError) as pending:
        await service.recheck(TENANT_A, action.id, user=user)
    assert pending.value.status == 409
    machine_action(env, "Succeeded")
    await env.make_verifications_due()
    await env.run_verify()
    with pytest.raises(ActionRequestError) as recent:
        await service.recheck(TENANT_A, action.id, user=user)
    assert recent.value.status == 429
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET verified_at = now() - interval '1 hour', "
                           "updated_at = now() - interval '1 hour' WHERE id = $1", action.id)
    reopened = await service.recheck(TENANT_A, action.id, user=user)
    assert reopened.verification == "pending" and reopened.verified_at is None
    assert reopened.verify_deadline is not None and "response_action.verification_rechecked" in await audit_actions(
        env.repos, action.id
    )
    machine_action(env, "Succeeded")
    await env.run_verify()
    assert (await env.get(action)).verification == "verified"


async def test_evidence_and_export_carry_verification_and_lineage_never_secrets(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env(ISO, credential="certificate")
    action = await executed(env)
    admin: UUID = (await env.repos.users.create(TENANT_A, f"x-{uuid4().hex[:6]}@example.com", "admin")).id
    rollback, _, _ = await RollbackService(env.service).request(TENANT_A, action.id, user=admin, role="admin", reason="r")
    await env.run_background()
    pack = await build_evidence_pack(env.repos, env.settings, TENANT_A, action.alert_id, generated_by={"actor_id": "t"})
    views = {a["id"]: a for a in pack["actions"]}
    original = views[str(action.id)]
    assert original["verification"] == "pending" and original["execution_owner"] == "workflow"
    assert original["attempts"] == 1 and original["rolled_back_by"] == str(rollback.id)
    assert views[str(rollback.id)]["rollback_of"] == str(action.id)
    assert views[str(rollback.id)]["verification"] == "verified"
    steps = [s["step"] for s in pack["human_oversight"]["steps"]]
    assert "rollback_requested:isolate_host" in steps
    assert any(o["kind"] == "action_rolled_back" for o in pack["human_oversight"]["overrides"])
    html = render_evidence_html(pack)
    assert "Verification" in html and "Rolls back" in html
    secret = env.secret["private_key_pem"]
    serialized = json.dumps(pack, default=str)
    assert secret not in serialized and "PRIVATE KEY" not in serialized

    tenant = await env.repos.tenants.get(TENANT_A)
    data = b"".join([c async for c in export_tenant_zip(env.repos.db, tenant, exported_by={"actor_id": "t"})])
    files = {n: zipfile.ZipFile(io.BytesIO(data)).read(n).decode() for n in zipfile.ZipFile(io.BytesIO(data)).namelist()}
    rows = [json.loads(line) for line in files["actions.jsonl"].splitlines()]
    exported = {r["id"]: r for r in rows}
    assert exported[str(action.id)]["verification"] == "pending"
    assert exported[str(rollback.id)]["rollback_of"] == str(action.id)
    assert exported[str(rollback.id)]["execution_owner"] == "scheduler"
    everything = "".join(files.values())
    assert secret not in everything and "PRIVATE KEY" not in everything
    integrations = [json.loads(line) for line in files["integrations.jsonl"].splitlines()]
    assert [i["has_secret"] for i in integrations if i["kind"] == "microsoft"] == [True]
