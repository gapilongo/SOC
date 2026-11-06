"""``/actions``: rollback, retry and verify endpoints, the verification filter and the new action fields."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterator

import pytest

from lg_sotf.db.repos import Integration, ResponseAction
from lg_sotf.integrations.config import encrypt_secret, validate_config
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from tests.fixtures.microsoft import fake_config
from tests.integration.api._support import ApiHarness
from tests.integration.db._support import TENANT_A, make_alert
from tests.unit.integrations.microsoft._support import FAKE_SPECS

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


async def microsoft(api: ApiHarness) -> Integration:
    config, secret = fake_config(capabilities={"defender.fake_isolation": {"enabled": True, "live": True}})
    config = validate_config("microsoft", config, require_https=True)
    integration_id = uuid.uuid4()
    assert api.ctx.secret_box is not None
    return await api.repos.integrations.create(
        TENANT_A, "microsoft", "Microsoft", integration_id=integration_id, config=config,
        secret_ciphertext=encrypt_secret(api.ctx.secret_box, TENANT_A, integration_id, secret),
    )


async def executed(api: ApiHarness, integration: Integration, **values: Any) -> ResponseAction:
    alert = await make_alert(api.repos, TENANT_A)
    await api.repos.runs.upsert_queued(TENANT_A, alert)
    action, _ = await api.repos.actions.propose(TENANT_A, alert, "isolate_host", f"ws-{uuid.uuid4().hex[:4]}", "high",
                                                status="approved")
    fields: Dict[str, Any] = {
        "status": "succeeded", "connector": "microsoft", "integration_id": integration.id, "attempts": 1,
        "external_ref": {"capability": "defender.fake_isolation", "reversible": True, "machine_id": "m1"},
        "result": {"changed": True, "summary": "isolated"},
    }
    fields.update(values)
    sets = ", ".join(f"{k} = ${i + 2}" for i, k in enumerate(fields))
    async with api.repos.db.system_tx() as conn:
        await conn.execute(f"UPDATE response_actions SET {sets}, executed_at = now() WHERE id = $1",  # noqa: S608
                           action.id, *fields.values())
    return await api.repos.actions.get(TENANT_A, action.id)


async def test_actions_carry_rollback_and_verification_fields(api: ApiHarness) -> None:
    integration = await microsoft(api)
    action = await executed(api, integration)
    viewer = await api.login_headers(TENANT_A, "viewer")
    item = (await api.client.get(f"/api/v1/actions/{action.id}", headers=viewer)).json()
    assert item["execution_owner"] == "workflow" and item["integration_id"] == str(integration.id)
    assert item["attempts"] == 1 and item["external_ref"]["reversible"] is True and item["verification"] is None
    assert item["rollback"] == {"available": True, "action_type": "release_host", "risk": "high", "until": None,
                                "reason": None}
    assert item["rolled_back_by"] is None
    await executed(api, integration, status="succeeded", verification="verified", verified_at=None)
    listed = (await api.client.get("/api/v1/actions", params={"verification": "verified"}, headers=viewer)).json()
    assert [a["verification"] for a in listed["items"]] == ["verified"]
    bad = await api.client.get("/api/v1/actions", params={"verification": "maybe"}, headers=viewer)
    assert bad.status_code == 422


async def test_rollback_endpoint(api: ApiHarness) -> None:
    integration = await microsoft(api)
    action = await executed(api, integration)
    admin = await api.login_headers(TENANT_A, "admin")
    viewer = await api.login_headers(TENANT_A, "viewer")
    assert (await api.client.post(f"/api/v1/actions/{action.id}/rollback", json={"reason": "x"}, headers=viewer)).status_code == 403
    assert (await api.client.post(f"/api/v1/actions/{action.id}/rollback", json={"reason": ""}, headers=admin)).status_code == 422
    created = await api.client.post(f"/api/v1/actions/{action.id}/rollback", json={"reason": "clean host"}, headers=admin)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["created"] is True and body["rollback"]["action_type"] == "release_host"
    assert body["rollback"]["status"] == "approved" and body["rollback"]["execution_owner"] == "scheduler"
    assert body["rollback"]["rollback"]["available"] is False  # not executed yet, and a rollback itself
    assert body["original"]["rolled_back_by"] == body["rollback"]["id"]
    assert body["original"]["rollback"]["reason"] == "rollback_exists"
    again = await api.client.post(f"/api/v1/actions/{action.id}/rollback", json={"reason": "again"}, headers=admin)
    assert again.status_code == 201 and again.json()["created"] is False
    assert again.json()["rollback"]["id"] == body["rollback"]["id"]

    analyst = await api.login_headers(TENANT_A, "analyst")
    other = await executed(api, integration)
    waiting = await api.client.post(f"/api/v1/actions/{other.id}/rollback", json={"reason": "r", "approve": True},
                                    headers=analyst)
    assert waiting.json()["rollback"]["status"] == "awaiting_approval"

    rehearsed = await executed(api, integration, status="dry_run")
    refused = await api.client.post(f"/api/v1/actions/{rehearsed.id}/rollback", json={"reason": "r"}, headers=admin)
    assert refused.status_code == 409
    error = refused.json()["error"]
    assert error["code"] == "rollback_unavailable" and error["details"] == [{"reason": "not_executed"}]
    missing = await api.client.post(f"/api/v1/actions/{uuid.uuid4()}/rollback", json={"reason": "r"}, headers=admin)
    assert missing.status_code == 404


async def test_retry_endpoint(api: ApiHarness) -> None:
    integration = await microsoft(api)
    action = await executed(api, integration, status="failed", result={"error": "throttled", "retryable": True})
    analyst = await api.login_headers(TENANT_A, "analyst")
    admin = await api.login_headers(TENANT_A, "admin")
    denied = await api.client.post(f"/api/v1/actions/{action.id}/retry", json={"reason": "again"}, headers=analyst)
    assert denied.status_code == 403
    ok = await api.client.post(f"/api/v1/actions/{action.id}/retry", json={"reason": "again"}, headers=admin)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "executing" and ok.json()["execution_owner"] == "scheduler"
    again = await api.client.post(f"/api/v1/actions/{action.id}/retry", json={"reason": "again"}, headers=admin)
    assert again.status_code == 409 and again.json()["error"]["code"] == "retry_unavailable"
    permanent = await executed(api, integration, status="failed", result={"error": "invalid_target", "retryable": False})
    refused = await api.client.post(f"/api/v1/actions/{permanent.id}/retry", json={"reason": "x"}, headers=admin)
    assert refused.status_code == 409


async def test_verify_endpoint(api: ApiHarness) -> None:
    integration = await microsoft(api)
    action = await executed(api, integration, verification="verified")
    admin = await api.login_headers(TENANT_A, "admin")
    too_soon = await api.client.post(f"/api/v1/actions/{action.id}/verify", json={}, headers=admin)
    assert too_soon.status_code == 429
    async with api.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET updated_at = now() - interval '1 hour', "
                           "verified_at = now() - interval '1 hour' WHERE id = $1", action.id)
    ok = await api.client.post(f"/api/v1/actions/{action.id}/verify", headers=admin)
    assert ok.status_code == 200 and ok.json()["verification"] == "pending"
    pending = await api.client.post(f"/api/v1/actions/{action.id}/verify", json={}, headers=admin)
    assert pending.status_code == 409
