"""The Microsoft integration through the API: catalog, create/update/delete with audit, connection test, routes."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Iterator, List

import httpx
import pytest

from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.connectors.microsoft import MicrosoftClients
from tests.fixtures.microsoft import FakeMicrosoft, fake_config, fake_secret
from tests.integration.api._support import ApiHarness
from tests.integration.db._support import TENANT_A
from tests.unit.integrations.microsoft._support import FAKE_SPECS

pytestmark = pytest.mark.integration

ISO = "defender.fake_isolation"


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


async def audit(api: ApiHarness, integration_id: str) -> List[Any]:
    page = await api.repos.audit.list(TENANT_A, resource_id=integration_id, limit=50)
    return list(reversed(page.items))


def body(**config: Any) -> Dict[str, Any]:
    credential = config.pop("credential", "client_secret")
    cfg, secret = fake_config(credential=credential, **config)
    return {"kind": "microsoft", "name": "Microsoft 365", "config": cfg, "secret": secret}


async def test_catalog_endpoint(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.get("/api/v1/integrations/microsoft/catalog", headers=admin)
    assert response.status_code == 200
    keys = [c["key"] for c in response.json()["capabilities"]]
    assert keys == ["defender.fake_isolation", "entra.fake_account"]
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.get("/api/v1/integrations/microsoft/catalog", headers=analyst)).status_code == 403


async def test_create_update_delete_are_audited_and_secrets_write_only(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    payload = body(capabilities={ISO: {"enabled": True, "options": {"limit": 3}}})
    created = await api.client.post("/api/v1/integrations", json=payload, headers=admin)
    assert created.status_code == 201, created.text
    out = created.json()
    assert out["events"] == [] and out["secrets"] == {"client_secret": True, "private_key_pem": False}
    assert payload["secret"]["client_secret"] not in json.dumps(out)
    assert out["config"]["capabilities"][ISO]["options"]["limit"] == 3
    integration_id = out["id"]
    duplicate = await api.client.post("/api/v1/integrations", json=body(), headers=admin)
    assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "integration_exists"

    live = {**out["config"], "capabilities": {ISO: {"enabled": True, "live": True, "options": {"limit": 3}}}}
    updated = await api.client.patch(f"/api/v1/integrations/{integration_id}", json={"config": live}, headers=admin)
    assert updated.status_code == 200, updated.text
    moved = {**out["config"], "directory_tenant_id": str(uuid.uuid4())}
    refused = await api.client.patch(f"/api/v1/integrations/{integration_id}", json={"config": moved}, headers=admin)
    assert refused.status_code == 422 and "secret.client_secret" in refused.json()["error"]["message"]
    rotated = await api.client.patch(
        f"/api/v1/integrations/{integration_id}", json={"secret": {"client_secret": fake_secret("rotated")}}, headers=admin
    )
    assert rotated.status_code == 200
    deleted = await api.client.delete(f"/api/v1/integrations/{integration_id}", headers=admin)
    assert deleted.status_code == 204

    entries = await audit(api, integration_id)
    assert [e.action for e in entries] == [
        "integration.created", "integration.updated", "integration.updated", "integration.deleted",
    ]
    created_audit, live_audit, rotate_audit, delete_audit = (e.details for e in entries)
    assert created_audit["capabilities_enabled"] == [ISO] and created_audit["credential_rotated"] is True
    assert created_audit["options"][ISO]["limit"] == 3
    assert live_audit["live_enabled"] == [ISO] and live_audit["credential_rotated"] is False
    assert rotate_audit["credential_rotated"] is True and rotate_audit["secret_fields"] == ["client_secret"]
    assert delete_audit["capabilities_disabled"] == [ISO] and delete_audit["live_disabled"] == [ISO]
    assert payload["secret"]["client_secret"] not in json.dumps([e.details for e in entries])


async def test_invalid_microsoft_configs_are_refused(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    with_url = body()
    with_url["config"]["graph_url"] = "https://evil.example"
    assert (await api.client.post("/api/v1/integrations", json=with_url, headers=admin)).status_code == 422
    with_events = {**body(), "events": ["action.failed"]}
    assert (await api.client.post("/api/v1/integrations", json=with_events, headers=admin)).status_code == 422
    no_secret = {**body(), "secret": {}}
    assert (await api.client.post("/api/v1/integrations", json=no_secret, headers=admin)).status_code == 422
    unknown = body(capabilities={"defender.nope": {"enabled": True}})
    assert (await api.client.post("/api/v1/integrations", json=unknown, headers=admin)).status_code == 422


async def test_certificate_details_are_derived(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    payload = body(credential="certificate")
    created = await api.client.post("/api/v1/integrations", json=payload, headers=admin)
    assert created.status_code == 201, created.text
    certificate = created.json()["config"]["certificate"]
    assert len(certificate["thumbprint_sha1"]) == 40 and certificate["not_after"]
    assert created.json()["secrets"] == {"client_secret": False, "private_key_pem": True}
    assert "PRIVATE KEY" not in created.text


async def test_connection_test_endpoint(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    fake = FakeMicrosoft()
    fake.grant("defender", ["Machine.Isolate", "Machine.Read.All"])
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    api.app.state.microsoft_clients = MicrosoftClients.create(
        api.ctx.settings, transport=fake.transport(), resolver=fake.resolver()
    )
    payload = body(capabilities={ISO: {"enabled": True}})
    integration_id = (await api.client.post("/api/v1/integrations", json=payload, headers=admin)).json()["id"]
    response = await api.client.post(f"/api/v1/integrations/{integration_id}/test", headers=admin)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["ok"] is True and result["microsoft"]["capabilities"][ISO]["status"] == "ok"
    assert all(r.method == "GET" or fake.is_token_request(r) for r in fake.requests)
    token = fake.api_requests()[0].headers["authorization"].split(" ", 1)[1]
    deliveries = (await api.client.get(f"/api/v1/integrations/{integration_id}/deliveries", headers=admin)).json()
    assert deliveries[0]["operation"] == "test" and deliveries[0]["status"] == "sent"
    stored = json.dumps(deliveries)
    assert token not in stored and payload["secret"]["client_secret"] not in stored
    assert (await audit(api, integration_id))[-1].action == "integration.tested"


async def test_response_routes(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    await api.client.post("/api/v1/integrations", json=body(capabilities={ISO: {"enabled": True}}), headers=admin)
    forced = (await api.client.get("/api/v1/tenant/response/routes", headers=admin)).json()
    assert forced["dry_run_forced"] is True  # the install default
    assert forced["routes"]["isolate_host"]["source"] == "kill_switch"

    ok = await api.client.patch("/api/v1/tenant/settings", json={"response": {"routes": {"disable_user": "microsoft"}}},
                                headers=admin)
    assert ok.status_code == 200, ok.text
    bad = await api.client.patch("/api/v1/tenant/settings", json={"response": {"routes": {"block_ip": "ticketing"}}},
                                 headers=admin)
    assert bad.status_code == 422


async def test_live_routes_show_capabilities(make_api: Any) -> None:
    api: ApiHarness = await make_api(response={"dry_run": False})
    admin = await api.login_headers(TENANT_A, "admin")
    await api.client.post("/api/v1/integrations", json=body(capabilities={ISO: {"enabled": True}}), headers=admin)
    await api.client.patch("/api/v1/tenant/settings", json={"response": {"dry_run": False}}, headers=admin)
    routes = (await api.client.get("/api/v1/tenant/response/routes", headers=admin)).json()
    assert routes["dry_run_forced"] is False
    assert routes["routes"]["isolate_host"] == {
        "connector": "microsoft", "source": "capability", "capability": ISO, "live": False, "problem": None,
    }
    assert routes["routes"]["block_ip"]["source"] == "default"
