"""``POST /api/v1/platform/tenants``: tenant provisioning by platform admins."""

from __future__ import annotations

import pytest

from lg_sotf.db.errors import NotFound
from tests.integration.api.conftest import TENANT_A, ApiHarness

pytestmark = pytest.mark.integration

NEW_ADMIN_PASSWORD = "a long enough new tenant passphrase"


async def test_platform_admin_provisions_a_tenant_with_its_first_admin(api: ApiHarness) -> None:
    platform = await api.user(TENANT_A, "admin", email="platform@a.example.com", platform_admin=True)
    body = {"id": "globex", "name": " Globex ", "admin_email": "Root@Globex.example", "admin_password": NEW_ADMIN_PASSWORD}

    created = await api.client.post("/api/v1/platform/tenants", json=body, headers=api.auth(platform))

    assert created.status_code == 201, created.text
    out = created.json()
    assert (out["id"], out["name"], out["status"]) == ("globex", "Globex", "active")
    assert out["admin"]["email"] == "root@globex.example" and out["admin"]["role"] == "admin"
    assert out["admin"]["is_platform_admin"] is False and "password" not in created.text
    tenant = await api.repos.tenants.get("globex")
    assert tenant.settings == {}

    login = await api.client.post(
        "/api/v1/auth/login", json={"email": "root@globex.example", "password": NEW_ADMIN_PASSWORD, "tenant": "globex"}
    )
    assert login.status_code == 200, login.text
    me = await api.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    assert me.json()["tenant_id"] == "globex"

    own = (await api.repos.audit.list("globex", resource_type="tenant")).items
    assert [(e.action, e.actor_id) for e in own] == [("tenant.created", str(platform.id))]
    assert own[0].details["home_tenant_id"] == TENANT_A
    assert [e.action for e in (await api.repos.audit.list("globex", action="user.created")).items] == ["user.created"]
    home = (await api.repos.audit.list(TENANT_A, action="platform.tenant_created")).items
    assert [(e.resource_id, e.actor_id) for e in home] == [("globex", str(platform.id))]
    assert (await api.repos.audit.verify_chain("globex")).ok

    again = await api.client.post("/api/v1/platform/tenants", json={"id": "globex", "name": "Other"}, headers=api.auth(platform))
    assert again.status_code == 409 and "already exists" in again.json()["error"]["message"]
    assert (await api.repos.tenants.get("globex")).name == "Globex"


async def test_provisioning_without_admin_and_input_validation(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_A, "admin", platform_admin=True)

    bare = await api.client.post("/api/v1/platform/tenants", json={"id": "initech", "name": "Initech"}, headers=headers)
    assert bare.status_code == 201 and bare.json()["admin"] is None
    assert await api.repos.users.list("initech") == []

    for body in (
        {"id": "Bad Id", "name": "x"},
        {"id": "x", "name": "too short id"},
        {"id": "ok-id", "name": ""},
        {"id": "ok-id", "name": "   "},
        {"id": "ok-id", "name": "x", "admin_password": NEW_ADMIN_PASSWORD},
        {"id": "ok-id", "name": "x", "admin_email": "a@b.example", "admin_password": "short"},
        {"id": "ok-id", "name": "x", "settings": {"autonomy": {"high": "auto"}}},
    ):
        response = await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)
        assert response.status_code == 422, (body, response.text)
    with pytest.raises(NotFound):
        await api.repos.tenants.get("ok-id")


async def test_only_platform_admins_provision_tenants(api: ApiHarness) -> None:
    for headers in (
        await api.login_headers(TENANT_A, "admin"),
        await api.login_headers(TENANT_A, "analyst", platform_admin=True),
        await api.key_headers(TENANT_A, ["read", "write", "ingest"]),
    ):
        response = await api.client.post("/api/v1/platform/tenants", json={"id": "nope", "name": "N"}, headers=headers)
        assert response.status_code == 403, response.text
    unauthenticated = await api.client.post("/api/v1/platform/tenants", json={"id": "nope", "name": "N"})
    assert unauthenticated.status_code == 401
    assert not [t for t in await api.repos.tenants.list_all_tenants() if t.id == "nope"]
