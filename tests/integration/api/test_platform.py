"""``POST /api/v1/platform/tenants``: tenant provisioning by platform admins."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos.audit import AuditRepo
from lg_sotf.db.repos.users import UsersRepo
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

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
    assert (await api.repos.users.list("initech")).items == []

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


# ------------------------------------------------------------- atomic provisioning


async def _platform_headers(api: ApiHarness) -> Dict[str, str]:
    return api.auth(await api.user(TENANT_A, "admin", email="platform@a.example.com", platform_admin=True))


async def _left_behind(api: ApiHarness, tenant_id: str) -> List[Any]:
    """What a failed provisioning must not leave: the tenant, its users, its own and its home audit entries."""
    rows: List[Any] = []
    try:
        rows.append(await api.repos.tenants.get(tenant_id))
    except NotFound:
        pass
    rows.extend((await api.repos.users.list(tenant_id)).items)
    rows.extend((await api.repos.audit.list(tenant_id)).items)
    rows.extend(e for e in (await api.repos.audit.list(TENANT_A)).items if e.resource_id == tenant_id)
    return rows


def _fail_audit(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    original = AuditRepo.append

    async def append(self: AuditRepo, tenant_id: str, actor_type: str, actor_id: Any, act: str, *a: Any, **kw: Any) -> Any:
        if act == action:
            raise RuntimeError("audit_log unavailable")
        return await original(self, tenant_id, actor_type, actor_id, act, *a, **kw)

    monkeypatch.setattr(AuditRepo, "append", append)


async def test_provisioning_audits_the_new_home_and_copied_tenants_with_unchanged_details(api: ApiHarness) -> None:
    headers = await _platform_headers(api)
    await api.repos.tenants.update_settings(TENANT_B, {"retention": {"alerts_days": 90}})
    body = {"id": "initech", "name": "Initech", "admin_email": "boss@initech.example", "copy_settings_from": TENANT_B}
    created = await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)
    assert created.status_code == 201, created.text
    tenant_details = {
        "name": "Initech",
        "home_tenant_id": TENANT_A,
        "with_admin": True,
        "copied_from": TENANT_B,
        "settings_keys": ["retention"],
    }
    own = {e.action: e.details for e in (await api.repos.audit.list("initech")).items}
    assert own == {
        "tenant.created": tenant_details,
        "user.created": {"role": "admin", "sso_only": True, "home_tenant_id": TENANT_A},
    }
    home = (await api.repos.audit.list(TENANT_A, action="platform.tenant_created")).items
    assert [(e.resource_id, e.details) for e in home] == [("initech", tenant_details)]
    copied = [(e.action, e.resource_id, e.details) for e in (await api.repos.audit.list(TENANT_B)).items]
    assert copied == [
        (
            "platform.settings_copied",
            "initech",
            {"home_tenant_id": TENANT_A, "to_tenant": "initech", "keys": ["retention"]},
        )
    ]
    for tenant_id in ("initech", TENANT_A, TENANT_B):
        assert (await api.repos.audit.verify_chain(tenant_id)).ok


async def test_a_failed_admin_creation_leaves_no_tenant_and_a_retry_succeeds(
    api: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _platform_headers(api)
    original = UsersRepo.create

    async def failing(self: UsersRepo, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("connection lost")

    monkeypatch.setattr(UsersRepo, "create", failing)
    body = {"id": "globex", "name": "Globex", "profile": "balanced", "admin_email": "root@globex.example"}
    assert (await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)).status_code == 500
    assert await _left_behind(api, "globex") == []

    monkeypatch.setattr(UsersRepo, "create", original)
    retried = await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)
    assert retried.status_code == 201, retried.text
    assert retried.json()["admin"]["email"] == "root@globex.example"
    assert (await api.repos.tenants.get("globex")).settings["autonomy"]["low"] == "auto"


async def test_a_failed_home_audit_leaves_no_tenant(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = await _platform_headers(api)
    _fail_audit(monkeypatch, "platform.tenant_created")
    body = {"id": "hooli", "name": "Hooli", "admin_email": "root@hooli.example"}
    assert (await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)).status_code == 500
    assert await _left_behind(api, "hooli") == []
    monkeypatch.undo()
    assert (await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)).status_code == 201


async def test_concurrent_provisioning_of_one_id_creates_it_once(
    api: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _platform_headers(api)
    original = UsersRepo.create

    async def slow(self: UsersRepo, *args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(0.3)  # keep the first transaction open while the second one inserts
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(UsersRepo, "create", slow)
    bodies = [{"id": "umbrella", "name": name, "admin_email": f"root@{name}.example"} for name in ("first", "second")]
    responses = await asyncio.gather(
        *(api.client.post("/api/v1/platform/tenants", json=body, headers=headers) for body in bodies)
    )
    assert sorted(r.status_code for r in responses) == [201, 409]
    winner = next(r for r in responses if r.status_code == 201).json()
    assert (await api.repos.tenants.get("umbrella")).name == winner["name"]
    assert [u.email for u in (await api.repos.users.list("umbrella")).items] == [winner["admin"]["email"]]
    assert len((await api.repos.audit.list("umbrella", action="tenant.created")).items) == 1


async def test_a_tenant_update_rolls_back_when_the_home_audit_fails(
    api: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _platform_headers(api)
    _fail_audit(monkeypatch, "platform.tenant_updated")
    path = f"/api/v1/platform/tenants/{TENANT_B}"
    assert (await api.client.patch(path, json={"status": "suspended"}, headers=headers)).status_code == 500
    assert (await api.repos.tenants.get(TENANT_B)).status == "active"
    assert (await api.repos.audit.list(TENANT_B)).items == []
    monkeypatch.undo()
    assert (await api.client.patch(path, json={"status": "suspended"}, headers=headers)).status_code == 200
    home = (await api.repos.audit.list(TENANT_A, action="platform.tenant_updated")).items
    assert [e.details["tenant_action"] for e in home] == ["tenant.suspended"]
