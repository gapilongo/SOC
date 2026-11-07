"""The delegated-access API: organisations, members, and grants given and revoked by the customer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import pytest

from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"


def _grant_body(**overrides: Any) -> Dict[str, Any]:
    body = {
        "organisation_id": ORG,
        "role": "analyst",
        "reason": "MSSP contract 42",
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }
    body.update(overrides)
    return body


async def _actions(api: ApiHarness, tenant_id: str) -> List[str]:
    return [e.action for e in (await api.repos.audit.list(tenant_id, limit=100)).items]


async def test_organisation_members_and_grant_lifecycle(api: ApiHarness) -> None:
    await api.repos.tenants.create(ORG, "MSSP")
    platform = await api.login_headers(TENANT_A, "admin", platform_admin=True)
    org_admin = await api.user(ORG, "admin")
    staff = await api.user(ORG, "analyst")
    customer = await api.login_headers(TENANT_B, "admin")

    assert (await api.client.put(f"{API}/platform/organisations/{ORG}", json={"name": "x"}, headers=customer)).status_code == 403
    saved = await api.client.put(f"{API}/platform/organisations/{ORG}", json={"name": " Acme MSSP "}, headers=platform)
    assert saved.status_code == 200, saved.text
    assert saved.json()["name"] == "Acme MSSP"
    missing = await api.client.put(f"{API}/platform/organisations/no-such-org", json={"name": "x"}, headers=platform)
    assert missing.status_code == 404

    added = await api.client.put(f"{API}/organisation/members/{staff.id}", headers=api.auth(org_admin))
    assert added.status_code == 200, added.text
    stranger = await api.user(TENANT_B, "analyst")
    assert (await api.client.put(f"{API}/organisation/members/{stranger.id}", headers=api.auth(org_admin))).status_code == 404
    assert (await api.client.put(f"{API}/organisation/members/{staff.id}", headers=api.auth(staff))).status_code == 403
    members = await api.client.get(f"{API}/organisation/members", headers=api.auth(staff))
    assert [m["user_id"] for m in members.json()] == [str(staff.id)]
    assert "organisation.saved" in await _actions(api, ORG) and "organisation.member_added" in await _actions(api, ORG)

    created = await api.client.post(f"{API}/tenant/grants", json=_grant_body(), headers=customer)
    assert created.status_code == 201, created.text
    grant = created.json()
    assert (grant["tenant_id"], grant["organisation_id"], grant["role"]) == (TENANT_B, ORG, "analyst")
    # Recorded in both chains.
    assert "grant.created" in await _actions(api, TENANT_B)
    assert "grant.received" in await _actions(api, ORG)
    listed = await api.client.get(f"{API}/tenant/grants", headers=customer)
    assert [g["id"] for g in listed.json()] == [grant["id"]]
    held = await api.client.get(f"{API}/organisation/grants", headers=api.auth(staff))
    assert [g["id"] for g in held.json()] == [grant["id"]]
    as_staff = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/alerts", headers=as_staff)).status_code == 200

    revoked = await api.client.post(f"{API}/tenant/grants/{grant['id']}/revoke", headers=customer)
    assert revoked.status_code == 200 and revoked.json()["revoked_at"] is not None
    assert "grant.revoked" in await _actions(api, TENANT_B) and "grant.revoked" in await _actions(api, ORG)
    assert (await api.client.post(f"{API}/tenant/grants/{grant['id']}/revoke", headers=customer)).status_code == 404
    assert (await api.client.get(f"{API}/alerts", headers=as_staff)).status_code == 403
    assert (await api.client.get(f"{API}/organisation/grants", headers=api.auth(staff))).json() == []

    personal = await api.client.post(f"{API}/tenant/grants", json=_grant_body(user_id=str(staff.id)), headers=customer)
    assert personal.status_code == 201, personal.text
    removed = await api.client.delete(f"{API}/organisation/members/{staff.id}", headers=api.auth(org_admin))
    assert removed.status_code == 204
    # The member's own grant went with the membership.
    assert [g["id"] for g in (await api.client.get(f"{API}/tenant/grants", headers=customer)).json()] == [grant["id"]]
    assert (await api.client.delete(f"{API}/organisation/members/{staff.id}", headers=api.auth(org_admin))).status_code == 404


async def test_grant_validation(api: ApiHarness) -> None:
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    customer = await api.login_headers(TENANT_B, "admin")
    now = datetime.now(UTC)
    for body, status in (
        (_grant_body(expires_at=(now - timedelta(minutes=1)).isoformat()), 422),
        (_grant_body(expires_at=(now + timedelta(days=400)).isoformat()), 422),
        (_grant_body(organisation_id=TENANT_B), 422),
        (_grant_body(organisation_id=TENANT_A), 404),  # not an organisation
        (_grant_body(reason=""), 422),
        (_grant_body(role="owner"), 422),
    ):
        response = await api.client.post(f"{API}/tenant/grants", json=body, headers=customer)
        assert response.status_code == status, (body, response.text)
    analyst = await api.login_headers(TENANT_B, "analyst")
    assert (await api.client.post(f"{API}/tenant/grants", json=_grant_body(), headers=analyst)).status_code == 403
    assert (await api.client.get(f"{API}/tenant/grants", headers=analyst)).status_code == 403


async def test_only_the_customers_own_admins_give_grants(api: ApiHarness) -> None:
    """Neither a grant holder nor a platform admin's X-Tenant-ID can give (or read) the customer's grants."""
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    await api.repos.grants.create(
        TENANT_B, ORG, "admin", reason="r", created_by="c", expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    under_grant = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    platform = {**(await api.login_headers(TENANT_A, "admin", platform_admin=True)), "X-Tenant-ID": TENANT_B}
    for headers in (under_grant, platform):
        response = await api.client.post(f"{API}/tenant/grants", json=_grant_body(role="admin"), headers=headers)
        assert response.status_code == 403, response.text
    assert (await api.client.get(f"{API}/tenant/grants", headers=under_grant)).status_code == 403
    assert (await api.client.get(f"{API}/tenant/grants", headers=platform)).status_code == 200
    assert len(await api.repos.grants.list_for_tenant(TENANT_B)) == 1
