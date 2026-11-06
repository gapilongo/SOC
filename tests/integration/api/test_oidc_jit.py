"""OIDC just-in-time provisioning and role mapping (JWKS mocked like test_oidc)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import httpx
import pytest

from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness
from tests.integration.api.test_oidc import AUDIENCE, ISSUER, IdP, bearer
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ROLE_MAP = {"SOC-Viewers": "viewer", "SOC-Analysts": "analyst", "SOC-Admins": "admin"}


@pytest.fixture
def idp() -> IdP:
    return IdP()


async def _jit_api(make_api: Any, idp: IdP, **auth: Any) -> ApiHarness:
    settings = {
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_role_claim": "groups",
        "oidc_jit_provisioning": True,
        "oidc_role_map": ROLE_MAP,
        **auth,
    }
    return await make_api(transport=httpx.MockTransport(idp.handler), auth=settings)


def _token(idp: IdP, groups: List[str], **claims: Any) -> str:
    base: Dict[str, Any] = {"sub": "entra-oid-1", "email": "jit.user@a.example.com", "groups": groups, "roles": None}
    base.update(claims)
    return idp.token(**base)


async def _audit(api: ApiHarness, action: str, tenant_id: str = TENANT_A) -> List[Any]:
    return (await api.repos.audit.list(tenant_id, action=action)).items


async def test_first_sign_in_provisions_a_usable_account(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    token = _token(idp, ["Everyone", "SOC-Analysts"])
    me = await api.client.get(f"{API}/auth/me", headers=bearer(token))
    assert me.status_code == 200, me.text
    body = me.json()
    assert (body["auth_method"], body["role"], body["is_platform_admin"]) == ("oidc", "analyst", False)
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None and body["user_id"] == str(user.id)
    assert (user.email, user.role, user.password_hash, user.is_platform_admin) == (
        "jit.user@a.example.com",
        "analyst",
        None,
        False,
    )
    entry = (await _audit(api, "user.provisioned"))[0]
    assert (entry.actor_type, entry.actor_id, entry.details["role"]) == ("system", "oidc", "analyst")

    # A second request reuses the account.
    again = await api.client.get(f"{API}/auth/me", headers=bearer(token))
    assert again.json()["user_id"] == str(user.id)
    assert len(await _audit(api, "user.provisioned")) == 1

    # The provisioned account satisfies decisions and approvals (a real local user).
    alert_id = await make_alert(api.repos, TENANT_A, title="Needs review")
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, alert_id, reason="uncertain", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    claimed = await api.client.post(
        f"{API}/escalations/{escalation.id}/claim", json={"version": escalation.version}, headers=bearer(token)
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["assigned_to"] == str(user.id)

    admin = await api.user(TENANT_A, "admin", email="adm@a.example.com")
    listed = {u["email"]: u for u in (await api.client.get(f"{API}/users", headers=api.auth(admin))).json()}
    assert listed["jit.user@a.example.com"]["oidc_provisioned"] is True


async def test_accepted_tokens_keep_the_last_sign_in_of_a_provisioned_account_current(make_api: Any, idp: IdP) -> None:
    # Slack approvals by SSO accounts rely on last_login_at (integrations.slack_sso_max_age_hours).
    api = await _jit_api(make_api, idp)
    token = _token(idp, ["SOC-Analysts"])
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(token))).status_code == 200
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None and user.last_login_at is not None
    assert datetime.now(UTC) - user.last_login_at < timedelta(minutes=1)
    old = datetime.now(UTC) - timedelta(hours=20)
    await api.repos.users.record_sign_in(TENANT_A, user.id, now=old)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(token))).status_code == 200
    refreshed = await api.repos.users.get(TENANT_A, user.id)
    assert refreshed.last_login_at is not None and refreshed.last_login_at > old + timedelta(hours=19)


async def test_role_follows_the_mapping_on_later_sign_ins(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Viewers"])))).status_code == 200
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None and user.role == "viewer"
    promoted = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Viewers", "SOC-Admins"])))
    assert promoted.json()["role"] == "admin"
    assert (await api.repos.users.get(TENANT_A, user.id)).role == "admin"
    synced = (await _audit(api, "user.role_synced"))[0]
    assert synced.details == {"from": "viewer", "to": "admin", "via": "oidc_role_map"}
    # Unchanged mapping: no write, no audit entry.
    await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    assert len(await _audit(api, "user.role_synced")) == 1


async def test_no_matching_group_is_refused_unless_a_default_role_is_set(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    refused = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["Everyone"])))
    assert refused.status_code == 403
    assert await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1") is None

    idp2 = IdP()
    lenient = await _jit_api(make_api, idp2, oidc_default_role="viewer")
    me = await lenient.client.get(f"{API}/auth/me", headers=bearer(_token(idp2, ["Everyone"])))
    assert me.status_code == 200 and me.json()["role"] == "viewer"


async def test_oidc_never_grants_platform_admin(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    token = _token(idp, ["SOC-Admins"], is_platform_admin=True, pa=True)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(token))).json()["is_platform_admin"] is False
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None and not user.is_platform_admin
    # Even when the local row carries the flag, the OIDC principal does not.
    await api.repos.users.update(TENANT_A, user.id, is_platform_admin=True)
    me = await api.client.get(f"{API}/auth/me", headers=bearer(token))
    assert me.json()["is_platform_admin"] is False
    override = await api.client.get(f"{API}/alerts", headers={**bearer(token), "X-Tenant-ID": TENANT_B})
    assert override.status_code == 403


async def test_only_verified_identities_are_provisioned(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    unverified = _token(idp, ["SOC-Analysts"], email_verified=False)
    me = await api.client.get(f"{API}/auth/me", headers=bearer(unverified))
    assert me.status_code == 200 and me.json()["user_id"] is None
    no_email = _token(idp, ["SOC-Analysts"], email=None)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(no_email))).json()["user_id"] is None
    assert (await api.repos.users.list(TENANT_A)).items == []


async def test_provisioning_is_off_by_default(make_api: Any, idp: IdP) -> None:
    api = await make_api(
        transport=httpx.MockTransport(idp.handler),
        auth={"oidc_issuer": ISSUER, "oidc_audience": AUDIENCE, "oidc_role_claim": "groups", "oidc_role_map": ROLE_MAP},
    )
    me = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Analysts"])))
    assert me.status_code == 200 and me.json()["role"] == "analyst" and me.json()["user_id"] is None
    assert (await api.repos.users.list(TENANT_A)).items == []


async def test_provisioned_accounts_have_no_password_login_and_can_be_disabled(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    token = _token(idp, ["SOC-Analysts"])
    await api.client.get(f"{API}/auth/me", headers=bearer(token))
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None
    login = await api.client.post(f"{API}/auth/login", json={"email": "jit.user@a.example.com", "password": PASSWORD})
    assert login.status_code == 401
    await api.repos.users.update(TENANT_A, user.id, is_active=False)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(token))).status_code == 401


async def test_an_account_of_another_subject_is_never_linked_by_email(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    owner = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert owner is not None
    impostor = _token(idp, ["SOC-Viewers"], sub="another-subject")
    me = await api.client.get(f"{API}/auth/me", headers=bearer(impostor))
    assert me.status_code == 200 and me.json()["user_id"] is None and me.json()["role"] == "viewer"
    assert (await api.repos.users.get(TENANT_A, owner.id)).role == "admin"
    assert len((await api.repos.users.list(TENANT_A)).items) == 1


async def test_hand_made_accounts_keep_their_stored_role(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    local = await api.user(TENANT_A, "viewer", email="jit.user@a.example.com", password=None)
    me = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    assert me.json()["user_id"] == str(local.id) and me.json()["role"] == "admin"
    assert (await api.repos.users.get(TENANT_A, local.id)).role == "viewer"
    assert not await _audit(api, "user.provisioned")


async def test_a_suspended_tenant_gains_no_accounts_or_audit_rows(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    await api.repos.tenants.set_status(TENANT_A, "suspended")
    refused = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Analysts"])))
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "tenant_suspended"
    assert (await api.repos.users.list(TENANT_A)).items == []
    assert (await api.repos.audit.list(TENANT_A)).items == []


async def test_a_suspended_tenant_does_not_sync_roles(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Viewers"])))).status_code == 200
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None
    audit_before = len((await api.repos.audit.list(TENANT_A)).items)
    await api.repos.tenants.set_status(TENANT_A, "suspended")
    api.ctx.tenants.invalidate(TENANT_A)
    refused = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    assert refused.status_code == 403
    assert (await api.repos.users.get(TENANT_A, user.id)).role == "viewer"
    assert len((await api.repos.audit.list(TENANT_A)).items) == audit_before


async def test_provisioning_respects_the_user_quota(make_api: Any, idp: IdP) -> None:
    api = await _jit_api(make_api, idp)
    await api.user(TENANT_A, "admin", email="adm@a.example.com")
    await api.repos.tenants.update_admin(TENANT_A, max_users=1)
    refused = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Analysts"])))
    assert refused.status_code == 409, refused.text
    error = refused.json()["error"]
    assert error["code"] == "quota_exceeded" and error["details"][0]["quota"] == "max_users"
    assert await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1") is None
    assert not await _audit(api, "user.provisioned")

    await api.repos.tenants.update_admin(TENANT_A, max_users=2)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Analysts"])))).status_code == 200
    assert await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1") is not None
