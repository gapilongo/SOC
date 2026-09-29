"""Local login, refresh rotation with reuse detection, logout, lockout, API keys and the tenant override."""

from __future__ import annotations

import pytest

from lg_sotf.api.routers.auth import REFRESH_COOKIE
from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def _login(api: ApiHarness, email: str, password: str = PASSWORD, tenant: str | None = None):
    body = {"email": email, "password": password}
    if tenant is not None:
        body["tenant"] = tenant
    return await api.client.post("/api/v1/auth/login", json=body)


async def _refresh_with(api: ApiHarness, value: str):
    api.client.cookies.clear()
    api.client.cookies.set(REFRESH_COOKIE, value)
    return await api.client.post("/api/v1/auth/refresh")


def _refresh_cookie_header(response) -> str:
    return next(v for k, v in response.headers.multi_items() if k == "set-cookie" and v.startswith(REFRESH_COOKIE))


async def test_login_returns_access_token_and_hardened_refresh_cookie(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "analyst", email="Ana@Tenant-A.example.com")
    response = await _login(api, "ana@tenant-a.example.com")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == api.ctx.settings.auth.access_token_ttl_s
    assert body["user"]["id"] == str(user.id)
    assert "password_hash" not in body["user"]
    cookie = _refresh_cookie_header(response).lower()
    for attribute in ("httponly", "secure", "samesite=strict", "path=/api/v1/auth"):
        assert attribute in cookie
    me = await api.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["user_id"] == str(user.id)
    assert me.json()["role"] == "analyst"
    assert me.json()["tenant_id"] == TENANT_A
    entries = (await api.repos.audit.list(TENANT_A, action="auth.login")).items
    assert len(entries) == 1


async def test_unknown_user_and_wrong_password_get_the_same_answer(api: ApiHarness) -> None:
    await api.user(TENANT_A, "viewer", email="v@a.example.com")
    unknown = await _login(api, "nobody@a.example.com")
    wrong = await _login(api, "v@a.example.com", "wrong password here")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["error"]["code"] == wrong.json()["error"]["code"] == "invalid_credentials"
    assert unknown.json()["error"]["message"] == wrong.json()["error"]["message"]
    assert REFRESH_COOKIE not in unknown.headers.get("set-cookie", "")


async def test_lockout_after_max_attempts_refuses_even_the_right_password(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "analyst", email="lock@a.example.com")
    for _ in range(api.ctx.settings.auth.max_login_attempts):
        assert (await _login(api, "lock@a.example.com", "not the password")).status_code == 401
    locked = await api.repos.users.get(TENANT_A, user.id)
    assert locked.is_locked()
    response = await _login(api, "lock@a.example.com", PASSWORD)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"
    reasons = [
        e.details.get("reason") for e in (await api.repos.audit.list(TENANT_A, action="auth.login_failed")).items
    ]
    assert "locked_now" in reasons and "locked" in reasons


async def test_disabled_and_sso_only_accounts_cannot_log_in(api: ApiHarness) -> None:
    await api.user(TENANT_A, "analyst", email="off@a.example.com", active=False)
    await api.user(TENANT_A, "analyst", email="sso@a.example.com", password=None)
    assert (await _login(api, "off@a.example.com")).status_code == 401
    assert (await _login(api, "sso@a.example.com")).status_code == 401


async def test_email_in_two_tenants_needs_the_tenant(api: ApiHarness) -> None:
    await api.user(TENANT_A, "analyst", email="both@example.com")
    b_user = await api.user(TENANT_B, "viewer", email="both@example.com")
    assert (await _login(api, "both@example.com")).status_code == 401
    response = await _login(api, "both@example.com", tenant=TENANT_B)
    assert response.status_code == 200
    assert response.json()["user"]["id"] == str(b_user.id)


async def test_refresh_rotates_and_reuse_revokes_the_family(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "analyst", email="rot@a.example.com")
    login = await _login(api, "rot@a.example.com")
    first = login.cookies[REFRESH_COOKIE]

    rotated = await api.client.post("/api/v1/auth/refresh")
    assert rotated.status_code == 200, rotated.text
    second = rotated.cookies[REFRESH_COOKIE]
    assert second and second != first
    assert rotated.json()["access_token"]

    # Replaying the first (already rotated) token is reuse: the whole family is revoked.
    replay = await _refresh_with(api, first)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "invalid_session"
    assert (
        'lgsotf_refresh=""' in replay.headers.get("set-cookie", "")
        or "max-age=0" in replay.headers.get("set-cookie", "").lower()
    )
    after = await _refresh_with(api, second)
    assert after.status_code == 401
    audit = (await api.repos.audit.list(TENANT_A, action="auth.refresh_reuse_detected")).items
    assert len(audit) == 1 and audit[0].actor_id == str(user.id)


async def test_refresh_without_or_with_unknown_cookie_is_refused(api: ApiHarness) -> None:
    assert (await api.client.post("/api/v1/auth/refresh")).status_code == 401
    response = await _refresh_with(api, "not-a-real-token")
    assert response.status_code == 401


async def test_logout_revokes_refresh_and_access_token(api: ApiHarness) -> None:
    await api.user(TENANT_A, "analyst", email="out@a.example.com")
    login = await _login(api, "out@a.example.com")
    access = login.json()["access_token"]
    cookie = login.cookies[REFRESH_COOKIE]
    headers = {"Authorization": f"Bearer {access}"}
    assert (await api.client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    out = await api.client.post("/api/v1/auth/logout", headers=headers)
    assert out.status_code == 204
    assert (await _refresh_with(api, cookie)).status_code == 401
    me = await api.client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 401


async def test_deactivated_user_token_stops_working_immediately(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "admin")
    headers = api.auth(user)
    assert (await api.client.get("/api/v1/alerts", headers=headers)).status_code == 200
    await api.repos.users.update(TENANT_A, user.id, is_active=False)
    assert (await api.client.get("/api/v1/alerts", headers=headers)).status_code == 401


async def test_role_change_applies_to_existing_tokens(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "admin")
    headers = api.auth(user)
    assert (await api.client.get("/api/v1/users", headers=headers)).status_code == 200
    await api.repos.users.update(TENANT_A, user.id, role="viewer")
    assert (await api.client.get("/api/v1/users", headers=headers)).status_code == 403


async def test_tampered_expired_and_foreign_tokens_are_rejected(api: ApiHarness) -> None:
    import jwt as pyjwt

    user = await api.user(TENANT_A, "admin")
    token = api.token(user)
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    forged = pyjwt.encode(
        {
            "sub": str(user.id),
            "tenant": TENANT_A,
            "role": "admin",
            "typ": "access",
            "jti": "x",
            "iss": "lg-sotf",
            "aud": "lg-sotf-api",
            "iat": 1,
            "exp": 4_000_000_000,
        },
        "some-other-secret-that-is-long-enough-000",
        algorithm="HS256",
    )
    unsigned = pyjwt.encode({"sub": str(user.id)}, key=None, algorithm="none")
    for bad in (tampered, forged, unsigned, "garbage"):
        response = await api.client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {bad}"})
        assert response.status_code == 401, bad
        assert response.json()["error"]["code"] == "unauthorized"
        assert response.headers["www-authenticate"] == "Bearer"
    assert (await api.client.get("/api/v1/alerts")).status_code == 401
    basic = await api.client.get("/api/v1/alerts", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert basic.status_code == 401


async def test_api_keys_via_header_or_bearer_and_revocation(api: ApiHarness) -> None:
    key, token = await api.api_key(TENANT_A, ["read"])
    for headers in ({"X-API-Key": token}, {"Authorization": f"Bearer {token}"}):
        response = await api.client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["kind"] == "api_key"
        assert response.json()["scopes"] == ["read"]
    wrong_secret = token[:-6] + "abcdef"
    assert (await api.client.get("/api/v1/alerts", headers={"X-API-Key": wrong_secret})).status_code == 401
    await api.repos.api_keys.revoke(TENANT_A, key.id)
    assert (await api.client.get("/api/v1/alerts", headers={"X-API-Key": token})).status_code == 401
    refreshed = await api.repos.api_keys.get_by_id(TENANT_A, key.id)
    assert refreshed is not None and refreshed.last_used_at is not None


async def test_suspended_tenant_is_refused(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_B, "admin")
    await api.repos.tenants.set_status(TENANT_B, "suspended")
    api.ctx.tenants.invalidate(TENANT_B)
    response = await api.client.get("/api/v1/alerts", headers=headers)
    assert response.status_code == 403


async def test_platform_admin_override_is_audited_and_others_cannot(api: ApiHarness) -> None:
    alert_b = await make_alert(api.repos, TENANT_B, title="B only")
    platform = await api.user(TENANT_A, "admin", platform_admin=True)
    ordinary = await api.user(TENANT_A, "admin")

    denied = await api.client.get(f"/api/v1/alerts/{alert_b}", headers={**api.auth(ordinary), "X-Tenant-ID": TENANT_B})
    assert denied.status_code == 403

    headers = {**api.auth(platform), "X-Tenant-ID": TENANT_B}
    allowed = await api.client.get(f"/api/v1/alerts/{alert_b}", headers=headers)
    assert allowed.status_code == 200
    assert allowed.json()["tenant_id"] == TENANT_B
    entries = (await api.repos.audit.list(TENANT_B, action="platform_admin.tenant_access")).items
    assert len(entries) == 1
    assert entries[0].actor_id == str(platform.id)
    assert entries[0].details["home_tenant_id"] == TENANT_A
    assert entries[0].details["path"] == f"/api/v1/alerts/{alert_b}"

    missing = await api.client.get("/api/v1/alerts", headers={**api.auth(platform), "X-Tenant-ID": "no-such-tenant"})
    assert missing.status_code == 404


async def test_repeated_auth_failures_from_one_address_are_throttled(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 1})
    headers = {"Authorization": "Bearer not-a-token"}
    statuses = [(await api.client.get("/api/v1/alerts", headers=headers)).status_code for _ in range(25)]
    assert statuses[0] == 401
    assert statuses[-1] == 429


async def test_login_is_rate_limited_per_address_and_account(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 2})
    statuses = []
    for _ in range(3):
        response = await api.client.post("/api/v1/auth/login", json={"email": "x@a.example.com", "password": "p"})
        statuses.append(response.status_code)
    assert statuses == [401, 401, 429]
    assert int(response.headers["retry-after"]) >= 1
    assert response.json()["error"]["code"] == "rate_limited"
