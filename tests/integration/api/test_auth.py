"""Local login, refresh rotation with reuse detection, logout, lockout, API keys and the tenant override."""

from __future__ import annotations

import pytest

from lg_sotf.api.routers.auth import REFRESH_COOKIE
from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness, fresh_rate_window
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


async def test_concurrent_logins_cannot_exceed_the_lockout_budget(api: ApiHarness, monkeypatch) -> None:
    """AUTHZ-1: attempts are counted before argon2, so a burst runs at most max checks and a
    correct password that arrives while the account locks is refused."""
    import asyncio

    import httpx

    from lg_sotf.api.auth import service as auth_service

    max_attempts = api.ctx.settings.auth.max_login_attempts
    user = await api.user(TENANT_A, "admin", email="burst@a.example.com")
    checks = 0
    real_verify = auth_service.averify_password

    async def counting_verify(hashed: str, password: str) -> bool:
        nonlocal checks
        checks += 1
        await asyncio.sleep(0.05)  # keep every request in flight together
        return await real_verify(hashed, password)

    monkeypatch.setattr(auth_service, "averify_password", counting_verify)

    async def attempt(i: int, password: str) -> int:
        transport = httpx.ASGITransport(app=api.app, client=(f"10.9.{i // 250}.{i % 250 + 1}", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            response = await client.post(
                "/api/v1/auth/login", json={"email": "burst@a.example.com", "password": password}
            )
            return response.status_code

    guesses = [f"wrong-guess-{i:04d}-xyz" for i in range(2 * max_attempts)] + [PASSWORD]
    statuses = await asyncio.gather(*(attempt(i, pw) for i, pw in enumerate(guesses)))
    assert checks <= max_attempts, f"{checks} password checks ran, budget is {max_attempts}"
    assert statuses[-1] == 401
    assert set(statuses) == {401}
    after = await api.repos.users.get(TENANT_A, user.id)
    assert after.is_locked()
    assert not (await api.repos.audit.list(TENANT_A, action="auth.login")).items


async def test_correct_password_in_flight_does_not_clear_a_fresh_lock(api: ApiHarness) -> None:
    user = await api.user(TENANT_A, "analyst", email="inflight@a.example.com")
    reserved = await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15)
    assert reserved is not None
    for _ in range(2):
        assert await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15) is not None
    assert await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15) is None
    locked = await api.repos.users.record_login_failure(
        TENANT_A, user.id, max_attempts=3, lockout_minutes=15, counted=True
    )
    assert locked.is_locked()
    # The first reservation was the right password; it must not wipe the lock.
    assert await api.repos.users.record_login_success(TENANT_A, user.id) is None
    assert (await api.repos.users.get(TENANT_A, user.id)).is_locked()


async def test_unsettled_reservations_become_a_lock_that_expires(api: ApiHarness) -> None:
    """Attempts reserved by requests that never settled (crash) must not refuse the account forever."""
    from datetime import UTC, datetime, timedelta

    user = await api.user(TENANT_A, "analyst", email="crashed@a.example.com")
    for _ in range(3):
        assert await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15) is not None
    assert await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15) is None
    assert (await api.repos.users.get(TENANT_A, user.id)).is_locked()
    later = datetime.now(UTC) + timedelta(minutes=16)
    again = await api.repos.users.reserve_login_attempt(TENANT_A, user.id, max_attempts=3, lockout_minutes=15, now=later)
    assert again is not None and again.failed_logins == 1 and again.locked_until is None


async def test_email_registered_in_another_tenant_does_not_block_tenantless_login(api: ApiHarness) -> None:
    """AUTHZ-7: another tenant's admin registering the same email cannot break sign-in."""
    victim = await api.user(TENANT_A, "admin", email="ceo@victim.example")
    await api.user(TENANT_B, "viewer", email="ceo@victim.example", password="some other long password")
    response = await _login(api, "ceo@victim.example")
    assert response.status_code == 200, response.text
    assert response.json()["user"]["id"] == str(victim.id)
    squatter = await _login(api, "ceo@victim.example", "some other long password")
    assert squatter.status_code == 200
    assert squatter.json()["user"]["tenant_id"] == TENANT_B
    wrong = await _login(api, "ceo@victim.example", "neither of the two passwords")
    assert wrong.status_code == 401 and wrong.json()["error"]["code"] == "invalid_credentials"


async def test_disabled_and_sso_only_accounts_cannot_log_in(api: ApiHarness) -> None:
    await api.user(TENANT_A, "analyst", email="off@a.example.com", active=False)
    await api.user(TENANT_A, "analyst", email="sso@a.example.com", password=None)
    assert (await _login(api, "off@a.example.com")).status_code == 401
    assert (await _login(api, "sso@a.example.com")).status_code == 401


async def test_email_in_two_tenants_needs_the_tenant(api: ApiHarness) -> None:
    await api.user(TENANT_A, "analyst", email="both@example.com")
    b_user = await api.user(TENANT_B, "viewer", email="both@example.com")
    ambiguous = await _login(api, "both@example.com")
    assert ambiguous.status_code == 401
    assert ambiguous.json()["error"]["code"] == "tenant_required"
    # The ambiguous answer does not use up the accounts' lockout budgets.
    assert (await api.repos.users.get_by_email(TENANT_B, "both@example.com")).failed_logins == 0
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


async def test_logout_racing_a_refresh_revokes_the_rotated_cookie(api: ApiHarness) -> None:
    # The sign-out e2e flake: a reload's refresh rotated the cookie before the
    # logout (which presented the old one) revoked it, and the new one survived.
    await api.user(TENANT_A, "analyst", email="race@a.example.com")
    old = (await _login(api, "race@a.example.com")).cookies[REFRESH_COOKIE]
    rotated = await _refresh_with(api, old)
    assert rotated.status_code == 200
    new = rotated.cookies[REFRESH_COOKIE]

    api.client.cookies.clear()
    api.client.cookies.set(REFRESH_COOKIE, old)
    assert (await api.client.post("/api/v1/auth/logout")).status_code == 204
    assert (await _refresh_with(api, new)).status_code == 401


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
    await fresh_rate_window()
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


async def test_per_address_login_cap_counts_only_failures(make_api) -> None:
    """WSC-1: users sharing one address (a proxy) are not refused because of each other's valid logins,
    while failures from that address are still capped."""
    api = await make_api(api={"login_rate_limit_per_minute": 1})  # address cap: 10 per minute
    for i in range(12):
        await api.user(TENANT_A, "viewer", email=f"shared{i}@a.example.com")
    await fresh_rate_window()
    for i in range(12):
        ok = await api.client.post(
            "/api/v1/auth/login", json={"email": f"shared{i}@a.example.com", "password": PASSWORD}
        )
        assert ok.status_code == 200, (i, ok.text)
    failures = [
        (
            await api.client.post("/api/v1/auth/login", json={"email": f"nobody{i}@a.example.com", "password": "wrong"})
        ).status_code
        for i in range(12)
    ]
    assert failures[:10] == [401] * 10 and failures[10:] == [429, 429]


async def test_cookie_endpoints_refuse_other_origins(api: ApiHarness) -> None:
    """WSC-8: a same-site sibling origin cannot rotate (and so revoke) or log out a user's session."""
    from tests.integration.api.conftest import UI_ORIGIN

    await api.user(TENANT_A, "analyst", email="csrf@a.example.com")
    assert (await _login(api, "csrf@a.example.com")).status_code == 200
    evil = {"Origin": "https://attacker.soc.example.com", "Content-Type": "text/plain"}
    for path in ("/api/v1/auth/refresh", "/api/v1/auth/logout"):
        refused = await api.client.post(path, headers=evil)
        assert refused.status_code == 403, (path, refused.text)
    cross = await api.client.post("/api/v1/auth/refresh", headers={"Sec-Fetch-Site": "cross-site"})
    assert cross.status_code == 403
    assert not (await api.repos.audit.list(TENANT_A, action="auth.refresh_reuse_detected")).items
    # The session is intact: the UI's own origin and non-browser clients still work.
    assert (await api.client.post("/api/v1/auth/refresh", headers={"Origin": UI_ORIGIN})).status_code == 200
    assert (await api.client.post("/api/v1/auth/refresh")).status_code == 200
    assert (await api.client.post("/api/v1/auth/logout", headers={"Origin": "https://testserver"})).status_code == 204
