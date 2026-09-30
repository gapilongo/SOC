"""TOTP MFA end to end: enrollment, the challenge step, replay, lockout, forced enrollment, admin reset."""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytest

from lg_sotf.api.auth import mfa as mfa_module
from lg_sotf.api.routers.auth import REFRESH_COOKIE
from lg_sotf.db.repos import User
from lg_sotf.security import totp
from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

API = "/api/v1"


class Clock:
    """The TOTP clock, advanced one 30 s step at a time so each test code is fresh."""

    def __init__(self) -> None:
        self.now = float(int(time.time()) // 30 * 30 + 5)

    def __call__(self) -> float:
        return self.now

    def tick(self, steps: int = 1) -> None:
        self.now += totp.STEP_S * steps


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(mfa_module, "clock", c)
    return c


def code_now(secret: str, clock: Clock) -> str:
    return totp.totp(secret, at=clock.now)


async def login(api: ApiHarness, email: str, password: str = PASSWORD, tenant: Optional[str] = None):
    body: Dict[str, Any] = {"email": email, "password": password}
    if tenant:
        body["tenant"] = tenant
    return await api.client.post(f"{API}/auth/login", json=body)


async def verify(api: ApiHarness, token: str, code: str):
    return await api.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": token, "code": code})


async def enroll(api: ApiHarness, user: User, clock: Clock) -> Tuple[str, List[str]]:
    headers = api.auth(user)
    started = await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=headers)
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    confirmed = await api.client.post(
        f"{API}/auth/mfa/confirm", json={"code": code_now(secret, clock)}, headers=headers
    )
    assert confirmed.status_code == 200, confirmed.text
    clock.tick()
    return secret, confirmed.json()["recovery_codes"]


async def challenge(api: ApiHarness, email: str) -> str:
    response = await login(api, email)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mfa_required"] is True and body["enrollment_required"] is False
    return body["mfa_token"]


def bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def actions(api: ApiHarness, tenant_id: str, action: str) -> List[Any]:
    return (await api.repos.audit.list(tenant_id, action=action)).items


# ---------------------------------------------------------------- enrollment and sign-in


async def test_enroll_confirm_then_sign_in_with_totp(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="mfa@a.example.com")
    headers = api.auth(user)
    status = (await api.client.get(f"{API}/auth/mfa", headers=headers)).json()
    assert status == {**status, "available": True, "enabled": False, "required": False}

    started = await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=headers)
    assert started.status_code == 200, started.text
    body = started.json()
    secret = body["secret"]
    assert body["otpauth_uri"].startswith("otpauth://totp/LG-SOTF:mfa@a.example.com?secret=" + secret)
    assert body["qr"] and len(body["qr"]) == len(body["qr"][0]) and set("".join(body["qr"])) <= {"0", "1"}
    # Pending only: login still works with the password alone.
    assert "access_token" in (await login(api, "mfa@a.example.com")).json()

    stored = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert stored is not None and not stored.enabled
    assert secret not in (stored.pending_secret_ciphertext or "")
    wrong = await api.client.post(f"{API}/auth/mfa/confirm", json={"code": "000000"}, headers=headers)
    assert wrong.status_code == 400 and wrong.json()["error"]["code"] == "invalid_mfa_code"

    confirmed = await api.client.post(
        f"{API}/auth/mfa/confirm", json={"code": code_now(secret, clock)}, headers=headers
    )
    assert confirmed.status_code == 200, confirmed.text
    codes = confirmed.json()["recovery_codes"]
    assert len(codes) == 10 and confirmed.json()["session"] is None
    stored = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert stored is not None and stored.enabled and stored.recovery_codes_remaining == 10
    assert all(c.replace("-", "") not in "".join(stored.recovery_code_hashes) for c in codes)
    assert len(await actions(api, TENANT_A, "auth.mfa_enrolled")) == 1
    again = await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=headers)
    assert again.status_code == 409

    clock.tick()
    first = await login(api, "mfa@a.example.com")
    assert first.status_code == 200
    step = first.json()
    assert step["mfa_required"] is True and step["methods"] == ["totp", "recovery_code"]
    assert "access_token" not in step
    assert REFRESH_COOKIE not in first.headers.get("set-cookie", "")

    done = await verify(api, step["mfa_token"], code_now(secret, clock))
    assert done.status_code == 200, done.text
    session = done.json()
    assert session["user"]["id"] == str(user.id) and session["user"]["mfa_enabled"] is True
    assert REFRESH_COOKIE in done.headers.get("set-cookie", "")
    me = await api.client.get(f"{API}/auth/me", headers=bearer(session["access_token"]))
    assert me.status_code == 200 and me.json()["user_id"] == str(user.id)
    logins = await actions(api, TENANT_A, "auth.login")
    assert logins[0].details["method"] == "password+totp"


async def test_a_code_cannot_be_used_twice(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="replay@a.example.com")
    secret, _ = await enroll(api, user, clock)
    code = code_now(secret, clock)
    assert (await verify(api, await challenge(api, "replay@a.example.com"), code)).status_code == 200
    replayed = await verify(api, await challenge(api, "replay@a.example.com"), code)
    assert replayed.status_code == 401
    assert replayed.json()["error"]["code"] == "invalid_mfa_code"
    # The previous step is inside the window but older than the one used: refused as well.
    previous = totp.totp(secret, at=clock.now - totp.STEP_S)
    assert (await verify(api, await challenge(api, "replay@a.example.com"), previous)).status_code == 401
    failures = await actions(api, TENANT_A, "auth.mfa_failed")
    assert [e.details["reason"] for e in failures] == ["bad_code", "bad_code"]
    clock.tick()
    assert (await verify(api, await challenge(api, "replay@a.example.com"), code_now(secret, clock))).status_code == 200


async def test_recovery_codes_sign_in_once_each(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "viewer", email="recover@a.example.com")
    _, codes = await enroll(api, user, clock)
    used = await verify(api, await challenge(api, "recover@a.example.com"), codes[3].upper())
    assert used.status_code == 200, used.text
    assert used.json()["recovery_codes_remaining"] == 9
    assert (await verify(api, await challenge(api, "recover@a.example.com"), codes[3])).status_code == 401
    assert (await actions(api, TENANT_A, "auth.mfa_recovery_code_used"))[0].details["recovery_codes_remaining"] == 9
    assert (await actions(api, TENANT_A, "auth.login"))[0].details["method"] == "password+recovery_code"


# ---------------------------------------------------------------- the challenge token


async def test_challenge_token_is_not_a_session_and_is_single_use(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "admin", email="chal@a.example.com")
    secret, _ = await enroll(api, user, clock)
    token = await challenge(api, "chal@a.example.com")
    for method, path in (("GET", "/auth/me"), ("GET", "/alerts"), ("GET", "/users"), ("GET", "/auth/mfa")):
        response = await api.client.request(method, f"{API}{path}", headers=bearer(token))
        assert response.status_code == 401, (path, response.status_code)
    # An enroll/confirm request cannot use a verification challenge (would replace the authenticator).
    hijack = await api.client.post(f"{API}/auth/mfa/enroll", json={"mfa_token": token})
    assert hijack.status_code == 401 and hijack.json()["error"]["code"] == "invalid_mfa_token"
    assert (await verify(api, token, code_now(secret, clock))).status_code == 200
    clock.tick()
    reused = await verify(api, token, code_now(secret, clock))
    assert reused.status_code == 401 and reused.json()["error"]["code"] == "invalid_mfa_token"


async def test_challenge_is_bound_to_its_user(api: ApiHarness, clock: Clock) -> None:
    alice = await api.user(TENANT_A, "analyst", email="alice@a.example.com")
    bob = await api.user(TENANT_A, "analyst", email="bob@a.example.com")
    await enroll(api, alice, clock)
    bob_secret, _ = await enroll(api, bob, clock)
    alice_token = await challenge(api, "alice@a.example.com")
    # Bob's valid code does not complete Alice's sign-in, and the body cannot name another user.
    assert (await verify(api, alice_token, code_now(bob_secret, clock))).status_code == 401
    smuggled = await api.client.post(
        f"{API}/auth/mfa/verify",
        json={"mfa_token": alice_token, "code": code_now(bob_secret, clock), "user_id": str(bob.id)},
    )
    assert smuggled.status_code == 422
    # A tampered token (another user's id, same signature) is refused.
    head, payload, signature = alice_token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = str(bob.id)
    forged_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    forged = f"{head}.{forged_payload}.{signature}"
    assert (await verify(api, forged, code_now(bob_secret, clock))).json()["error"]["code"] == "invalid_mfa_token"


async def test_challenge_expires_and_dies_with_a_password_change(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="exp@a.example.com")
    secret, _ = await enroll(api, user, clock)
    current = await api.repos.users.get(TENANT_A, user.id)
    stale = api.ctx.tokens.issue_mfa_challenge(current, "mfa", now=datetime.now(UTC) - timedelta(minutes=6))
    expired = await verify(api, stale.token, code_now(secret, clock))
    assert expired.status_code == 401 and expired.json()["error"]["code"] == "invalid_mfa_token"

    token = await challenge(api, "exp@a.example.com")
    admin = await api.user(TENANT_A, "admin", email="boss@a.example.com")
    changed = await api.client.patch(
        f"{API}/users/{user.id}", json={"password": "an entirely new passphrase"}, headers=api.auth(admin)
    )
    assert changed.status_code == 200
    assert (await verify(api, token, code_now(secret, clock))).json()["error"]["code"] == "invalid_mfa_token"


# ---------------------------------------------------------------- lockout


async def test_wrong_codes_count_toward_the_lockout(api: ApiHarness, clock: Clock) -> None:
    max_attempts = api.ctx.settings.auth.max_login_attempts
    assert max_attempts == 3
    user = await api.user(TENANT_A, "analyst", email="guess@a.example.com")
    secret, _ = await enroll(api, user, clock)
    # Re-entering the right password between guesses never resets the count.
    assert (await verify(api, await challenge(api, "guess@a.example.com"), "111111")).status_code == 401
    assert (await verify(api, await challenge(api, "guess@a.example.com"), "222222")).status_code == 401
    token = await challenge(api, "guess@a.example.com")
    assert (await verify(api, token, "333333")).status_code == 401
    locked = await api.repos.users.get(TENANT_A, user.id)
    assert locked.is_locked()
    # Locked: neither the password nor a right code gets through.
    assert (await login(api, "guess@a.example.com")).status_code == 401
    assert (await verify(api, token, code_now(secret, clock))).status_code == 401
    reasons = [e.details["reason"] for e in await actions(api, TENANT_A, "auth.mfa_failed")]
    assert "locked_now" in reasons and "locked" in reasons
    assert not await actions(api, TENANT_A, "auth.login")


async def test_a_successful_second_factor_clears_earlier_failures(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="ok@a.example.com")
    secret, _ = await enroll(api, user, clock)
    assert (await login(api, "ok@a.example.com", "wrong password")).status_code == 401
    assert (await verify(api, await challenge(api, "ok@a.example.com"), "111111")).status_code == 401
    assert (await api.repos.users.get(TENANT_A, user.id)).failed_logins == 2
    assert (await verify(api, await challenge(api, "ok@a.example.com"), code_now(secret, clock))).status_code == 200
    assert (await api.repos.users.get(TENANT_A, user.id)).failed_logins == 0


# ---------------------------------------------------------------- policy and forced enrollment


async def test_tenant_policy_forces_enrollment_before_anything_else(api: ApiHarness, clock: Clock) -> None:
    admin = await api.user(TENANT_A, "admin", email="admin@a.example.com")
    user = await api.user(TENANT_A, "analyst", email="late@a.example.com")
    old_session = await login(api, "late@a.example.com")
    assert old_session.status_code == 200
    refresh_cookie = old_session.cookies[REFRESH_COOKIE]

    patched = await api.client.patch(
        f"{API}/tenant/settings", json={"security": {"require_mfa": True}}, headers=api.auth(admin)
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["settings"]["security"] == {"require_mfa": True}
    bad = await api.client.patch(
        f"{API}/tenant/settings", json={"security": {"require_mfa": "yes"}}, headers=api.auth(admin)
    )
    assert bad.status_code == 422

    # An existing session cannot be refreshed past the new policy.
    api.client.cookies.clear()
    api.client.cookies.set(REFRESH_COOKIE, refresh_cookie)
    assert (await api.client.post(f"{API}/auth/refresh")).status_code == 401
    api.client.cookies.clear()

    first = (await login(api, "late@a.example.com")).json()
    assert first["mfa_required"] is True and first["enrollment_required"] is True and first["methods"] == []
    token = first["mfa_token"]
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(token))).status_code == 401
    assert (await verify(api, token, "123456")).json()["error"]["code"] == "invalid_mfa_token"
    no_token = await api.client.post(f"{API}/auth/mfa/confirm", json={"code": "123456"})
    assert no_token.status_code == 401

    started = await api.client.post(f"{API}/auth/mfa/enroll", json={"mfa_token": token})
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    wrong = await api.client.post(f"{API}/auth/mfa/confirm", json={"mfa_token": token, "code": "000000"})
    assert wrong.status_code == 401 and wrong.json()["error"]["code"] == "invalid_mfa_code"
    done = await api.client.post(
        f"{API}/auth/mfa/confirm", json={"mfa_token": token, "code": code_now(secret, clock)}
    )
    assert done.status_code == 200, done.text
    body = done.json()
    assert len(body["recovery_codes"]) == 10
    assert body["session"]["user"]["id"] == str(user.id)
    assert REFRESH_COOKIE in done.headers.get("set-cookie", "")
    me = await api.client.get(f"{API}/auth/me", headers=bearer(body["session"]["access_token"]))
    assert me.status_code == 200
    # The enrollment challenge is spent.
    assert (await api.client.post(f"{API}/auth/mfa/enroll", json={"mfa_token": token})).status_code == 401
    assert (await actions(api, TENANT_A, "auth.login"))[0].details["method"] == "password+mfa_enrollment"
    # From now on the normal challenge applies.
    clock.tick()
    assert (await verify(api, await challenge(api, "late@a.example.com"), code_now(secret, clock))).status_code == 200


async def test_platform_admins_must_enroll_when_the_install_requires_it(make_api, clock: Clock) -> None:
    api = await make_api(auth={"require_mfa_for_platform_admins": True})
    await api.user(TENANT_A, "admin", email="root@a.example.com", platform_admin=True)
    await api.user(TENANT_A, "admin", email="plain@a.example.com")
    root = (await login(api, "root@a.example.com")).json()
    assert root["mfa_required"] is True and root["enrollment_required"] is True
    assert "access_token" in (await login(api, "plain@a.example.com")).json()


async def test_platform_admin_mfa_is_off_by_default_in_tests(api: ApiHarness) -> None:
    await api.user(TENANT_A, "admin", email="root2@a.example.com", platform_admin=True)
    assert "access_token" in (await login(api, "root2@a.example.com")).json()


# ---------------------------------------------------------------- self-service management


async def test_disable_needs_password_and_code_and_counts_failures(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="off@a.example.com")
    secret, codes = await enroll(api, user, clock)
    headers = api.auth(user)
    bad_password = await api.client.post(
        f"{API}/auth/mfa/disable", json={"password": "not it", "code": code_now(secret, clock)}, headers=headers
    )
    assert bad_password.status_code == 400 and bad_password.json()["error"]["code"] == "invalid_credentials"
    bad_code = await api.client.post(
        f"{API}/auth/mfa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )
    assert bad_code.status_code == 400 and bad_code.json()["error"]["code"] == "invalid_mfa_code"
    assert (await api.repos.users.get(TENANT_A, user.id)).failed_logins == 2
    ok = await api.client.post(
        f"{API}/auth/mfa/disable", json={"password": PASSWORD, "code": code_now(secret, clock)}, headers=headers
    )
    assert ok.status_code == 204, ok.text
    assert await api.repos.user_mfa.get(TENANT_A, user.id) is None
    assert len(await actions(api, TENANT_A, "auth.mfa_disabled")) == 1
    assert "access_token" in (await login(api, "off@a.example.com")).json()
    assert codes  # recovery codes died with the enrollment
    again = await api.client.post(
        f"{API}/auth/mfa/disable", json={"password": PASSWORD, "code": codes[0]}, headers=headers
    )
    assert again.status_code == 409


async def test_regenerate_recovery_codes_needs_a_totp_code(api: ApiHarness, clock: Clock) -> None:
    user = await api.user(TENANT_A, "analyst", email="regen@a.example.com")
    secret, old_codes = await enroll(api, user, clock)
    headers = api.auth(user)
    with_recovery = await api.client.post(
        f"{API}/auth/mfa/recovery-codes", json={"code": old_codes[0]}, headers=headers
    )
    assert with_recovery.status_code == 400
    fresh = await api.client.post(
        f"{API}/auth/mfa/recovery-codes", json={"code": code_now(secret, clock)}, headers=headers
    )
    assert fresh.status_code == 200, fresh.text
    new_codes = fresh.json()["recovery_codes"]
    assert len(new_codes) == 10 and not set(new_codes) & set(old_codes)
    assert (await verify(api, await challenge(api, "regen@a.example.com"), old_codes[1])).status_code == 401
    assert (await verify(api, await challenge(api, "regen@a.example.com"), new_codes[1])).status_code == 200
    assert len(await actions(api, TENANT_A, "auth.mfa_recovery_codes_regenerated")) == 1


async def test_sso_and_api_key_principals_cannot_manage_mfa(api: ApiHarness) -> None:
    sso = await api.user(TENANT_A, "analyst", email="sso@a.example.com", password=None)
    assert (await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=api.auth(sso))).status_code == 403
    status = await api.client.get(f"{API}/auth/mfa", headers=api.auth(sso))
    assert status.json()["available"] is False
    key = await api.key_headers(TENANT_A, ["read", "write"])
    assert (await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=key)).status_code == 403


# ---------------------------------------------------------------- admin reset


async def test_admin_resets_a_user_s_mfa_and_ends_their_sessions(api: ApiHarness, clock: Clock) -> None:
    admin = await api.user(TENANT_A, "admin", email="adm@a.example.com")
    user = await api.user(TENANT_A, "analyst", email="lost@a.example.com")
    await enroll(api, user, clock)
    await api.repos.refresh_tokens.create(
        TENANT_A, user.id, "a" * 64, datetime.now(UTC) + timedelta(days=1)
    )
    listed = await api.client.get(f"{API}/users", headers=api.auth(admin))
    flags = {u["email"]: u["mfa_enabled"] for u in listed.json()}
    assert flags == {"adm@a.example.com": False, "lost@a.example.com": True}

    analyst = await api.user(TENANT_A, "analyst", email="peer@a.example.com")
    assert (await api.client.post(f"{API}/users/{user.id}/mfa/reset", headers=api.auth(analyst))).status_code == 403
    assert (await api.client.post(f"{API}/users/{admin.id}/mfa/reset", headers=api.auth(admin))).status_code == 403
    reset = await api.client.post(f"{API}/users/{user.id}/mfa/reset", headers=api.auth(admin))
    assert reset.status_code == 204, reset.text
    assert await api.repos.user_mfa.get(TENANT_A, user.id) is None
    entry = (await actions(api, TENANT_A, "auth.mfa_reset"))[0]
    assert entry.actor_id == str(admin.id)
    assert entry.details["was_enabled"] is True and entry.details["revoked_sessions"] == 1
    assert "access_token" in (await login(api, "lost@a.example.com")).json()


async def test_reset_is_confined_to_the_admin_s_tenant(api: ApiHarness, clock: Clock) -> None:
    victim = await api.user(TENANT_A, "analyst", email="victim@a.example.com")
    await enroll(api, victim, clock)
    other_admin = await api.user(TENANT_B, "admin", email="adm@b.example.com")
    cross = await api.client.post(f"{API}/users/{victim.id}/mfa/reset", headers=api.auth(other_admin))
    assert cross.status_code == 404
    override = await api.client.post(
        f"{API}/users/{victim.id}/mfa/reset", headers={**api.auth(other_admin), "X-Tenant-ID": TENANT_A}
    )
    assert override.status_code == 403
    assert (await api.repos.user_mfa.get(TENANT_A, victim.id)) is not None
    assert not await actions(api, TENANT_A, "auth.mfa_reset")


async def test_only_a_platform_admin_resets_a_platform_admin_or_across_tenants(api: ApiHarness, clock: Clock) -> None:
    root = await api.user(TENANT_A, "admin", email="root@a.example.com", platform_admin=True)
    await enroll(api, root, clock)
    tenant_admin = await api.user(TENANT_A, "admin", email="adm@a.example.com")
    refused = await api.client.post(f"{API}/users/{root.id}/mfa/reset", headers=api.auth(tenant_admin))
    assert refused.status_code == 403

    operator = await api.user(TENANT_B, "admin", email="ops@b.example.com", platform_admin=True)
    reset = await api.client.post(
        f"{API}/users/{root.id}/mfa/reset", headers={**api.auth(operator), "X-Tenant-ID": TENANT_A}
    )
    assert reset.status_code == 204, reset.text
    entry = (await actions(api, TENANT_A, "auth.mfa_reset"))[0]
    assert entry.actor_id == str(operator.id)
    assert entry.details["by_platform_admin"] is True and entry.details["actor_home_tenant_id"] == TENANT_B
    assert await actions(api, TENANT_A, "platform_admin.tenant_access")


async def test_cli_reset_is_audited(api: ApiHarness, clock: Clock) -> None:
    from lg_sotf.runtime.ops import OperationError, reset_mfa

    user = await api.user(TENANT_A, "analyst", email="cli@a.example.com")
    await enroll(api, user, clock)
    report = await reset_mfa(api.ctx.settings, tenant_id=TENANT_A, email="CLI@a.example.com")
    assert report.was_enabled and report.user_id == str(user.id)
    assert await api.repos.user_mfa.get(TENANT_A, user.id) is None
    entry = (await actions(api, TENANT_A, "auth.mfa_reset"))[0]
    assert (entry.actor_type, entry.actor_id, entry.details["via"]) == ("system", "cli", "cli")
    with pytest.raises(OperationError):
        await reset_mfa(api.ctx.settings, tenant_id=TENANT_B, email="cli@a.example.com")
