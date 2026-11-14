"""Break-glass sign-in (SEC6.5): off by default, never silent, time-boxed, failures audited and limited.

The acceptance test is ``test_break_glass_use_is_audited_and_alerts_every_platform_admin``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.db.migrate import grant_runtime_privileges
from lg_sotf.db.repos.audit import AuditRepo
from lg_sotf.integrations.delivery import OutboxDelivery
from lg_sotf.services import break_glass
from lg_sotf.settings import DatabaseSettings
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, password_hash

pytestmark = pytest.mark.integration

URL = "/api/v1/auth/break-glass"
CREDENTIAL = "test-only-" + "sealed-break-glass-credential"
REASON = "IdP outage, incident INC-4711"
SMTP = {"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"}
ROOT = "root@a.example.com"


class Mailbox:
    """An SMTP client that keeps what it is asked to send."""

    sent: List[Any] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        pass

    def __enter__(self) -> Mailbox:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def starttls(self, context: Any) -> None:
        return None

    def send_message(self, message: Any) -> None:
        Mailbox.sent.append(message)


async def _enabled(make_api: Callable[..., Any], **overrides: Any) -> ApiHarness:
    """An API with break-glass on, and its platform admins: ``ROOT`` in tenant A, one more in tenant B."""
    auth = {"break_glass_credential_hash": password_hash(CREDENTIAL), "bootstrap_tenant_id": TENANT_A}
    api: ApiHarness = await make_api(auth=auth, integrations=SMTP, **overrides)
    await api.user(TENANT_A, "admin", email=ROOT, platform_admin=True)
    await api.user(TENANT_B, "analyst", email="second@b.example.com", platform_admin=True)
    await api.user(TENANT_B, "admin", email="left@b.example.com", platform_admin=True, active=False)
    await api.user(TENANT_A, "admin", email="tenant-admin@a.example.com")
    return api


def _body(**changes: Any) -> Dict[str, Any]:
    return {"email": ROOT, "credential": CREDENTIAL, "reason": REASON, **changes}


async def _alerts(api: ApiHarness, tenant_id: str = TENANT_A) -> List[Any]:
    async with api.repos.db.tenant_tx(tenant_id) as conn:
        return list(await conn.fetch("SELECT * FROM notification_outbox WHERE integration_id IS NULL ORDER BY created_at"))


async def _audited(api: ApiHarness, action: str) -> List[Any]:
    return (await api.repos.audit.list(TENANT_A, action=action)).items


async def test_break_glass_use_is_audited_and_alerts_every_platform_admin(make_api: Callable[..., Any]) -> None:
    api = await _enabled(make_api)
    root = await api.repos.users.get_by_email(TENANT_A, ROOT)
    assert root is not None

    response = await api.client.post(URL, json=_body())
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]

    # Audited: who, from where, why, and which session.
    [entry] = await _audited(api, "auth.break_glass_used")
    assert (entry.actor_type, entry.actor_id, entry.resource_id) == ("user", str(root.id), str(root.id))
    claims = api.ctx.tokens.verify_access(token)
    assert entry.details["reason"] == REASON and entry.details["client_ip"]
    assert entry.details["token_id"] == claims["jti"] and entry.details["admins_notified"] == 2

    # One alert per active platform admin of the install, whatever their tenant; nobody else.
    queued = await _alerts(api)
    assert sorted(row["payload"]["recipients"][0] for row in queued) == [ROOT, "second@b.example.com"]
    assert {(row["operation"], row["event_type"], row["status"]) for row in queued} == {
        ("email", "auth.break_glass_used", "pending")
    }

    # The scheduler mails each of them through the install's SMTP.
    Mailbox.sent = []
    assert await OutboxDelivery(api.repos, api.ctx.settings, smtp_factory=Mailbox).run_once() == 2
    assert sorted(message["To"] for message in Mailbox.sent) == [ROOT, "second@b.example.com"]
    subject = Mailbox.sent[0]["Subject"]
    assert subject.startswith("[LG-SOTF security] Break-glass access used") and ROOT in subject
    assert REASON in Mailbox.sent[0].get_body(("plain",)).get_content()
    assert {row["status"] for row in await _alerts(api)} == {"sent"}

    # A platform-admin session, shorter than a normal one, that cannot be extended.
    bearer = {"Authorization": f"Bearer {token}"}
    me = await api.client.get("/api/v1/auth/me", headers=bearer)
    assert me.status_code == 200 and me.json()["is_platform_admin"] is True and me.json()["email"] == ROOT
    ttl = api.ctx.settings.auth.break_glass_ttl_s
    assert response.json()["expires_in"] == claims["exp"] - claims["iat"] == ttl < api.ctx.settings.auth.access_token_ttl_s
    assert "set-cookie" not in response.headers
    assert (await api.client.post("/api/v1/auth/refresh")).status_code == 401
    # Its holder ends it early by signing out (the runbook's last step).
    assert (await api.client.post("/api/v1/auth/logout", headers=bearer)).status_code == 204
    assert (await api.client.get("/api/v1/auth/me", headers=bearer)).status_code == 401


@pytest.mark.parametrize("broken", ["audit", "alerts"])
async def test_break_glass_cannot_be_done_silently(
    make_api: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, broken: str
) -> None:
    """No session without its audit entry and its alerts: when one cannot be written, neither is and the sign-in fails."""
    api = await _enabled(make_api)

    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        if broken == "alerts" or args[4] == "auth.break_glass_used":
            raise RuntimeError(f"{broken} unavailable")
        return await append(*args, **kwargs)

    append = AuditRepo.append
    if broken == "audit":
        monkeypatch.setattr(AuditRepo, "append", unavailable)
    else:
        monkeypatch.setattr(break_glass, "enqueue_on", unavailable)

    response = await api.client.post(URL, json=_body())
    assert response.status_code == 500 and "access_token" not in response.text
    assert await _audited(api, "auth.break_glass_used") == [] and await _alerts(api) == []

    monkeypatch.undo()
    assert (await api.client.post(URL, json=_body())).status_code == 200
    assert len(await _audited(api, "auth.break_glass_used")) == 1 and len(await _alerts(api)) == 2


async def test_break_glass_is_off_by_default(make_api: Callable[..., Any]) -> None:
    """Without the operator's credential hash, or without SMTP to mail the alert, the endpoint does not exist."""
    off: ApiHarness = await make_api()
    await off.user(TENANT_A, "admin", email=ROOT, platform_admin=True)
    assert (await off.client.post(URL, json=_body())).status_code == 404

    no_mail: ApiHarness = await make_api(auth={"break_glass_credential_hash": password_hash(CREDENTIAL)})
    assert (await no_mail.client.post(URL, json=_body())).status_code == 404
    assert await _audited(off, "auth.break_glass_used") == [] and await _alerts(off) == []


async def test_a_failed_attempt_is_audited_and_gets_no_session(make_api: Callable[..., Any]) -> None:
    api = await _enabled(make_api)
    attempts = {
        "bad_credential": _body(credential="test-only-" + "wrong"),
        # The right credential opens only an active platform-admin account.
        "unknown_account": _body(email="tenant-admin@a.example.com"),
    }
    for body in (*attempts.values(), _body(email="left@b.example.com"), _body(tenant=TENANT_B)):
        response = await api.client.post(URL, json=body)
        assert response.status_code == 401 and response.json()["error"]["code"] == "invalid_credentials"

    failures = await _audited(api, "auth.break_glass_failed")
    assert [f.details["reason"] for f in reversed(failures)] == ["bad_credential"] + ["unknown_account"] * 3
    assert all(f.details["client_ip"] and f.details["email"] for f in failures)
    assert await _audited(api, "auth.break_glass_used") == [] and await _alerts(api) == []
    assert (await api.client.post(URL, json=_body(reason="short"))).status_code == 422


async def test_break_glass_is_rate_limited_like_a_login(make_api: Callable[..., Any]) -> None:
    api = await _enabled(make_api, api={"login_rate_limit_per_minute": 2})
    wrong = _body(credential="test-only-" + "wrong")
    assert [(await api.client.post(URL, json=wrong)).status_code for _ in range(3)] == [401, 401, 429]
    # Per address, whatever account is named; the right credential waits as well.
    limited = await api.client.post(URL, json=_body(email="second@b.example.com"))
    assert limited.status_code == 429 and limited.headers["Retry-After"]
    assert len(await _audited(api, "auth.break_glass_failed")) == 2


async def test_break_glass_works_as_the_runtime_role(make_api: Callable[..., Any], migrated_database_url: str) -> None:
    """The API's least-privilege role can read who the platform admins are and queue their alerts, nothing more."""
    role = "pg_database_owner"
    await asyncio.to_thread(grant_runtime_privileges, role, migrated_database_url, DatabaseSettings())
    separator = "&" if "?" in migrated_database_url else "?"
    api = await _enabled(make_api, database={"url": f"{migrated_database_url}{separator}role={role}"})
    async with api.ctx.db.connection() as conn:
        assert await conn.fetchval("SELECT current_user") == role

    assert (await api.client.post(URL, json=_body())).status_code == 200
    assert len(await _alerts(api)) == 2 and len(await _audited(api, "auth.break_glass_used")) == 1
    async with api.ctx.db.tenant_tx(TENANT_A) as conn:
        assert [row["email"] for row in await conn.fetch("SELECT email FROM users WHERE is_platform_admin")] == [ROOT]
