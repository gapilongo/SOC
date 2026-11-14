"""Break-glass sign-in (SEC6.5): off by default, never silent, time-boxed, failures audited and limited.

The acceptance test is ``test_break_glass_use_is_audited_and_alerts_every_platform_admin``.
"""

from __future__ import annotations

import asyncio
import smtplib
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

import pytest

from lg_sotf.db.migrate import grant_runtime_privileges
from lg_sotf.db.repos.audit import AuditRepo
from lg_sotf.integrations.delivery import UNDELIVERED_SECURITY_ALERTS, OutboxDelivery
from lg_sotf.security.hashing import sha256_hex
from lg_sotf.services import break_glass
from lg_sotf.settings import DatabaseSettings
from tests.integration.api._break_glass import (
    CREDENTIAL,
    REASON,
    ROOT,
    SMTP,
    URL,
    Mailbox,
    alerts,
    audited,
    body,
    enabled,
)
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, password_hash
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

WRONG = "test-only-" + "wrong"


async def test_break_glass_use_is_audited_and_alerts_every_platform_admin(make_api: Callable[..., Any]) -> None:
    api = await enabled(make_api)
    root = await api.repos.users.get_by_email(TENANT_A, ROOT)
    assert root is not None

    response = await api.client.post(URL, json=body())
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]

    # Audited: who, from where, why, and which session.
    [entry] = await audited(api, "auth.break_glass_used")
    assert (entry.actor_type, entry.actor_id, entry.resource_id) == ("user", str(root.id), str(root.id))
    claims = api.ctx.tokens.verify_access(token)
    assert entry.details["reason"] == REASON and entry.details["client_ip"]
    assert entry.details["token_id"] == claims["jti"] and entry.details["admins_notified"] == 2

    # One alert per active platform admin of the install, whatever their tenant; nobody else.
    queued = await alerts(api)
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
    assert {row["status"] for row in await alerts(api)} == {"sent"}

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


async def test_the_session_is_marked_in_the_audit_log_and_honours_no_grant(make_api: Callable[..., Any]) -> None:
    """The token says ``break_glass``: its audit entries carry the method, and a grant to its organisation is not used."""
    api = await enabled(make_api)
    root = await api.repos.users.get_by_email(TENANT_A, ROOT)
    assert root is not None
    # Tenant A is an MSSP organisation, the account a member, and tenant B granted it the admin role.
    await api.repos.organisations.upsert(TENANT_A, "MSSP")
    await api.repos.organisations.add_member(TENANT_A, root.id)
    await api.repos.grants.create(
        TENANT_B, TENANT_A, "admin", reason="24/7 cover", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=8),
    )
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_B, await make_alert(api.repos, TENANT_B), reason="review",
        sla_deadline=datetime.now(UTC) + timedelta(hours=1),
    )
    decision = {"decision": "false_positive", "version": escalation.version}
    path = f"/api/v1/escalations/{escalation.id}/decision"

    token = (await api.client.post(URL, json=body())).json()["access_token"]
    session = {"Authorization": f"Bearer {token}", "X-Tenant-ID": TENANT_B}
    assert (await api.client.get("/api/v1/auth/me", headers=session)).json()["auth_method"] == "break_glass"
    assert (await api.client.post(path, json=decision, headers=session)).status_code == 403
    assert await audited(api, "grant.tenant_access", TENANT_B) == []
    accesses = await audited(api, "platform_admin.tenant_access", TENANT_B)
    assert accesses and all(entry.details["auth_method"] == "break_glass" for entry in accesses)

    # The same account signed in the normal way does act under the grant, and is not marked.
    normal = {**api.auth(root), "X-Tenant-ID": TENANT_B}
    assert (await api.client.post(path, json=decision, headers=normal)).status_code == 200
    [granted, *_] = await audited(api, "grant.tenant_access", TENANT_B)
    assert "auth_method" not in granted.details


async def test_an_alert_that_cannot_be_mailed_is_retried_then_counted(make_api: Callable[..., Any]) -> None:
    """A rejecting relay does not end the alert at once; when it is given up, a metric an operator pages on moves."""

    class Rejecting(Mailbox):
        def send_message(self, message: Any) -> None:
            raise smtplib.SMTPSenderRefused(550, b"relay access denied", "soc@example.com")

    api = await enabled(make_api, integrations={**SMTP, "max_attempts": 2})
    assert (await api.client.post(URL, json=body())).status_code == 200
    delivery = OutboxDelivery(api.repos, api.ctx.settings, smtp_factory=Rejecting)
    undelivered = UNDELIVERED_SECURITY_ALERTS.labels(event_type="auth.break_glass_used")
    before = undelivered._value.get()

    await delivery.run_once()
    assert {(row["status"], row["attempts"]) for row in await alerts(api)} == {("failed", 1)}
    async with api.repos.db.system_tx() as conn:
        await conn.execute("UPDATE notification_outbox SET next_attempt_at = now()")
    await delivery.run_once()
    assert {(row["status"], row["attempts"]) for row in await alerts(api)} == {("dead", 2)}
    assert undelivered._value.get() - before == 2


@pytest.mark.parametrize("broken", ["audit", "alerts"])
async def test_break_glass_cannot_be_done_silently(
    make_api: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, broken: str
) -> None:
    """No session without its audit entry and its alerts: when one cannot be written, neither is and the sign-in fails."""
    api = await enabled(make_api)

    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        if broken == "alerts" or args[4] == "auth.break_glass_used":
            raise RuntimeError(f"{broken} unavailable")
        return await append(*args, **kwargs)

    append = AuditRepo.append
    if broken == "audit":
        monkeypatch.setattr(AuditRepo, "append", unavailable)
    else:
        monkeypatch.setattr(break_glass, "enqueue_on", unavailable)

    response = await api.client.post(URL, json=body())
    assert response.status_code == 500 and "access_token" not in response.text
    assert await audited(api, "auth.break_glass_used") == [] and await alerts(api) == []

    monkeypatch.undo()
    assert (await api.client.post(URL, json=body())).status_code == 200
    assert len(await audited(api, "auth.break_glass_used")) == 1 and len(await alerts(api)) == 2


async def test_break_glass_is_off_by_default(make_api: Callable[..., Any]) -> None:
    """Without the operator's credential hash, or without SMTP to mail the alert, the route does not exist."""
    off: ApiHarness = await make_api()
    await off.user(TENANT_A, "admin", email=ROOT, platform_admin=True)

    def answer(response: Any) -> Any:
        error = response.json()["error"]
        return response.status_code, error["code"], error["message"]

    unknown = answer(await off.client.post("/api/v1/auth/no-such-route", json=body()))
    assert unknown[0] == 404
    for api in (off, await make_api(auth={"break_glass_credential_hash": password_hash(CREDENTIAL)})):
        for request in (api.client.post(URL, json=body()), api.client.post(URL, json={}), api.client.get(URL)):
            assert answer(await request) == unknown
        assert URL not in api.app.openapi()["paths"]
    assert await audited(off, "auth.break_glass_used") == [] and await alerts(off) == []


async def test_a_failed_attempt_is_audited_and_gets_no_session(make_api: Callable[..., Any]) -> None:
    api = await enabled(make_api)
    root = await api.repos.users.get_by_email(TENANT_A, ROOT)
    assert root is not None
    pasted = "test-only-" + "credential-pasted-into-the-email-field"
    attempts = (
        body(credential=WRONG),  # a wrong credential naming a real platform admin: audited like a failed login
        body(credential=WRONG, email=pasted),  # ...naming nobody: logged only, as an unknown login is
        # The right credential opens only an active platform-admin account.
        body(email=pasted),
        body(email="tenant-admin@a.example.com"),
        body(email="left@b.example.com"),
        body(tenant=TENANT_B),
    )
    for attempt in attempts:
        response = await api.client.post(URL, json=attempt)
        assert response.status_code == 401 and response.json()["error"]["code"] == "invalid_credentials"

    failures = list(reversed(await audited(api, "auth.break_glass_failed")))
    assert [f.details["reason"] for f in failures] == ["bad_credential"] + ["unknown_account"] * 4
    assert (failures[0].resource_type, failures[0].resource_id) == ("user", str(root.id))
    assert failures[1].details["account_sha256"] == sha256_hex(pasted)[:16]
    # What the caller typed as the account is never stored, only the address and a short hash.
    assert all(f.details["client_ip"] and "email" not in f.details and pasted not in str(f.details) for f in failures)
    assert await audited(api, "auth.break_glass_used") == [] and await alerts(api) == []
    assert (await api.client.post(URL, json=body(reason="short"))).status_code == 422


async def test_only_failures_are_rate_limited(make_api: Callable[..., Any]) -> None:
    api = await enabled(make_api, api={"login_rate_limit_per_minute": 2})
    # Successful uses never count: the path cannot be exhausted by using it.
    assert [(await api.client.post(URL, json=body())).status_code for _ in range(3)] == [200, 200, 200]
    wrong = body(credential=WRONG)
    assert [(await api.client.post(URL, json=wrong)).status_code for _ in range(3)] == [401, 401, 429]
    # An address that keeps failing waits, whatever account it names and even with the right credential.
    limited = await api.client.post(URL, json=body(email="second@b.example.com"))
    assert limited.status_code == 429 and limited.headers["Retry-After"]
    assert len(await audited(api, "auth.break_glass_failed")) == 2


async def test_break_glass_works_as_the_runtime_role(make_api: Callable[..., Any], migrated_database_url: str) -> None:
    """The API's least-privilege role can read who the platform admins are and queue their alerts, nothing more."""
    role = "pg_database_owner"
    await asyncio.to_thread(grant_runtime_privileges, role, migrated_database_url, DatabaseSettings())
    separator = "&" if "?" in migrated_database_url else "?"
    api = await enabled(make_api, database={"url": f"{migrated_database_url}{separator}role={role}"})
    async with api.ctx.db.connection() as conn:
        assert await conn.fetchval("SELECT current_user") == role

    assert (await api.client.post(URL, json=body())).status_code == 200
    assert len(await alerts(api)) == 2 and len(await audited(api, "auth.break_glass_used")) == 1
    async with api.ctx.db.tenant_tx(TENANT_A) as conn:
        assert [row["email"] for row in await conn.fetch("SELECT email FROM users WHERE is_platform_admin")] == [ROOT]
