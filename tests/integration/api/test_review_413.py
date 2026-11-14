"""Reviewer probes for PR #413 (SEC6.5). Each test states what a sound implementation would do."""

from __future__ import annotations

import smtplib
from typing import Any, Callable

import pytest

from lg_sotf.integrations.delivery import OutboxDelivery
from lg_sotf.integrations.events import clean_text
from lg_sotf.runtime.scheduler import Scheduler
from tests.integration.api._break_glass import CREDENTIAL, ROOT, SMTP, URL, Mailbox
from tests.integration.api._break_glass import alerts as _alerts
from tests.integration.api._break_glass import body as _body
from tests.integration.api._break_glass import enabled as _enabled
from tests.integration.api._support import TENANT_A, ApiHarness, password_hash

pytestmark = pytest.mark.integration


async def test_no_session_when_nothing_will_deliver_the_alert(make_api: Callable[..., Any]) -> None:
    """integrations.enabled=false removes the scheduler's delivery job; break-glass must then be off."""
    auth = {"break_glass_credential_hash": password_hash(CREDENTIAL), "bootstrap_tenant_id": TENANT_A}
    api: ApiHarness = await make_api(auth=auth, integrations={**SMTP, "enabled": False})
    await api.user(TENANT_A, "admin", email=ROOT, platform_admin=True)
    response = await api.client.post(URL, json=_body())
    scheduler = Scheduler(api.ctx.settings, api.ctx.db, api.ctx.redis, lambda: None, None, None)  # type: ignore[arg-type]
    delivers = "notifications" in scheduler.jobs
    print("status", response.status_code, "delivery job registered", delivers, "queued", len(await _alerts(api)))
    assert response.status_code == 404 or delivers, "a session was issued and its alert rows are never mailed"


async def test_off_answers_like_an_unknown_route(make_api: Callable[..., Any]) -> None:
    off: ApiHarness = await make_api(api={"login_rate_limit_per_minute": 2})
    unknown = "/api/v1/auth/break-glasz"
    seen = []
    for name, call in (
        ("valid body", lambda u: off.client.post(u, json=_body())),
        ("empty body", lambda u: off.client.post(u, json={})),
        ("get", lambda u: off.client.get(u)),
        ("third post", lambda u: off.client.post(u, json=_body())),
        ("fourth post", lambda u: off.client.post(u, json=_body())),
    ):
        real, missing = await call(URL), await call(unknown)
        seen.append((name, real.status_code, missing.status_code, real.text[:120], missing.text[:120]))
    for row in seen:
        print(row)
    assert all(row[1] == row[2] for row in seen), seen


class Refusing(Mailbox):
    def send_message(self, message: Any) -> None:
        raise smtplib.SMTPSenderRefused(550, b"relay access denied", "soc@example.com")


async def test_a_rejecting_relay_does_not_end_the_alert_after_one_attempt(make_api: Callable[..., Any]) -> None:
    api = await _enabled(make_api)
    assert (await api.client.post(URL, json=_body())).status_code == 200
    await OutboxDelivery(api.repos, api.ctx.settings, smtp_factory=Refusing).run_once()
    rows = await _alerts(api)
    print([(r["status"], r["attempts"], r["last_error"]) for r in rows])
    assert {r["status"] for r in rows} != {"dead"}, "every alert is dead after one attempt; the session stays valid"


def test_reason_cannot_hide_the_account_or_address() -> None:
    for reason in (
        "password=x " * 20,
        "Authorization: Bearer abc.def.ghi and more words here",
        "x" * 300,
    ):
        title = clean_text(f"root@a.example.com (tenant acme) signed in from 203.0.113.9. Reason: {reason}")
        print(repr(title))
        assert title is not None and "root@a.example.com" in title and "203.0.113.9" in title
