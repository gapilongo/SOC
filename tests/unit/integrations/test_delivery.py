"""Outbox delivery decisions (sent / retry with backoff / dead / deferred), rate limits, HTTP guard rails."""

from __future__ import annotations

import json
import smtplib
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List, Optional

import httpx
import pytest

from lg_sotf.integrations.config import encrypt_secret
from lg_sotf.integrations.delivery import OutboxDelivery, RateLimiter, backoff_s, safe_error
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.settings import Settings
from tests.unit.integrations._support import (
    Recorder,
    event,
    fake_secret,
    integration,
    outbox_entry,
    public_resolver,
    slack_url,
)

pytestmark = pytest.mark.unit


async def _no_sleep(_: float) -> None:
    return None


def _delivery(settings: Settings, recorder: Recorder, box: SecretBox, **kwargs: Any) -> OutboxDelivery:
    http = IntegrationHttp(settings, transport=recorder.transport, resolver=public_resolver, sleep=_no_sleep)
    return OutboxDelivery(object(), settings, http=http, secret_box=box, rand=lambda: 0.5, **kwargs)  # type: ignore[arg-type]


def _slack(box: SecretBox, **kwargs: Any) -> Any:
    item = integration("slack", **kwargs)
    ciphertext = encrypt_secret(box, item.tenant_id, item.id, {"webhook_url": slack_url()})
    return item.model_copy(update={"secret_ciphertext": ciphertext})


@pytest.fixture
def box() -> SecretBox:
    return SecretBox([generate_key()])


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(integrations={"backoff_base_s": 10.0, "backoff_max_s": 100.0, "max_attempts": 3},
                         api={"public_url": "https://soc.example.com"})


def test_backoff_doubles_with_jitter_and_is_capped() -> None:
    mid = lambda: 0.5  # noqa: E731 - no jitter
    assert [backoff_s(n, base_s=30, max_s=3_600, rand=mid) for n in (1, 2, 3, 4)] == [30, 60, 120, 240]
    assert backoff_s(20, base_s=30, max_s=3_600, rand=mid) == 3_600
    assert backoff_s(1, base_s=30, max_s=3_600, rand=lambda: 0.0) == 24
    assert backoff_s(1, base_s=30, max_s=3_600, rand=lambda: 1.0) == pytest.approx(36)


def test_token_bucket_rate_limit() -> None:
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    key = integration("slack").id
    assert all(limiter.acquire(key, 3) == 0 for _ in range(3))
    wait = limiter.acquire(key, 3)
    assert wait == pytest.approx(20.0)
    now[0] += 20.0
    assert limiter.acquire(key, 3) == 0


def test_errors_are_redacted() -> None:
    text = safe_error(DeliveryError("HTTP 400: token=" + "q" * 32, retryable=False))
    assert "q" * 32 not in text and text.startswith("DeliveryError: HTTP 400")


def test_errors_are_redacted_before_they_are_cut() -> None:
    text = safe_error(RuntimeError("x" * 975 + " token=" + "q" * 40))
    assert "q" * 8 not in text and len(text) == 1_000 and text.endswith("...")


async def test_success_posts_block_kit_to_the_webhook(settings: Settings, box: SecretBox) -> None:
    recorder = Recorder(httpx.Response(200, text="ok"))
    slack = _slack(box)
    outcome = await _delivery(settings, recorder, box).deliver(outbox_entry(slack.id, event()), slack)
    assert outcome.status == "sent" and outcome.result == {"http_status": 200}
    sent = recorder.requests[0]
    assert str(sent.url) == slack_url() and json.loads(sent.content)["blocks"][0]["type"] == "header"


@pytest.mark.parametrize(
    ("response", "attempts", "status", "retry_in"),
    [
        (httpx.Response(500), 1, "failed", 10.0),
        (httpx.Response(503), 2, "failed", 20.0),
        (httpx.Response(429, headers={"Retry-After": "45"}), 1, "failed", 45.0),
        (httpx.Response(500), 3, "dead", None),  # max_attempts reached
        (httpx.Response(404, text="no_team"), 1, "dead", None),  # permanent
        (httpx.Response(302, headers={"Location": "https://elsewhere"}), 1, "dead", None),
        (httpx.ConnectError("refused"), 1, "failed", 10.0),
    ],
)
async def test_failures_retry_with_backoff_or_die(
    settings: Settings, box: SecretBox, response: Any, attempts: int, status: str, retry_in: Optional[float]
) -> None:
    slack = _slack(box)
    outcome = await _delivery(settings, Recorder(response), box).deliver(
        outbox_entry(slack.id, event(), attempts=attempts), slack
    )
    assert outcome.status == status
    assert outcome.retry_in_s == retry_in
    assert outcome.error and "hooks.slack.com" not in outcome.error  # the URL is a credential


async def test_disabled_expired_and_unreadable_integrations(settings: Settings, box: SecretBox) -> None:
    recorder = Recorder()
    delivery = _delivery(settings, recorder, box)
    slack = _slack(box)
    assert (await delivery.deliver(outbox_entry(slack.id, event()), slack.model_copy(update={"enabled": False}))).status == "dead"
    assert (await delivery.deliver(outbox_entry(slack.id, event()), None)).status == "dead"
    old = outbox_entry(slack.id, event(), created_at=datetime.now(UTC) - timedelta(hours=25))
    assert (await delivery.deliver(old, slack)).error.startswith("expired")  # type: ignore[union-attr]
    other_box = SecretBox([generate_key()])
    outcome = await _delivery(settings, recorder, other_box).deliver(outbox_entry(slack.id, event()), slack)
    assert outcome.status == "failed" and "decrypted" in (outcome.error or "")  # the admin can fix the keys
    assert recorder.requests == []


async def test_rate_limited_rows_are_deferred_without_using_an_attempt(settings: Settings, box: SecretBox) -> None:
    recorder = Recorder()
    slack = _slack(box, config={"rate_limit_per_minute": 1})
    delivery = _delivery(settings, recorder, box)
    first = await delivery.deliver(outbox_entry(slack.id, event()), slack)
    second = await delivery.deliver(outbox_entry(slack.id, event()), slack)
    assert first.status == "sent"
    assert second.refund and second.status == "pending" and second.retry_in_s and second.retry_in_s > 30
    assert len(recorder.requests) == 1


async def test_generic_webhook_is_signed_and_carries_the_event_id(settings: Settings, box: SecretBox) -> None:
    from lg_sotf.services.connectors.webhook import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify_signature

    secret = fake_secret("hmac")
    hook = integration("webhook", config={"url": "https://soar.example.com/lgsotf"})
    hook = hook.model_copy(update={"secret_ciphertext": encrypt_secret(box, hook.tenant_id, hook.id, {"signing_secret": secret})})
    recorder = Recorder(httpx.Response(202))
    payload = event()
    outcome = await _delivery(settings, recorder, box).deliver(outbox_entry(hook.id, payload), hook)
    assert outcome.status == "sent"
    request = recorder.requests[0]
    body = json.loads(request.content)
    assert body["id"] == payload["id"] and body["schema"] == "lg-sotf.event.v1"
    assert request.headers["Idempotency-Key"] == payload["id"]
    # Receivers verify with the response connector's reference implementation.
    assert verify_signature(secret, request.headers[TIMESTAMP_HEADER], request.content, request.headers[SIGNATURE_HEADER])


class FakeSMTP:
    sent: List[Any] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port = host, port
        self.calls: List[str] = []

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context: Any) -> None:
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append("login")

    def send_message(self, message: Any) -> None:
        FakeSMTP.sent.append((self.calls[:], message))


async def test_email_uses_starttls_and_install_settings(make_settings: Callable[..., Settings], box: SecretBox) -> None:
    FakeSMTP.sent = []
    settings = make_settings(integrations={"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com",
                                           "smtp_username": "soc", "smtp_password": fake_secret("smtp")})
    mail = integration("email", config={"recipients": ["oncall@example.com"]})
    outcome = await _delivery(settings, Recorder(), box, smtp_factory=FakeSMTP).deliver(outbox_entry(mail.id, event()), mail)
    assert outcome.status == "sent" and outcome.result == {"recipients": 1}
    calls, message = FakeSMTP.sent[0]
    assert calls == ["ehlo", "starttls", "ehlo", "login"] and message["To"] == "oncall@example.com"


async def test_email_without_smtp_settings_or_refused_recipients(settings: Settings, box: SecretBox,
                                                                make_settings: Callable[..., Settings]) -> None:
    mail = integration("email", config={"recipients": ["oncall@example.com"]})
    outcome = await _delivery(settings, Recorder(), box).deliver(outbox_entry(mail.id, event()), mail)
    assert outcome.status == "failed" and "SMTP is not configured" in (outcome.error or "")

    class Refusing(FakeSMTP):
        def send_message(self, message: Any) -> None:
            raise smtplib.SMTPRecipientsRefused({"oncall@example.com": (550, b"no")})

    configured = make_settings(integrations={"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"})
    outcome = await _delivery(configured, Recorder(), box, smtp_factory=Refusing).deliver(outbox_entry(mail.id, event()), mail)
    assert outcome.status == "dead"


async def test_a_row_without_an_integration_is_mailed_whatever_the_tenant_state(
    settings: Settings, box: SecretBox, make_settings: Callable[..., Settings]
) -> None:
    """Operation ``email`` (a break-glass alert): no integration to disable, and suspension does not hold it back."""
    FakeSMTP.sent = []
    configured = make_settings(integrations={"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"})
    entry = outbox_entry(None, {**event(), "recipients": ["root@example.com"]}, operation="email")
    outcome = await _delivery(configured, Recorder(), box, smtp_factory=FakeSMTP).deliver(entry, None, suspended=True)
    assert outcome.status == "sent" and outcome.result == {"recipients": 1}
    message = FakeSMTP.sent[0][1]
    assert message["To"] == "root@example.com" and message["Subject"].startswith("[LG-SOTF security]")
    # Without SMTP the row is retried, never dropped.
    assert (await _delivery(settings, Recorder(), box).deliver(entry, None)).status == "failed"

    # A relay that answers 5xx is retried too (an integration's mail would be dead at once)...
    class Rejecting(FakeSMTP):
        def send_message(self, message: Any) -> None:
            raise smtplib.SMTPSenderRefused(550, b"relay access denied", "soc@example.com")

    rejecting = _delivery(configured, Recorder(), box, smtp_factory=Rejecting)
    assert (await rejecting.deliver(entry, None)).status == "failed"
    # ...and given up only after the last attempt.
    last = outbox_entry(None, entry.payload, operation="email", attempts=configured.integrations.max_attempts)
    assert (await rejecting.deliver(last, None)).status == "dead"


async def test_destination_policy_refuses_internal_addresses(settings: Settings) -> None:
    async def loopback(host: str, port: int) -> List[str]:
        return ["127.0.0.1"]

    http = IntegrationHttp(settings, transport=Recorder().transport, resolver=loopback, sleep=_no_sleep)
    with pytest.raises(DeliveryError) as err:
        await http.request("POST", "https://hooks.example.com/x", json_body={})
    assert err.value.code == "destination_refused" and not err.value.retryable


async def test_https_required_in_production(make_settings: Callable[..., Settings]) -> None:
    prod = make_settings(environment="production")
    http = IntegrationHttp(prod, transport=Recorder().transport, resolver=public_resolver)
    with pytest.raises(DeliveryError, match="https"):
        await http.request("POST", "http://hooks.example.com/x", json_body={})


async def test_response_size_is_bounded(settings: Settings) -> None:
    http = IntegrationHttp(settings, transport=Recorder(httpx.Response(200, content=b"x" * 5_000)).transport,
                           resolver=public_resolver, max_response_bytes=1_000)
    with pytest.raises(DeliveryError, match="too large"):
        await http.request("GET", "https://jira.example.com/rest")


async def test_bounded_retries_for_synchronous_calls(settings: Settings) -> None:
    recorder = Recorder(httpx.Response(503), httpx.Response(503), httpx.Response(200, json={"ok": True}))
    http = IntegrationHttp(settings, transport=recorder.transport, resolver=public_resolver, sleep=_no_sleep)
    result = await http.request("GET", "https://jira.example.com/rest", retries=2)
    assert result.status == 200 and len(recorder.requests) == 3
    with pytest.raises(DeliveryError) as err:
        await IntegrationHttp(settings, transport=Recorder(httpx.Response(503)).transport, resolver=public_resolver,
                              sleep=_no_sleep).request("GET", "https://jira.example.com/rest", retries=1)
    assert err.value.retryable and err.value.status == 503


def _guarded(settings: Settings, recorder: Recorder) -> IntegrationHttp:
    return IntegrationHttp(settings, transport=recorder.transport, resolver=public_resolver, sleep=_no_sleep)


@pytest.mark.parametrize(
    "failure",
    [httpx.Response(502), httpx.Response(504), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("dropped")],
    ids=["502", "504", "read-timeout", "dropped"],
)
async def test_non_idempotent_write_is_not_resent_after_an_ambiguous_failure(settings: Settings, failure: Any) -> None:
    # The server may have created the ticket: a blind resend would open a second one.
    recorder = Recorder(failure, httpx.Response(201, json={"key": "SOC-1"}))
    with pytest.raises(DeliveryError) as err:
        await _guarded(settings, recorder).request(
            "POST", "https://jira.example.com/rest/api/3/issue", json_body={}, retries=2, idempotent=False
        )
    assert len(recorder.requests) == 1 and err.value.retryable


@pytest.mark.parametrize(
    "failure", [httpx.Response(429), httpx.ConnectError("refused"), httpx.ConnectTimeout("no route")],
    ids=["429", "connect-error", "connect-timeout"],
)
async def test_non_idempotent_write_is_retried_when_it_never_reached_the_server(settings: Settings, failure: Any) -> None:
    recorder = Recorder(failure, httpx.Response(201, json={"key": "SOC-1"}))
    result = await _guarded(settings, recorder).request(
        "POST", "https://jira.example.com/rest/api/3/issue", json_body={}, retries=2, idempotent=False
    )
    assert result.status == 201 and len(recorder.requests) == 2
