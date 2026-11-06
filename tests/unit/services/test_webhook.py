"""WebhookConnector and ConnectorRegistry: signing, retries, idempotency, destination policy, TLS, caps."""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, List, Optional, Sequence

import httpx
import pytest

from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.services.connectors import (
    ConnectorConfigError,
    ConnectorRegistry,
    DryRunConnector,
    MisconfiguredConnector,
    WebhookConnector,
    WebhookTarget,
    encrypt_webhook_secret,
    sign,
    verify_request,
    verify_signature,
)
from lg_sotf.services.connectors.webhook import (
    DELIVERY_HEADER,
    EVENT_HEADER,
    IDEMPOTENCY_HEADER,
    SCHEMA,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
)
from lg_sotf.settings import Settings
from tests.unit.services._support import make_action

SECRET = b"s3cr3t-webhook-key-0123456789abcdef"
URL = "https://soar.example.com/hooks/lgsotf"
NOW = 1_790_000_000.0


class Soar:
    """A MockTransport handler that answers with a scripted sequence of responses and records requests."""

    def __init__(self, responses: Sequence[Any]) -> None:
        self.responses = list(responses)
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        return item


def resolver_to(*addresses: str) -> Callable[[str, int], Any]:
    async def resolve(host: str, port: int) -> List[str]:
        return list(addresses)

    return resolve


def connector(
    soar: Soar,
    *,
    policy: Optional[DestinationPolicy] = None,
    resolver: Optional[Callable[[str, int], Any]] = None,
    url: str = URL,
    **kw: Any,
) -> tuple[WebhookConnector, List[float]]:
    sleeps: List[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    return (
        WebhookConnector(
            WebhookTarget(url=url, secret=SECRET),
            policy=policy or DestinationPolicy(require_https=True),
            target_kinds={"block_ip": "ip"},
            transport=httpx.MockTransport(soar),
            resolver=resolver or resolver_to("93.184.216.34"),
            sleep=sleep,
            rand=lambda: 0.5,
            clock=lambda: NOW,
            **kw,
        ),
        sleeps,
    )


async def test_signed_request_with_idempotency_key_and_documented_payload() -> None:
    soar = Soar([httpx.Response(200, json={"status": "succeeded", "reference": "case-42"})])
    hook, _ = connector(soar)
    action = make_action()
    result = await hook.execute(action)

    assert result.status == "succeeded"
    assert result.detail["http_status"] == 200 and result.detail["response"] == {"status": "succeeded", "reference": "case-42"}
    (request,) = soar.requests
    assert request.method == "POST" and str(request.url) == URL
    headers = request.headers
    assert headers[IDEMPOTENCY_HEADER] == str(action.id)
    assert headers[EVENT_HEADER] == "response_action.execute"
    assert headers["content-type"] == "application/json"
    assert headers[TIMESTAMP_HEADER] == str(int(NOW))
    assert verify_signature(SECRET, headers[TIMESTAMP_HEADER], request.content, headers[SIGNATURE_HEADER], now=NOW)
    assert not verify_signature(b"wrong-secret-0123456789", headers[TIMESTAMP_HEADER], request.content,
                                headers[SIGNATURE_HEADER], now=NOW)
    assert not verify_signature(SECRET, headers[TIMESTAMP_HEADER], request.content + b" ", headers[SIGNATURE_HEADER], now=NOW)
    assert not verify_signature(SECRET, headers[TIMESTAMP_HEADER], request.content, headers[SIGNATURE_HEADER], now=NOW + 301)

    body = json.loads(request.content)
    assert body["schema"] == SCHEMA and body["event"] == "response_action.execute" and body["tenant_id"] == "t1"
    assert body["action"] == {
        "id": str(action.id), "idempotency_key": action.idempotency_key, "type": "block_ip",
        "target": "185.220.101.44", "target_type": "ip", "risk_level": "medium", "params": {"playbook": "malware"},
        "requested_by": "agent:workflow", "approved_by": "u1", "approved_at": action.approved_at.isoformat(),
    }
    assert body["alert"] == {"id": "a1", "severity": "high", "title": "C2 beacon"}


def test_sign_is_hmac_sha256_over_timestamp_and_body() -> None:
    import hashlib
    import hmac

    expected = hmac.new(SECRET, b"123.{}", hashlib.sha256).hexdigest()
    assert sign(SECRET, "123", b"{}") == f"v1={expected}"
    assert not verify_signature(SECRET, "not-a-number", b"{}", sign(SECRET, "123", b"{}"))


async def test_retries_5xx_and_429_with_backoff_and_same_idempotency_key() -> None:
    soar = Soar([
        httpx.Response(503),
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.ConnectError("reset"),
        httpx.Response(202),
    ])
    hook, sleeps = connector(soar, max_retries=3)
    result = await hook.execute(make_action())
    assert result.status == "succeeded" and result.detail["attempts"] == 4
    assert sleeps == [0.375, 2.0, 1.5]  # backoff(0), Retry-After, backoff(2); rand fixed at 0.5
    keys = {r.headers[IDEMPOTENCY_HEADER] for r in soar.requests}
    deliveries = {r.headers[DELIVERY_HEADER] for r in soar.requests}
    bodies = {r.content for r in soar.requests}
    assert len(soar.requests) == 4 and len(keys) == 1 and len(deliveries) == 1 and len(bodies) == 1


async def test_gives_up_after_max_retries() -> None:
    soar = Soar([httpx.Response(500)])
    hook, sleeps = connector(soar, max_retries=2)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "http_status" and result.detail["http_status"] == 500
    assert len(soar.requests) == 3 and len(sleeps) == 2


async def test_long_retry_after_fails_instead_of_stalling() -> None:
    soar = Soar([httpx.Response(429, headers={"Retry-After": "3600"})])
    hook, sleeps = connector(soar, max_retry_after_s=60)
    result = await hook.execute(make_action())
    assert result.status == "failed" and len(soar.requests) == 1 and sleeps == []


async def test_network_errors_exhaust_to_failed() -> None:
    soar = Soar([httpx.ConnectError("down")])
    hook, _ = connector(soar, max_retries=1)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "network_error" and result.detail["attempts"] == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_client_errors_are_not_retried(status: int) -> None:
    soar = Soar([httpx.Response(status)])
    hook, sleeps = connector(soar)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["http_status"] == status
    assert len(soar.requests) == 1 and sleeps == []


async def test_redirects_are_not_followed() -> None:
    soar = Soar([httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})])
    hook, _ = connector(soar)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "unexpected_redirect" and len(soar.requests) == 1


async def test_receiver_reported_failure_and_redacted_capped_response() -> None:
    soar = Soar([httpx.Response(200, json={"status": "failed", "api_key": "sk-live-abcdefghijklmnop"})])
    hook, _ = connector(soar)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "receiver_reported_failure"
    assert result.detail["response"]["api_key"] == "[REDACTED]"

    big = Soar([httpx.Response(200, json={"status": "ok", "blob": "x" * 5_000})])
    hook, _ = connector(big)
    result = await hook.execute(make_action())
    assert result.status == "succeeded" and result.detail["response"] == {"_truncated": True}


async def test_response_body_size_cap() -> None:
    soar = Soar([httpx.Response(200, content=b"x" * 2_048)])
    hook, _ = connector(soar, max_response_bytes=1_024)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "response_too_large"


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "fd00:ec2::254"])
async def test_destination_policy_refuses_internal_addresses(address: str) -> None:
    soar = Soar([httpx.Response(200)])
    hook, _ = connector(soar, resolver=resolver_to("93.184.216.34", address))
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "destination_refused"
    assert soar.requests == []


async def test_private_destinations_only_when_the_install_allows_them() -> None:
    soar = Soar([httpx.Response(200)])
    hook, _ = connector(soar, policy=DestinationPolicy(require_https=True, allow_private=True), resolver=resolver_to("10.1.2.3"))
    assert (await hook.execute(make_action())).status == "succeeded"
    metadata, _ = connector(soar, policy=DestinationPolicy(require_https=True, allow_private=True),
                            resolver=resolver_to("169.254.169.254"))
    assert (await metadata.execute(make_action())).detail["error"] == "destination_refused"


def test_https_required_and_no_credentials_in_url() -> None:
    with pytest.raises(ConnectorConfigError):
        connector(Soar([httpx.Response(200)]), url="http://soar.example.com/hook")
    with pytest.raises(ConnectorConfigError):
        connector(Soar([httpx.Response(200)]), url="https://user:pw@soar.example.com/hook")
    with pytest.raises(ConnectorConfigError):
        connector(Soar([httpx.Response(200)]), url="ftp://soar.example.com/hook")
    with pytest.raises(ConnectorConfigError):
        WebhookTarget(url=URL, secret=b"short")


def test_target_verifies_tls_by_default() -> None:
    target = WebhookTarget(url=URL, secret=SECRET)
    assert target.verify is True and "secret" not in repr(target)


# ----------------------------------------------------------------- registry


def registry(settings: Settings, box: Optional[SecretBox] = None, **kw: Any) -> ConnectorRegistry:
    return ConnectorRegistry(settings, secret_box=box, resolver=resolver_to("93.184.216.34"), **kw)


def test_registry_selection(make_settings: Callable[..., Settings]) -> None:
    forced = registry(make_settings())
    assert isinstance(forced.for_tenant("t1", {"response": {"connector": "webhook"}}), DryRunConnector)

    live = make_settings(response={"dry_run": False})
    assert isinstance(registry(live).for_tenant("t1", {}), DryRunConnector)
    missing = registry(live).for_tenant("t1", {"response": {"connector": "webhook"}})
    assert isinstance(missing, MisconfiguredConnector) and "no webhook_url" in missing.reason
    unknown = registry(live).for_tenant("t1", {"response": {"connector": "crowdstrike"}})
    assert isinstance(unknown, MisconfiguredConnector)

    install = make_settings(response={"dry_run": False, "webhook_url": URL, "webhook_secret": SECRET.decode()})
    hook = registry(install).for_tenant("t1", {})
    assert isinstance(hook, WebhookConnector) and hook.origin == "install"
    assert isinstance(registry(install).for_tenant("t1", {"response": {"dry_run": True}}), DryRunConnector)
    no_secret = make_settings(response={"dry_run": False, "webhook_url": URL})
    assert isinstance(registry(no_secret).for_tenant("t1", {}), MisconfiguredConnector)


async def test_misconfigured_connector_fails_actions_visibly() -> None:
    result = await MisconfiguredConnector("webhook", "no webhook_url configured").execute(make_action())
    assert result.status == "failed" and result.detail == {"error": "connector_misconfigured", "reason": "no webhook_url configured"}


def test_tenant_webhook_needs_its_own_encrypted_secret(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(response={"dry_run": False, "webhook_url": URL, "webhook_secret": SECRET.decode()})
    box = SecretBox([generate_key()])
    tenant_url = "https://tenant-soar.example.net/hook"

    without = registry(settings, box).for_tenant("t1", {"response": {"connector": "webhook", "webhook_url": tenant_url}})
    assert isinstance(without, MisconfiguredConnector) and "webhook_secret_ciphertext" in without.reason

    ciphertext = encrypt_webhook_secret(box, "t1", "tenant-secret-0123456789")
    tenant = {"response": {"connector": "webhook", "webhook_url": tenant_url, "webhook_secret_ciphertext": ciphertext}}
    hook = registry(settings, box).for_tenant("t1", tenant)
    assert isinstance(hook, WebhookConnector) and hook.origin == "tenant"
    # Ciphertext is bound to the tenant: another tenant cannot reuse it.
    other = registry(settings, box).for_tenant("t2", tenant)
    assert isinstance(other, MisconfiguredConnector) and "cannot be decrypted" in other.reason
    with pytest.raises(ConnectorConfigError):
        encrypt_webhook_secret(box, "t1", "short")


def test_tenant_tls_options(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(response={"dry_run": False})
    box = SecretBox([generate_key()])
    base = {"connector": "webhook", "webhook_url": URL,
            "webhook_secret_ciphertext": encrypt_webhook_secret(box, "t1", "tenant-secret-0123456789")}
    insecure = registry(settings, box).for_tenant("t1", {"response": {**base, "tls_verify": False}})
    assert isinstance(insecure, MisconfiguredConnector)
    server_path = registry(settings, box).for_tenant("t1", {"response": {**base, "ca_bundle": "/etc/passwd"}})
    assert isinstance(server_path, WebhookConnector)  # ca_bundle is ignored for tenants: only ca_cert_pem is read
    bad_pem = registry(settings, box).for_tenant("t1", {"response": {**base, "ca_cert_pem": "not a cert"}})
    assert isinstance(bad_pem, MisconfiguredConnector)
    ok = registry(settings, box).for_tenant("t1", {"response": base})
    assert isinstance(ok, WebhookConnector) and ok._target.verify is True


async def test_registry_webhook_end_to_end_with_mock_transport(make_settings: Callable[..., Settings]) -> None:
    soar = Soar([httpx.Response(200, json={"status": "accepted"})])
    settings = make_settings(response={"dry_run": False, "webhook_url": URL, "webhook_secret": SECRET.decode()})
    reg = registry(settings, transport=httpx.MockTransport(soar), target_kinds={"block_ip": "ip"})
    result = await reg.for_tenant("t1", {}).execute(make_action())
    assert result.status == "succeeded"
    req = soar.requests[0]
    assert verify_signature(SECRET, req.headers[TIMESTAMP_HEADER], req.content, req.headers[SIGNATURE_HEADER])


# ----------------------------------------------------------------- deadline and signing (RR-4, RR-7)


class FakeTime:
    """Wall clock and monotonic clock that advance only when the connector sleeps or a request takes time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: List[float] = []

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def wall(self) -> float:
        return NOW + self.now

    def mono(self) -> float:
        return self.now


def timed_connector(soar: Any, clock: FakeTime, **kw: Any) -> WebhookConnector:
    return WebhookConnector(
        WebhookTarget(url=URL, secret=SECRET),
        policy=DestinationPolicy(require_https=True),
        target_kinds={"block_ip": "ip"},
        transport=httpx.MockTransport(soar),
        resolver=resolver_to("93.184.216.34"),
        sleep=clock.sleep,
        rand=lambda: 0.5,
        clock=clock.wall,
        monotonic=clock.mono,
        **kw,
    )


async def test_every_attempt_is_signed_afresh_with_the_same_body_and_key() -> None:
    clock = FakeTime()
    soar = Soar([httpx.Response(503, headers={"Retry-After": "7"}), httpx.Response(503, headers={"Retry-After": "7"}),
                 httpx.Response(200)])
    hook = timed_connector(soar, clock)
    assert (await hook.execute(make_action())).status == "succeeded"
    stamps = [r.headers[TIMESTAMP_HEADER] for r in soar.requests]
    assert stamps == [str(int(NOW)), str(int(NOW + 7)), str(int(NOW + 14))]
    for request in soar.requests:
        # Each attempt verifies at the time it was sent, so a receiver's 5-minute tolerance holds for late retries.
        sent = float(request.headers[TIMESTAMP_HEADER])
        assert verify_signature(SECRET, request.headers[TIMESTAMP_HEADER], request.content,
                                request.headers[SIGNATURE_HEADER], now=sent)
    assert len({r.content for r in soar.requests}) == 1
    assert len({r.headers[IDEMPOTENCY_HEADER] for r in soar.requests}) == 1


async def test_deadline_bounds_retries_and_retry_after() -> None:
    """RR-4 probe: a receiver answering 429 + Retry-After: 60 forever used to cost 180 s of sleep."""
    clock = FakeTime()
    soar = Soar([httpx.Response(429, headers={"Retry-After": "12"})])
    hook = timed_connector(soar, clock, deadline_s=30.0, max_retries=10)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "deadline" and result.detail["http_status"] == 429
    assert clock.sleeps == [12.0, 12.0] and clock.now <= 30.0
    assert result.detail["attempts"] == 3 and len(soar.requests) == 3

    default = timed_connector(Soar([httpx.Response(429, headers={"Retry-After": "60"})]), FakeTime())
    result = await default.execute(make_action())
    assert result.detail["error"] == "http_status"  # 60 s is over the default 15 s Retry-After cap: no waiting


async def test_deadline_bounds_network_error_retries() -> None:
    clock = FakeTime()
    soar = Soar([httpx.ConnectError("down")])
    hook = timed_connector(soar, clock, deadline_s=2.0, max_retries=10, backoff_base_s=0.5)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "deadline"
    assert result.detail["error_type"] == "ConnectError" and clock.now <= 2.0


async def test_each_attempt_timeout_is_cut_to_the_time_left() -> None:
    clock = FakeTime()
    seen: List[float] = []

    class Hook(WebhookConnector):
        async def _post(self, client: Any, body: bytes, headers: Any, timeout_s: float) -> Any:
            seen.append(timeout_s)
            clock.now += timeout_s
            raise TimeoutError()

    hook = Hook(
        WebhookTarget(url=URL, secret=SECRET), policy=DestinationPolicy(require_https=True),
        transport=httpx.MockTransport(Soar([httpx.Response(200)])), resolver=resolver_to("93.184.216.34"),
        sleep=clock.sleep, rand=lambda: 0.5, clock=clock.wall, monotonic=clock.mono,
        timeout_s=15.0, deadline_s=20.0, max_retries=5,
    )
    result = await hook.execute(make_action())
    assert result.detail["error"] == "deadline"
    assert seen[0] == 15.0 and seen[1] < 5.0 and clock.now <= 20.0


def test_verify_request_binds_the_idempotency_key_to_the_signed_action_id() -> None:
    action_id = str(uuid.uuid4())
    body = json.dumps({"action": {"id": action_id}}).encode()
    ts = str(int(NOW))
    headers = httpx.Headers({TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign(SECRET, ts, body), IDEMPOTENCY_HEADER: action_id})
    assert verify_request(SECRET, headers, body, now=NOW) == action_id
    # A captured request replayed under a new Idempotency-Key is refused.
    replay = httpx.Headers({**headers, IDEMPOTENCY_HEADER: str(uuid.uuid4())})
    assert verify_request(SECRET, replay, body, now=NOW) is None
    no_key = httpx.Headers({TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign(SECRET, ts, body)})
    assert verify_request(SECRET, no_key, body, now=NOW) == action_id
    assert verify_request(SECRET, headers, body, now=NOW + 301) is None
    assert verify_request(SECRET, headers, body + b" ", now=NOW) is None
    unsigned_id = json.dumps({"action": {}}).encode()
    headers2 = httpx.Headers({TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign(SECRET, ts, unsigned_id)})
    assert verify_request(SECRET, headers2, unsigned_id, now=NOW) is None


async def test_real_request_passes_verify_request() -> None:
    soar = Soar([httpx.Response(200)])
    hook, _ = connector(soar)
    action = make_action()
    await hook.execute(action)
    (request,) = soar.requests
    assert verify_request(SECRET, request.headers, request.content, now=NOW) == str(action.id)


def test_registry_derives_the_webhook_deadline_from_the_node_timeout(make_settings: Callable[..., Settings]) -> None:
    base = {"dry_run": False, "webhook_url": URL, "webhook_secret": SECRET.decode()}
    default = registry(make_settings(response=base)).for_tenant("t1", {})
    assert isinstance(default, WebhookConnector) and default.deadline_s == 60.0  # 180 s node timeout / 3
    short = registry(make_settings(response=base, worker={"node_timeout_s": 30.0})).for_tenant("t1", {})
    assert isinstance(short, WebhookConnector) and short.deadline_s == 10.0
