"""examples/soar/receiver: the reference receiver accepts what the webhook connector signs and nothing else.

Requests are built and signed by the connector's own code (``build_payload``,
``encode_body``, ``sign`` and :class:`WebhookConnector` itself over an
``httpx.MockTransport``), so a change to the wire format breaks these tests.
"""

from __future__ import annotations

import importlib
import json
import socket
import sys
import threading
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

import httpx
import pytest

from lg_sotf.db.repos.actions import ResponseAction, action_idempotency_key
from lg_sotf.ingestion.sources.netpolicy import DestinationPolicy
from lg_sotf.services.connectors import WebhookConnector, WebhookTarget, sign, verify_request
from lg_sotf.services.connectors.webhook import (
    IDEMPOTENCY_HEADER,
    SCHEMA,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    build_payload,
    encode_body,
)
from lg_sotf.services.response import ACTION_CATALOG

RECEIVER_DIR = Path(__file__).resolve().parents[3] / "examples" / "soar" / "receiver"
# Built at runtime: no credential-shaped literal in the repository.
SECRET = "-".join(("fake", "webhook", "signing", "secret")).encode()
PREVIOUS_SECRET = "-".join(("fake", "previous", "signing", "secret")).encode()
OTHER_SECRET = "-".join(("fake", "attacker", "signing", "secret")).encode()
NOW = 1_790_000_000.0
URL = "https://soar.example.com/lgsotf/actions"


def _load(name: str) -> ModuleType:
    if str(RECEIVER_DIR) not in sys.path:
        sys.path.insert(0, str(RECEIVER_DIR))
    return importlib.import_module(name)


rx = _load("lgsotf_receiver")
stubs = _load("lgsotf_handlers")


def make_action(**kw: Any) -> ResponseAction:
    now = datetime.now(UTC)
    base: Dict[str, Any] = dict(
        id=uuid.uuid4(), tenant_id="t1", alert_id="a1", action_type="block_ip", target="185.220.101.44",
        params={"playbook": "malware", "alert": {"severity": "high", "title": "C2 beacon"}}, risk_level="medium",
        idempotency_key=action_idempotency_key("t1", "a1", "block_ip", "185.220.101.44"), status="executing",
        blocked_reason=None, requested_by="agent:workflow", approved_by="u1", approved_at=now, executed_at=now,
        connector="webhook", result=None, rollback_of=None, created_at=now, updated_at=now,
    )
    base.update(kw)
    return ResponseAction(**base)


def signed(
    action: Optional[ResponseAction] = None,
    *,
    secret: bytes = SECRET,
    at: float = NOW,
    payload: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], bytes]:
    """Headers and body exactly as the connector sends them (``WebhookConnector._headers``)."""
    action = action or make_action()
    if payload is None:
        kind = ACTION_CATALOG[action.action_type].target_kind if action.action_type in ACTION_CATALOG else None
        payload = build_payload(action, target_type=kind, sent_at=datetime.fromtimestamp(at, UTC))
    body = encode_body(payload)
    timestamp = str(int(at))
    return {
        "Content-Type": "application/json",
        IDEMPOTENCY_HEADER: str(action.id),
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: sign(secret, timestamp, body),
    }, body


class Recorder:
    """A handler that records calls and returns a scripted outcome (or raises)."""

    def __init__(self, result: Any = None) -> None:
        self.calls: List[Any] = []
        self.result = result if result is not None else rx.Outcome.succeeded(reference="fw-rule-7", rule="lgsotf")

    def __call__(self, action: Any) -> Any:
        self.calls.append(action)
        if isinstance(self.result, BaseException):
            raise self.result
        if callable(self.result):
            return self.result(action)
        return self.result


def receiver(
    handlers: Optional[Mapping[str, Callable[..., Any]]] = None,
    *,
    store: Any = None,
    clock: Callable[[], float] = lambda: NOW,
    **kw: Any,
) -> Any:
    return rx.Receiver(
        [SECRET], dict(handlers or {}), store or rx.IdempotencyStore(clock=clock), clock=clock, **kw
    )


# --------------------------------------------------------------------------- with the real connector


def bridge(target: Any) -> httpx.MockTransport:
    """Serve the connector's requests with the receiver (no network)."""

    def handle(request: httpx.Request) -> httpx.Response:
        reply = target.handle(request.headers.multi_items(), request.content)
        return httpx.Response(reply.status, content=reply.encoded(), headers={**reply.headers, "Content-Type": "application/json"})

    return httpx.MockTransport(handle)


def connector(target: Any, *, secret: bytes = SECRET, **kw: Any) -> Tuple[WebhookConnector, List[float]]:
    sleeps: List[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def resolve(host: str, port: int) -> List[str]:
        return ["93.184.216.34"]

    hook = WebhookConnector(
        WebhookTarget(url=URL, secret=secret),
        policy=DestinationPolicy(require_https=True),
        target_kinds={name: spec.target_kind for name, spec in ACTION_CATALOG.items()},
        transport=bridge(target),
        resolver=resolve,
        sleep=sleep,
        rand=lambda: 0.5,
        clock=lambda: NOW,
        **kw,
    )
    return hook, sleeps


async def test_connector_delivery_is_accepted_and_recorded_as_succeeded() -> None:
    handler = Recorder()
    hook, _ = connector(receiver({"block_ip": handler}))
    action = make_action()

    result = await hook.execute(action)

    assert result.status == "succeeded" and result.detail["attempts"] == 1
    assert result.detail["response"] == {
        "status": "succeeded", "action_id": str(action.id), "action_type": "block_ip", "reference": "fw-rule-7",
        "detail": {"rule": "lgsotf"},
    }
    (seen,) = handler.calls
    assert (seen.id, seen.type, seen.target, seen.target_type, seen.tenant_id) == (
        str(action.id), "block_ip", "185.220.101.44", "ip", "t1",
    )
    assert seen.params == {"playbook": "malware"} and seen.alert == {"id": "a1", "severity": "high", "title": "C2 beacon"}
    assert seen.rollback_of is None


async def test_a_rollback_reaches_the_inverse_handler_with_the_original_action_id() -> None:
    handler = Recorder()
    hook, _ = connector(receiver({"unblock_ip": handler}))
    original = make_action()
    rollback = make_action(
        action_type="unblock_ip", rollback_of=original.id, execution_owner="scheduler",
        params={"rollback": {"of": str(original.id), "reason": "false positive", "requested_by": "user:u1"}},
    )

    result = await hook.execute(rollback)

    assert result.status == "succeeded"
    (seen,) = handler.calls
    assert seen.type == "unblock_ip" and seen.target == original.target and seen.rollback_of == str(original.id)
    assert seen.params["rollback"]["of"] == str(original.id)


async def test_reexecution_of_the_same_action_acts_once_and_gets_the_original_answer() -> None:
    handler = Recorder()
    hook, _ = connector(receiver({"block_ip": handler}))
    action = make_action()

    first = await hook.execute(action)
    again = await hook.execute(action)  # an interrupted execution is run again: new delivery, new signature

    assert len(handler.calls) == 1
    assert again.status == "succeeded" and again.detail["response"] == first.detail["response"]


async def test_handler_failure_and_stub_are_recorded_as_failed() -> None:
    failing = Recorder(rx.Outcome.failed("vendor_error", "firewall answered 500", http_status=500))
    hook, sleeps = connector(receiver({"block_ip": failing, "isolate_host": stubs.isolate_host}))

    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["error"] == "receiver_reported_failure" and sleeps == []
    assert result.detail["response"]["error"] == "vendor_error"
    assert result.detail["response"]["message"] == "firewall answered 500"

    stub = await hook.execute(make_action(action_type="isolate_host", target="ws-042"))
    assert stub.status == "failed" and stub.detail["response"]["status"] == "rejected"
    assert stub.detail["response"]["error"] == "not_implemented"


async def test_wrong_secret_fails_without_retry_and_never_reaches_a_handler() -> None:
    handler = Recorder()
    hook, sleeps = connector(receiver({"block_ip": handler}), secret=OTHER_SECRET)
    result = await hook.execute(make_action())
    assert result.status == "failed" and result.detail["http_status"] == 401 and sleeps == []
    assert handler.calls == []


async def test_retry_later_is_retried_by_the_connector_and_then_succeeds() -> None:
    outcomes: List[Any] = [rx.RetryLater(2), rx.Outcome.succeeded()]

    def flaky(action: Any) -> Any:
        item = outcomes.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    handler = Recorder(flaky)
    hook, sleeps = connector(receiver({"block_ip": handler}))
    result = await hook.execute(make_action())
    assert result.status == "succeeded" and result.detail["attempts"] == 2
    assert sleeps == [2.0] and len(handler.calls) == 2  # Retry-After honoured


# --------------------------------------------------------------------------- signature, timestamp, replay


def test_accepts_every_catalog_action_signed_by_the_connector() -> None:
    handler = Recorder()
    target = receiver({name: handler for name in ACTION_CATALOG})
    for name, spec in ACTION_CATALOG.items():
        value = {"alert": "alert:a1", "email": "evil@phish.example", "message": "<m1@phish.example>"}.get(
            spec.target_kind, "x-1"
        )
        headers, body = signed(make_action(action_type=name, target=value))
        reply = target.handle(headers, body)
        assert reply.status == 200 and reply.body["status"] == "succeeded", name
    assert [a.type for a in handler.calls] == list(ACTION_CATALOG)


@pytest.mark.parametrize(
    "tamper",
    ["wrong_secret", "body", "timestamp", "signature_version", "missing_signature", "missing_timestamp", "uppercase_hex"],
)
def test_rejects_bad_signatures(tamper: str) -> None:
    handler = Recorder()
    headers, body = signed(secret=OTHER_SECRET if tamper == "wrong_secret" else SECRET)
    if tamper == "body":
        body = body.replace(b"185.220.101.44", b"185.220.101.45")
    elif tamper == "timestamp":
        headers[TIMESTAMP_HEADER] = str(int(NOW) - 1)
    elif tamper == "signature_version":
        headers[SIGNATURE_HEADER] = "v2=" + headers[SIGNATURE_HEADER][3:]
    elif tamper == "missing_signature":
        del headers[SIGNATURE_HEADER]
    elif tamper == "missing_timestamp":
        del headers[TIMESTAMP_HEADER]
    elif tamper == "uppercase_hex":
        headers[SIGNATURE_HEADER] = headers[SIGNATURE_HEADER].upper()
    reply = receiver({"block_ip": handler}).handle(headers, body)
    assert reply.status == 401 and reply.body == {"status": "rejected", "error": "unauthorized"}
    assert handler.calls == []


@pytest.mark.parametrize("skew, accepted", [(-301, False), (-300, True), (0, True), (300, True), (301, False)])
def test_timestamp_window_matches_the_connector_reference(skew: int, accepted: bool) -> None:
    headers, body = signed(at=NOW + skew)
    reply = receiver({"block_ip": Recorder()}).handle(headers, body)
    assert (reply.status == 200) is accepted
    assert (verify_request(SECRET, httpx.Headers(headers), body, now=NOW) is not None) is accepted


def test_rejects_stale_and_replayed_requests() -> None:
    handler = Recorder()
    clock = [NOW]
    target = receiver({"block_ip": handler}, clock=lambda: clock[0])
    headers, body = signed()

    first = target.handle(headers, body)
    replay = target.handle(headers, body)  # a captured request sent again inside the window
    assert first.status == replay.status == 200 and replay.body == first.body
    assert replay.headers == {"Idempotent-Replayed": "true"} and len(handler.calls) == 1

    moved = dict(headers, **{IDEMPOTENCY_HEADER: str(uuid.uuid4())})  # replay under a new key
    assert target.handle(moved, body).status == 401

    clock[0] = NOW + 301  # the same request after the window
    assert target.handle(headers, body).status == 401
    fresh_headers, fresh_body = signed(at=NOW + 301)
    assert target.handle(fresh_headers, fresh_body).status == 200
    assert len(handler.calls) == 2


def test_idempotency_header_is_optional_but_must_match_when_present() -> None:
    headers, body = signed()
    del headers[IDEMPOTENCY_HEADER]
    assert receiver({"block_ip": Recorder()}).handle(headers, body).status == 200
    headers, body = signed()
    headers[IDEMPOTENCY_HEADER] = ""
    assert receiver({"block_ip": Recorder()}).handle(headers, body).status == 401


def test_repeated_security_headers_are_refused() -> None:
    headers, body = signed()
    pairs = [*headers.items(), (SIGNATURE_HEADER.lower(), headers[SIGNATURE_HEADER])]
    assert receiver({"block_ip": Recorder()}).handle(pairs, body).status == 401


def test_previous_secret_is_accepted_during_rotation() -> None:
    target = rx.Receiver([SECRET, PREVIOUS_SECRET], {"block_ip": Recorder()}, rx.IdempotencyStore(), clock=lambda: NOW)
    for secret, status in ((PREVIOUS_SECRET, 200), (SECRET, 200), (OTHER_SECRET, 401)):
        headers, body = signed(secret=secret)
        assert target.handle(headers, body).status == status


def test_short_or_missing_secrets_are_refused() -> None:
    with pytest.raises(ValueError):
        rx.Receiver([], {}, rx.IdempotencyStore())
    with pytest.raises(ValueError):
        rx.Receiver([b"x" * 15], {}, rx.IdempotencyStore())


# --------------------------------------------------------------------------- dispatch and answers


def test_unknown_action_type_schema_and_tenant_are_rejected_with_a_reason() -> None:
    handler = Recorder()
    target = receiver({"block_ip": handler}, tenants=["t1"])

    headers, body = signed(make_action(action_type="wipe_host", target="ws-042"))
    reply = target.handle(headers, body)
    assert reply.status == 200 and reply.body["status"] == "rejected" and reply.body["error"] == "unsupported_action_type"

    action = make_action()
    payload = build_payload(action, target_type="ip", sent_at=datetime.fromtimestamp(NOW, UTC))
    headers, body = signed(action, payload={**payload, "schema": "lg-sotf.response-action.v2"})
    assert target.handle(headers, body).body["error"] == "unsupported_schema"

    headers, body = signed(make_action(tenant_id="t2"))
    assert target.handle(headers, body).body["error"] == "tenant_not_allowed"
    assert handler.calls == []


def test_malformed_signed_payload_is_a_bad_request() -> None:
    headers, body = signed(payload={"schema": SCHEMA, "action": {"type": "block_ip"}})
    assert receiver().handle(headers, body).status == 400


def test_handler_exception_is_recorded_as_failed_once() -> None:
    handler = Recorder(RuntimeError("vendor client bug"))
    target = receiver({"block_ip": handler})
    headers, body = signed()
    reply = target.handle(headers, body)
    assert reply.status == 200 and reply.body["status"] == "failed" and reply.body["error"] == "handler_error"
    assert "vendor client bug" not in json.dumps(reply.body)
    assert target.handle(headers, body).body == reply.body and len(handler.calls) == 1


def test_duplicate_while_running_asks_for_a_retry() -> None:
    store = rx.IdempotencyStore(clock=lambda: NOW)
    target = receiver({"block_ip": Recorder()}, store=store)
    action = make_action()
    headers, body = signed(action)
    fingerprint = rx._fingerprint(rx._parse_action(json.loads(body)))
    assert store.claim(str(action.id), fingerprint).state == "new"  # another request is running it

    reply = target.handle(headers, body)
    assert reply.status == 503 and reply.headers == {"Retry-After": "5"}


def test_claim_left_by_a_crash_is_settled_as_interrupted_not_redone() -> None:
    clock = [NOW]
    store = rx.IdempotencyStore(clock=lambda: clock[0])
    handler = Recorder()
    target = receiver({"block_ip": handler}, store=store, clock=lambda: clock[0])
    action = make_action()
    headers, body = signed(action)
    store.claim(str(action.id), rx._fingerprint(rx._parse_action(json.loads(body))))

    clock[0] = NOW + rx.STALE_CLAIM_S + 1
    headers, body = signed(action, at=clock[0])
    reply = target.handle(headers, body)
    assert reply.status == 200 and reply.body["status"] == "failed" and reply.body["error"] == "interrupted"
    assert handler.calls == []


def test_same_id_with_another_target_is_a_conflict() -> None:
    target = receiver({"block_ip": Recorder()})
    action = make_action()
    assert target.handle(*signed(action)).status == 200
    reply = target.handle(*signed(action.model_copy(update={"target": "185.220.101.99"})))
    assert reply.status == 409 and reply.body["error"] == "idempotency_conflict"


def test_answer_is_small_and_bounded() -> None:
    handler = Recorder(rx.Outcome.failed("x" * 500, "m" * 5_000, blob="b" * 5_000))
    reply = receiver({"block_ip": handler}).handle(*signed())
    assert len(reply.body["error"]) == 64 and len(reply.body["message"]) == rx.MAX_MESSAGE_CHARS
    assert reply.body["detail"] == {"_truncated": True} and len(reply.encoded()) < 2_000
    with pytest.raises(ValueError):
        rx.Outcome("done")


def test_dedup_survives_a_restart(tmp_path: Path) -> None:
    db = str(tmp_path / "receiver.sqlite3")
    handler = Recorder()
    headers, body = signed()
    first = receiver({"block_ip": handler}, store=rx.IdempotencyStore(db)).handle(headers, body)
    again = receiver({"block_ip": handler}, store=rx.IdempotencyStore(db)).handle(headers, body)
    assert again.body == first.body and len(handler.calls) == 1


def test_old_entries_are_purged() -> None:
    clock = [NOW]
    store = rx.IdempotencyStore(clock=lambda: clock[0], retention_s=3600)
    store.claim("a", "f")
    store.finish("a", {"status": "succeeded"})
    clock[0] = NOW + 3601
    assert store.purge() == 1 and store.claim("a", "f").state == "new"


def test_stubs_cover_the_catalog_and_never_claim_success() -> None:
    missing = sorted(set(ACTION_CATALOG) - set(stubs.HANDLERS))
    assert not missing, f"add handler stubs to examples/soar/receiver/lgsotf_handlers.py for: {missing}"
    target = receiver(stubs.HANDLERS)
    for name in stubs.HANDLERS:
        reply = target.handle(*signed(make_action(action_type=name, target="alert:a1")))
        assert reply.body["status"] == "rejected" and reply.body["error"] == "not_implemented", name


def test_sample_request_is_signed_like_the_connector() -> None:
    headers, body = rx.sample_request(SECRET, now=NOW)
    action_id = verify_request(SECRET, httpx.Headers(headers), body, now=NOW)
    payload = json.loads(body)
    assert action_id == payload["action"]["id"] and payload["schema"] == SCHEMA
    assert body == encode_body(payload)  # the connector's canonical encoding
    reply = receiver(stubs.HANDLERS).handle(headers, body)
    assert reply.status == 200 and reply.body["action_type"] == "send_alert"


# --------------------------------------------------------------------------- HTTP server


@pytest.fixture
def server() -> Iterator[Tuple[str, Recorder]]:
    handler = Recorder()
    target = rx.Receiver([SECRET], {"send_alert": handler}, rx.IdempotencyStore())
    httpd = rx.ReceiverHTTPServer(("127.0.0.1", 0), target)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", handler
    finally:
        httpd.shutdown()
        httpd.server_close()


def post(url: str, body: bytes, headers: Mapping[str, str]) -> Tuple[int, Dict[str, Any], Mapping[str, str]]:
    request = urllib.request.Request(url, data=body, method="POST", headers=dict(headers))  # noqa: S310 - local test server
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - local test server
            return response.status, json.loads(response.read()), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), exc.headers


def test_http_server_accepts_a_signed_request_and_refuses_the_rest(server: Tuple[str, Recorder]) -> None:
    base, handler = server
    headers, body = rx.sample_request(SECRET)
    status, answer, reply_headers = post(base + rx.DEFAULT_PATH, body, headers)
    assert status == 200 and answer["status"] == "succeeded" and len(handler.calls) == 1
    assert reply_headers["Cache-Control"] == "no-store"
    status, _, reply_headers = post(base + rx.DEFAULT_PATH, body, headers)
    assert status == 200 and reply_headers["Idempotent-Replayed"] == "true" and len(handler.calls) == 1

    assert post(base + "/other", body, headers)[0] == 404
    assert post(base + rx.DEFAULT_PATH, body, {**headers, "Content-Type": "text/plain"})[0] == 415
    # Refused on the declared length, before the body is read.
    assert post(base + rx.DEFAULT_PATH, body, {**headers, "Content-Length": str(rx.MAX_BODY_BYTES + 1)})[0] == 413
    forged = dict(headers, **{SIGNATURE_HEADER: sign(OTHER_SECRET, headers[TIMESTAMP_HEADER], body)})
    assert post(base + rx.DEFAULT_PATH, body, forged)[0] == 401
    port = int(base.rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        raw.sendall(b"POST " + rx.DEFAULT_PATH.encode() + b" HTTP/1.1\r\nHost: t\r\nContent-Length: 1e3\r\n\r\n")
        assert raw.recv(64).startswith(b"HTTP/1.0 411")
    with urllib.request.urlopen(base + "/healthz", timeout=10) as response:  # noqa: S310 - local test server
        assert json.loads(response.read()) == {"status": "ok"}


# --------------------------------------------------------------------------- gateway mode


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, limit: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class FakeOpener:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.requests: List[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> Any:
        self.requests.append(request)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def forwarded(outcome: Any) -> Tuple[Any, FakeOpener]:
    opener = FakeOpener(outcome)
    action = rx._parse_action(json.loads(signed()[1]))
    forwarder = rx.Forwarder(
        "https://shuffle.example.com/api/v1/hooks/webhook_x", {"Authorization": "x" * 24}, opener=opener
    )
    return forwarder(action), opener


def http_error(code: int, headers: Optional[Dict[str, str]] = None) -> urllib.error.HTTPError:
    import email.message
    import io

    message = email.message.Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return urllib.error.HTTPError("https://shuffle.example.com", code, "error", message, io.BytesIO(b"{}"))


def test_forwarder_passes_the_verified_action_on() -> None:
    result, opener = forwarded(FakeResponse(200, b'{"execution_id": "exec-9"}'))
    assert result.status == "succeeded" and result.reference == "exec-9"
    (request,) = opener.requests
    sent = json.loads(bytes(request.data or b""))
    assert sent["action"]["target"] == "185.220.101.44" and request.headers["Authorization"] == "x" * 24
    assert request.headers["Idempotency-key"] == sent["action"]["id"]


def test_forwarder_maps_soar_answers() -> None:
    assert forwarded(FakeResponse(200, b'{"status": "failed", "error": "no such host"}'))[0].status == "failed"
    assert forwarded(http_error(500))[0].error == "forward_rejected"
    assert forwarded(urllib.error.URLError(TimeoutError()))[0].error == "forward_timeout"
    with pytest.raises(rx.RetryLater) as retry:
        forwarded(http_error(429, {"Retry-After": "7"}))
    assert retry.value.retry_after_s == 7
    with pytest.raises(rx.RetryLater):
        forwarded(urllib.error.URLError(ConnectionRefusedError()))


def test_forwarder_requires_https_unless_allowed() -> None:
    with pytest.raises(ValueError):
        rx.Forwarder("http://shuffle.internal:3001/api/v1/hooks/webhook_x")
    rx.Forwarder("http://shuffle.internal:3001/api/v1/hooks/webhook_x", allow_http=True)


def test_the_examples_are_linted_type_checked_and_scanned() -> None:
    """The receiver customers deploy is held to the same gates as the product (make lint, make security-scan)."""
    makefile = (Path(__file__).resolve().parents[3] / "Makefile").read_text(encoding="utf-8")

    def recipe(target: str) -> List[str]:
        return [line.strip() for line in makefile.split(f"\n{target}:", 1)[1].split("\n\n", 1)[0].splitlines()[1:]]

    ruff = next(line for line in recipe("lint") if line.startswith("ruff check"))
    assert "examples" in ruff.split()
    assert "mypy examples/soar/receiver examples/soar/n8n/build_workflow.py" in recipe("lint")
    bandit = next(line for line in recipe("security-scan") if line.startswith("bandit"))
    assert "examples" in bandit.split() and "src/lg_sotf" in bandit.split()
