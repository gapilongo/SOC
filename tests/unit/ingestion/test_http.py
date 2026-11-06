from __future__ import annotations

import json
from typing import Any, Callable, List

import httpx
import pytest

from lg_sotf.ingestion.errors import (
    SourceAuthError,
    SourceConfigError,
    SourceProtocolError,
    SourceRateLimited,
    SourceRequestError,
    SourceUnavailable,
)
from lg_sotf.ingestion.sources import http as http_mod
from lg_sotf.ingestion.sources.http import (
    BasicAuth,
    HeaderAuth,
    OAuth2ClientCredentials,
    SourceHttpClient,
)
from tests.unit.ingestion._support import FakeClock

SECRET = "client-secret-value-1234567890"


def client(handler: Callable[[httpx.Request], httpx.Response], clock: FakeClock, **kwargs: Any) -> SourceHttpClient:
    return SourceHttpClient(
        source_type="test",
        base_url="https://api.example.com",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        rand=lambda: 0.0,
        backoff_base_s=1.0,
        **kwargs,
    )


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


async def test_retries_429_honouring_retry_after() -> None:
    calls: List[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"ok": True})

    clock = FakeClock()
    c = client(handler, clock)
    resp = await c.request("GET", "/x")
    assert resp.json() == {"ok": True}
    assert clock.sleeps == [2.0, 2.0]
    await c.aclose()


async def test_retries_5xx_with_exponential_backoff_and_jitter() -> None:
    statuses = [503, 502, 500, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(statuses.pop(0), json={})

    clock = FakeClock()
    c = SourceHttpClient(
        source_type="test",
        base_url="https://api.example.com",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        rand=lambda: 1.0,
        backoff_base_s=0.5,
        backoff_max_s=1.5,
    )
    await c.request("GET", "/x")
    assert clock.sleeps == [0.5, 1.0, 1.5]
    await c.aclose()


async def test_gives_up_after_max_retries() -> None:
    clock = FakeClock()
    c = client(lambda r: httpx.Response(429), clock, max_retries=2)
    with pytest.raises(SourceRateLimited):
        await c.request("GET", "/x")
    assert len(clock.sleeps) == 2
    c2 = client(lambda r: httpx.Response(503), clock, max_retries=1)
    with pytest.raises(SourceUnavailable, match="HTTP 503"):
        await c2.request("GET", "/x")


async def test_long_retry_after_ends_the_request_without_sleeping() -> None:
    clock = FakeClock()
    c = client(lambda r: httpx.Response(429, headers={"Retry-After": "3600"}), clock, max_retry_after_s=60)
    with pytest.raises(SourceRateLimited) as info:
        await c.request("GET", "/x")
    assert info.value.retry_after_s == 3600
    assert clock.sleeps == []


async def test_network_errors_are_retried_then_raised() -> None:
    attempts: List[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("boom", request=request)

    clock = FakeClock()
    c = client(handler, clock, max_retries=3)
    with pytest.raises(SourceUnavailable, match="ConnectError"):
        await c.request("GET", "/x")
    assert len(attempts) == 4


async def test_client_errors_are_not_retried() -> None:
    clock = FakeClock()
    c = client(lambda r: httpx.Response(404, text="secret body"), clock)
    with pytest.raises(SourceRequestError) as info:
        await c.request("GET", "/missing?token=abc")
    assert info.value.status_code == 404
    assert "secret body" not in str(info.value) and "token=abc" not in str(info.value)
    assert clock.sleeps == []
    c2 = client(lambda r: httpx.Response(403), clock)
    with pytest.raises(SourceAuthError):
        await c2.request("GET", "/x")


async def test_response_size_cap() -> None:
    c = client(lambda r: httpx.Response(200, content=b"x" * 5000), FakeClock(), max_response_bytes=1000)
    with pytest.raises(SourceProtocolError):
        await c.request("GET", "/x")


async def test_invalid_json_is_a_protocol_error() -> None:
    c = client(lambda r: httpx.Response(200, content=b"<html>"), FakeClock())
    resp = await c.request("GET", "/x")
    with pytest.raises(SourceProtocolError):
        resp.json()


def _oauth_handler(state: dict) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            state["token_calls"] += 1
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            assert form["grant_type"] == "client_credentials"
            assert form["client_secret"] == SECRET
            return httpx.Response(200, json={"access_token": f"tok{state['token_calls']}", "expires_in": 600})
        state["api_calls"] += 1
        auth = request.headers.get("Authorization")
        if auth in state.get("reject", set()):
            return httpx.Response(401)
        state.setdefault("seen", []).append(auth)
        return httpx.Response(200, json={})

    return handler


async def test_oauth_token_is_cached_and_refreshed_before_expiry() -> None:
    state = {"token_calls": 0, "api_calls": 0}
    now = Clock()
    auth = OAuth2ClientCredentials("/oauth2/token", "cid", SECRET, refresh_margin_s=60, clock=now)
    c = client(_oauth_handler(state), FakeClock(), auth=auth)
    for _ in range(3):
        await c.request("GET", "/api")
    assert state["token_calls"] == 1
    now.t += 539
    await c.request("GET", "/api")
    assert state["token_calls"] == 1
    now.t += 2  # inside the 60 s refresh margin of the 600 s token
    await c.request("GET", "/api")
    assert state["token_calls"] == 2
    assert state["seen"][-1] == "Bearer tok2"


async def test_401_refreshes_token_and_retries_once() -> None:
    state: dict = {"token_calls": 0, "api_calls": 0, "reject": {"Bearer tok1"}}
    auth = OAuth2ClientCredentials("/oauth2/token", "cid", SECRET)
    c = client(_oauth_handler(state), FakeClock(), auth=auth)
    await c.request("GET", "/api")
    assert state["token_calls"] == 2
    assert state["api_calls"] == 2
    assert state["seen"] == ["Bearer tok2"]


async def test_persistent_401_raises_after_a_single_refresh() -> None:
    state: dict = {"token_calls": 0, "api_calls": 0, "reject": {"Bearer tok1", "Bearer tok2", "Bearer tok3"}}
    auth = OAuth2ClientCredentials("/oauth2/token", "cid", SECRET)
    c = client(_oauth_handler(state), FakeClock(), auth=auth)
    with pytest.raises(SourceAuthError) as info:
        await c.request("GET", "/api")
    assert state["api_calls"] == 2
    assert state["token_calls"] == 2
    assert SECRET not in str(info.value) and "tok" not in str(info.value)


async def test_token_endpoint_rejection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client", "secret": SECRET})

    c = client(handler, FakeClock(), auth=OAuth2ClientCredentials("/oauth2/token", "cid", SECRET))
    with pytest.raises(SourceAuthError) as info:
        await c.request("GET", "/api")
    assert SECRET not in str(info.value)


async def test_static_and_basic_auth_headers() -> None:
    seen: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200, json={})

    c = client(handler, FakeClock(), auth=HeaderAuth({"Authorization": "Bearer abc"}))
    await c.request("GET", "/x")
    c2 = client(handler, FakeClock(), auth=BasicAuth("u", "p"))
    await c2.request("GET", "/x")
    assert seen == ["Bearer abc", "Basic dTpw"]
    assert "abc" not in repr(HeaderAuth({"Authorization": "Bearer abc"}))


def test_client_verifies_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    real = httpx.AsyncClient

    def spy(**kwargs: Any) -> httpx.AsyncClient:
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(http_mod.httpx, "AsyncClient", spy)
    SourceHttpClient(source_type="t", base_url="https://api.example.com")
    assert captured["verify"] is True
    assert captured["follow_redirects"] is False
    assert captured["timeout"].connect is not None


def test_rejects_non_http_base_url() -> None:
    with pytest.raises(SourceConfigError):
        SourceHttpClient(source_type="t", base_url="file:///etc/passwd")


def test_json_helper_roundtrip() -> None:
    resp = http_mod.HttpResponse(200, httpx.Headers(), json.dumps({"a": 1}).encode())
    assert http_mod.json_mapping(resp, "x") == {"a": 1}
    with pytest.raises(SourceProtocolError):
        http_mod.json_mapping(http_mod.HttpResponse(200, httpx.Headers(), b"[1]"), "x")
