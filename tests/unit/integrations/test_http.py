"""Characterization of :class:`IntegrationHttp` (roadmap X2.1).

Pins today's behaviour before the client builder and the capped read move to
``lg_sotf.net.http``: retries and backoff, what a non-idempotent write does on
an ambiguous failure, the 15 s ``Retry-After`` ceiling for in-request waits,
the response cap, redirects, the destination policy and an unreadable CA.
Every request goes to an ``httpx.MockTransport``; DNS is a stub.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence

import httpx
import pytest

from lg_sotf.integrations.http import (
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_S,
    DeliveryError,
    HttpResult,
    IntegrationHttp,
    error_snippet,
    raise_for_status,
    tls_verify,
)
from lg_sotf.net.egress import Resolver
from lg_sotf.settings import Settings
from tests.unit.integrations._support import public_resolver

URL = "https://jira.example.com/rest/api/2/issue"


class Server:
    """Answers each request with the next scripted response (or raises the scripted exception)."""

    def __init__(self, *answers: object) -> None:
        self.answers: List[object] = list(answers)
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, type) and issubclass(answer, Exception):
            raise answer("scripted failure", request=request)
        assert isinstance(answer, httpx.Response)
        return answer


class Sleeps:
    def __init__(self) -> None:
        self.calls: List[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def make_http(
    make_settings: Callable[..., Settings],
    server: Server,
    sleeps: Sleeps,
    *,
    max_response_bytes: Optional[int] = None,
    resolver: Resolver = public_resolver,
) -> IntegrationHttp:
    return IntegrationHttp(
        make_settings(),
        transport=httpx.MockTransport(server),
        resolver=resolver,
        sleep=sleeps,
        rand=lambda: 1.0,  # no jitter: backoff is min(8, 0.5 * 2**attempt)
        max_response_bytes=max_response_bytes if max_response_bytes is not None else DEFAULT_MAX_RESPONSE_BYTES,
    )


# -- retries ---------------------------------------------------------------------------------------------------


async def test_transient_statuses_are_retried_with_exponential_backoff(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(503), httpx.Response(502), httpx.Response(200, json={"ok": True})), Sleeps()
    result = await make_http(make_settings, server, sleeps).request("GET", URL, retries=2)
    assert result.status == 200 and result.json() == {"ok": True}
    assert len(server.requests) == 3 and sleeps.calls == [0.5, 1.0]


async def test_connection_errors_are_retried(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.ConnectError, httpx.Response(200)), Sleeps()
    result = await make_http(make_settings, server, sleeps).request("GET", URL, retries=1)
    assert result.status == 200 and len(server.requests) == 2 and sleeps.calls == [0.5]


async def test_retries_are_bounded_and_the_last_answer_raises(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(503, content=b"down for maintenance")), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("GET", URL, retries=2)
    err = info.value
    assert (err.status, err.code, err.retryable) == (503, "http_status", True)
    assert str(err) == "HTTP 503: down for maintenance"
    assert len(server.requests) == 3 and sleeps.calls == [0.5, 1.0]


async def test_no_retries_by_default(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(503)), Sleeps()
    with pytest.raises(DeliveryError):
        await make_http(make_settings, server, sleeps).request("GET", URL)
    assert len(server.requests) == 1 and sleeps.calls == []


async def test_network_errors_after_the_last_retry_are_retryable_delivery_errors(
    make_settings: Callable[..., Settings],
) -> None:
    server, sleeps = Server(httpx.ReadTimeout), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("GET", URL, retries=1)
    err = info.value
    assert (err.code, err.retryable, err.status) == ("network_error", True, None)
    assert str(err) == "network error (ReadTimeout)"
    assert len(server.requests) == 2


async def test_client_errors_are_not_retried(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(400, json={"error": "bad field"})), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("POST", URL, json_body={}, retries=3)
    assert (info.value.status, info.value.retryable) == (400, False)
    assert len(server.requests) == 1


async def test_expect_ok_false_returns_the_error_answer(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(404, json={"missing": True})), Sleeps()
    result = await make_http(make_settings, server, sleeps).request("GET", URL, expect_ok=False)
    assert isinstance(result, HttpResult) and result.status == 404 and result.json() == {"missing": True}


# -- idempotent=False -----------------------------------------------------------------------------------------


async def test_a_write_is_not_retried_after_a_read_timeout(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.ReadTimeout, httpx.Response(201)), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("POST", URL, json_body={}, retries=3, idempotent=False)
    assert info.value.code == "network_error" and info.value.retryable
    assert len(server.requests) == 1 and sleeps.calls == []


@pytest.mark.parametrize("status", [500, 502, 503, 504])
async def test_a_write_is_not_retried_after_a_5xx(make_settings: Callable[..., Settings], status: int) -> None:
    server, sleeps = Server(httpx.Response(status), httpx.Response(201)), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("POST", URL, json_body={}, retries=3, idempotent=False)
    assert info.value.status == status and info.value.retryable
    assert len(server.requests) == 1


@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout])
async def test_a_write_is_retried_when_it_never_reached_the_server(
    make_settings: Callable[..., Settings], failure: type
) -> None:
    server, sleeps = Server(failure, httpx.Response(201)), Sleeps()
    result = await make_http(make_settings, server, sleeps).request(
        "POST", URL, json_body={}, retries=1, idempotent=False
    )
    assert result.status == 201 and len(server.requests) == 2


async def test_a_write_is_retried_after_a_429(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(201)), Sleeps()
    result = await make_http(make_settings, server, sleeps).request(
        "POST", URL, json_body={}, retries=1, idempotent=False
    )
    assert result.status == 201 and sleeps.calls == [2.0]


# -- Retry-After -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("header", "slept"), [("0", 0.0), ("1.5", 1.5), ("15", 15.0)])
async def test_a_short_retry_after_is_waited_for(
    make_settings: Callable[..., Settings], header: str, slept: float
) -> None:
    server, sleeps = Server(httpx.Response(429, headers={"Retry-After": header}), httpx.Response(200)), Sleeps()
    await make_http(make_settings, server, sleeps).request("GET", URL, retries=1)
    assert sleeps.calls == [slept]


async def test_an_unreadable_retry_after_falls_back_to_backoff(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(503, headers={"Retry-After": "soon"}), httpx.Response(200)), Sleeps()
    await make_http(make_settings, server, sleeps).request("GET", URL, retries=1)
    assert sleeps.calls == [0.5]


async def test_a_retry_after_above_15s_is_returned_to_the_caller_not_waited(
    make_settings: Callable[..., Settings],
) -> None:
    server, sleeps = Server(httpx.Response(429, headers={"Retry-After": "16"}), httpx.Response(200)), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("GET", URL, retries=3)
    assert (info.value.status, info.value.retry_after, info.value.retryable) == (429, 16.0, True)
    assert len(server.requests) == 1 and sleeps.calls == []


def test_the_retry_after_hint_on_the_error_is_capped() -> None:
    result = HttpResult(503, httpx.Headers({"Retry-After": "999999"}), b"")
    with pytest.raises(DeliveryError) as info:
        raise_for_status(result)
    assert info.value.retry_after == MAX_RETRY_AFTER_S == 3_600.0


# -- response cap ------------------------------------------------------------------------------------------------


async def test_a_body_at_the_cap_is_read(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(200, content=b"a" * 64)), Sleeps()
    result = await make_http(make_settings, server, sleeps, max_response_bytes=64).request("GET", URL)
    assert result.body == b"a" * 64


@pytest.mark.parametrize("declared", [True, False])
async def test_a_body_over_the_cap_is_refused_and_not_retried(
    make_settings: Callable[..., Settings], declared: bool
) -> None:
    body = b"a" * 65
    response = httpx.Response(200, content=body) if declared else httpx.Response(200, stream=httpx.ByteStream(body))
    server, sleeps = Server(response), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps, max_response_bytes=64).request("GET", URL, retries=2)
    assert (info.value.code, info.value.retryable, str(info.value)) == (
        "response_too_large",
        False,
        "response too large",
    )
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert len(server.requests) == 1


# -- redirects ----------------------------------------------------------------------------------------------------


async def test_redirects_are_not_followed(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(302, headers={"Location": "https://elsewhere.example.net/"})), Sleeps()
    http = make_http(make_settings, server, sleeps)
    with pytest.raises(DeliveryError) as info:
        await http.request("GET", URL, retries=2)
    assert (info.value.code, info.value.status, info.value.retryable) == ("unexpected_redirect", 302, False)
    assert [r.url.host for r in server.requests] == ["jira.example.com"]
    result = await http.request("GET", URL, expect_ok=False)
    assert result.status == 302 and len(server.requests) == 2


# -- destination policy ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"])
async def test_a_refused_destination_is_never_contacted(make_settings: Callable[..., Settings], address: str) -> None:
    async def internal(host: str, port: int) -> Sequence[str]:
        return [address]

    server, sleeps = Server(httpx.Response(200)), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps, resolver=internal).request("GET", URL, retries=2)
    assert (info.value.code, info.value.retryable) == ("destination_refused", False)
    assert str(info.value) == "destination refused by the network policy"
    assert server.requests == [] and sleeps.calls == []


@pytest.mark.parametrize("url", ["ftp://jira.example.com/x", "https://user:pw@jira.example.com/x", "https:///x"])
async def test_a_malformed_url_is_refused_before_any_request(make_settings: Callable[..., Settings], url: str) -> None:
    server, sleeps = Server(httpx.Response(200)), Sleeps()
    with pytest.raises(DeliveryError) as info:
        await make_http(make_settings, server, sleeps).request("GET", url)
    assert info.value.code == "destination_refused" and str(info.value).startswith("destination rejected: ")
    assert server.requests == []


async def test_requests_carry_the_user_agent_and_the_original_host(make_settings: Callable[..., Settings]) -> None:
    server, sleeps = Server(httpx.Response(200)), Sleeps()
    await make_http(make_settings, server, sleeps).request("GET", URL, params={"q": "1"})
    (sent,) = server.requests
    assert sent.headers["User-Agent"] == "lg-sotf-integrations/1"
    assert sent.url.host == "jira.example.com" and sent.url.params["q"] == "1"


# -- TLS ------------------------------------------------------------------------------------------------------------


def test_an_unreadable_ca_is_an_invalid_ca_error() -> None:
    with pytest.raises(DeliveryError) as info:
        tls_verify({"ca_cert_pem": "not a certificate"})
    assert (info.value.code, info.value.retryable, str(info.value)) == ("invalid_ca", False, "invalid CA certificate")


def test_no_ca_means_the_system_trust_store() -> None:
    assert tls_verify({}) is True
    assert tls_verify({"ca_cert_pem": ""}) is True


# -- error text ----------------------------------------------------------------------------------------------------


def test_error_snippets_are_collapsed_and_truncated() -> None:
    assert error_snippet(b"  line one\n\n line   two ") == "line one line two"
    assert len(error_snippet(b"x " * 5_000)) == 300
