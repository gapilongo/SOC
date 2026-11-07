"""Characterization of the enrichment providers' :class:`JsonHttpClient` (roadmap X2.1 gap tests).

Pins the transport rules before the capped read moves to ``lg_sotf.net.http``:
redirects are returned, not followed; the body cap holds with and without a
``Content-Length``; ``Retry-After`` is read for 429 and 503 only; one client
per provider instance. Every request goes to an ``httpx.MockTransport``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any, List

import httpx
import pytest

from lg_sotf.tools.enrichment.http import USER_AGENT, JsonHttpClient, ProviderHTTPError

URL = "https://lookup.example.com/api/v3/files/abc"


class Server:
    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def client(server: Server, **kwargs: Any) -> JsonHttpClient:
    return JsonHttpClient("lookup", transport=httpx.MockTransport(server), **kwargs)


async def test_json_is_parsed_and_headers_are_sent() -> None:
    server = Server(httpx.Response(200, json={"data": {"id": "abc"}}))
    response = await client(server).get_json(URL, headers={"x-apikey": "k"}, params={"limit": 1})
    assert (response.status, response.body, response.retry_after_s) == (200, {"data": {"id": "abc"}}, None)
    (sent,) = server.requests
    assert sent.headers["User-Agent"] == USER_AGENT and sent.headers["Accept"] == "application/json"
    assert sent.headers["x-apikey"] == "k" and sent.url.params["limit"] == "1"


async def test_a_body_that_is_not_json_is_none() -> None:
    response = await client(Server(httpx.Response(200, content=b"<html/>"))).get_json(URL, headers={})
    assert response.status == 200 and response.body is None


async def test_redirects_are_returned_not_followed() -> None:
    server = Server(httpx.Response(302, headers={"Location": "https://elsewhere.example.net/"}))
    response = await client(server).get_json(URL, headers={})
    assert response.status == 302 and len(server.requests) == 1


async def test_a_body_at_the_cap_is_read() -> None:
    body = b'{"v":"' + b"a" * 92 + b'"}'
    assert len(body) == 100
    response = await client(Server(httpx.Response(200, content=body)), max_response_bytes=100).get_json(URL, headers={})
    assert response.body == {"v": "a" * 92}


@pytest.mark.parametrize("declared", [True, False])
async def test_a_body_over_the_cap_is_an_error(declared: bool) -> None:
    body = b"x" * 101
    response = httpx.Response(200, content=body) if declared else httpx.Response(200, stream=httpx.ByteStream(body))
    with pytest.raises(ProviderHTTPError) as info:
        await client(Server(response), max_response_bytes=100).get_json(URL, headers={})
    assert str(info.value) == "lookup: response larger than the configured limit"


async def test_a_declared_oversized_body_is_refused_before_it_is_read() -> None:
    lying = httpx.Response(200, headers={"Content-Length": "5000"}, stream=httpx.ByteStream(b"{}"))
    with pytest.raises(ProviderHTTPError, match="larger than the configured limit"):
        await client(Server(lying), max_response_bytes=100).get_json(URL, headers={})


@pytest.mark.parametrize("status", [429, 503])
async def test_retry_after_is_read_for_rate_limits(status: int) -> None:
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=90), usegmt=True)
    response = await client(Server(httpx.Response(status, headers={"Retry-After": when}))).get_json(URL, headers={})
    assert response.retry_after_s is not None and 80 <= response.retry_after_s <= 90
    response = await client(Server(httpx.Response(status, headers={"Retry-After": "7.5"}))).get_json(URL, headers={})
    assert response.retry_after_s == 7.5


@pytest.mark.parametrize("status", [200, 500, 502])
async def test_retry_after_is_ignored_for_other_statuses(status: int) -> None:
    response = await client(Server(httpx.Response(status, headers={"Retry-After": "30"}))).get_json(URL, headers={})
    assert response.retry_after_s is None


async def test_transport_failures_name_the_provider_and_the_error_type_only() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect to 10.0.0.1 failed", request=request)

    http = JsonHttpClient("lookup", transport=httpx.MockTransport(refused))
    with pytest.raises(ProviderHTTPError) as info:
        await http.get_json(URL, headers={"x-apikey": "k"})
    assert str(info.value) == "lookup: request failed (ConnectError)"


async def test_one_client_per_instance_until_closed() -> None:
    http = client(Server(httpx.Response(200, json={})))
    await http.get_json(URL, headers={})
    first = http._client
    await http.get_json(URL, headers={})
    assert first is not None and http._client is first
    await http.aclose()
    assert http._client is None and first.is_closed


def test_construction_rules() -> None:
    with pytest.raises(ValueError):
        JsonHttpClient("lookup", verify=False)
    with pytest.raises(ValueError):
        JsonHttpClient("lookup", timeout_s=0)
