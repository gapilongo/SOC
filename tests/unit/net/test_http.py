"""The shared outbound HTTP pieces: :func:`read_capped` and :func:`guarded_client`."""

from __future__ import annotations

import gzip
from typing import Any, AsyncIterator, Dict, List, Sequence

import httpx
import pytest

from lg_sotf.net.egress import DestinationPolicy, DestinationRefused, GuardedTransport
from lg_sotf.net.http import ResponseTooLarge, guarded_client, read_capped
from tests.unit.ingestion._support import public_resolver

TIMEOUT = httpx.Timeout(5.0)


class CountingStream(httpx.AsyncByteStream):
    """Yields ``chunks`` and records how many were pulled, so tests can see where reading stopped."""

    def __init__(self, chunks: Sequence[bytes]) -> None:
        self.chunks = list(chunks)
        self.pulled = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.pulled += 1
            yield chunk


async def _streamed(response: httpx.Response, max_bytes: int) -> bytes:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _r: response)) as client:
        async with client.stream("GET", "https://api.example.com/x") as streamed:
            return await read_capped(streamed, max_bytes)


async def test_a_body_up_to_the_limit_is_returned() -> None:
    assert await _streamed(httpx.Response(200, content=b"a" * 10), 10) == b"a" * 10
    assert await _streamed(httpx.Response(204), 0) == b""


async def test_reading_stops_at_the_first_chunk_past_the_limit() -> None:
    stream = CountingStream([b"a" * 4] * 10)
    with pytest.raises(ResponseTooLarge) as info:
        await _streamed(httpx.Response(200, stream=stream), 10)
    assert stream.pulled == 3
    assert info.value.max_bytes == 10 and str(info.value) == "response body exceeds 10 bytes"


async def test_a_declared_length_over_the_limit_is_refused_before_reading() -> None:
    stream = CountingStream([b"{}"])
    with pytest.raises(ResponseTooLarge):
        await _streamed(httpx.Response(200, headers={"Content-Length": "11"}, stream=stream), 10)
    assert stream.pulled == 0


async def test_an_encoded_body_is_capped_on_its_decoded_size() -> None:
    raw = b"a" * 1_000
    packed = gzip.compress(raw)
    assert len(packed) < 100
    headers = {"Content-Encoding": "gzip", "Content-Length": str(len(packed))}
    with pytest.raises(ResponseTooLarge):
        await _streamed(httpx.Response(200, headers=headers, content=packed), 100)
    assert await _streamed(httpx.Response(200, headers=headers, content=packed), 1_000) == raw


async def test_an_encoded_body_is_not_judged_by_its_declared_length() -> None:
    packed = gzip.compress(b"")  # the gzip framing is larger than the empty body it carries
    headers = {"Content-Encoding": "gzip", "Content-Length": str(len(packed))}
    assert await _streamed(httpx.Response(200, headers=headers, content=packed), 5) == b""


@pytest.mark.parametrize("declared", ["abc", "-1", ""])
async def test_an_unreadable_declared_length_falls_back_to_counting(declared: str) -> None:
    response = httpx.Response(200, headers={"Content-Length": declared}, stream=CountingStream([b"ok"]))
    assert await _streamed(response, 10) == b"ok"


# -- guarded_client ---------------------------------------------------------------------------------------------


class Recorder:
    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


async def test_the_guarded_client_checks_the_destination_and_never_follows_redirects() -> None:
    recorder = Recorder(httpx.Response(302, headers={"Location": "https://elsewhere.example.net/"}))
    client = guarded_client(
        policy=DestinationPolicy(require_https=True),
        verify=True,
        user_agent="lg-sotf-test/1",
        timeout=TIMEOUT,
        transport=httpx.MockTransport(recorder),
        resolver=public_resolver,
        pin=False,
    )
    async with client:
        assert isinstance(client._transport, GuardedTransport)
        response = await client.get("https://hooks.example.com/a", headers={"X-Extra": "1"})
        assert response.status_code == 302
        with pytest.raises(DestinationRefused):
            await client.get("https://127.0.0.1/a")
    (sent,) = recorder.requests
    assert sent.url.host == "hooks.example.com"  # an injected transport is not pinned
    assert sent.headers["User-Agent"] == "lg-sotf-test/1" and sent.headers["X-Extra"] == "1"
    assert client.timeout == TIMEOUT and client.follow_redirects is False


async def test_the_guarded_client_takes_a_base_url_and_default_headers() -> None:
    recorder = Recorder(httpx.Response(200))
    client = guarded_client(
        policy=DestinationPolicy(require_https=True),
        verify=True,
        user_agent="lg-sotf-test/1",
        timeout=TIMEOUT,
        base_url="https://siem.example.com/api",
        transport=httpx.MockTransport(recorder),
        resolver=public_resolver,
        pin=False,
        headers={"Accept": "application/json"},
    )
    async with client:
        await client.get("/events")
    (sent,) = recorder.requests
    assert str(sent.url) == "https://siem.example.com/api/events"
    assert sent.headers["Accept"] == "application/json"


async def test_without_a_policy_the_transport_is_used_as_is() -> None:
    recorder = Recorder(httpx.Response(200))
    transport = httpx.MockTransport(recorder)
    client = guarded_client(policy=None, verify=True, user_agent="t", timeout=TIMEOUT, transport=transport, pin=False)
    async with client:
        assert client._transport is transport
        await client.get("http://127.0.0.1/x")
    assert len(recorder.requests) == 1


def test_without_a_transport_a_real_one_is_built_with_the_verify_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    built: List[Dict[str, Any]] = []
    real = httpx.AsyncHTTPTransport

    def spy(**kwargs: Any) -> httpx.AsyncHTTPTransport:
        built.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", spy)
    client = guarded_client(
        policy=DestinationPolicy(require_https=True), verify=False, user_agent="t", timeout=TIMEOUT, pin=True
    )
    assert built == [{"verify": False}]
    assert isinstance(client._transport, GuardedTransport) and client._transport._pin is True
