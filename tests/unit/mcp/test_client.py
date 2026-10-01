"""The MCP server's REST client: URL policy, retries, redirects, size cap, key handling."""

from __future__ import annotations

from typing import List

import httpx
import pytest

from lg_sotf.mcp.client import ApiCallError, ApiConfigError, LgSotfApiClient, validate_api_url
from tests.unit.mcp._support import StubApi, fake_key, make_client


@pytest.mark.parametrize(
    "url",
    [
        "https://soc.example.com",
        "https://soc.example.com/prefix/",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_allowed_api_urls(url: str) -> None:
    assert validate_api_url(url) == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://soc.example.com",
        "http://10.0.0.5:8000",
        "ftp://soc.example.com",
        "https://user:pw@soc.example.com",
        "https://soc.example.com/?x=1",
        "https://",
        "not a url",
    ],
)
def test_refused_api_urls(url: str) -> None:
    with pytest.raises(ApiConfigError):
        validate_api_url(url)


def test_key_is_required_and_not_in_repr() -> None:
    with pytest.raises(ApiConfigError):
        LgSotfApiClient("https://soc.example.com", " ")
    key = fake_key()
    client = LgSotfApiClient("https://soc.example.com", key)
    assert key not in repr(client)


# The key may come from LG_SOTF_MCP__API_KEY or from the file LG_SOTF_MCP__API_KEY_FILE names: the client's
# messages name both, never only the variable a key-file user never set.
BOTH_SOURCES = "the API key (LG_SOTF_MCP__API_KEY or LG_SOTF_MCP__API_KEY_FILE)"


@pytest.mark.parametrize("bad", ["\ufeff", "\u200b", "\x00", "\u00e9"], ids=["bom", "zero-width", "nul", "non-ascii"])
def test_a_key_with_invalid_characters_is_refused_naming_both_sources(bad: str) -> None:
    key = fake_key()
    with pytest.raises(ApiConfigError) as caught:
        LgSotfApiClient("https://soc.example.com", bad + key)
    assert str(caught.value) == f"{BOTH_SOURCES} contains invalid characters"
    with pytest.raises(ApiConfigError, match=r"is not set") as missing:
        LgSotfApiClient("https://soc.example.com", "")
    assert BOTH_SOURCES in str(missing.value)


@pytest.mark.parametrize("status", [401, 403])
async def test_an_auth_failure_names_both_key_sources(status: int) -> None:
    stub = StubApi()
    stub.json("GET /api/v1/alerts", {"error": {"code": "unauthorized", "message": "bad key"}}, status=status)
    with pytest.raises(ApiCallError) as caught:
        await make_client(stub).get("/api/v1/alerts")
    assert f"Check that {BOTH_SOURCES} is valid and has the scope this tool needs." in str(caught.value)


async def test_get_retries_on_503_then_succeeds() -> None:
    stub = StubApi()
    answers: List[httpx.Response] = [
        httpx.Response(503, headers={"Retry-After": "1"}),
        httpx.Response(502),
        httpx.Response(200, json={"items": []}),
    ]
    stub.routes["GET /api/v1/alerts"] = lambda _r: answers.pop(0)
    client = make_client(stub, max_retries=2)
    assert await client.get("/api/v1/alerts") == {"items": []}
    assert len(stub.requests) == 3
    assert len({r.headers["X-Request-ID"] for r in stub.requests}) == 3


async def test_get_gives_up_after_bounded_retries() -> None:
    stub = StubApi()
    stub.routes["GET /api/v1/alerts"] = lambda _r: httpx.Response(503)
    client = make_client(stub, max_retries=2)
    with pytest.raises(ApiCallError) as info:
        await client.get("/api/v1/alerts")
    assert info.value.status == 503 and len(stub.requests) == 3


async def test_post_is_never_retried() -> None:
    stub = StubApi()
    stub.routes["POST /api/v1/alerts/a/notes"] = lambda _r: httpx.Response(503)
    client = make_client(stub, max_retries=3)
    with pytest.raises(ApiCallError):
        await client.post("/api/v1/alerts/a/notes", {"text": "n"})
    assert len(stub.requests) == 1


async def test_transport_errors_are_retried_for_get_and_reported_safely() -> None:
    key = fake_key()
    calls = []

    def fail(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ConnectError("connection refused", request=request)

    client = LgSotfApiClient(
        "https://soc.example.com", key, transport=httpx.MockTransport(fail), max_retries=1, sleep=_no_sleep
    )
    with pytest.raises(ApiCallError) as info:
        await client.get("/api/v1/alerts")
    assert len(calls) == 2 and "could not be reached" in str(info.value) and key not in str(info.value)


async def _no_sleep(_s: float) -> None:
    return None


async def test_redirects_are_not_followed() -> None:
    stub = StubApi()
    stub.routes["GET /api/v1/alerts"] = lambda _r: httpx.Response(
        302, headers={"Location": "https://evil.example.net/steal"}
    )
    client = make_client(stub)
    with pytest.raises(ApiCallError) as info:
        await client.get("/api/v1/alerts")
    assert "redirect" in str(info.value)
    assert [r.url.host for r in stub.requests] == ["soc.example.com"]


async def test_oversized_responses_are_refused() -> None:
    stub = StubApi()
    stub.routes["GET /api/v1/alerts"] = lambda _r: httpx.Response(200, content=b'{"x":"' + b"a" * 5_000 + b'"}')
    client = make_client(stub, max_response_bytes=1_024)
    with pytest.raises(ApiCallError) as info:
        await client.get("/api/v1/alerts")
    assert "limit" in str(info.value)

    def chunked(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"a" * 5_000))  # no trustworthy Content-Length check

    stub.routes["GET /api/v1/alerts"] = chunked
    with pytest.raises(ApiCallError):
        await client.get("/api/v1/alerts")


async def test_non_json_response_is_an_error() -> None:
    stub = StubApi()
    stub.routes["GET /api/v1/alerts"] = lambda _r: httpx.Response(200, content=b"<html>proxy</html>")
    with pytest.raises(ApiCallError):
        await make_client(stub).get("/api/v1/alerts")


async def test_key_sent_in_header_only() -> None:
    key = fake_key()
    stub = StubApi()
    stub.json("GET /api/v1/alerts", {"items": []})
    await make_client(stub, key=key).get("/api/v1/alerts", {"q": "x"})
    sent = stub.requests[0]
    assert sent.headers["X-API-Key"] == key
    assert key not in str(sent.url) and "authorization" not in sent.headers


async def test_base_url_path_prefix_is_kept() -> None:
    stub = StubApi()
    stub.routes["GET /soc/api/v1/alerts"] = lambda _r: httpx.Response(200, json={"items": []})
    client = make_client(stub, url="https://soc.example.com/soc/")
    assert await client.get("/api/v1/alerts") == {"items": []}


async def test_paths_must_be_api_paths() -> None:
    client = make_client(StubApi())
    with pytest.raises(ValueError):
        await client.get("https://evil.example.net/api/v1/alerts")
