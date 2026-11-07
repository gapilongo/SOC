"""OIDC discovery and JWKS documents are read up to ``MAX_JWKS_BYTES``, streamed (roadmap X2.3).

Before X2.3 the verifier buffered the whole response and only then compared
its length with the cap, so a hostile or broken IdP could make the API hold an
unbounded body in memory. These tests count the chunks the verifier pulls.
"""

from __future__ import annotations

import json
from typing import AsyncIterator, Dict, List

import httpx
import pytest

from lg_sotf.api.auth.oidc import MAX_JWKS_BYTES, OIDCUnavailable, OIDCVerifier
from lg_sotf.settings import AuthSettings

ISSUER = "https://idp.example.com"
CHUNK = 64 * 1024


class Chunks(httpx.AsyncByteStream):
    """An endless-looking body: ``count`` chunks of ``CHUNK`` bytes, recording how many were pulled."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.pulled = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(self.count):
            self.pulled += 1
            yield b" " * CHUNK


class Idp:
    def __init__(self, jwks: httpx.Response) -> None:
        self.jwks = jwks
        self.paths: List[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"})
        return self.jwks


def verifier(idp: Idp) -> OIDCVerifier:
    return OIDCVerifier(AuthSettings(oidc_issuer=ISSUER, oidc_audience="api"), transport=httpx.MockTransport(idp))


async def test_an_oversized_jwks_is_refused_before_it_is_fully_buffered() -> None:
    body = Chunks(count=64)  # 4 MiB on offer, 16 times the cap
    oidc = verifier(Idp(httpx.Response(200, stream=body)))
    with pytest.raises(OIDCUnavailable) as info:
        await oidc._fetch_keys()
    assert str(info.value) == f"{ISSUER}/jwks returned an oversized document"
    assert info.value.__cause__ is None
    assert body.pulled == MAX_JWKS_BYTES // CHUNK + 1  # stopped at the first chunk past the cap
    await oidc.aclose()


async def test_a_declared_oversized_jwks_is_refused_without_reading_it() -> None:
    body = Chunks(count=64)
    response = httpx.Response(200, headers={"Content-Length": str(MAX_JWKS_BYTES + 1)}, stream=body)
    oidc = verifier(Idp(response))
    with pytest.raises(OIDCUnavailable, match="oversized document"):
        await oidc._fetch_keys()
    assert body.pulled == 0
    await oidc.aclose()


async def test_an_oversized_discovery_document_is_refused() -> None:
    body = Chunks(count=8)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=body)

    oidc = OIDCVerifier(AuthSettings(oidc_issuer=ISSUER, oidc_audience="api"), transport=httpx.MockTransport(handler))
    with pytest.raises(OIDCUnavailable, match="openid-configuration returned an oversized document"):
        await oidc._fetch_keys()
    assert body.pulled == 5
    await oidc.aclose()


async def test_a_jwks_at_the_cap_is_accepted() -> None:
    keys: Dict[str, object] = {"keys": [{"kid": "k1", "kty": "RSA"}]}
    text = json.dumps(keys).encode()
    padded = text + b" " * (MAX_JWKS_BYTES - len(text))
    assert len(padded) == MAX_JWKS_BYTES
    oidc = verifier(Idp(httpx.Response(200, content=padded)))
    assert list(await oidc._fetch_keys()) == ["k1"]
    await oidc.aclose()


async def test_an_error_status_is_reported_without_reading_the_body() -> None:
    body = Chunks(count=64)
    oidc = verifier(Idp(httpx.Response(503, stream=body)))
    with pytest.raises(OIDCUnavailable) as info:
        await oidc._fetch_keys()
    assert str(info.value) == f"fetching {ISSUER}/jwks returned 503"
    assert body.pulled == 0
    await oidc.aclose()


@pytest.mark.parametrize(("content", "message"), [(b"<html/>", "did not return JSON"), (b"[1]", "JSON object")])
async def test_a_document_that_is_not_a_json_object_is_refused(content: bytes, message: str) -> None:
    oidc = verifier(Idp(httpx.Response(200, content=content)))
    with pytest.raises(OIDCUnavailable, match=message):
        await oidc._fetch_keys()
    await oidc.aclose()


async def test_transport_failures_are_unavailable() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    oidc = OIDCVerifier(AuthSettings(oidc_issuer=ISSUER, oidc_audience="api"), transport=httpx.MockTransport(refused))
    with pytest.raises(OIDCUnavailable, match="failed: ConnectError"):
        await oidc._fetch_keys()
    await oidc.aclose()
