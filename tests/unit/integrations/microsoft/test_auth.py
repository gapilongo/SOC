"""Token client: secret and certificate credentials, cache isolation, refresh, single flight, errors."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from typing import Any, Dict, List

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from lg_sotf.integrations.microsoft.auth import (
    AppCredentials,
    MicrosoftAuthError,
    TokenProvider,
    client_assertion,
)
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from tests.fixtures.microsoft import (
    TOKEN_PATH,
    FakeMicrosoft,
    fake_config,
    fake_secret,
    make_credentials,
    ms_settings,
    token_error,
    unsigned_token,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def provider(fake: FakeMicrosoft, clock: Clock, sleeps: List[float]) -> TokenProvider:
    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    http = MicrosoftHttpFactory(ms_settings(), transport=fake.transport(), resolver=fake.resolver(), sleep=sleep)
    return TokenProvider(http, clock=clock)


def deadline(seconds: float = 30.0) -> float:
    return asyncio.get_running_loop().time() + seconds


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def test_client_secret_request_shape() -> None:
    fake = FakeMicrosoft()
    fake.grant("graph", ["User.Read.All"])
    creds = make_credentials(fake)
    tokens = provider(fake, Clock(), [])
    token = await tokens.token(creds, "graph", deadline=deadline())
    (request,) = fake.requests
    assert request.method == "POST" and request.url.host == "login.microsoftonline.com"
    assert request.url.path == f"/{creds.directory_tenant_id}/oauth2/v2.0/token"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    form = fake.token_forms()[0]
    assert form == {
        "grant_type": "client_credentials",
        "client_id": creds.client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": creds.client_secret,
    }
    assert tokens.roles(token) == frozenset({"User.Read.All"})
    assert creds.client_secret not in repr(creds) and "client_secret=" not in str(creds)


async def test_defender_token_uses_the_legacy_audience() -> None:
    fake = FakeMicrosoft()
    tokens = provider(fake, Clock(), [])
    await tokens.token(make_credentials(fake), "defender", deadline=deadline())
    assert fake.token_forms()[0]["scope"] == "https://api.securitycenter.microsoft.com/.default"


async def test_certificate_assertion() -> None:
    fake = FakeMicrosoft()
    config, secret = fake_config(credential="certificate")
    creds = make_credentials(fake, config=config, secret=secret)
    assert creds.private_key_pem and creds.private_key_pem not in repr(creds)
    tokens = provider(fake, Clock(), [])
    await tokens.token(creds, "graph", deadline=deadline())
    tokens.invalidate(creds, "graph")
    await tokens.token(creds, "graph", deadline=deadline())
    forms = fake.token_forms()
    assert all("client_secret" not in f for f in forms)
    assert {f["client_assertion_type"] for f in forms} == {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}
    certificate = x509.load_pem_x509_certificate(config["certificate_pem"].encode())
    der = certificate.public_bytes(serialization.Encoding.DER)
    token_url = f"https://login.microsoftonline.com/{config['directory_tenant_id']}/oauth2/v2.0/token"
    jtis = set()
    for form in forms:
        assertion = form["client_assertion"]
        header = jwt.get_unverified_header(assertion)
        assert header["alg"] == "PS256" and header["typ"] == "JWT"
        assert header["x5t"] == b64url(hashlib.sha1(der, usedforsecurity=False).digest())
        assert header["x5t#S256"] == b64url(hashlib.sha256(der).digest())
        claims = jwt.decode(assertion, certificate.public_key(), algorithms=["PS256"], audience=token_url)
        assert claims["iss"] == claims["sub"] == config["client_id"]
        assert claims["nbf"] == claims["iat"] and claims["exp"] - claims["iat"] == 300
        jtis.add(claims["jti"])
    assert len(jtis) == 2


def test_assertion_needs_the_key() -> None:
    fake = FakeMicrosoft()
    creds = make_credentials(fake)
    with pytest.raises(ValueError):
        client_assertion(creds)


async def test_cache_key_isolates_tenants_integrations_and_rotation() -> None:
    fake = FakeMicrosoft()
    tokens = provider(fake, Clock(), [])
    config, secret = fake_config()
    first = make_credentials(fake, config=config, secret=secret, tenant_id="tenant-a")
    same = make_credentials(fake, config=config, secret=secret, tenant_id="tenant-a",
                            integration_id=first.integration_id)
    other_tenant = make_credentials(fake, config=config, secret=secret, tenant_id="tenant-b",
                                    integration_id=first.integration_id)
    rotated = make_credentials(fake, config=config, secret={"client_secret": fake_secret("rotated")},
                               tenant_id="tenant-a", integration_id=first.integration_id)
    a = await tokens.token(first, "graph", deadline=deadline())
    assert await tokens.token(same, "graph", deadline=deadline()) == a
    b = await tokens.token(other_tenant, "graph", deadline=deadline())
    c = await tokens.token(rotated, "graph", deadline=deadline())
    assert len({a, b, c}) == 3 and fake.tokens_issued == 3
    assert fake.token_forms()[-1]["client_secret"] == rotated.client_secret


@pytest.mark.parametrize(("expires_in", "margin"), [(3600, 300), (600, 150)])
async def test_refresh_margin(expires_in: int, margin: int) -> None:
    fake = FakeMicrosoft()
    fake.token_lifetime_s = expires_in
    clock = Clock()
    tokens = provider(fake, clock, [])
    creds = make_credentials(fake)
    first = await tokens.token(creds, "graph", deadline=deadline())
    clock.now += expires_in - margin - 1
    assert await tokens.token(creds, "graph", deadline=deadline()) == first
    clock.now += 2
    assert await tokens.token(creds, "graph", deadline=deadline()) != first
    assert fake.tokens_issued == 2


async def test_single_flight() -> None:
    fake = FakeMicrosoft()
    calls: List[int] = []

    async def slow(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599,
                                         "access_token": unsigned_token({"roles": []})})

    fake.route("POST", "login", TOKEN_PATH, slow)  # type: ignore[arg-type]
    tokens = provider(fake, Clock(), [])
    creds = make_credentials(fake)
    results = await asyncio.gather(*(tokens.token(creds, "graph", deadline=deadline()) for _ in range(5)))
    assert len(set(results)) == 1 and len(calls) == 1


@pytest.mark.parametrize(
    ("error", "aadsts", "ledger"),
    [
        ("invalid_client", 7000215, "credentials_invalid"),
        ("invalid_grant", 700024, "credentials_invalid"),
        ("unauthorized_client", 700016, "app_not_in_tenant"),
        ("invalid_resource", 500011, "app_not_in_tenant"),
        ("invalid_scope", 70011, "consent_missing"),
        ("interaction_required", 53003, "conditional_access_blocked"),
        # The AADSTS number never decides: a consent code under invalid_client is still a credential problem.
        ("invalid_client", 65001, "credentials_invalid"),
        ("invalid_scope", 7000215, "consent_missing"),
    ],
)
async def test_errors_branch_on_the_oauth_error_only(error: str, aadsts: int, ledger: str) -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error(error, aadsts=aadsts))
    tokens = provider(fake, Clock(), [])
    with pytest.raises(MicrosoftAuthError) as exc:
        await tokens.token(make_credentials(fake), "graph", deadline=deadline())
    assert exc.value.ledger_error == ledger and exc.value.oauth_error == error and exc.value.aadsts == aadsts
    assert exc.value.trace_id and exc.value.correlation_id and exc.value.hint
    assert "fake description" not in str(exc.value) and "fake description" not in exc.value.hint


async def test_aadsts_chooses_the_hint() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("invalid_client", aadsts=7000222))
    tokens = provider(fake, Clock(), [])
    with pytest.raises(MicrosoftAuthError) as exc:
        await tokens.token(make_credentials(fake), "graph", deadline=deadline())
    assert "expired" in exc.value.hint


async def test_negative_cache_for_invalid_credentials() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("invalid_client", aadsts=7000215), times=1)
    clock = Clock()
    tokens = provider(fake, clock, [])
    creds = make_credentials(fake)
    for _ in range(3):
        with pytest.raises(MicrosoftAuthError):
            await tokens.token(creds, "graph", deadline=deadline())
    assert len(fake.requests) == 1
    clock.now += 61
    assert await tokens.token(creds, "graph", deadline=deadline())
    assert len(fake.requests) == 2


async def test_transient_token_errors_are_retried_then_retryable() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("temporarily_unavailable", status=503), times=1)
    fake.route("POST", "login", TOKEN_PATH, httpx.Response(429, headers={"Retry-After": "2"}), times=1)
    sleeps: List[float] = []
    tokens = provider(fake, Clock(), sleeps)
    assert await tokens.token(make_credentials(fake), "graph", deadline=deadline())
    assert len(fake.requests) == 3 and sleeps[-1] == 2.0

    always = FakeMicrosoft()
    always.route("POST", "login", TOKEN_PATH, httpx.Response(500))
    tokens = provider(always, Clock(), [])
    with pytest.raises(MicrosoftAuthError) as exc:
        await tokens.token(make_credentials(always), "graph", deadline=deadline())
    assert exc.value.ledger_error == "token_unavailable" and exc.value.retryable


async def test_optional_response_fields() -> None:
    """ext_expires_in and error_uri are optional; expires_in drives the cache."""
    fake = FakeMicrosoft()
    body: Dict[str, Any] = {"token_type": "Bearer", "expires_in": 3599, "access_token": unsigned_token({"roles": ["A"]}),
                            "ext_expires_in": 0}
    fake.route("POST", "login", TOKEN_PATH, httpx.Response(200, json=body), times=1)
    tokens = provider(fake, Clock(), [])
    creds = make_credentials(fake)
    token = await tokens.token(creds, "graph", deadline=deadline())
    assert tokens.roles(token) == frozenset({"A"})
    assert tokens.roles("not-a-jwt") is None and tokens.roles(unsigned_token({})) == frozenset()


def test_credentials_repr_never_shows_secrets() -> None:
    fake = FakeMicrosoft()
    config, secret = fake_config(credential="certificate")
    creds: AppCredentials = make_credentials(fake, config=config, secret=secret)
    text = repr(creds) + str(creds)
    assert "PRIVATE KEY" not in text and "BEGIN" not in text
    assert json.dumps({"c": repr(creds)})  # safe to log
