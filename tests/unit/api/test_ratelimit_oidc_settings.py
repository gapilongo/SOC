"""Rate limiter windows, OIDC key caching/rotation guard and tenant settings helpers."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

import fakeredis.aioredis
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from redis.exceptions import ConnectionError as RedisConnectionError

from lg_sotf.api.auth.oidc import OIDCError, OIDCUnavailable, OIDCVerifier
from lg_sotf.api.ratelimit import RateLimiter
from lg_sotf.api.routers.tenant import redact_ciphertexts
from lg_sotf.settings import AuthSettings

# ------------------------------------------------------------------ rate limits


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


async def test_fixed_window_counts_and_resets() -> None:
    redis = fakeredis.aioredis.FakeRedis()
    clock = Clock(1_000_040.0)
    limiter = RateLimiter(redis, "p", clock=clock)
    decisions = [await limiter.hit("api", "user:1", 2) for _ in range(3)]
    assert [d.allowed for d in decisions] == [True, True, False]
    assert decisions[-1].retry_after_s == 40
    assert (await limiter.hit("api", "user:2", 2)).allowed  # other identities are independent
    clock.now += 60
    assert (await limiter.hit("api", "user:1", 2)).allowed
    key = limiter.key("api", "user:1", int(clock.now // 60))
    assert 0 < await redis.ttl(key) <= 61
    assert limiter.key("api", "x", 5, tenant_id="t1") == "p:t:t1:rl:api:x:5"


async def test_limiter_fails_open_when_redis_is_down() -> None:
    class Broken:
        def pipeline(self, **_: Any) -> Any:
            raise RedisConnectionError("down")

        async def get(self, *_: Any) -> Any:
            raise RedisConnectionError("down")

    limiter = RateLimiter(Broken(), "p")  # type: ignore[arg-type]
    assert (await limiter.hit("login", "1.2.3.4", 1)).allowed
    assert await limiter.peek("login", "1.2.3.4") == 0


# ------------------------------------------------------------------------ OIDC

ISSUER = "https://idp.example.com"


class JWKS:
    def __init__(self) -> None:
        self.keys: Dict[str, Any] = {"k1": rsa.generate_private_key(public_exponent=65537, key_size=2048)}
        self.published = ["k1"]
        self.fetches = 0
        self.discovery_issuer = ISSUER

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": self.discovery_issuer, "jwks_uri": f"{ISSUER}/jwks"})
        self.fetches += 1
        keys: List[Dict[str, Any]] = []
        for kid in self.published:
            key = self.keys[kid]
            algorithm = ECAlgorithm if isinstance(key, ec.EllipticCurvePrivateKey) else RSAAlgorithm
            keys.append({**json.loads(algorithm.to_jwk(key.public_key())), "kid": kid})
        return httpx.Response(200, json={"keys": keys})

    def token(self, kid: str = "k1", alg: str = "RS256", **claims: Any) -> str:
        now = int(time.time())
        body = {
            "iss": ISSUER,
            "aud": "api",
            "sub": "s",
            "iat": now,
            "exp": now + 60,
            "tenant_id": "t1",
            "roles": "admin",
        }
        body.update(claims)
        return jwt.encode(body, self.keys[kid], algorithm=alg, headers={"kid": kid})


def _verifier(jwks: JWKS, clock: Clock, **settings: Any) -> OIDCVerifier:
    auth = AuthSettings(oidc_issuer=ISSUER, oidc_audience="api", **settings)
    return OIDCVerifier(auth, transport=httpx.MockTransport(jwks.handler), clock=clock)


async def test_verifier_uses_discovery_and_caches_keys() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    verifier = _verifier(jwks, clock)
    identity = await verifier.verify(jwks.token())
    assert (identity.subject, identity.tenant_id, identity.roles) == ("s", "t1", ["admin"])
    await verifier.verify(jwks.token())
    assert jwks.fetches == 1
    clock.now += 601
    await verifier.verify(jwks.token())
    assert jwks.fetches == 2
    await verifier.aclose()


async def test_unknown_kid_refetches_at_most_every_30_seconds() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    verifier = _verifier(jwks, clock)
    await verifier.verify(jwks.token())
    jwks.keys["k2"] = ec.generate_private_key(ec.SECP256R1())
    clock.now += 5
    jwks.published.append("k2")
    with pytest.raises(OIDCError):
        await verifier.verify(jwks.token("k2", "ES256"))  # within the guard: no refetch
    assert jwks.fetches == 1
    clock.now += 30
    assert (await verifier.verify(jwks.token("k2", "ES256"))).subject == "s"
    assert jwks.fetches == 2
    await verifier.aclose()


async def test_key_type_must_match_the_algorithm() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    jwks.keys["e"] = ec.generate_private_key(ec.SECP256R1())
    jwks.published.append("e")
    verifier = _verifier(jwks, clock)
    forged_header = jwks.token("e", "ES256").split(".")
    header = json.loads(jwt.utils.base64url_decode(forged_header[0]))
    header["alg"] = "RS256"
    tampered = ".".join([jwt.utils.base64url_encode(json.dumps(header).encode()).decode(), *forged_header[1:]])
    with pytest.raises(OIDCError):
        await verifier.verify(tampered)
    await verifier.aclose()


async def test_discovery_for_another_issuer_is_refused() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    jwks.discovery_issuer = "https://evil.example.com"
    verifier = _verifier(jwks, clock)
    with pytest.raises(OIDCUnavailable):
        await verifier.verify(jwks.token())
    await verifier.aclose()


async def test_audience_must_be_configured() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    verifier = OIDCVerifier(AuthSettings(oidc_issuer=ISSUER), transport=httpx.MockTransport(jwks.handler), clock=clock)
    with pytest.raises(OIDCError):
        await verifier.verify(jwks.token())
    await verifier.aclose()


async def test_default_tenant_and_custom_claims() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    verifier = _verifier(jwks, clock, oidc_default_tenant="fallback", oidc_role_claim="groups", oidc_email_claim="upn")
    identity = await verifier.verify(jwks.token(tenant_id=None, groups=["viewer", 7], upn="u@example.com"))
    assert identity.tenant_id == "fallback"
    assert identity.roles == ["viewer"]
    assert identity.email == "u@example.com"
    assert verifier.accepts(jwks.token())
    assert not verifier.accepts("not.a.token")
    await verifier.aclose()


@pytest.mark.parametrize(
    ("claim", "expected"),
    [(True, True), ("true", True), ("TRUE", True), (False, False), ("false", False), (None, False), (1, False)],
)
async def test_email_verified_is_only_true_when_asserted(claim: Any, expected: bool) -> None:
    jwks, clock = JWKS(), Clock(0.0)
    verifier = _verifier(jwks, clock)
    claims: Dict[str, Any] = {"email": "u@example.com"}
    if claim is not None:
        claims["email_verified"] = claim
    identity = await verifier.verify(jwks.token(**claims))
    assert identity.email_verified is expected
    await verifier.aclose()


async def test_email_verified_claim_name_is_configurable() -> None:
    jwks, clock = JWKS(), Clock(0.0)
    assert AuthSettings().oidc_email_verified_claim == "email_verified"
    verifier = _verifier(jwks, clock, oidc_email_verified_claim="custom:email_verified")
    custom = await verifier.verify(jwks.token(email="u@example.com", **{"custom:email_verified": "true"}))
    assert custom.email_verified is True
    standard_only = await verifier.verify(jwks.token(email="u@example.com", email_verified=True))
    assert standard_only.email_verified is False
    await verifier.aclose()


# ---------------------------------------------------------------- websocket origins


def test_websocket_origin_check_uses_the_normalised_cors_list() -> None:
    from types import SimpleNamespace

    from lg_sotf.api.routers.ws import _origin_allowed
    from lg_sotf.settings import Settings

    settings = Settings.model_construct(
        api=SimpleNamespace(cors_origins=["https://ui.example.com/", " https://ops.example.com ", "*"])
    )
    ctx = SimpleNamespace(settings=settings)
    assert _origin_allowed(ctx, None)  # non-browser clients
    assert _origin_allowed(ctx, "https://ui.example.com")
    assert _origin_allowed(ctx, "https://ops.example.com")
    assert not _origin_allowed(ctx, "https://evil.example")
    assert not _origin_allowed(ctx, "*")


# ---------------------------------------------------------------- tenant settings


def test_ciphertexts_are_replaced_by_configured_flags() -> None:
    settings = {
        "response": {"webhook_url": "https://x", "webhook_secret_ciphertext": "gAAAA..."},
        "tools": {"vt": {"enabled": True, "api_key_ciphertext": "gAAAA..."}, "abuse": {"api_key_ciphertext": ""}},
        "autonomy": {"low": "auto"},
    }
    out = redact_ciphertexts(settings)
    assert out == {
        "response": {"webhook_url": "https://x", "webhook_secret_configured": True},
        "tools": {"vt": {"enabled": True, "api_key_configured": True}, "abuse": {}},
        "autonomy": {"low": "auto"},
    }
    assert "gAAAA" not in json.dumps(out)
