"""Helpers shared by the API tests: the harness, test users and tokens, MFA and OIDC helpers.

The fixtures that build a harness (``make_api``, ``api``) live in
``tests/integration/conftest.py`` because other packages start the API too.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from lg_sotf.api.context import ApiContext
from lg_sotf.api.ratelimit import WINDOW_S
from lg_sotf.db.repos import ApiKey, Repositories, User
from lg_sotf.security import totp
from lg_sotf.security.hashing import generate_api_key, hash_password
from tests.integration.db._support import TENANT_A, TENANT_B

__all__ = [
    "API", "AUDIENCE", "BASE_URL", "ISSUER", "PASSWORD", "ROLE_MAP", "TENANT_A", "TENANT_B", "TEST_JWT_SECRET",
    "UI_ORIGIN", "ApiClock", "ApiHarness", "IdP", "TotpClock", "bearer", "challenge", "code_now", "enroll",
    "jit_api", "jit_token", "login", "password_hash", "verify",
]

API = "/api/v1"
BASE_URL = "https://testserver"
UI_ORIGIN = "https://ui.example.com"
TEST_JWT_SECRET = "lg-sotf-test-suite-only-jwt-secret-not-for-use"
PASSWORD = "correct horse battery staple"



class ApiClock:
    """The rate limiter's clock: frozen one second into a fixed window, moved only by ``advance``.

    The limiter counts in fixed 60 s windows; on the wall clock a burst that
    straddles a minute boundary is split across two counters and never
    reaches its cap. Frozen, every burst in a test lands in one window.
    """

    def __init__(self) -> None:
        self.now = float(int(time.time()) // WINDOW_S * WINDOW_S + 1)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


_HASH_CACHE: Dict[str, str] = {}


def password_hash(password: str) -> str:
    """argon2 is deliberately slow; hash each test password once per session."""
    if password not in _HASH_CACHE:
        _HASH_CACHE[password] = hash_password(password)
    return _HASH_CACHE[password]


@dataclass
class ApiHarness:
    app: FastAPI
    client: httpx.AsyncClient
    repos: Repositories
    clock: ApiClock = field(default_factory=ApiClock)

    @property
    def ctx(self) -> ApiContext:
        return self.app.state.ctx

    async def user(
        self,
        tenant_id: str = TENANT_A,
        role: str = "analyst",
        *,
        email: Optional[str] = None,
        password: Optional[str] = PASSWORD,
        platform_admin: bool = False,
        active: bool = True,
    ) -> User:
        return await self.repos.users.create(
            tenant_id,
            email or f"{role}-{len((await self.repos.users.list(tenant_id)).items) + 1}@{tenant_id}.example.com",
            role,
            password_hash=password_hash(password) if password else None,
            is_platform_admin=platform_admin,
            is_active=active,
        )

    def token(self, user: User) -> str:
        return self.ctx.tokens.issue_access(user).token

    def auth(self, user: User) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token(user)}"}

    async def login_headers(self, tenant_id: str = TENANT_A, role: str = "analyst", **kwargs: Any) -> Dict[str, str]:
        return self.auth(await self.user(tenant_id, role, **kwargs))

    async def api_key(self, tenant_id: str = TENANT_A, scopes: Iterable[str] = ("ingest",)) -> Tuple[ApiKey, str]:
        generated = generate_api_key()
        key = await self.repos.api_keys.create(
            tenant_id, "test key", generated.prefix, generated.key_hash, list(scopes), key_id=generated.key_id
        )
        return key, generated.token

    async def key_headers(self, tenant_id: str = TENANT_A, scopes: Iterable[str] = ("ingest",)) -> Dict[str, str]:
        _, token = await self.api_key(tenant_id, scopes)
        return {"X-API-Key": token}


def bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------------------- MFA

class TotpClock:
    """The TOTP clock, advanced one 30 s step at a time so each test code is fresh."""

    def __init__(self) -> None:
        self.now = float(int(time.time()) // 30 * 30 + 5)

    def __call__(self) -> float:
        return self.now

    def tick(self, steps: int = 1) -> None:
        self.now += totp.STEP_S * steps


def code_now(secret: str, clock: TotpClock) -> str:
    return totp.totp(secret, at=clock.now)


async def login(api: ApiHarness, email: str, password: str = PASSWORD, tenant: Optional[str] = None):
    body: Dict[str, Any] = {"email": email, "password": password}
    if tenant:
        body["tenant"] = tenant
    return await api.client.post(f"{API}/auth/login", json=body)


async def verify(api: ApiHarness, token: str, code: str):
    return await api.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": token, "code": code})


async def enroll(api: ApiHarness, user: User, clock: TotpClock) -> Tuple[str, List[str]]:
    headers = api.auth(user)
    started = await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=headers)
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    confirmed = await api.client.post(
        f"{API}/auth/mfa/confirm", json={"code": code_now(secret, clock)}, headers=headers
    )
    assert confirmed.status_code == 200, confirmed.text
    clock.tick()
    return secret, confirmed.json()["recovery_codes"]


async def challenge(api: ApiHarness, email: str) -> str:
    response = await login(api, email)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mfa_required"] is True and body["enrollment_required"] is False
    return body["mfa_token"]


# ------------------------------------------------------------------------------ OIDC

ISSUER = "https://idp.example.com/realms/soc"
AUDIENCE = "lg-sotf-api"


class IdP:
    """A tiny identity provider: signing keys, a discovery document and a JWKS endpoint."""

    def __init__(self) -> None:
        self.keys: Dict[str, Any] = {}
        self.published: List[str] = []
        self.jwks_fetches = 0
        self.available = True
        self.add_rsa("rsa-1")

    def add_rsa(self, kid: str, publish: bool = True) -> None:
        self.keys[kid] = ("RS256", rsa.generate_private_key(public_exponent=65537, key_size=2048))
        if publish:
            self.published.append(kid)

    def add_ec(self, kid: str) -> None:
        self.keys[kid] = ("ES256", ec.generate_private_key(ec.SECP256R1()))
        self.published.append(kid)

    def jwks(self) -> Dict[str, Any]:
        out = []
        for kid in self.published:
            alg, key = self.keys[kid]
            algorithm = RSAAlgorithm if alg == "RS256" else ECAlgorithm
            jwk = json.loads(algorithm.to_jwk(key.public_key()))
            out.append({**jwk, "kid": kid, "use": "sig", "alg": alg})
        return {"keys": out}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not self.available:
            return httpx.Response(503)
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs"})
        if request.url.path.endswith("/certs"):
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        return httpx.Response(404)

    def token(self, kid: str = "rsa-1", *, alg: Optional[str] = None, **claims: Any) -> str:
        key_alg, key = self.keys[kid]
        now = int(time.time())
        body = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "idp-user-1",
            "iat": now,
            "exp": now + 300,
            "tenant_id": TENANT_A,
            "roles": ["viewer", "analyst"],
            "email": "sso.analyst@a.example.com",
            "email_verified": True,
        }
        body.update(claims)
        body = {k: v for k, v in body.items() if v is not None}
        return jwt.encode(body, key, algorithm=alg or key_alg, headers={"kid": kid})


ROLE_MAP = {"SOC-Viewers": "viewer", "SOC-Analysts": "analyst", "SOC-Admins": "admin"}


async def jit_api(make_api: Any, idp: IdP, **auth: Any) -> ApiHarness:
    settings = {
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_role_claim": "groups",
        "oidc_jit_provisioning": True,
        "oidc_role_map": ROLE_MAP,
        **auth,
    }
    return await make_api(transport=httpx.MockTransport(idp.handler), auth=settings)


def jit_token(idp: IdP, groups: List[str], **claims: Any) -> str:
    base: Dict[str, Any] = {"sub": "entra-oid-1", "email": "jit.user@a.example.com", "groups": groups, "roles": None}
    base.update(claims)
    return idp.token(**base)
