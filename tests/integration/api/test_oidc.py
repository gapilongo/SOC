"""OIDC bearer tokens verified against a locally generated JWKS served through ``httpx.MockTransport``."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from tests.integration.api.conftest import TENANT_A, ApiHarness

pytestmark = pytest.mark.integration

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


@pytest.fixture
def idp() -> IdP:
    return IdP()


@pytest.fixture
async def oidc_api(make_api, idp: IdP) -> ApiHarness:
    return await make_api(
        transport=httpx.MockTransport(idp.handler),
        auth={"oidc_issuer": ISSUER, "oidc_audience": AUDIENCE},
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _hmac_token(header: Dict[str, Any], claims: Dict[str, Any], secret: bytes) -> str:
    """HS256 signed with the IdP's public key: the classic algorithm-confusion forgery (built by hand)."""
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_valid_token_maps_tenant_role_and_local_user(oidc_api: ApiHarness, idp: IdP) -> None:
    anonymous = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))
    assert anonymous.status_code == 200, anonymous.text
    body = anonymous.json()
    assert (body["auth_method"], body["tenant_id"], body["role"]) == ("oidc", TENANT_A, "analyst")
    assert body["user_id"] is None
    assert body["email"] == "sso.analyst@a.example.com"

    local = await oidc_api.user(TENANT_A, "viewer", email="sso.analyst@a.example.com", password=None)
    linked = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))
    assert linked.json()["user_id"] == str(local.id)
    assert linked.json()["role"] == "analyst"  # the IdP's role claim decides
    assert (await oidc_api.client.get("/api/v1/alerts", headers=bearer(idp.token()))).status_code == 200


@pytest.mark.parametrize("verified", [False, "false", None])
async def test_unverified_email_never_links_a_local_user(oidc_api: ApiHarness, idp: IdP, verified: Any) -> None:
    await oidc_api.user(TENANT_A, "admin", email="sso.analyst@a.example.com", password=None)
    response = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token(email_verified=verified)))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user_id"] is None
    assert body["email"] is None
    assert body["is_platform_admin"] is False


async def test_string_true_email_verified_links(oidc_api: ApiHarness, idp: IdP) -> None:
    local = await oidc_api.user(TENANT_A, "viewer", email="sso.analyst@a.example.com", password=None)
    response = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token(email_verified="true")))
    assert response.json()["user_id"] == str(local.id)


async def test_oidc_never_grants_platform_admin(oidc_api: ApiHarness, idp: IdP) -> None:
    ops = await oidc_api.user(TENANT_A, "viewer", email="ops@a.example.com", password=None, platform_admin=True)
    for verified in (True, False):
        token = idp.token(sub="attacker-sub", email="ops@a.example.com", email_verified=verified, roles=["viewer"])
        me = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(token))
        assert me.status_code == 200, me.text
        assert me.json()["is_platform_admin"] is False
        assert me.json()["user_id"] == (str(ops.id) if verified else None)
        other = await oidc_api.client.get("/api/v1/alerts", headers={**bearer(token), "X-Tenant-ID": "tenant-b"})
        assert other.status_code == 403


async def test_identity_without_local_account_cannot_review(oidc_api: ApiHarness, idp: IdP) -> None:
    response = await oidc_api.client.post(
        "/api/v1/escalations/x/claim", json={"version": 1}, headers=bearer(idp.token(roles=["admin"]))
    )
    assert response.status_code == 403
    assert "provisioned user account" in response.json()["error"]["message"]


async def test_disabled_local_account_blocks_sso(oidc_api: ApiHarness, idp: IdP) -> None:
    await oidc_api.user(TENANT_A, "analyst", email="sso.analyst@a.example.com", password=None, active=False)
    assert (await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))).status_code == 401


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "someone-else"},
        {"exp": int(time.time()) - 3_600, "iat": int(time.time()) - 7_200},
        {"exp": None},
        {"iss": "https://evil.example.com"},
        {"tenant_id": "no such tenant!"},
        {"tenant_id": "unknown-tenant"},
    ],
)
async def test_invalid_claims_are_rejected(oidc_api: ApiHarness, idp: IdP, claims: Dict[str, Any]) -> None:
    response = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token(**claims)))
    assert response.status_code == 401, response.text


async def test_no_known_role_is_forbidden(oidc_api: ApiHarness, idp: IdP) -> None:
    response = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token(roles=["superuser"])))
    assert response.status_code == 403


async def test_algorithm_confusion_and_unsigned_tokens_are_rejected(oidc_api: ApiHarness, idp: IdP) -> None:
    _, key = idp.keys["rsa-1"]
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "x",
        "iat": now,
        "exp": now + 300,
        "tenant_id": TENANT_A,
        "roles": ["admin"],
    }
    hs256 = _hmac_token({"alg": "HS256", "typ": "JWT", "kid": "rsa-1"}, claims, public_pem)
    none = jwt.encode(claims, key=None, algorithm="none", headers={"kid": "rsa-1"})
    rs512 = jwt.encode(claims, key, algorithm="RS512", headers={"kid": "rsa-1"})
    for token in (hs256, none, rs512):
        assert (await oidc_api.client.get("/api/v1/auth/me", headers=bearer(token))).status_code == 401


async def test_es256_keys_and_kid_rotation(oidc_api: ApiHarness, idp: IdP) -> None:
    assert (await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))).status_code == 200
    assert idp.jwks_fetches == 1
    assert (await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))).status_code == 200
    assert idp.jwks_fetches == 1  # cached

    idp.add_ec("ec-2")
    verifier = oidc_api.ctx.oidc
    assert verifier is not None
    verifier._fetched_at = (verifier._fetched_at or 0) - 60  # past the refetch guard for unknown kids
    rotated = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token("ec-2")))
    assert rotated.status_code == 200, rotated.text
    assert idp.jwks_fetches == 2

    # A token naming an unpublished key right after a refresh does not trigger another fetch.
    idp.add_rsa("rsa-unpublished", publish=False)
    unknown = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token("rsa-unpublished")))
    assert unknown.status_code == 401
    assert idp.jwks_fetches == 2


async def test_idp_outage_is_503_not_401(oidc_api: ApiHarness, idp: IdP) -> None:
    idp.available = False
    response = await oidc_api.client.get("/api/v1/auth/me", headers=bearer(idp.token()))
    assert response.status_code == 503


async def test_local_tokens_still_work_alongside_oidc(oidc_api: ApiHarness) -> None:
    headers = await oidc_api.login_headers(TENANT_A, "admin")
    response = await oidc_api.client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["auth_method"] == "password"
