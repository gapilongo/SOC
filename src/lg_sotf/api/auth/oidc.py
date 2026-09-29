"""Verification of OIDC bearer tokens against the issuer's JWKS.

* Only ``RS256`` and ``ES256`` are accepted, and the key's type must match
  the algorithm (no HS256/``none`` confusion with a public key).
* ``iss``, ``aud`` (``auth.oidc_audience``, required), ``exp`` and ``iat``
  are checked with a small leeway.
* The JWKS comes from ``auth.oidc_jwks_url`` or the issuer's discovery
  document, is cached for :data:`JWKS_TTL_S`, and is refetched when a token
  names an unknown ``kid`` (key rotation), at most once per
  :data:`MIN_REFRESH_INTERVAL_S` so unknown kids cannot hammer the IdP.
* The email-verified flag (claim ``auth.oidc_email_verified_claim``,
  default ``email_verified``) is surfaced so callers link an identity to a
  local user only by a verified email.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import AuthSettings

log = get_logger(__name__)

ALLOWED_ALGORITHMS = ("RS256", "ES256")
_KEY_TYPES = {"RS256": "RSA", "ES256": "EC"}
JWKS_TTL_S = 600.0
MIN_REFRESH_INTERVAL_S = 30.0
HTTP_TIMEOUT_S = 5.0
LEEWAY_S = 30
MAX_JWKS_BYTES = 256 * 1024


class OIDCError(Exception):
    """The token cannot be accepted (reason is for logs, not clients)."""


class OIDCUnavailable(OIDCError):
    """The issuer's keys could not be fetched."""


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    tenant_id: Optional[str]
    roles: List[str]
    email: Optional[str]
    expires_at: float
    #: Whether the IdP asserted that ``email`` belongs to the subject. Only a
    #: verified email may be used to link the identity to a local user.
    email_verified: bool
    claims: Dict[str, Any]


class OIDCVerifier:
    def __init__(
        self,
        settings: AuthSettings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not settings.oidc_issuer:
            raise ValueError("auth.oidc_issuer is not set")
        self._settings = settings
        self._issuer = settings.oidc_issuer
        self._audience = settings.oidc_audience
        self._jwks_url = settings.oidc_jwks_url
        self._client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, transport=transport, follow_redirects=False)
        self._clock = clock
        self._keys: Dict[str, Any] = {}
        self._fetched_at: Optional[float] = None
        self._lock = asyncio.Lock()

    @property
    def issuer(self) -> str:
        return self._issuer

    async def aclose(self) -> None:
        await self._client.aclose()

    def accepts(self, token: str) -> bool:
        """Whether the unverified token claims to come from the configured issuer."""
        try:
            header = jwt.get_unverified_header(token)
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return False
        return header.get("alg") in ALLOWED_ALGORITHMS and claims.get("iss") == self._issuer

    async def verify(self, token: str) -> OIDCIdentity:
        if not self._audience:
            raise OIDCError("auth.oidc_audience is not configured")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OIDCError("malformed token header") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise OIDCError(f"algorithm {str(alg)[:16]!r} is not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OIDCError("token has no kid")
        key = await self._key(kid, alg)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=self._audience,
                issuer=self._issuer,
                leeway=LEEWAY_S,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(type(exc).__name__) from exc
        return self._identity(claims)

    def _identity(self, claims: Mapping[str, Any]) -> OIDCIdentity:
        s = self._settings
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise OIDCError("sub claim missing")
        tenant = claims.get(s.oidc_tenant_claim)
        if tenant is None:
            tenant = s.oidc_default_tenant
        if tenant is not None and not isinstance(tenant, str):
            raise OIDCError("tenant claim is not a string")
        raw_roles = claims.get(s.oidc_role_claim)
        if isinstance(raw_roles, str):
            roles = [raw_roles]
        elif isinstance(raw_roles, list):
            roles = [r for r in raw_roles if isinstance(r, str)]
        else:
            roles = []
        email = claims.get(s.oidc_email_claim)
        verified = claims.get(s.oidc_email_verified_claim)
        # Some IdPs (e.g. Cognito) send the flag as a string.
        email_verified = verified is True or (isinstance(verified, str) and verified.lower() == "true")
        return OIDCIdentity(
            subject=subject,
            tenant_id=tenant,
            roles=roles,
            email=email if isinstance(email, str) and email else None,
            expires_at=float(claims["exp"]),
            email_verified=email_verified,
            claims=dict(claims),
        )

    async def _key(self, kid: str, alg: str) -> Any:
        now = self._clock()
        stale = self._fetched_at is None or now - self._fetched_at > JWKS_TTL_S
        if stale or kid not in self._keys:
            async with self._lock:
                now = self._clock()
                stale = self._fetched_at is None or now - self._fetched_at > JWKS_TTL_S
                recently = self._fetched_at is not None and now - self._fetched_at < MIN_REFRESH_INTERVAL_S
                if stale or (kid not in self._keys and not recently):
                    self._keys = await self._fetch_keys()
                    self._fetched_at = self._clock()
        jwk = self._keys.get(kid)
        if jwk is None:
            raise OIDCError("unknown signing key")
        expected = _KEY_TYPES[alg]
        if jwk.get("kty") != expected:
            raise OIDCError("key type does not match the algorithm")
        if jwk.get("use") not in (None, "sig"):
            raise OIDCError("key is not a signing key")
        if jwk.get("alg") not in (None, alg):
            raise OIDCError("key is bound to another algorithm")
        try:
            if expected == "RSA":
                return RSAAlgorithm.from_jwk(json.dumps(jwk))
            return ECAlgorithm.from_jwk(json.dumps(jwk))
        except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
            raise OIDCError("signing key is malformed") from exc

    async def _get_json(self, url: str) -> Dict[str, Any]:
        try:
            response = await self._client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise OIDCUnavailable(f"fetching {url} failed: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise OIDCUnavailable(f"fetching {url} returned {response.status_code}")
        if len(response.content) > MAX_JWKS_BYTES:
            raise OIDCUnavailable(f"{url} returned an oversized document")
        try:
            data = response.json()
        except ValueError as exc:
            raise OIDCUnavailable(f"{url} did not return JSON") from exc
        if not isinstance(data, dict):
            raise OIDCUnavailable(f"{url} did not return a JSON object")
        return data

    async def _jwks_uri(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        discovery = await self._get_json(self._issuer.rstrip("/") + "/.well-known/openid-configuration")
        if discovery.get("issuer") != self._issuer:
            raise OIDCUnavailable("discovery document names another issuer")
        uri = discovery.get("jwks_uri")
        if not isinstance(uri, str) or not uri.startswith(("https://", "http://")):
            raise OIDCUnavailable("discovery document has no jwks_uri")
        self._jwks_url = uri
        return uri

    async def _fetch_keys(self) -> Dict[str, Any]:
        data = await self._get_json(await self._jwks_uri())
        keys = data.get("keys")
        if not isinstance(keys, list):
            raise OIDCUnavailable("JWKS has no keys")
        out: Dict[str, Any] = {}
        for jwk in keys:
            if isinstance(jwk, dict) and isinstance(jwk.get("kid"), str):
                out[jwk["kid"]] = jwk
        log.info("oidc.jwks_refreshed", keys=len(out))
        return out
