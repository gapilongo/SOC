"""Locally issued access tokens (HS256 JWT) and opaque refresh tokens."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

import jwt

from lg_sotf.db.repos import User
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.hashing import generate_token, sha256_hex
from lg_sotf.settings import Settings

log = get_logger(__name__)

ACCESS_ALGORITHM = "HS256"
ACCESS_TOKEN_TYPE = "access"  # noqa: S105 - a claim value, not a secret
LEEWAY_S = 10
MIN_SECRET_BYTES = 32
REQUIRED_CLAIMS = ("iss", "aud", "exp", "iat", "jti", "sub", "tenant", "role", "typ")


class InvalidToken(Exception):
    """The token is malformed, expired, or not signed by this deployment (never shown in detail)."""


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime
    expires_in: int


@dataclass(frozen=True)
class RefreshToken:
    """A new refresh token; only ``token_hash`` is stored."""

    token: str
    token_hash: str
    expires_at: datetime

    def __repr__(self) -> str:
        return f"RefreshToken(expires_at={self.expires_at.isoformat()})"


def jwt_secret(settings: Settings) -> bytes:
    """The signing secret; development without one gets a per-process random secret."""
    if settings.auth.jwt_secret is not None:
        value = settings.auth.jwt_secret.get_secret_value().encode("utf-8")
        if len(value) < MIN_SECRET_BYTES and settings.is_production:
            raise RuntimeError("auth.jwt_secret must be at least 32 bytes")
        return value
    if settings.is_production:
        raise RuntimeError("auth.jwt_secret must be set")
    log.warning("auth.ephemeral_jwt_secret", reason="auth.jwt_secret is not set; tokens die with this process")
    return secrets.token_bytes(48)


class TokenService:
    def __init__(self, settings: Settings, secret: Optional[bytes] = None) -> None:
        self._auth = settings.auth
        self._secret = secret if secret is not None else jwt_secret(settings)

    @property
    def access_ttl_s(self) -> int:
        return int(self._auth.access_token_ttl_s)

    @property
    def refresh_ttl_s(self) -> int:
        return int(self._auth.refresh_token_ttl_s)

    def issue_access(self, user: User, *, now: Optional[datetime] = None) -> IssuedToken:
        now = now or datetime.now(UTC)
        expires = now + timedelta(seconds=self.access_ttl_s)
        jti = uuid.uuid4().hex
        claims: Dict[str, Any] = {
            "iss": self._auth.jwt_issuer,
            "aud": self._auth.jwt_audience,
            "sub": str(user.id),
            "tenant": user.tenant_id,
            "role": user.role,
            "pa": bool(user.is_platform_admin),
            "typ": ACCESS_TOKEN_TYPE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": jti,
        }
        token = jwt.encode(claims, self._secret, algorithm=ACCESS_ALGORITHM, headers={"typ": "JWT"})
        return IssuedToken(token=token, jti=jti, expires_at=expires, expires_in=self.access_ttl_s)

    def verify_access(self, token: str) -> Dict[str, Any]:
        """Claims of a valid access token; :class:`InvalidToken` otherwise."""
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[ACCESS_ALGORITHM],
                audience=self._auth.jwt_audience,
                issuer=self._auth.jwt_issuer,
                leeway=LEEWAY_S,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(type(exc).__name__) from exc
        if claims.get("typ") != ACCESS_TOKEN_TYPE:
            raise InvalidToken("wrong token type")
        for name in ("sub", "tenant", "role", "jti"):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise InvalidToken(f"malformed {name} claim")
        return claims

    def new_refresh(self, *, now: Optional[datetime] = None) -> RefreshToken:
        now = now or datetime.now(UTC)
        token = generate_token(32)
        return RefreshToken(
            token=token, token_hash=sha256_hex(token), expires_at=now + timedelta(seconds=self.refresh_ttl_s)
        )


def is_local_token(token: str) -> bool:
    """Whether the (unverified) header says HS256, i.e. the token claims to be ours."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return False
    return header.get("alg") == ACCESS_ALGORITHM
