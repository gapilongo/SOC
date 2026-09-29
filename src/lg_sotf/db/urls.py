"""Conversions between the configured database URL and driver-specific forms."""

from __future__ import annotations

from typing import Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCHEMES = ("postgresql", "postgres")


def _split_scheme(url: str) -> tuple[str, str]:
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise ValueError("database URL must look like postgresql://user:pass@host:port/db")
    base = scheme.split("+", 1)[0].lower()
    if base not in _SCHEMES:
        raise ValueError(f"unsupported database URL scheme: {scheme!r}")
    return base, rest


def to_libpq_url(url: str) -> str:
    """Return a plain ``postgresql://`` URL usable by asyncpg and psycopg."""
    _, rest = _split_scheme(url)
    return f"postgresql://{rest}"


def to_sqlalchemy_url(url: str) -> str:
    """Return a ``postgresql+psycopg://`` URL for SQLAlchemy (Alembic)."""
    _, rest = _split_scheme(url)
    return f"postgresql+psycopg://{rest}"


def with_query_params(url: str, params: Dict[str, Optional[str]], *, override: bool = False) -> str:
    """Set query parameters on ``url``; ``None`` values are ignored.

    Without ``override`` a parameter already present in the URL wins.
    """
    parts = urlsplit(url)
    existing = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in params.items():
        if value is not None and (override or key not in existing):
            existing[key] = value
    return urlunsplit(parts._replace(query=urlencode(existing)))


def database_name(url: str) -> str:
    return urlsplit(to_libpq_url(url)).path.lstrip("/")


_SECRET_QUERY_KEYS = frozenset({"password", "sslpassword", "passfile"})
_MASK = "***"


def redact_url(url: str) -> str:
    """Mask the password (userinfo and libpq query parameters) so the URL can be logged."""
    parts = urlsplit(url)
    if parts.password is not None:
        host = parts.netloc.rsplit("@", 1)[-1]
        parts = parts._replace(netloc=f"{parts.username or ''}:{_MASK}@{host}")
    if parts.query:
        query = [
            (key, _MASK if key.lower() in _SECRET_QUERY_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        parts = parts._replace(query=urlencode(query, safe="*"))
    return urlunsplit(parts)
