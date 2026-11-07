"""Hashing primitives: indicator HMACs, API keys, opaque tokens and passwords."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar, Union
from urllib.parse import urlsplit, urlunsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from lg_sotf.security.insecure import is_insecure_secret
from lg_sotf.settings import Settings

API_KEY_PREFIX = "lgk"
_API_KEY_RE = re.compile(r"^lgk_(?P<id>[0-9a-f]{32})_(?P<secret>[A-Za-z0-9_-]{32,128})$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class SecurityConfigError(RuntimeError):
    """A required security key is not configured."""


class InvalidApiKey(ValueError):
    """The presented string is not a well-formed LG-SOTF API key."""


def sha256_hex(data: Union[str, bytes]) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def constant_time_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    ab = a.encode("utf-8") if isinstance(a, str) else a
    bb = b.encode("utf-8") if isinstance(b, str) else b
    return hmac.compare_digest(ab, bb)


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------

_HASH_TYPES = frozenset({"hash", "md5", "sha1", "sha256", "sha512", "file_hash", "imphash", "ssdeep"})
_CASE_INSENSITIVE_TYPES = frozenset({"domain", "hostname", "host", "fqdn", "email", "user", "username", "account"})


def normalize_indicator(indicator_type: str, value: str) -> str:
    """Canonical form used for hashing so equivalent indicators collide."""
    itype = indicator_type.strip().lower()
    v = value.strip()
    if itype in ("ip", "ipv4", "ipv6", "ip_address", "src_ip", "dst_ip"):
        try:
            return ipaddress.ip_address(v.strip("[]")).compressed
        except ValueError:
            return v.lower()
    if itype in ("domain", "hostname", "fqdn"):
        v = v.lower().rstrip(".")
        try:
            return v.encode("idna").decode("ascii")
        except UnicodeError:
            return v
    if itype in _HASH_TYPES:
        return v.lower() if _HEX_RE.match(v) else v
    if itype == "url":
        try:
            parts = urlsplit(v)
        except ValueError:
            return v
        if not parts.scheme:
            return v
        netloc = parts.netloc.lower()
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    if itype in _CASE_INSENSITIVE_TYPES:
        return v.lower()
    return v


def indicator_hmac_key(settings: Settings) -> bytes:
    if settings.security.indicator_hmac_key is None:
        raise SecurityConfigError("security.indicator_hmac_key is not configured")
    value = settings.security.indicator_hmac_key.get_secret_value()
    if len(value.encode("utf-8")) < 16:
        raise SecurityConfigError("security.indicator_hmac_key must be at least 16 bytes")
    if settings.is_production and is_insecure_secret(value):
        raise SecurityConfigError(
            "security.indicator_hmac_key is a published development/test key; generate a new one"
        )
    return value.encode("utf-8")


def hmac_indicator(
    indicator_type: str,
    value: str,
    *,
    key: Optional[bytes] = None,
    settings: Optional[Settings] = None,
) -> str:
    """HMAC-SHA256 of a normalised indicator, domain-separated by type.

    Keyed by ``key``, or else by the ``indicator_hmac_key`` of ``settings``; one of them is required.
    """
    if key is not None:
        k = key
    elif settings is not None:
        k = indicator_hmac_key(settings)
    else:
        raise TypeError("hmac_indicator() needs key= or settings=")
    itype = indicator_type.strip().lower()
    msg = f"{itype}\x1f{normalize_indicator(itype, value)}".encode()
    return hmac.new(k, msg, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# API keys and opaque tokens
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GeneratedApiKey:
    key_id: uuid.UUID
    token: str
    prefix: str
    key_hash: str

    def __repr__(self) -> str:
        return f"GeneratedApiKey(key_id={self.key_id!s}, prefix={self.prefix!r})"


@dataclass(frozen=True)
class ParsedApiKey:
    key_id: uuid.UUID
    secret: str

    def __repr__(self) -> str:
        return f"ParsedApiKey(key_id={self.key_id!s})"


def generate_api_key(key_id: Optional[uuid.UUID] = None) -> GeneratedApiKey:
    """Create a new API key. Only ``key_hash`` and ``prefix`` may be persisted."""
    kid = key_id or uuid.uuid4()
    secret = secrets.token_urlsafe(32)
    token = f"{API_KEY_PREFIX}_{kid.hex}_{secret}"
    return GeneratedApiKey(key_id=kid, token=token, prefix=kid.hex[:8], key_hash=sha256_hex(token))


def parse_api_key(token: str) -> ParsedApiKey:
    m = _API_KEY_RE.match(token.strip())
    if not m:
        raise InvalidApiKey("malformed API key")
    return ParsedApiKey(key_id=uuid.UUID(hex=m.group("id")), secret=m.group("secret"))


def looks_like_api_key(token: str) -> bool:
    return token.startswith(f"{API_KEY_PREFIX}_")


def hash_api_key(token: str) -> str:
    return sha256_hex(token.strip())


def verify_api_key(token: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented key against its stored hash."""
    return constant_time_equals(hash_api_key(token), stored_hash)


def generate_token(nbytes: int = 32) -> str:
    """Opaque random token (refresh tokens, invitation links); store ``sha256_hex`` of it."""
    return secrets.token_urlsafe(nbytes)


# --------------------------------------------------------------------------
# Passwords (argon2id)
# --------------------------------------------------------------------------

# RFC 9106 second recommended option (memory-constrained): t=3, m=64 MiB, p=4.
_ARGON2_MEMORY_KIB = 64 * 1024
_password_hasher = PasswordHasher(
    time_cost=3, memory_cost=_ARGON2_MEMORY_KIB, parallelism=4, hash_len=32, salt_len=16
)
_DUMMY_HASH: Optional[str] = None
_T = TypeVar("_T")


def _usable_cpus() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


# Each argon2 computation holds 64 MiB and runs 4 lanes. Bounding concurrent hashes per
# process caps a login burst at PASSWORD_HASH_WORKERS * 64 MiB (e.g. 2 workers = 128 MiB)
# instead of letting the default executor run up to 32 at once; extra requests queue.
PASSWORD_HASH_WORKERS = max(1, _usable_cpus() // 2)
PASSWORD_HASH_MEMORY_BUDGET_BYTES = PASSWORD_HASH_WORKERS * _ARGON2_MEMORY_KIB * 1024
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()


def _password_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(max_workers=PASSWORD_HASH_WORKERS, thread_name_prefix="argon2")
        return _executor


async def _run_bounded(fn: Callable[..., _T], *args: str) -> _T:
    # A dedicated executor (not an asyncio.Semaphore) so the bound holds across event loops.
    return await asyncio.get_running_loop().run_in_executor(_password_executor(), fn, *args)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _password_hasher.check_needs_rehash(password_hash)


def burn_password_check(password: str) -> None:
    """Spend the same time as a real verification (unknown user / locked account)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _password_hasher.hash(secrets.token_urlsafe(16))
    verify_password(_DUMMY_HASH, password)


async def ahash_password(password: str) -> str:
    """``hash_password`` off the event loop on the bounded argon2 pool."""
    return await _run_bounded(hash_password, password)


async def averify_password(password_hash: str, password: str) -> bool:
    return await _run_bounded(verify_password, password_hash, password)


async def aburn_password_check(password: str) -> None:
    await _run_bounded(burn_password_check, password)
