"""Time-based one-time passwords (RFC 6238) and single-use recovery codes.

* TOTP as authenticator apps implement it: HMAC-SHA-1, 6 digits, 30 s time
  step, a 160-bit random secret shown base32-encoded (RFC 4226 section 4
  recommends at least 128 bits, 160 is the de-facto standard).
* :func:`verify_totp` accepts the current step and one step either side
  (clock drift), compares in constant time and returns the *matched* step so
  the caller can refuse any step at or below the last one used (a code is
  never accepted twice, even within its window).
* Recovery codes are 10 characters from a 32-symbol alphabet without
  look-alike characters (50 bits each). They are stored as HMAC-SHA-256 under
  an install key and bound to the tenant and user, see
  :func:`hash_recovery_code`.

Standard library only (``hmac``, ``hashlib``, ``base64``, ``secrets``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from typing import Callable, List, Optional
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_S = 30
WINDOW = 1
SECRET_BYTES = 20
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_CHARS = 10
# 32 symbols (5 bits each), Crockford-style: no i, l, o or u, so 0 and 1 are unambiguous.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstvwxyz0123456789"
_DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class InvalidSecret(ValueError):
    """The stored or presented TOTP secret is not valid base32."""


def generate_secret() -> str:
    """A new random secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def decode_secret(secret: str) -> bytes:
    cleaned = secret.replace(" ", "").upper()
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(padded, casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSecret("secret is not valid base32") from exc
    if len(key) < 10:
        raise InvalidSecret("secret is too short")
    return key


def hotp(key: bytes, counter: int, *, digits: int = DIGITS, algorithm: str = "SHA1") -> str:
    """RFC 4226 HOTP value for ``counter`` (dynamic truncation, zero padded)."""
    if counter < 0:
        raise ValueError("counter must not be negative")
    digest = hmac.new(key, counter.to_bytes(8, "big"), _DIGESTS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def time_step(at: Optional[float] = None, *, step_s: int = STEP_S) -> int:
    return int((time.time() if at is None else at) // step_s)


def totp(secret: str, *, at: Optional[float] = None, digits: int = DIGITS, algorithm: str = "SHA1") -> str:
    return hotp(decode_secret(secret), time_step(at), digits=digits, algorithm=algorithm)


def normalize_code(code: str) -> str:
    """Digits of a presented TOTP code (users paste ``123 456`` or ``123-456``)."""
    return "".join(ch for ch in code if ch not in " -")


def verify_totp(
    secret: str,
    code: str,
    *,
    at: Optional[float] = None,
    window: int = WINDOW,
    after_step: Optional[int] = None,
) -> Optional[int]:
    """The time step ``code`` is valid for, or ``None``.

    Steps ``current - window .. current + window`` are tried; a step at or
    below ``after_step`` (the last one used) never matches, which makes
    every code single-use. Every candidate is compared, so the time taken
    does not depend on which step matched.
    """
    presented = normalize_code(code)
    if len(presented) != DIGITS or not (presented.isascii() and presented.isdigit()):
        return None
    key = decode_secret(secret)
    current = time_step(at)
    matched: Optional[int] = None
    for step in range(current - window, current + window + 1):
        if step < 0:
            continue
        ok = hmac.compare_digest(hotp(key, step).encode("ascii"), presented.encode("ascii"))
        if ok and (after_step is None or step > after_step) and matched is None:
            matched = step
    return matched


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """``otpauth://totp/...`` URI for authenticator apps (Key Uri Format)."""
    label = quote(f"{issuer}:{account}", safe="@:")
    query = urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP_S},
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"


# --------------------------------------------------------------------------
# Recovery codes
# --------------------------------------------------------------------------


def generate_recovery_codes(
    count: int = RECOVERY_CODE_COUNT, *, choice: Callable[[str], str] = secrets.choice
) -> List[str]:
    """``count`` distinct codes shown as ``xxxxx-xxxxx``."""
    codes: List[str] = []
    while len(codes) < count:
        raw = "".join(choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_CHARS))
        code = f"{raw[:5]}-{raw[5:]}"
        if code not in codes:
            codes.append(code)
    return codes


def normalize_recovery_code(code: str) -> Optional[str]:
    """Canonical form (lower case, no separators) or ``None`` when it cannot be a recovery code."""
    cleaned = "".join(ch for ch in code.strip().lower() if ch not in " -")
    if len(cleaned) != RECOVERY_CODE_CHARS or any(ch not in _RECOVERY_ALPHABET for ch in cleaned):
        return None
    return cleaned


def looks_like_recovery_code(code: str) -> bool:
    return normalize_recovery_code(code) is not None


def recovery_key(install_key: bytes) -> bytes:
    """Domain-separated key for recovery-code hashes, derived from an install secret."""
    return hmac.new(install_key, b"lg-sotf/mfa-recovery-codes/v1", hashlib.sha256).digest()


def hash_recovery_code(key: bytes, tenant_id: str, user_id: str, code: str) -> str:
    """HMAC-SHA-256 of the canonical code, bound to the tenant and user.

    Recovery codes carry 50 bits of randomness, so a slow password hash buys
    nothing against guessing (online guesses are bounded by the lockout),
    and a keyed hash makes a stolen database useless without the install key.
    HMAC also lets a presented code be checked against the stored set in one
    constant-time pass, instead of up to ten argon2 runs per attempt.
    """
    canonical = normalize_recovery_code(code)
    if canonical is None:
        raise ValueError("not a recovery code")
    message = f"{tenant_id}\x1f{user_id}\x1f{canonical}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()
