"""Canonical JSON, bundle digests and the evidence signing key.

Canonical form (what ``bundle_sha256`` and the signature cover): the
document *without* its top-level ``integrity`` member, serialised as UTF-8
JSON with object keys sorted by code point, no insignificant whitespace,
non-ASCII characters written as-is and no NaN/Infinity — exactly
``json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False).encode("utf-8")``. Every value in a bundle is already a
JSON-native type (see :func:`jsonable`), so serialising the downloaded file
reproduces the bytes that were hashed.

Signatures are HMAC-SHA256 over the canonical bytes with a *dedicated*
signing key: HKDF-SHA256 over the install's ``security.indicator_hmac_key``
(stable for the life of an install, because rotating it would break
indicator correlation) with the info string :data:`SIGNING_KEY_INFO`. The
key never leaves the server; ``key_id`` (a digest of the key) tells a
verifier which key signed a bundle. Anyone holding the install secrets can
verify with ``lg-sotf evidence-verify``; everyone else can still check
``bundle_sha256`` against a copy of the digest recorded in the audit log.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import math
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lg_sotf.security.hashing import SecurityConfigError, indicator_hmac_key
from lg_sotf.settings import Settings

SIGNING_KEY_INFO = b"lg-sotf/evidence-signing/v1"
SIGNATURE_ALG = "HMAC-SHA256"
CANONICALIZATION = "json-sorted-keys-compact-utf8-v1"
INTEGRITY_KEY = "integrity"
_MAX_DEPTH = 64


def jsonable(value: Any, _depth: int = 0) -> Any:
    """``value`` as JSON-native types: datetimes as ISO 8601, UUIDs as strings, Decimals as floats.

    Non-finite floats become ``None`` (JSON has no NaN) and nesting deeper
    than 64 levels is cut, so the result always serialises canonically.
    """
    if _depth > _MAX_DEPTH:
        return None
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, enum.Enum):
        return jsonable(value.value, _depth + 1)
    if isinstance(value, Mapping):
        return {str(k): jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [jsonable(v, _depth + 1) for v in items]
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """Canonical UTF-8 JSON of ``document`` minus its top-level ``integrity`` member."""
    body = {k: v for k, v in document.items() if k != INTEGRITY_KEY}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signing_key(settings: Settings) -> bytes:
    """The evidence signing key (32 bytes, HKDF from ``security.indicator_hmac_key``).

    Raises :class:`SecurityConfigError` when the install secret is missing.
    """
    ikm = indicator_hmac_key(settings)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SIGNING_KEY_INFO).derive(ikm)


def key_id(key: bytes) -> str:
    """Public identifier of a signing key (not usable to recover it)."""
    return hashlib.sha256(b"lg-sotf key id\x1f" + key).hexdigest()[:16]


def seal(document: Dict[str, Any], key: Optional[bytes]) -> Dict[str, Any]:
    """Add ``integrity`` (digest, and a signature when ``key`` is given) to ``document`` and return it."""
    data = canonical_bytes(document)
    integrity: Dict[str, Any] = {
        "canonicalization": CANONICALIZATION,
        "bundle_sha256": sha256_hex(data),
        "signature": None,
    }
    if key is not None:
        integrity["signature"] = {
            "alg": SIGNATURE_ALG,
            "key_id": key_id(key),
            "value": hmac.new(key, data, hashlib.sha256).hexdigest(),
        }
    document[INTEGRITY_KEY] = integrity
    return document


def optional_signing_key(settings: Settings) -> Optional[bytes]:
    """The signing key, or ``None`` when the install has no indicator HMAC key (bundles are then unsigned)."""
    try:
        return signing_key(settings)
    except SecurityConfigError:
        return None


@dataclass(frozen=True)
class Verification:
    """Outcome of :func:`verify`.

    ``signature`` is ``valid``, ``invalid``, ``absent`` (the bundle is not
    signed), ``no_key`` (signed, but no key was available to check it) or
    ``unknown_key`` (signed with another key). A digest alone proves only
    that the file is internally consistent: anyone can recompute it, so
    rely on ``signed_ok`` (or on a digest recorded elsewhere, such as the
    export's audit entry).
    """

    digest_ok: bool
    signature: str

    @property
    def signed_ok(self) -> bool:
        return self.digest_ok and self.signature == "valid"

    def as_dict(self) -> Dict[str, Any]:
        return {"digest_ok": self.digest_ok, "signature": self.signature, "signed_ok": self.signed_ok}


def verify(document: Mapping[str, Any], key: Optional[bytes]) -> Verification:
    """Recompute the digest of a sealed document and check its signature with ``key``."""
    integrity = document.get(INTEGRITY_KEY)
    if not isinstance(integrity, Mapping):
        return Verification(False, "absent")
    data = canonical_bytes(document)
    claimed = integrity.get("bundle_sha256")
    digest_ok = isinstance(claimed, str) and hmac.compare_digest(claimed, sha256_hex(data))
    signature = integrity.get("signature")
    if not isinstance(signature, Mapping):
        return Verification(digest_ok, "absent")
    if key is None:
        return Verification(digest_ok, "no_key")
    if signature.get("key_id") != key_id(key):
        return Verification(digest_ok, "unknown_key")
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    value = signature.get("value")
    valid = isinstance(value, str) and hmac.compare_digest(value, expected)
    return Verification(digest_ok, "valid" if valid else "invalid")


__all__ = [
    "CANONICALIZATION",
    "SIGNATURE_ALG",
    "SIGNING_KEY_INFO",
    "Verification",
    "canonical_bytes",
    "jsonable",
    "key_id",
    "optional_signing_key",
    "seal",
    "sha256_hex",
    "signing_key",
    "verify",
]
