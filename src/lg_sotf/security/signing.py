"""Signing of outbound webhooks: the ``X-LGSOTF-*`` HMAC scheme and its reference verifier.

The response webhook connector (:mod:`lg_sotf.services.connectors.webhook`)
and the outbound notification webhook (:mod:`lg_sotf.integrations.channels`)
both sign with this scheme: ``X-LGSOTF-Signature: v1=<hex>``, an HMAC-SHA256
over ``"<timestamp>.<raw body>"`` with the shared secret, plus
``X-LGSOTF-Timestamp``. :func:`verify_signature` and :func:`verify_request`
are the receiver-side reference implementations (constant-time comparison,
timestamp tolerance, ``Idempotency-Key`` bound to the signed ``action.id``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Mapping, Optional, Union

SIGNATURE_HEADER = "X-LGSOTF-Signature"
TIMESTAMP_HEADER = "X-LGSOTF-Timestamp"
EVENT_HEADER = "X-LGSOTF-Event"
DELIVERY_HEADER = "X-LGSOTF-Delivery"
IDEMPOTENCY_HEADER = "Idempotency-Key"
SIGNATURE_VERSION = "v1"
DEFAULT_TOLERANCE_S = 300
MIN_SECRET_BYTES = 16


def _secret_bytes(secret: Union[str, bytes]) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def sign(secret: Union[str, bytes], timestamp: str, body: bytes) -> str:
    """``v1=<hex>`` HMAC-SHA256 over ``"<timestamp>.<body>"``."""
    mac = hmac.new(_secret_bytes(secret), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


def verify_signature(
    secret: Union[str, bytes],
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    now: Optional[float] = None,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> bool:
    """Receiver-side check (reference implementation): signature matches and the timestamp is fresh."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def verify_request(
    secret: Union[str, bytes],
    headers: Mapping[str, str],
    body: bytes,
    *,
    now: Optional[float] = None,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> Optional[str]:
    """Receiver-side check of a whole request; returns the action id to deduplicate on, or ``None``.

    Verifies the signature and timestamp, and that the (unsigned)
    ``Idempotency-Key`` header, when present, equals the signed body's
    ``action.id``. ``headers`` lookups must be case-insensitive (as in
    ``httpx.Headers`` or most web frameworks).
    """
    timestamp = headers.get(TIMESTAMP_HEADER)
    signature = headers.get(SIGNATURE_HEADER)
    if not timestamp or not signature:
        return None
    if not verify_signature(secret, timestamp, body, signature, now=now, tolerance_s=tolerance_s):
        return None
    payload = _json_object(body)
    action = payload.get("action") if payload is not None else None
    action_id = action.get("id") if isinstance(action, Mapping) else None
    if not isinstance(action_id, str) or not action_id:
        return None
    key = headers.get(IDEMPOTENCY_HEADER)
    if key is not None and not hmac.compare_digest(key.encode("utf-8"), action_id.encode("utf-8")):
        return None
    return action_id


def encode_body(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes (what the signature covers)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")


def _json_object(body: bytes) -> Optional[Dict[str, Any]]:
    if not body:
        return None
    try:
        value = json.loads(body)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
