"""Canonical JSON, bundle digests and evidence signatures."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Callable, Dict

import pytest

from lg_sotf.compliance.canonical import (
    canonical_bytes,
    jsonable,
    key_id,
    optional_signing_key,
    seal,
    sha256_hex,
    signing_key,
    verify,
)
from lg_sotf.security.hashing import indicator_hmac_key
from lg_sotf.settings import Settings


def _doc() -> Dict[str, Any]:
    return jsonable(
        {
            "b": [3, 1, 2],
            "a": {"z": "é ünïcode", "y": None, "when": datetime(2026, 9, 30, 12, 0, tzinfo=UTC)},
            "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
            "cost": Decimal("0.125"),
            "nan": float("nan"),
        }
    )


def test_jsonable_produces_json_native_values() -> None:
    doc = _doc()
    assert doc["a"]["when"] == "2026-09-30T12:00:00+00:00"
    assert doc["id"] == "12345678-1234-5678-1234-567812345678"
    assert doc["cost"] == 0.125 and doc["nan"] is None
    assert jsonable({1: {2}}) == {"1": [2]}


def test_canonical_form_is_sorted_compact_utf8_and_ignores_integrity() -> None:
    doc = _doc()
    data = canonical_bytes(doc)
    assert data.startswith(b'{"a":{"when":"2026-09-30T12:00:00+00:00","y":null,"z":"\xc3\xa9')
    assert b" " not in data.replace("é ünïcode".encode(), b"")
    reordered = json.loads(json.dumps(doc, sort_keys=False))
    reordered = dict(reversed(list(reordered.items())))
    assert canonical_bytes(reordered) == data
    assert canonical_bytes({**doc, "integrity": {"anything": 1}}) == data


def test_seal_is_stable_and_detects_changes(make_settings: Callable[..., Settings]) -> None:
    key = signing_key(make_settings())
    first = seal(_doc(), key)
    second = seal(json.loads(json.dumps(first)), key)
    assert first["integrity"] == second["integrity"]
    assert first["integrity"]["bundle_sha256"] == sha256_hex(canonical_bytes(first))
    assert first["integrity"]["signature"]["alg"] == "HMAC-SHA256"
    assert verify(first, key).signed_ok

    tampered = json.loads(json.dumps(first))
    tampered["b"].append(4)
    result = verify(tampered, key)
    assert not result.digest_ok and result.signature == "invalid" and not result.signed_ok

    # Recomputing the digest after tampering does not fool the signature.
    forged = seal({k: v for k, v in tampered.items() if k != "integrity"}, None)
    forged["integrity"]["signature"] = first["integrity"]["signature"]
    assert verify(forged, key).digest_ok and verify(forged, key).signature == "invalid"


def test_signing_key_is_dedicated_and_verification_needs_the_right_key(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    key = signing_key(settings)
    assert len(key) == 32 and key != indicator_hmac_key(settings)
    assert key not in hashlib.sha256(indicator_hmac_key(settings)).digest()
    assert signing_key(settings) == key and len(key_id(key)) == 16

    other = signing_key(make_settings(security={"indicator_hmac_key": "another-test-only-indicator-key"}))
    sealed = seal(_doc(), key)
    assert verify(sealed, other).signature == "unknown_key"
    assert verify(sealed, None).signature == "no_key" and not verify(sealed, None).signed_ok
    unsigned = seal(_doc(), None)
    assert unsigned["integrity"]["signature"] is None
    assert verify(unsigned, key).signature == "absent" and verify(unsigned, key).digest_ok
    assert verify({"no": "integrity"}, key).digest_ok is False


def test_unsigned_when_the_install_has_no_indicator_key(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(security={"indicator_hmac_key": None})
    assert optional_signing_key(settings) is None
    with pytest.raises(Exception, match="indicator_hmac_key"):
        signing_key(settings)
