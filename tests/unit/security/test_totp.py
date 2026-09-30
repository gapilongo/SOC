"""TOTP (RFC 6238 / RFC 4226 test vectors), the ±1 step window, replay refusal and recovery codes."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from lg_sotf.security import totp

# RFC 6238 appendix B seeds (ASCII), one per hash function.
SEED_SHA1 = b"12345678901234567890"
SEED_SHA256 = b"12345678901234567890123456789012"
SEED_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"

RFC6238_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
RFC4226_VECTORS = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]


def _b32(seed: bytes) -> str:
    return base64.b32encode(seed).decode().rstrip("=")


@pytest.mark.parametrize(("at", "sha1", "sha256", "sha512"), RFC6238_VECTORS)
def test_rfc6238_vectors(at: int, sha1: str, sha256: str, sha512: str) -> None:
    assert totp.totp(_b32(SEED_SHA1), at=at, digits=8) == sha1
    assert totp.totp(_b32(SEED_SHA256), at=at, digits=8, algorithm="SHA256") == sha256
    assert totp.totp(_b32(SEED_SHA512), at=at, digits=8, algorithm="SHA512") == sha512


def test_rfc4226_hotp_vectors() -> None:
    assert [totp.hotp(SEED_SHA1, counter) for counter in range(10)] == RFC4226_VECTORS


def test_six_digit_codes_are_the_low_digits_of_the_rfc_values() -> None:
    assert totp.totp(_b32(SEED_SHA1), at=59) == "287082"
    assert totp.totp(_b32(SEED_SHA1), at=1111111109) == "081804"


def test_window_accepts_one_step_either_side_and_returns_the_matched_step() -> None:
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    step = totp.time_step(now)
    for offset in (-1, 0, 1):
        code = totp.totp(secret, at=now + offset * totp.STEP_S)
        assert totp.verify_totp(secret, code, at=now) == step + offset
    for offset in (-2, 2):
        code = totp.totp(secret, at=now + offset * totp.STEP_S)
        assert totp.verify_totp(secret, code, at=now) is None


def test_a_used_step_or_an_older_one_never_matches_again() -> None:
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    step = totp.time_step(now)
    code = totp.totp(secret, at=now)
    assert totp.verify_totp(secret, code, at=now, after_step=step - 1) == step
    assert totp.verify_totp(secret, code, at=now, after_step=step) is None
    previous = totp.totp(secret, at=now - totp.STEP_S)
    assert totp.verify_totp(secret, previous, at=now, after_step=step) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5x", "１２３４５６"])
def test_malformed_codes_are_rejected(code: str) -> None:
    assert totp.verify_totp(totp.generate_secret(), code) is None


def test_codes_may_be_typed_with_separators() -> None:
    secret = totp.generate_secret()
    code = totp.totp(secret, at=1_700_000_000.0)
    assert totp.verify_totp(secret, f"{code[:3]} {code[3:]}", at=1_700_000_000.0) is not None
    assert totp.verify_totp(secret, f"{code[:3]}-{code[3:]}", at=1_700_000_000.0) is not None


def test_generated_secrets_are_160_bit_base32() -> None:
    secret = totp.generate_secret()
    assert len(totp.decode_secret(secret)) == 20
    assert secret == secret.upper() and "=" not in secret
    assert totp.generate_secret() != secret
    with pytest.raises(totp.InvalidSecret):
        totp.decode_secret("not base32!")
    with pytest.raises(totp.InvalidSecret):
        totp.decode_secret("MFRA")


def test_provisioning_uri_follows_the_key_uri_format() -> None:
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "ana+soc@example.com", "LG-SOTF")
    parts = urlsplit(uri)
    assert (parts.scheme, parts.netloc) == ("otpauth", "totp")
    assert parts.path == "/LG-SOTF:ana%2Bsoc@example.com"
    query = parse_qs(parts.query)
    assert query == {
        "secret": ["JBSWY3DPEHPK3PXP"],
        "issuer": ["LG-SOTF"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
    }


def test_recovery_codes_are_distinct_and_well_formed() -> None:
    codes = totp.generate_recovery_codes()
    assert len(codes) == totp.RECOVERY_CODE_COUNT == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert len(code) == 11 and code[5] == "-"
        assert totp.looks_like_recovery_code(code)
        assert totp.looks_like_recovery_code(code.upper().replace("-", " "))
    assert not totp.looks_like_recovery_code("123456")
    assert not totp.looks_like_recovery_code("abcde-fghi")  # too short
    assert not totp.looks_like_recovery_code("abcde-fghio")  # 'o' is not in the alphabet


def test_recovery_code_hashes_are_keyed_and_bound_to_the_account() -> None:
    key = totp.recovery_key(b"install-key-" + b"x" * 20)
    other_key = totp.recovery_key(b"install-key-" + b"y" * 20)
    code = totp.generate_recovery_codes(1)[0]
    digest = totp.hash_recovery_code(key, "tenant-a", "user-1", code)
    assert len(digest) == 64 and code.replace("-", "") not in digest
    assert totp.hash_recovery_code(key, "tenant-a", "user-1", code.upper().replace("-", "")) == digest
    assert totp.hash_recovery_code(key, "tenant-b", "user-1", code) != digest
    assert totp.hash_recovery_code(key, "tenant-a", "user-2", code) != digest
    assert totp.hash_recovery_code(other_key, "tenant-a", "user-1", code) != digest
    with pytest.raises(ValueError):
        totp.hash_recovery_code(key, "tenant-a", "user-1", "123456")
