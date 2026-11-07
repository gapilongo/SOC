"""Indicator HMACs, API keys and password hashing."""

from __future__ import annotations

import hashlib
import uuid
from typing import Callable

import pytest

from lg_sotf.security.hashing import (
    InvalidApiKey,
    SecurityConfigError,
    ahash_password,
    averify_password,
    burn_password_check,
    constant_time_equals,
    generate_api_key,
    generate_token,
    hash_api_key,
    hash_password,
    hmac_indicator,
    looks_like_api_key,
    normalize_indicator,
    parse_api_key,
    password_needs_rehash,
    sha256_hex,
    verify_api_key,
    verify_password,
)
from lg_sotf.settings import Settings

KEY = b"k" * 32


def test_sha256_hex() -> None:
    assert sha256_hex("abc") == hashlib.sha256(b"abc").hexdigest()
    assert sha256_hex(b"abc") == sha256_hex("abc")


def test_constant_time_equals() -> None:
    assert constant_time_equals("a", "a")
    assert not constant_time_equals("a", "b")
    assert constant_time_equals(b"x", "x")


@pytest.mark.parametrize(
    ("itype", "a", "b"),
    [
        ("ip", "::1", "0:0:0:0:0:0:0:1"),
        ("ip", " 10.0.0.1 ", "10.0.0.1"),
        ("domain", "Example.COM.", "example.com"),
        ("domain", "bücher.example", "xn--bcher-kva.example"),
        ("sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("url", "HTTPS://Evil.Example.com/Path?q=1#frag", "https://evil.example.com/Path?q=1"),
        ("url", "http://Host.example", "http://host.example/"),
        ("email", "Alice@Example.com", "alice@example.com"),
        ("user", "CORP\\Alice", "corp\\alice"),
    ],
)
def test_normalisation_makes_equivalents_collide(itype: str, a: str, b: str) -> None:
    assert normalize_indicator(itype, a) == normalize_indicator(itype, b)
    assert hmac_indicator(itype, a, key=KEY) == hmac_indicator(itype, b, key=KEY)


def test_case_preserved_where_meaningful() -> None:
    assert normalize_indicator("process", "C:\\Temp\\Evil.exe") == "C:\\Temp\\Evil.exe"
    assert normalize_indicator("url", "https://x.example/CaseSensitive") == "https://x.example/CaseSensitive"


def test_hmac_is_domain_separated_and_keyed() -> None:
    a = hmac_indicator("domain", "example.com", key=KEY)
    assert len(a) == 64
    assert a != hmac_indicator("hostname", "example.com", key=KEY)
    assert a != hmac_indicator("domain", "example.com", key=b"z" * 32)
    assert a != sha256_hex("example.com")


def test_hmac_key_from_settings(make_settings: Callable[..., Settings]) -> None:
    s = make_settings()
    assert hmac_indicator("ip", "1.2.3.4", settings=s) == hmac_indicator(
        "ip", "1.2.3.4", key=s.security.indicator_hmac_key.get_secret_value().encode()  # type: ignore[union-attr]
    )


def test_hmac_needs_a_key_or_settings() -> None:
    with pytest.raises(TypeError, match="key= or settings="):
        hmac_indicator("ip", "1.2.3.4")


def test_missing_or_weak_hmac_key(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(SecurityConfigError):
        hmac_indicator("ip", "1.2.3.4", settings=Settings(_env_file=None))
    with pytest.raises(SecurityConfigError):
        hmac_indicator("ip", "1.2.3.4", settings=make_settings(security={"indicator_hmac_key": "short"}))


def test_api_key_round_trip() -> None:
    key = generate_api_key()
    assert key.token.startswith(f"lgk_{key.key_id.hex}_")
    assert looks_like_api_key(key.token)
    assert key.prefix == key.key_id.hex[:8]
    assert key.key_hash == hash_api_key(key.token) == sha256_hex(key.token)
    assert key.token not in repr(key)

    parsed = parse_api_key(key.token)
    assert parsed.key_id == key.key_id
    assert parsed.secret not in repr(parsed)
    assert verify_api_key(key.token, key.key_hash)
    assert not verify_api_key(key.token + "x", key.key_hash)
    assert not verify_api_key(generate_api_key().token, key.key_hash)


def test_api_keys_are_unique_and_accept_fixed_id() -> None:
    kid = uuid.uuid4()
    a, b = generate_api_key(kid), generate_api_key(kid)
    assert a.key_id == b.key_id == kid
    assert a.token != b.token and a.key_hash != b.key_hash


@pytest.mark.parametrize(
    "token",
    ["", "lgk_", "lgk_nothex_secretsecretsecretsecretsecretsecret", "abc_" + "0" * 32 + "_" + "s" * 43,
     "lgk_" + "0" * 31 + "_" + "s" * 43, "lgk_" + "0" * 32 + "_short", "lgk_" + "0" * 32 + "_" + "s" * 43 + "!"],
)
def test_malformed_api_keys(token: str) -> None:
    with pytest.raises(InvalidApiKey):
        parse_api_key(token)


def test_generate_token() -> None:
    a, b = generate_token(), generate_token()
    assert a != b and len(a) >= 40


def test_password_hashing() -> None:
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert "correct horse" not in h
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong password")
    assert not verify_password("not-a-hash", "whatever")
    assert not password_needs_rehash(h)
    assert hash_password("same") != hash_password("same")
    with pytest.raises(ValueError):
        hash_password("")


def test_weaker_hashes_need_rehash() -> None:
    from argon2 import PasswordHasher

    old = PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1).hash("pw")
    assert verify_password(old, "pw")
    assert password_needs_rehash(old)


def test_burn_password_check_runs() -> None:
    burn_password_check("anything")


async def test_async_password_helpers() -> None:
    h = await ahash_password("async-password-123")
    assert await averify_password(h, "async-password-123")
    assert not await averify_password(h, "nope")


async def test_password_hashing_concurrency_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import threading
    import time as _time

    from lg_sotf.security import hashing

    active = peak = 0
    lock = threading.Lock()

    def slow_hash(password: str) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        _time.sleep(0.02)
        with lock:
            active -= 1
        return "h"

    monkeypatch.setattr(hashing, "hash_password", slow_hash)
    monkeypatch.setattr(hashing, "verify_password", lambda h, p: slow_hash(p) == "h")
    monkeypatch.setattr(hashing, "burn_password_check", lambda p: None if slow_hash(p) else None)
    calls = [hashing.ahash_password("p") for _ in range(12)]
    calls += [hashing.averify_password("h", "p") for _ in range(12)]
    calls += [hashing.aburn_password_check("p") for _ in range(12)]
    await asyncio.gather(*calls)
    assert peak <= hashing.PASSWORD_HASH_WORKERS
    assert hashing.PASSWORD_HASH_MEMORY_BUDGET_BYTES == hashing.PASSWORD_HASH_WORKERS * 64 * 1024 * 1024


def test_password_pool_works_across_event_loops() -> None:
    import asyncio

    for _ in range(2):
        assert asyncio.run(averify_password(hash_password("loop-password-1"), "loop-password-1"))


def test_published_hmac_key_refused_in_production(make_settings: Callable[..., Settings]) -> None:
    dev_key = "lg-sotf-development-only-indicator-hmac-key"
    assert hmac_indicator("ip", "1.2.3.4", settings=make_settings(security={"indicator_hmac_key": dev_key}))
    prod = make_settings(environment="production", security={"indicator_hmac_key": dev_key})
    with pytest.raises(SecurityConfigError):
        hmac_indicator("ip", "1.2.3.4", settings=prod)
    real = make_settings(environment="production", security={"indicator_hmac_key": "r" * 40})
    assert hmac_indicator("ip", "1.2.3.4", settings=real)
