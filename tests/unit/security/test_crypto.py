"""Fernet secret box: round trip, context binding and key rotation."""

from __future__ import annotations

from typing import Callable

import pytest

from lg_sotf.security.crypto import DecryptionError, SecretBox, generate_key, load_secret_box, parse_keys
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.settings import Settings


def test_json_round_trip() -> None:
    box = SecretBox([generate_key()])
    value = {"client_id": "abc", "client_secret": "s3cr3t", "scopes": ["a", "b"], "n": 1}
    token = box.encrypt_json(value)
    assert "s3cr3t" not in token
    assert box.decrypt_json(token) == value


def test_context_binding() -> None:
    box = SecretBox([generate_key()])
    token = box.encrypt_json({"password": "x"}, context="tenant-a:source-1")
    assert box.decrypt_json(token, context="tenant-a:source-1") == {"password": "x"}
    with pytest.raises(DecryptionError):
        box.decrypt_json(token, context="tenant-b:source-1")
    with pytest.raises(DecryptionError):
        box.decrypt_json(token)


def test_tampered_or_foreign_tokens_fail() -> None:
    box = SecretBox([generate_key()])
    token = box.encrypt_json("v")
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(DecryptionError):
        box.decrypt_json(tampered)
    with pytest.raises(DecryptionError):
        SecretBox([generate_key()]).decrypt_json(token)
    with pytest.raises(DecryptionError):
        box.decrypt("not a token é")


def test_non_envelope_plaintext_rejected() -> None:
    box = SecretBox([generate_key()])
    with pytest.raises(DecryptionError):
        box.decrypt_json(box.encrypt(b"plain bytes"))
    with pytest.raises(DecryptionError):
        box.decrypt_json(box.encrypt(b'{"v": 2, "data": 1}'))


def test_rotation() -> None:
    old_key, new_key = generate_key(), generate_key()
    old_box = SecretBox([old_key])
    token = old_box.encrypt_json({"api_key": "k"}, context="c")

    rotating = SecretBox([new_key, old_key])
    assert rotating.key_count == 2
    assert rotating.decrypt_json(token, context="c") == {"api_key": "k"}
    assert not rotating.is_primary(token)

    rotated = rotating.rotate(token)
    assert rotating.is_primary(rotated)
    assert SecretBox([new_key]).decrypt_json(rotated, context="c") == {"api_key": "k"}
    with pytest.raises(DecryptionError):
        old_box.decrypt_json(rotated, context="c")
    with pytest.raises(DecryptionError):
        SecretBox([generate_key()]).rotate(token)


def test_from_settings(make_settings: Callable[..., Settings]) -> None:
    k1, k2 = generate_key(), generate_key()
    box = SecretBox.from_settings(make_settings(security={"encryption_keys": f" {k1} , {k2} ,"}))
    assert box.key_count == 2
    assert SecretBox([k1]).decrypt_json(box.encrypt_json(1)) == 1


def test_configuration_errors(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(SecurityConfigError):
        SecretBox.from_settings(Settings(_env_file=None))
    with pytest.raises(SecurityConfigError):
        SecretBox.from_settings(make_settings(security={"encryption_keys": " , "}))
    with pytest.raises(SecurityConfigError):
        SecretBox(["not-a-fernet-key"])
    with pytest.raises(SecurityConfigError):
        SecretBox([])


def test_parse_keys() -> None:
    assert parse_keys("a, b,,c ") == ["a", "b", "c"]


@pytest.mark.parametrize(
    "keys",
    [
        "bGctc290Zi1kZXZlbG9wbWVudC1vbmx5LWtleS0wMDA=",
        "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA=",
        "{new},bGctc290Zi1kZXZlbG9wbWVudC1vbmx5LWtleS0wMDA=",
    ],
)
def test_published_keys_refused_in_production(make_settings: Callable[..., Settings], keys: str) -> None:
    keys = keys.format(new=generate_key())
    assert SecretBox.from_settings(make_settings(security={"encryption_keys": keys})).key_count >= 1
    with pytest.raises(SecurityConfigError):
        SecretBox.from_settings(make_settings(environment="staging", security={"encryption_keys": keys}))


def test_generated_keys_accepted_in_production(make_settings: Callable[..., Settings]) -> None:
    box = SecretBox.from_settings(make_settings(environment="production", security={"encryption_keys": generate_key()}))
    assert box.decrypt_json(box.encrypt_json({"a": 1})) == {"a": 1}


@pytest.mark.parametrize("keys", [None, ""])
def test_load_secret_box_is_none_only_when_keys_are_unset(make_settings: Callable[..., Settings], keys: object) -> None:
    assert load_secret_box(make_settings(security={"encryption_keys": keys})) is None


def test_load_secret_box_builds_the_box_from_the_keys(make_settings: Callable[..., Settings]) -> None:
    key = generate_key()
    box = load_secret_box(make_settings(security={"encryption_keys": key}))
    assert box is not None and box.key_count == 1
    assert SecretBox([key]).decrypt_json(box.encrypt_json({"a": 1})) == {"a": 1}


@pytest.mark.parametrize("keys", ["not-a-fernet-key", " , ", "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA="])
def test_load_secret_box_raises_on_invalid_keys(make_settings: Callable[..., Settings], keys: str) -> None:
    # The last one is the published test-suite key: valid Fernet, refused in production.
    with pytest.raises(SecurityConfigError):
        load_secret_box(make_settings(environment="production", security={"encryption_keys": keys}))
