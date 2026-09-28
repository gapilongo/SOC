"""Authenticated encryption for secrets at rest (source credentials, webhook secrets).

Keys come from ``security.encryption_keys`` as a comma-separated list of
Fernet keys; the first key encrypts, all keys decrypt. Rotating means
prepending a new key, re-encrypting stored values with :meth:`SecretBox.rotate`
and finally dropping the old key.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional, Sequence

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.security.insecure import is_insecure_secret
from lg_sotf.settings import Settings, get_settings

_ENVELOPE_VERSION = 1


class DecryptionError(ValueError):
    """Ciphertext is corrupt, was produced with an unknown key, or has the wrong context."""


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


def parse_keys(raw: str) -> List[str]:
    return [k.strip() for k in raw.split(",") if k.strip()]


class SecretBox:
    """Encrypts JSON values with optional context binding (e.g. tenant/source id)."""

    def __init__(self, keys: Sequence[str]):
        if not keys:
            raise SecurityConfigError("at least one encryption key is required")
        fernets = []
        for idx, key in enumerate(keys):
            try:
                fernets.append(Fernet(key.encode("ascii") if isinstance(key, str) else key))
            except (ValueError, TypeError) as exc:
                raise SecurityConfigError(f"encryption key #{idx + 1} is not a valid Fernet key") from exc
        self._fernet = MultiFernet(fernets)
        self._primary = fernets[0]
        self._key_count = len(fernets)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None) -> SecretBox:
        s = settings or get_settings()
        if s.security.encryption_keys is None:
            raise SecurityConfigError("security.encryption_keys is not configured")
        keys = parse_keys(s.security.encryption_keys.get_secret_value())
        if not keys:
            raise SecurityConfigError("security.encryption_keys is empty")
        if s.is_production and any(is_insecure_secret(k) for k in keys):
            raise SecurityConfigError(
                "security.encryption_keys contains a published development/test key; generate a new one"
            )
        return cls(keys)

    @property
    def key_count(self) -> int:
        return self._key_count

    def encrypt(self, data: bytes) -> str:
        return self._fernet.encrypt(data).decode("ascii")

    def decrypt(self, token: str) -> bytes:
        try:
            return self._fernet.decrypt(token.encode("ascii"))
        except (InvalidToken, UnicodeEncodeError) as exc:
            raise DecryptionError("unable to decrypt value") from exc

    def encrypt_json(self, value: Any, *, context: Optional[str] = None) -> str:
        envelope = {"v": _ENVELOPE_VERSION, "ctx": context, "data": value}
        return self.encrypt(json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def decrypt_json(self, token: str, *, context: Optional[str] = None) -> Any:
        plaintext = self.decrypt(token)
        try:
            envelope = json.loads(plaintext)
        except ValueError as exc:
            raise DecryptionError("decrypted value is not valid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("v") != _ENVELOPE_VERSION or "data" not in envelope:
            raise DecryptionError("unsupported secret envelope")
        if envelope.get("ctx") != context:
            raise DecryptionError("secret context mismatch")
        return envelope["data"]

    def rotate(self, token: str) -> str:
        """Re-encrypt ``token`` under the primary key (no-op on the plaintext)."""
        try:
            return self._fernet.rotate(token.encode("ascii")).decode("ascii")
        except (InvalidToken, UnicodeEncodeError) as exc:
            raise DecryptionError("unable to rotate value") from exc

    def is_primary(self, token: str) -> bool:
        """Whether ``token`` is already encrypted under the primary key."""
        try:
            self._primary.decrypt(token.encode("ascii"))
        except (InvalidToken, UnicodeEncodeError):
            return False
        return True
