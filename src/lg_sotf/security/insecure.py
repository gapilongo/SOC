"""Published placeholder secrets that must never protect a real deployment.

``configs/development.yaml`` and ``configs/testing.yaml`` ship recognisable
placeholder keys so a fresh checkout and the test suite run without setup.
They are public, so anyone could forge tokens or decrypt data protected by
them. :func:`insecure_secret_problems` flags them (and any secret carrying a
placeholder marker) so staging and production refuse to start; the key
consumers in this package also refuse them at the point of use.

Keep :data:`KNOWN_INSECURE_SECRETS` in sync with the shipped configs; a unit
test fails when a config contains a secret this module does not recognise.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING, Callable, FrozenSet, List, Optional, Tuple

from pydantic import SecretStr

if TYPE_CHECKING:
    from lg_sotf.settings import Settings

# Substrings that only appear in placeholder values. Real generated secrets never contain them.
INSECURE_MARKERS: Tuple[str, ...] = (
    "development-only",
    "test-suite-only",
    "do-not-use",
    "not-for-use",
    "change-me",
    "changeme",
    "replace-me",
)

KNOWN_INSECURE_SECRETS: FrozenSet[str] = frozenset(
    {
        # configs/development.yaml
        "lg-sotf-development-only-jwt-secret-do-not-use",
        "bGctc290Zi1kZXZlbG9wbWVudC1vbmx5LWtleS0wMDA=",
        "lg-sotf-development-only-indicator-hmac-key",
        # configs/testing.yaml and tests/conftest.py
        "lg-sotf-test-suite-only-jwt-secret-not-for-use",
        "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA=",
        "lg-sotf-test-suite-only-indicator-hmac-key",
    }
)

_SECRET_FIELDS: Tuple[Tuple[str, Callable[[Settings], Optional[SecretStr]]], ...] = (
    ("auth.jwt_secret", lambda s: s.auth.jwt_secret),
    ("auth.bootstrap_admin_password", lambda s: s.auth.bootstrap_admin_password),
    ("security.encryption_keys", lambda s: s.security.encryption_keys),
    ("security.indicator_hmac_key", lambda s: s.security.indicator_hmac_key),
    ("response.webhook_secret", lambda s: s.response.webhook_secret),
    ("api.metrics_token", lambda s: s.api.metrics_token),
)


def _decoded(value: str) -> Optional[str]:
    """Text behind a base64/Fernet-encoded key, when it decodes to ASCII."""
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def is_insecure_secret(value: str) -> bool:
    """Whether ``value`` is a published placeholder (exact match, marker, or encoded marker)."""
    candidate = value.strip()
    if not candidate:
        return False
    if candidate in KNOWN_INSECURE_SECRETS:
        return True
    texts = [candidate.lower()]
    decoded = _decoded(candidate)
    if decoded is not None:
        texts.append(decoded.lower())
    return any(marker in text for text in texts for marker in INSECURE_MARKERS)


def _values(field: str, secret: SecretStr) -> List[str]:
    raw = secret.get_secret_value()
    if field == "security.encryption_keys":
        return [k.strip() for k in raw.split(",") if k.strip()]
    return [raw]


def insecure_secret_problems(settings: Settings) -> List[str]:
    """One message per configured secret that uses a published placeholder value."""
    problems: List[str] = []
    for field, getter in _SECRET_FIELDS:
        secret = getter(settings)
        if secret is not None and any(is_insecure_secret(v) for v in _values(field, secret)):
            problems.append(f"{field} uses a published development/test placeholder; generate a new secret")
    return problems


def assert_no_insecure_secrets(settings: Settings) -> None:
    """Raise ``RuntimeError`` in staging/production when a placeholder secret is configured."""
    if settings.is_production:
        problems = insecure_secret_problems(settings)
        if problems:
            raise RuntimeError("Unsafe production configuration:\n- " + "\n- ".join(problems))
