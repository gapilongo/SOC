"""Integrations tests: real Postgres (outbox, RLS) with receivers stubbed by ``httpx.MockTransport``.

Helpers (``Receiver``, ``add_integration``) are in ``_support.py``; the API
harness used by ``test_api.py`` is in tests/integration/conftest.py.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

import pytest

from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings


@pytest.fixture
def integ_settings(
    make_settings: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> Callable[..., Settings]:
    def build(**overrides: Any) -> Settings:
        base: Dict[str, Any] = {
            "database": {"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            "redis": {"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            "api": {"public_url": "https://soc.example.com"},
            "integrations": {"backoff_base_s": 5.0, "backoff_max_s": 60.0, "max_attempts": 3},
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return make_settings(**base)

    return build


@pytest.fixture
def box(make_settings: Callable[..., Settings]) -> SecretBox:
    return SecretBox.from_settings(make_settings())
