"""Shared fixtures.

Integration tests use real services named by ``LG_SOTF_TEST_DATABASE_URL`` and
``LG_SOTF_TEST_REDIS_URL`` and are skipped when those are unset. Their
fixtures (``db``, ``repos``, ``redis_client``, the API harness) live in
``tests/integration/conftest.py``; see docs/testing.md.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Iterator

import pytest

from lg_sotf.settings import Settings, get_settings, reset_settings


def _reset_process_state() -> None:
    reset_settings()
    from lg_sotf.llm.client import reset_llm_state
    from lg_sotf.llm.usage import reset_usage_recorder

    reset_llm_state()
    reset_usage_recorder()


@pytest.fixture(autouse=True)
def _isolate_cached_state() -> Iterator[None]:
    """Cached settings, chat models and usage aggregates never leak between tests."""
    _reset_process_state()
    yield
    _reset_process_state()


@pytest.fixture
def settings_env(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Settings]:
    """Set environment variables, clear the settings cache and return ``get_settings()``.

    ``settings_env(LG_SOTF_LLM__PROVIDER="fake", LG_SOTF_ENVIRONMENT="test")``;
    a value of ``None`` removes the variable. Changes are undone after the test.
    """

    def apply(**env: Any) -> Settings:
        for key, value in env.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, str(value))
        reset_settings()
        return get_settings()

    return apply


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    """Build an explicit ``Settings`` (test environment, fake LLM, no .env) with overrides."""

    def build(**overrides: Any) -> Settings:
        base: dict[str, Any] = {
            "environment": "test",
            "llm": {"provider": "fake", "allow_fake": True},
            "security": {
                "encryption_keys": "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA=",
                "indicator_hmac_key": "lg-sotf-test-suite-only-indicator-hmac-key",
            },
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return Settings(_env_file=None, **base)

    return build


@pytest.fixture
def unique_prefix() -> str:
    return f"lgsotf-test-{uuid.uuid4().hex[:12]}"
