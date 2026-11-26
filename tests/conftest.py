"""Shared fixtures.

Integration tests use real services named by ``LG_SOTF_TEST_DATABASE_URL`` and
``LG_SOTF_TEST_REDIS_URL`` and are skipped when those are unset. Their
fixtures (``db``, ``repos``, ``redis_client``, the API harness) live in
``tests/integration/conftest.py``; see docs/testing.md.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Iterator, List

import pytest
import structlog

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


def _own_handlers(root: logging.Logger) -> List[logging.Handler]:
    """The root logger's handlers except pytest's own, which it installs and removes around each test phase."""
    return [h for h in root.handlers if not type(h).__module__.startswith("_pytest.")]


@pytest.fixture(autouse=True)
def _isolate_logging(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Logging configured by one test never reaches the next (issue #382).

    ``configure_logging`` (the CLI entry points and the API app call it, and tests call those in-process)
    sets structlog's ``cache_logger_on_first_use``. The first call through a module-level logger then
    binds that logger for good to the processors of the moment, and a later
    ``structlog.testing.capture_logs()``, which swaps the processors of the *current* configuration, saw
    no event from it. Which capture test lost its events depended on the tests that ran before it in the
    same process, so the suite failed only in some orders (pytest-xdist, pytest-randomly).

    While the suite runs no logger is cached, and after every test the structlog configuration, the root
    logger's level and the handlers the test put on the root logger are back to what the test found.
    """
    configure = structlog.configure

    def configure_without_cache(*args: Any, **kwargs: Any) -> None:
        configure(*args, **{**kwargs, "cache_logger_on_first_use": False})

    monkeypatch.setattr(structlog, "configure", configure_without_cache)
    root = logging.getLogger()
    handlers, level = _own_handlers(root), root.level
    configured, config = structlog.is_configured(), structlog.get_config()
    yield
    structlog.reset_defaults()
    if configured:
        configure(**config)
    for handler in _own_handlers(root):
        if handler not in handlers:
            root.removeHandler(handler)
    for handler in handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(level)
    logging.captureWarnings(False)


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
