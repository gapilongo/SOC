"""Published development/test placeholder secrets are refused in staging and production."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest
import yaml
from cryptography.fernet import Fernet

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import ConfigError
from lg_sotf.security.insecure import (
    KNOWN_INSECURE_SECRETS,
    assert_no_insecure_secrets,
    insecure_secret_problems,
    is_insecure_secret,
)
from lg_sotf.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIR = REPO_ROOT / "configs"
_SECRET_NAMES = ("jwt_secret", "encryption_keys", "indicator_hmac_key", "webhook_secret", "metrics_token", "api_key")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LG_SOTF_CONFIG_FILE", "LG_SOTF_ENVIRONMENT", "LG_SOTF_ENV", "DATABASE_URL", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def _literal_secrets(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _SECRET_NAMES and isinstance(value, str) and "${" not in value:
                yield from (v.strip() for v in value.split(",") if v.strip())
            else:
                yield from _literal_secrets(value)
    elif isinstance(node, list):
        for item in node:
            yield from _literal_secrets(item)


@pytest.mark.parametrize("name", ["development", "testing"])
def test_every_shipped_placeholder_secret_is_recognised(name: str) -> None:
    secrets = list(_literal_secrets(yaml.safe_load((CONFIG_DIR / f"{name}.yaml").read_text())))
    assert len(secrets) >= 3
    for secret in secrets:
        assert is_insecure_secret(secret), secret


def test_test_fixture_secrets_are_recognised(make_settings: Callable[..., Settings]) -> None:
    s = make_settings()
    assert s.security.encryption_keys is not None and s.security.indicator_hmac_key is not None
    assert is_insecure_secret(s.security.encryption_keys.get_secret_value())
    assert is_insecure_secret(s.security.indicator_hmac_key.get_secret_value())


@pytest.mark.parametrize(
    "value",
    [
        *sorted(KNOWN_INSECURE_SECRETS),
        "  lg-sotf-development-only-jwt-secret-do-not-use  ",
        "my-CHANGEME-secret-value-that-is-long-enough",
        "replace-me-with-a-real-secret-0000000000000",
        # base64 of "prod-key-change-me-xxxxxxxxxxxxxx" (a placeholder hidden inside a Fernet-shaped key)
        "cHJvZC1rZXktY2hhbmdlLW1lLXh4eHh4eHh4eHh4eHh4",
    ],
)
def test_placeholders_are_insecure(value: str) -> None:
    assert is_insecure_secret(value)


def test_generated_secrets_are_not_flagged() -> None:
    import secrets

    for _ in range(50):
        assert not is_insecure_secret(Fernet.generate_key().decode())
        assert not is_insecure_secret(secrets.token_urlsafe(48))
    assert not is_insecure_secret("")


def _production_from_development_yaml(**overrides: Any) -> Settings:
    kwargs: Dict[str, Any] = {
        "environment": "production",
        "auth": {"cookie_secure": True},
        "api": {"cors_origins": []},
        "database": {"url": "postgresql://lgsotf:Str0ng-Pa55@db.internal:5432/lgsotf"},
        "llm": {"api_key": "sk-ant-real-key"},
    }
    kwargs.update(overrides)
    return Settings(_env_file=None, config_file=str(CONFIG_DIR / "development.yaml"), **kwargs)


def test_development_yaml_in_production_is_refused() -> None:
    s = _production_from_development_yaml()
    assert s.auth.jwt_secret is not None
    assert s.auth.jwt_secret.get_secret_value() == "lg-sotf-development-only-jwt-secret-do-not-use"
    problems = insecure_secret_problems(s)
    assert [p.split(" ")[0] for p in problems] == [
        "auth.jwt_secret",
        "security.encryption_keys",
        "security.indicator_hmac_key",
    ]
    with pytest.raises(RuntimeError) as exc:
        assert_no_insecure_secrets(s)
    assert "auth.jwt_secret" in str(exc.value)
    with pytest.raises(ConfigError) as cexc:
        ConfigManager(settings=s).validate()
    assert "published development/test placeholder" in str(cexc.value)


def test_assert_safe_refuses_development_yaml_in_production() -> None:
    with pytest.raises(RuntimeError):
        _production_from_development_yaml().assert_safe()


def test_each_secret_field_is_checked() -> None:
    placeholder = "lg-sotf-development-only-placeholder-000000000"
    s = Settings(
        _env_file=None,
        environment="production",
        auth={"jwt_secret": "j" * 48, "bootstrap_admin_password": placeholder},
        security={"encryption_keys": Fernet.generate_key().decode(), "indicator_hmac_key": "h" * 32},
        response={"webhook_secret": placeholder},
        api={"metrics_token": placeholder},
    )
    fields: List[str] = [p.split(" ")[0] for p in insecure_secret_problems(s)]
    assert fields == ["auth.bootstrap_admin_password", "response.webhook_secret", "api.metrics_token"]


def test_development_is_not_blocked() -> None:
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / "development.yaml"))
    assert insecure_secret_problems(s)
    assert_no_insecure_secrets(s)
    assert ConfigManager(settings=s).validate() is True
