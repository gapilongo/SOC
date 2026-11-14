"""Settings precedence, fallbacks and production safety checks."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from lg_sotf.security.insecure import insecure_secret_problems
from lg_sotf.settings import Settings, get_settings, reset_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "configs"

_FALLBACK_VARS = (
    "DATABASE_URL",
    "REDIS_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "LG_SOTF_ENV",
    "LG_SOTF_ENVIRONMENT",
    "LG_SOTF_CONFIG_FILE",
    "LG_SOTF_DATABASE__URL",
    "LG_SOTF_REDIS__URL",
    "LG_SOTF_LLM__PROVIDER",
    "LG_SOTF_LLM__API_KEY",
    "LG_SOTF_LLM__FAST__MODEL",
)

_PRODUCTION_SECRETS = {
    "DATABASE_URL": "postgresql://lgsotf:Str0ng-Pa55@db.internal:5432/lgsotf",
    "REDIS_URL": "rediss://:redis-secret@redis.internal:6379/0",
    "ANTHROPIC_API_KEY": "sk-ant-test-key",
    "JWT_SECRET": "j" * 48,
    "ENCRYPTION_KEYS": Fernet.generate_key().decode(),
    "INDICATOR_HMAC_KEY": "h" * 32,
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _FALLBACK_VARS + tuple(_PRODUCTION_SECRETS):
        monkeypatch.delenv(var, raising=False)


def _yaml(tmp_path: Path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return str(path)


def test_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.environment == "development"
    assert s.llm.provider == "anthropic"
    assert s.llm.fast.max_tokens > 0
    assert s.agents == {} and s.routing == {}
    assert not s.is_production


def test_yaml_layer_is_below_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _yaml(tmp_path, "llm:\n  fast:\n    model: from-yaml\n    max_tokens: 111\nrouting:\n  analysis_threshold: 41\n")
    s = Settings(_env_file=None, config_file=path)
    assert s.llm.fast.model == "from-yaml"
    assert s.routing["analysis_threshold"] == 41

    monkeypatch.setenv("LG_SOTF_LLM__FAST__MODEL", "from-env")
    s = Settings(_env_file=None, config_file=path)
    assert s.llm.fast.model == "from-env"
    assert s.llm.fast.max_tokens == 111


def test_init_kwargs_beat_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_LLM__PROVIDER", "openai")
    assert Settings(_env_file=None).llm.provider == "openai"
    assert Settings(_env_file=None, llm={"provider": "fake"}).llm.provider == "fake"


def test_config_file_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_CONFIG_FILE", _yaml(tmp_path, "worker:\n  concurrency: 3\n"))
    assert Settings(_env_file=None).worker.concurrency == 3


def test_yaml_env_references(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_TEST_MODEL", "claude-haiku-4-5")
    monkeypatch.delenv("LG_TEST_MISSING", raising=False)
    path = _yaml(
        tmp_path,
        "llm:\n"
        "  fast:\n    model: ${LG_TEST_MODEL}\n"
        "  deep:\n    model: ${LG_TEST_MISSING:-claude-opus-5-5}\n"
        "  base_url: ${LG_TEST_MISSING}\n",
    )
    s = Settings(_env_file=None, config_file=path)
    assert s.llm.fast.model == "claude-haiku-4-5"
    assert s.llm.deep.model == "claude-opus-5-5"
    assert s.llm.base_url is None


def test_missing_config_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        Settings(_env_file=None, config_file=str(tmp_path / "nope.yaml"))


def test_standard_variable_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://a:b@db/x")
    monkeypatch.setenv("REDIS_URL", "redis://cache:6379/3")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fallback")
    s = Settings(_env_file=None)
    assert s.database.url.get_secret_value() == "postgresql://a:b@db/x"
    assert s.redis.url.get_secret_value() == "redis://cache:6379/3"
    assert s.llm.api_key is not None and s.llm.api_key.get_secret_value() == "sk-ant-fallback"

    monkeypatch.setenv("LG_SOTF_DATABASE__URL", "postgresql://explicit@db/x")
    assert Settings(_env_file=None).database.url.get_secret_value() == "postgresql://explicit@db/x"


def test_standard_variables_never_override_explicit_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # DATABASE_URL / REDIS_URL are the lowest-precedence source (module docstring, configuration.md).
    monkeypatch.setenv("DATABASE_URL", "postgresql://fallback@db/x")
    monkeypatch.setenv("REDIS_URL", "redis://fallback:6379/0")
    for name in ("LG_SOTF_DATABASE__URL", "LG_SOTF_REDIS__URL", "LG_SOTF_CONFIG_FILE"):
        monkeypatch.delenv(name, raising=False)

    kwargs = Settings(_env_file=None, database={"url": "postgresql://kwarg@db/x"}, redis={"url": "redis://kwarg:6379/0"})
    assert kwargs.database.url.get_secret_value() == "postgresql://kwarg@db/x"
    assert kwargs.redis.url.get_secret_value() == "redis://kwarg:6379/0"

    yaml_file = tmp_path / "c.yaml"
    yaml_file.write_text("database:\n  url: postgresql://yaml@db/x\nredis:\n  url: redis://yaml:6379/0\n")
    from_yaml = Settings(_env_file=None, config_file=str(yaml_file))
    assert from_yaml.database.url.get_secret_value() == "postgresql://yaml@db/x"
    assert from_yaml.redis.url.get_secret_value() == "redis://yaml:6379/0"

    dotenv = tmp_path / ".env"
    dotenv.write_text("LG_SOTF_DATABASE__URL=postgresql://dotenv@db/x\n")
    assert Settings(_env_file=str(dotenv)).database.url.get_secret_value() == "postgresql://dotenv@db/x"

    # A section that sets other keys but not the URL still takes the fallback.
    other = Settings(_env_file=None, database={"pool_max": 7})
    assert other.database.url.get_secret_value() == "postgresql://fallback@db/x" and other.database.pool_max == 7


def test_provider_specific_key_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    s = Settings(_env_file=None, llm={"provider": "openai"})
    assert s.llm.api_key is not None and s.llm.api_key.get_secret_value() == "sk-openai"


def test_environment_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_ENV", "staging")
    assert Settings(_env_file=None).environment == "staging"


def test_environment_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_ENVIRONMENT", "staging")
    assert Settings(_env_file=None).environment == "staging"


def test_get_settings_is_cached_until_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    first = get_settings()
    assert get_settings() is first
    monkeypatch.setenv("LG_SOTF_LLM__FAST__MODEL", "changed")
    assert get_settings().llm.fast.model != "changed"
    reset_settings()
    assert get_settings().llm.fast.model == "changed"


def test_assert_safe_only_enforced_for_production_like_environments() -> None:
    Settings(_env_file=None).assert_safe()
    with pytest.raises(RuntimeError) as exc:
        Settings(_env_file=None, environment="production").assert_safe()
    message = str(exc.value)
    assert "jwt_secret" in message and "encryption_keys" in message and "development password" in message


def test_fake_llm_refused_in_production_unless_allowed() -> None:
    base = {
        "environment": "production",
        "auth": {"jwt_secret": "x" * 40},
        "security": {"encryption_keys": "k", "indicator_hmac_key": "h" * 32},
        "database": {"url": "postgresql://u:strong@db/x"},
    }
    problems = Settings(_env_file=None, llm={"provider": "fake"}, **base).production_problems()
    assert any("fake" in p for p in problems)
    allowed = Settings(_env_file=None, llm={"provider": "fake", "allow_fake": True}, **base).production_problems()
    assert allowed == []


def test_break_glass_is_off_by_default_and_needs_smtp_for_its_alert() -> None:
    base = {
        "environment": "production",
        "auth": {"jwt_secret": "x" * 40},
        "security": {"encryption_keys": "k", "indicator_hmac_key": "h" * 32},
        "database": {"url": "postgresql://u:strong@db/x"},
        "llm": {"provider": "fake", "allow_fake": True},
    }
    assert Settings(_env_file=None, **base).break_glass_enabled is False
    sealed = {**base, "auth": {**base["auth"], "break_glass_credential_hash": "$argon2id$test-only"}}
    silent = Settings(_env_file=None, **sealed)
    assert silent.break_glass_enabled is False
    assert any("break_glass_credential_hash needs integrations.smtp_host" in p for p in silent.production_problems())
    mail = {"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"}
    alerting = Settings(_env_file=None, integrations=mail, **sealed)
    assert alerting.break_glass_enabled is True and alerting.production_problems() == []
    with pytest.raises(ValueError):
        Settings(_env_file=None, **{**sealed, "auth": {**sealed["auth"], "break_glass_ttl_s": 3_600}})


@pytest.mark.parametrize("name", ["development", "testing", "staging", "production"])
def test_shipped_configs_load(name: str) -> None:
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / f"{name}.yaml"))
    assert s.routing["analysis_threshold"] == 40
    for agent in ("triage", "correlation", "analysis"):
        assert agent in s.agents
    assert s.ingestion["llm_fallback"] is False


def test_testing_config_is_offline() -> None:
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / "testing.yaml"))
    assert s.environment == "test"
    assert s.llm.provider == "fake"


def test_development_config_uses_claude_tiers() -> None:
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / "development.yaml"))
    assert s.llm.provider == "anthropic"
    assert s.llm.fast.model == "claude-haiku-4-5"
    assert s.llm.deep.model == "claude-opus-5-5"
    assert "soc_dev_password" in s.database.url.get_secret_value()


@pytest.mark.parametrize("name", ["staging", "production"])
def test_production_configs_refuse_to_start_without_secrets(name: str) -> None:
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / f"{name}.yaml"))
    assert s.is_production
    with pytest.raises(RuntimeError):
        s.assert_safe()


@pytest.mark.parametrize("name", ["staging", "production"])
def test_production_configs_take_secrets_from_environment(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in _PRODUCTION_SECRETS.items():
        monkeypatch.setenv(key, value)
    s = Settings(_env_file=None, config_file=str(CONFIG_DIR / f"{name}.yaml"))
    assert s.production_problems() == []
    assert insecure_secret_problems(s) == []
    assert s.auth.jwt_secret is not None and s.auth.jwt_secret.get_secret_value() == _PRODUCTION_SECRETS["JWT_SECRET"]
    assert s.database.url.get_secret_value() == _PRODUCTION_SECRETS["DATABASE_URL"]
    assert "*" not in s.api.cors_origins
    s.assert_safe()


def test_production_yaml_contains_no_literal_secrets() -> None:
    text = (CONFIG_DIR / "production.yaml").read_text()
    for field in ("jwt_secret:", "encryption_keys:", "indicator_hmac_key:", "api_key:", "webhook_secret:", "metrics_token:"):
        for line in text.splitlines():
            if line.strip().startswith(field):
                assert "${" in line, line


def _active_env_lines(text: str) -> dict[str, str]:
    pairs = (line.split("=", 1) for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return {k.strip(): v for k, v in pairs}


def test_env_example_does_not_rely_on_dotenv_for_the_yaml_layer() -> None:
    active = _active_env_lines((REPO_ROOT / ".env.example").read_text())
    # Settings only reads LG_SOTF_CONFIG_FILE from init kwargs or the process environment.
    assert "LG_SOTF_CONFIG_FILE" not in active
    assert all(k.startswith("LG_SOTF_") for k in active), sorted(k for k in active if not k.startswith("LG_SOTF_"))


def test_env_example_contains_no_secrets() -> None:
    active = _active_env_lines((REPO_ROOT / ".env.example").read_text())
    for key in ("LG_SOTF_AUTH__JWT_SECRET", "LG_SOTF_SECURITY__ENCRYPTION_KEYS", "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY",
                "LG_SOTF_LLM__API_KEY", "LG_SOTF_API__METRICS_TOKEN", "LG_SOTF_RESPONSE__WEBHOOK_SECRET"):
        assert key not in active


def test_config_file_named_in_dotenv_is_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("routing:\n  marker: 1\nllm:\n  provider: fake\n")
    (tmp_path / ".env").write_text(f"LG_SOTF_CONFIG_FILE={config}\n")
    monkeypatch.chdir(tmp_path)
    s = Settings()
    assert s.routing == {"marker": 1}
    assert s.llm.provider == "fake"
