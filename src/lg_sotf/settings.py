"""Typed application settings.

Precedence (highest first): explicit init kwargs, environment variables
(``LG_SOTF_<SECTION>__<KEY>``), ``.env`` file, YAML file
(``LG_SOTF_CONFIG_FILE``), field defaults. YAML values may reference
environment variables as ``${VAR}`` or ``${VAR:-default}``.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Type

import yaml
from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

Environment = Literal["development", "test", "staging", "production"]
LLMProvider = Literal["anthropic", "openai", "gemini", "fake"]

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")

        expanded = _ENV_REF.sub(repl, value)
        return expanded if expanded != "" or value == "" else None
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _drop_empty(value: Any) -> Any:
    """Remove keys whose ${VAR} expanded to nothing so defaults still apply."""
    if isinstance(value, dict):
        return {k: _drop_empty(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_empty(v) for v in value]
    return value


class _EnvironmentAliasSource(PydanticBaseSettingsSource):
    """Legacy ``LG_SOTF_ENV``; ranks below ``LG_SOTF_ENVIRONMENT`` and above files."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> Tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> Dict[str, Any]:
        value = os.environ.get("LG_SOTF_ENV")
        return {"environment": value} if value else {}


class YamlFileSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: Type[BaseSettings], path: Optional[str]):
        super().__init__(settings_cls)
        self._data: Dict[str, Any] = {}
        if path:
            p = Path(path)
            if not p.is_file():
                raise FileNotFoundError(f"Config file not found: {p}")
            loaded = yaml.safe_load(p.read_text()) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file {p} must contain a mapping")
            self._data = _drop_empty(_expand_env(loaded))

    def get_field_value(self, field: FieldInfo, field_name: str) -> Tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> Dict[str, Any]:
        return {k: v for k, v in self._data.items() if k in self.settings_cls.model_fields}


class DatabaseSettings(BaseModel):
    # Runtime connection (API/worker). In production this is a non-owner role.
    url: SecretStr = SecretStr("postgresql://soc:soc_dev_password@localhost:5432/soc")
    # Schema-owner connection for migrate/scheduler; defaults to ``url``.
    migration_url: Optional[SecretStr] = None
    # Login role that ``lg-sotf migrate`` grants runtime privileges to.
    runtime_role: Optional[str] = None
    pool_min: int = 2
    pool_max: int = 10
    command_timeout_s: float = 30.0
    statement_timeout_ms: int = 30_000
    ssl_mode: Optional[Literal["disable", "prefer", "require", "verify-ca", "verify-full"]] = None
    ssl_root_cert: Optional[str] = None


class RedisSettings(BaseModel):
    url: SecretStr = SecretStr("redis://localhost:6379/0")
    max_connections: int = 64
    key_prefix: str = "lgsotf"
    socket_timeout_s: float = 10.0


class LLMTierSettings(BaseModel):
    model: str
    max_tokens: int = 2048
    temperature: Optional[float] = 0.0
    effort: Optional[Literal["low", "medium", "high", "xhigh", "max"]] = None
    timeout_s: float = 60.0
    max_retries: int = 2
    max_concurrency: int = 16


class LLMSettings(BaseModel):
    enabled: bool = True
    provider: LLMProvider = "anthropic"
    api_key: Optional[SecretStr] = None
    base_url: Optional[str] = None
    fast: LLMTierSettings = LLMTierSettings(model="claude-haiku-4-5", max_tokens=2048)
    # Opus 5.5 always thinks and bills thinking as output, so leave room in max_tokens.
    deep: LLMTierSettings = LLMTierSettings(
        model="claude-opus-5-5", max_tokens=16_000, timeout_s=300.0, max_concurrency=8
    )
    refusal_fallback: bool = True
    prices: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    allow_fake: bool = False
    max_input_chars: int = 24_000
    max_field_chars: int = 2_000
    max_list_items: int = 50
    prompt_caching: bool = True
    daily_token_budget_per_tenant: Optional[int] = None


class AuthSettings(BaseModel):
    jwt_secret: Optional[SecretStr] = None
    jwt_issuer: str = "lg-sotf"
    jwt_audience: str = "lg-sotf-api"
    access_token_ttl_s: int = 900
    refresh_token_ttl_s: int = 14 * 24 * 3600
    cookie_secure: bool = True
    cookie_domain: Optional[str] = None
    password_min_length: int = 12
    max_login_attempts: int = 10
    lockout_minutes: int = 15
    oidc_issuer: Optional[str] = None
    oidc_audience: Optional[str] = None
    oidc_jwks_url: Optional[str] = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_role_claim: str = "roles"
    oidc_email_claim: str = "email"
    oidc_email_verified_claim: str = "email_verified"
    oidc_default_tenant: Optional[str] = None
    bootstrap_admin_email: Optional[str] = None
    bootstrap_admin_password: Optional[SecretStr] = None
    bootstrap_tenant_id: str = "default"
    bootstrap_tenant_name: str = "Default"


class APISettings(BaseModel):
    host: str = "0.0.0.0"  # noqa: S104 - containers must listen on all interfaces
    port: int = 8000
    public_url: str = "http://localhost:8000"
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"])
    max_body_bytes: int = 1_048_576
    max_ingest_body_bytes: int = 10_485_760
    max_ingest_batch: int = 500
    rate_limit_per_minute: int = 600
    ingest_rate_limit_per_minute: int = 6_000
    login_rate_limit_per_minute: int = 20
    metrics_token: Optional[SecretStr] = None
    docs_enabled: bool = True
    forwarded_allow_ips: str = "127.0.0.1"


class WorkerSettings(BaseModel):
    concurrency: int = 16
    node_timeout_s: float = 180.0
    analysis_timeout_s: float = 420.0
    run_timeout_s: float = 900.0
    max_deliveries: int = 5
    visibility_timeout_s: int = 1_200
    block_ms: int = 5_000
    drain_timeout_s: float = 60.0
    per_tenant_concurrency: int = 8


class SchedulerSettings(BaseModel):
    tick_s: float = 5.0
    sla_sweep_interval_s: float = 60.0
    stale_run_sweep_interval_s: float = 60.0
    maintenance_interval_s: float = 3_600.0
    leader_lease_s: int = 30


class RetentionSettings(BaseModel):
    alerts_days: int = 90
    events_days: int = 90
    audit_days: int = 365
    indicators_days: int = 30
    llm_usage_days: int = 400
    checkpoints_days: int = 30


class SecuritySettings(BaseModel):
    encryption_keys: Optional[SecretStr] = None
    indicator_hmac_key: Optional[SecretStr] = None


class ObservabilitySettings(BaseModel):
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    metrics_enabled: bool = True
    otlp_endpoint: Optional[str] = None
    service_name: str = "lg-sotf"


class ResponseSettings(BaseModel):
    dry_run: bool = True
    default_autonomy: Dict[str, Literal["auto", "approval", "disabled"]] = Field(
        default_factory=lambda: {
            "low": "approval",
            "medium": "approval",
            "high": "approval",
            "critical": "disabled",
        }
    )
    max_actions_per_hour_per_tenant: int = 50
    webhook_url: Optional[str] = None
    webhook_secret: Optional[SecretStr] = None
    webhook_timeout_s: float = 15.0


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LG_SOTF_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    environment: Environment = "development"
    config_file: Optional[str] = None

    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    llm: LLMSettings = LLMSettings()
    auth: AuthSettings = AuthSettings()
    api: APISettings = APISettings()
    worker: WorkerSettings = WorkerSettings()
    scheduler: SchedulerSettings = SchedulerSettings()
    retention: RetentionSettings = RetentionSettings()
    security: SecuritySettings = SecuritySettings()
    observability: ObservabilitySettings = ObservabilitySettings()
    response: ResponseSettings = ResponseSettings()

    # Free-form tuning sections consumed by agents and routing.
    agents: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    routing: Dict[str, Any] = Field(default_factory=dict)
    tools: Dict[str, Any] = Field(default_factory=dict)
    ingestion: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        init_kwargs = getattr(init_settings, "init_kwargs", {}) or {}
        dotenv_vars = getattr(dotenv_settings, "env_vars", {}) or {}
        path = (
            init_kwargs.get("config_file")
            or os.environ.get("LG_SOTF_CONFIG_FILE")
            or dotenv_vars.get("lg_sotf_config_file")
            or dotenv_vars.get("LG_SOTF_CONFIG_FILE")
        )
        return (
            init_settings,
            env_settings,
            _EnvironmentAliasSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
            YamlFileSource(settings_cls, path),
        )

    @model_validator(mode="after")
    def _fallbacks(self) -> Settings:
        if "LG_SOTF_DATABASE__URL" not in os.environ and os.environ.get("DATABASE_URL"):
            self.database.url = SecretStr(os.environ["DATABASE_URL"])
        if "LG_SOTF_REDIS__URL" not in os.environ and os.environ.get("REDIS_URL"):
            self.redis.url = SecretStr(os.environ["REDIS_URL"])
        if self.llm.api_key is None:
            env_key = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "gemini": "GOOGLE_API_KEY",
            }.get(self.llm.provider)
            if env_key and os.environ.get(env_key):
                self.llm.api_key = SecretStr(os.environ[env_key])
        return self

    @property
    def is_production(self) -> bool:
        return self.environment in ("staging", "production")

    def production_problems(self) -> List[str]:
        """Return reasons this configuration is unsafe to run in production."""
        problems: List[str] = []
        secret = self.auth.jwt_secret.get_secret_value() if self.auth.jwt_secret else ""
        if len(secret.encode()) < 32:
            problems.append("auth.jwt_secret must be set and at least 32 bytes")
        if not self.security.encryption_keys:
            problems.append("security.encryption_keys must be set (Fernet keys, comma separated)")
        if not self.security.indicator_hmac_key:
            problems.append("security.indicator_hmac_key must be set")
        if self.llm.enabled and self.llm.provider == "fake" and not self.llm.allow_fake:
            problems.append("llm.provider=fake is not allowed in production (set llm.allow_fake to override)")
        if self.llm.enabled and self.llm.provider != "fake" and self.llm.api_key is None:
            problems.append(f"llm.api_key (or the provider's standard env var) is required for {self.llm.provider}")
        if "*" in self.api.cors_origins:
            problems.append("api.cors_origins must not contain '*'")
        if not self.auth.cookie_secure:
            problems.append("auth.cookie_secure must be true")
        if "soc_dev_password" in self.database.url.get_secret_value():
            problems.append("database.url uses the development password")
        from lg_sotf.security.insecure import insecure_secret_problems

        problems.extend(insecure_secret_problems(self))
        return problems

    def assert_safe(self) -> None:
        if self.is_production:
            problems = self.production_problems()
            if problems:
                raise RuntimeError("Unsafe production configuration:\n- " + "\n- ".join(problems))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings() -> None:
    get_settings.cache_clear()
