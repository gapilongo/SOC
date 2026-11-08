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
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

Environment = Literal["development", "test", "staging", "production"]
LLMProvider = Literal["anthropic", "openai", "gemini", "ollama", "openai_compatible", "fake"]
# Self-hosted, OpenAI-compatible servers (Ollama, vLLM, llama.cpp, LM Studio, ...): the API key is
# optional and their usage is metered at zero cost.
SELF_HOSTED_PROVIDERS = frozenset({"ollama", "openai_compatible"})
StructuredOutput = Literal["auto", "json_schema", "json_mode", "function_calling"]

MAX_ALLOWED_HOSTS = 256
# A host name, an IPv4/IPv6 literal, or "*." followed by a domain (ingestion.allowed_destination_hosts).
_ALLOWED_HOST = re.compile(r"(?:\*\.)?[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9])?|[0-9a-f:.]{2,45}")
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
    # Concurrent calls of this tier per process. None (the default) = worker.concurrency, so
    # every run in flight can call the model at once; set a number only to respect a provider
    # rate limit.
    max_concurrency: Optional[int] = Field(default=None, ge=1)
    # Concurrent calls of this tier per process for shadow runs (AI-E1.5d): their own slots, never
    # production's, so a shadow run cannot make a live call wait.
    shadow_max_concurrency: int = Field(default=1, ge=1)


class FastTierSettings(LLMTierSettings):
    model: str = "claude-haiku-4-5"


class DeepTierSettings(LLMTierSettings):
    # Opus 5.5 always thinks and bills thinking as output, so leave room in max_tokens.
    model: str = "claude-opus-5-5"
    max_tokens: int = 16_000
    timeout_s: float = 300.0


class LLMSettings(BaseModel):
    enabled: bool = True
    provider: LLMProvider = "anthropic"
    api_key: Optional[SecretStr] = None
    base_url: Optional[str] = None
    # How self-hosted providers return structured output: json_schema (response_format with the
    # schema, constrained decoding where the server supports it), json_mode (response_format
    # json_object) or function_calling. "auto" = json_schema. Cloud providers use their native
    # method, except openai with llm.base_url and a value other than "auto".
    structured_output: StructuredOutput = "auto"
    fast: FastTierSettings = Field(default_factory=FastTierSettings)
    deep: DeepTierSettings = Field(default_factory=DeepTierSettings)
    refusal_fallback: bool = True
    prices: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    allow_fake: bool = False
    max_input_chars: int = 24_000
    max_field_chars: int = 2_000
    max_list_items: int = 50
    prompt_caching: bool = True
    daily_token_budget_per_tenant: Optional[int] = None


MAX_OIDC_ROLE_MAP_ENTRIES = 500
MAX_OIDC_CLAIM_VALUE_CHARS = 256


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
    # Just-in-time provisioning: a verified OIDC login with a tenant claim and no local account
    # creates one (role from oidc_role_map). The map sends values of the oidc_role_claim claim to
    # LG-SOTF roles; an empty map accepts the role names themselves. No match: oidc_default_role,
    # or the login is refused when that is unset. OIDC never grants the platform-admin flag.
    oidc_jit_provisioning: bool = False
    oidc_role_map: Dict[str, Literal["viewer", "analyst", "admin"]] = Field(default_factory=dict)
    oidc_default_role: Optional[Literal["viewer", "analyst", "admin"]] = None
    # TOTP MFA. None: required for platform admins in staging/production, optional in
    # development/test (see Settings.platform_admin_mfa_required).
    require_mfa_for_platform_admins: Optional[bool] = None
    mfa_issuer: str = Field(default="LG-SOTF", min_length=1, max_length=64)
    mfa_challenge_ttl_s: int = Field(default=300, ge=30, le=900)
    bootstrap_admin_email: Optional[str] = None
    bootstrap_admin_password: Optional[SecretStr] = None
    bootstrap_tenant_id: str = "default"
    bootstrap_tenant_name: str = "Default"


    @field_validator("oidc_role_map")
    @classmethod
    def _bounded_role_map(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) > MAX_OIDC_ROLE_MAP_ENTRIES:
            raise ValueError(f"at most {MAX_OIDC_ROLE_MAP_ENTRIES} entries")
        if any(not key or len(key) > MAX_OIDC_CLAIM_VALUE_CHARS for key in value):
            raise ValueError(f"claim values must be 1-{MAX_OIDC_CLAIM_VALUE_CHARS} characters")
        return value


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
    # Live-event WebSockets (per API process): concurrent sockets per principal and per
    # tenant, the whole process, each subscriber's event buffer, and how often an open
    # socket re-checks its token, account and tenant.
    ws_max_per_principal: int = Field(default=5, ge=1)
    ws_max_per_tenant: int = Field(default=100, ge=1)
    ws_max_subscribers: int = Field(default=1_000, ge=1)
    ws_subscriber_buffer: int = Field(default=256, ge=1)
    ws_revalidate_s: float = Field(default=15.0, gt=0)
    # Single-alert ingest admission: requests allowed to be in flight on the ingest routes at
    # once (per API process); more get 503 + Retry-After immediately instead of queueing.
    max_inflight_ingest: int = Field(default=64, ge=1)


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
    # Daily usage counters (invoicing, quotas).
    usage_days: int = Field(default=400, ge=1)
    # Bounds for the per-tenant ``retention.alerts_days``/``indicators_days`` overrides.
    tenant_min_days: int = Field(default=7, ge=1, le=99_999)
    tenant_max_days: int = Field(default=730, ge=1, le=99_999)

    @model_validator(mode="after")
    def _tenant_bounds(self) -> RetentionSettings:
        if self.tenant_min_days > self.tenant_max_days:
            raise ValueError("retention.tenant_min_days must not exceed retention.tenant_max_days")
        return self


class SecuritySettings(BaseModel):
    encryption_keys: Optional[SecretStr] = None
    indicator_hmac_key: Optional[SecretStr] = None


class ObservabilitySettings(BaseModel):
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    metrics_enabled: bool = True
    # Deprecated and ignored: tracing was removed (ADR-0008). Still accepted so existing configurations
    # load; configure_logging warns when it is set.
    otlp_endpoint: Optional[str] = None
    service_name: str = "lg-sotf"


Autonomy = Literal["auto", "approval", "disabled"]


def _default_autonomy() -> Dict[str, Autonomy]:
    return {
        "low": "approval",
        "medium": "approval",
        "high": "approval",
        "critical": "disabled",
    }


class ResponseSettings(BaseModel):
    dry_run: bool = True
    default_autonomy: Dict[str, Autonomy] = Field(default_factory=_default_autonomy)
    max_actions_per_hour_per_tenant: int = 50
    webhook_url: Optional[str] = None
    webhook_secret: Optional[SecretStr] = None
    webhook_timeout_s: float = 15.0
    # Verification of executed actions (lg_sotf.services.verification): job interval, time per check,
    # checks at once, and the longest any verification may stay pending (4 days).
    verify_interval_s: float = Field(default=15.0, ge=1.0, le=3_600.0)
    verify_check_timeout_s: float = Field(default=30.0, ge=1.0, le=300.0)
    verify_concurrency: int = Field(default=4, ge=1, le=64)
    verify_max_s: float = Field(default=345_600.0, ge=60.0, le=2_592_000.0)
    # Background execution (rollbacks, retries, late approvals, deferred and handed-off actions).
    background_interval_s: float = Field(default=5.0, ge=1.0, le=3_600.0)
    background_deadline_s: float = Field(default=120.0, ge=10.0, le=900.0)
    background_concurrency: int = Field(default=4, ge=1, le=64)
    # An approval the scheduler has not executed within this time is blocked (approval_expired).
    approval_ttl_s: float = Field(default=86_400.0, ge=60.0, le=2_592_000.0)
    # Execution attempts of one action before it fails with attempts_exhausted.
    max_execution_attempts: int = Field(default=5, ge=1, le=50)
    # Microsoft Graph and Defender requests: timeout per attempt and retries per request.
    microsoft_timeout_s: float = Field(default=15.0, ge=1.0, le=120.0)
    microsoft_retries: int = Field(default=3, ge=0, le=10)


class MCPSettings(BaseModel):
    """``lg-sotf mcp``: the LG-SOTF API the MCP server calls on the analyst's behalf.

    Set the key with ``LG_SOTF_MCP__API_KEY`` or, so no credential sits in the
    launching shell's environment, ``LG_SOTF_MCP__API_KEY_FILE`` (a file only its
    owner can read or write); never a command-line argument. An API key with the
    ``read`` scope, plus ``write`` for ``add_note`` or ``ingest`` for test alerts.

    ``tenant_id`` pins every call to one customer tenant (``X-Tenant-ID``):
    an MSSP organisation's key acting under that customer's grant. It is
    configuration, never a tool argument, so nothing the model reads can
    point the server at another tenant.
    """

    api_url: str = "http://127.0.0.1:8000"
    api_key: Optional[SecretStr] = None
    api_key_file: Optional[str] = None
    tenant_id: Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{1,62}$")
    timeout_s: float = Field(default=30.0, gt=0, le=300)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_response_bytes: int = Field(default=4_194_304, ge=1_024)
    max_output_chars: int = Field(default=60_000, ge=1_000)


class IntegrationsSettings(BaseModel):
    """Outbound notifications and ticketing (``lg_sotf.integrations``); delivered by the scheduler."""

    enabled: bool = True
    # Links in notifications point here (``/alerts?alert=<id>``); defaults to api.public_url.
    ui_base_url: Optional[str] = None
    batch_size: int = Field(default=50, ge=1, le=500)
    delivery_concurrency: int = Field(default=8, ge=1, le=64)
    max_attempts: int = Field(default=8, ge=1, le=50)
    backoff_base_s: float = Field(default=30.0, gt=0)
    backoff_max_s: float = Field(default=3_600.0, gt=0)
    max_age_hours: float = Field(default=24.0, gt=0)
    http_timeout_s: float = Field(default=10.0, gt=0, le=120)
    outbox_retention_days: int = Field(default=30, ge=1)
    ticket_sync_interval_s: float = Field(default=300.0, ge=30)
    ticket_sync_batch_per_tenant: int = Field(default=25, ge=1, le=500)
    # Slack approvals by an SSO (OIDC-provisioned) account need a sign-in to LG-SOTF within this many hours.
    slack_sso_max_age_hours: float = Field(default=12.0, gt=0, le=720)
    smtp_host: Optional[str] = None
    smtp_port: int = Field(default=587, ge=1, le=65_535)
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: Optional[str] = None
    smtp_password: Optional[SecretStr] = None
    smtp_from: Optional[str] = None
    smtp_timeout_s: float = Field(default=15.0, gt=0, le=120)


class IngestionSection(BaseModel):
    """The fields of the free-form ``settings.ingestion`` section (field-only; not part of ``Settings`` validation).

    ``Settings.ingestion`` stays a plain mapping, so an invalid key there never
    stops the API or the scheduler from starting. Two readers validate it:

    * :class:`lg_sotf.ingestion.options.IngestionOptions` (a subclass) reads
      it strictly: ingestion and pull sources refuse to run on an invalid
      section (:class:`~lg_sotf.errors.SourceConfigError`).
    * :func:`lg_sotf.net.egress.egress_policy` reads only
      ``allow_private_destinations``, leniently: an invalid section means
      ``False`` (private destinations refused), so integrations and webhooks
      fail closed instead of failing to build (ADR-0007).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    llm_fallback: bool = False
    llm_fallback_max_per_call: int = Field(default=20, ge=0, le=1_000)
    llm_fallback_concurrency: int = Field(default=4, ge=1, le=64)
    llm_fallback_timeout_s: float = Field(default=60.0, gt=0, le=3_600)
    batch_size: int = Field(default=500, ge=1, le=5_000)
    max_event_bytes: int = Field(default=1_048_576, ge=1_024)
    max_raw_bytes: int = Field(default=262_144, ge=1_024)
    redact_in_thread_bytes: int = Field(default=65_536, ge=0)
    max_future_skew_s: float = Field(default=900.0, ge=0)
    page_size: int = Field(default=200, ge=1, le=10_000)
    max_pages_per_poll: int = Field(default=20, ge=1, le=10_000)
    overlap_s: float = Field(default=300.0, ge=0, le=86_400)
    http_timeout_s: float = Field(default=30.0, gt=0, le=600)
    http_connect_timeout_s: float = Field(default=10.0, gt=0, le=120)
    http_max_retries: int = Field(default=4, ge=0, le=10)
    http_backoff_base_s: float = Field(default=0.5, ge=0)
    http_backoff_max_s: float = Field(default=30.0, ge=0)
    http_max_retry_after_s: float = Field(default=120.0, ge=0)
    # Install-level: let sources, integrations and webhooks reach RFC 1918 / ULA addresses.
    allow_private_destinations: bool = False
    # Install-level egress allow-list (None: no list). When set, sources, integrations, webhooks,
    # Microsoft Graph and the LLM endpoint reach only these hosts; "*.example.com" allows subdomains.
    allowed_destination_hosts: Optional[List[str]] = Field(default=None, max_length=MAX_ALLOWED_HOSTS)
    # Install-level: refuse pull sources that write back (the mailbox sources mark or move messages).
    read_only_sources: bool = False

    @field_validator("allowed_destination_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value: Any) -> Any:
        # An environment variable arrives as one string: "a.example.com, b.example.com".
        return [v for v in re.split(r"[\s,]+", value) if v] if isinstance(value, str) else value

    @field_validator("allowed_destination_hosts")
    @classmethod
    def _hosts(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        hosts = list(dict.fromkeys(v.strip().strip("[]").lower().rstrip(".") for v in value))
        bad = [h for h in hosts if not _ALLOWED_HOST.fullmatch(h)]
        if bad:
            raise ValueError("allowed_destination_hosts entries must be host names, IP addresses or *.domain")
        return hosts


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
    mcp: MCPSettings = MCPSettings()
    integrations: IntegrationsSettings = IntegrationsSettings()

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
        # DATABASE_URL / REDIS_URL rank lowest: they apply only when no other source (init
        # kwargs, LG_SOTF_* env, .env, YAML) set the URL, so they never override explicit config.
        if "url" not in self.database.model_fields_set and os.environ.get("DATABASE_URL"):
            self.database.url = SecretStr(os.environ["DATABASE_URL"])
        if "url" not in self.redis.model_fields_set and os.environ.get("REDIS_URL"):
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

    @property
    def platform_admin_mfa_required(self) -> bool:
        """``auth.require_mfa_for_platform_admins``, defaulting to on in staging/production."""
        value = self.auth.require_mfa_for_platform_admins
        return self.is_production if value is None else value

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
        if (
            self.llm.enabled
            and self.llm.provider != "fake"
            and self.llm.provider not in SELF_HOSTED_PROVIDERS
            and self.llm.api_key is None
        ):
            problems.append(f"llm.api_key (or the provider's standard env var) is required for {self.llm.provider}")
        if self.llm.enabled and self.llm.provider != "fake":
            from lg_sotf.llm.endpoint import base_url_problem

            problem = base_url_problem(self)
            if problem:
                problems.append(problem)
        if "*" in self.api.cors_origins:
            problems.append("api.cors_origins must not contain '*'")
        if not self.auth.cookie_secure:
            problems.append("auth.cookie_secure must be true")
        if "soc_dev_password" in self.database.url.get_secret_value():
            problems.append("database.url uses the development password")
        if self.integrations.smtp_host and self.integrations.smtp_security == "none":
            problems.append("integrations.smtp_security=none sends mail and SMTP credentials in clear text")
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
