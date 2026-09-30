"""Per-kind configuration and credential schemas of integrations, and their encryption.

``config`` is stored as plain JSON and returned by the API; everything that
grants access (webhook URLs that embed a token, API tokens, passwords,
signing secrets) is a *secret*: validated here, encrypted with the install's
:class:`~lg_sotf.security.crypto.SecretBox` bound to the tenant and the
integration id, and never returned (the API reports which secret fields are
set).

URLs are checked for shape and scheme here (``https`` in staging and
production); every request is checked again, resolved and pinned by the
destination policy when it is sent (:mod:`lg_sotf.integrations.http`).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, Type
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from lg_sotf.integrations.events import EVENT_TYPES, LEVELS, SEVERITIES, TICKETING_EVENTS
from lg_sotf.security.crypto import DecryptionError, SecretBox

Kind = Literal["slack", "teams", "email", "webhook", "jira", "servicenow"]
KINDS: Tuple[str, ...] = ("slack", "teams", "email", "webhook", "jira", "servicenow")
NOTIFY_KINDS: Tuple[str, ...] = ("slack", "teams", "email", "webhook")
TICKETING_KINDS: Tuple[str, ...] = ("jira", "servicenow")
SLACK_WEBHOOK_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
MIN_SIGNING_SECRET_BYTES = 16
MAX_RECIPIENTS = 20
DEFAULT_RATE_LIMITS: Dict[str, int] = {
    "slack": 60,  # Slack incoming webhooks accept about one message per second
    "teams": 30,
    "email": 30,
    "webhook": 120,
    "jira": 60,
    "servicenow": 60,
}
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,49}$")
_LABEL = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class IntegrationConfigError(ValueError):
    """The integration's configuration or credentials are invalid (message is safe to return)."""


def secret_context(tenant_id: str, integration_id: UUID) -> str:
    return f"tenant:{tenant_id}:integration:{integration_id}"


def check_http_url(value: str, *, require_https: bool, what: str) -> str:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, TypeError) as exc:
        raise ValueError(f"{what} is not a valid URL") from exc
    scheme = url.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"{what} must be an http(s) URL")
    if require_https and scheme != "https":
        raise ValueError(f"{what} must use https in staging and production")
    if not url.host:
        raise ValueError(f"{what} has no host")
    if url.userinfo:
        raise ValueError(f"{what} must not contain credentials")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class _Common(_Model):
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=600)


# ------------------------------------------------------------------ configs


class SlackConfig(_Common):
    channel_label: Optional[str] = Field(default=None, max_length=100, description="Display only (the webhook picks the channel).")
    interactive_approvals: bool = False


class TeamsConfig(_Common):
    pass


class EmailConfig(_Common):
    recipients: List[str] = Field(min_length=1, max_length=MAX_RECIPIENTS)
    subject_prefix: str = Field(default="[LG-SOTF]", max_length=50)

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, value: List[str]) -> List[str]:
        out: List[str] = []
        for item in value:
            address = item.strip().lower()
            if len(address) > 254 or not _EMAIL.fullmatch(address):
                raise ValueError("recipients must be email addresses")
            out.append(address)
        return list(dict.fromkeys(out))


class WebhookConfig(_Common):
    url: str = Field(min_length=8, max_length=2048)


class JiraConfig(_Common):
    base_url: str = Field(min_length=8, max_length=512, description="https://your-site.atlassian.net")
    deployment: Literal["cloud", "datacenter"] = "cloud"
    email: Optional[str] = Field(default=None, max_length=254, description="Account email (Cloud basic auth).")
    project_key: str
    issue_type: str = Field(default="Task", min_length=1, max_length=100)
    labels: List[str] = Field(default_factory=lambda: ["lg-sotf"], max_length=10)
    min_level: Optional[Literal["L1", "L2", "L3"]] = None
    comment_on_decision: bool = True
    resolve_transition: Optional[str] = Field(default=None, max_length=100, description="Transition name or id applied on a final decision.")
    priority_map: Dict[str, str] = Field(default_factory=dict)

    @field_validator("project_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _PROJECT_KEY.fullmatch(value):
            raise ValueError("project_key must be a Jira project key (A-Z, 0-9, _)")
        return value

    @field_validator("labels")
    @classmethod
    def _labels(cls, value: List[str]) -> List[str]:
        if any(not _LABEL.fullmatch(v) for v in value):
            raise ValueError("labels may contain letters, digits and _ . : - only")
        return value

    @field_validator("priority_map")
    @classmethod
    def _priorities(cls, value: Dict[str, str]) -> Dict[str, str]:
        if any(k not in SEVERITIES or not 0 < len(v) <= 50 for k, v in value.items()):
            raise ValueError("priority_map maps alert severities to Jira priority names")
        return value


class ServiceNowConfig(_Common):
    instance_url: str = Field(min_length=8, max_length=512, description="https://your-instance.service-now.com")
    username: str = Field(min_length=1, max_length=200)
    assignment_group: Optional[str] = Field(default=None, max_length=200)
    caller_id: Optional[str] = Field(default=None, max_length=200)
    category: Optional[str] = Field(default=None, max_length=100)
    min_level: Optional[Literal["L1", "L2", "L3"]] = None
    comment_on_decision: bool = True
    comment_field: Literal["work_notes", "comments"] = "work_notes"
    resolve_on_decision: bool = False
    resolve_state: str = Field(default="6", max_length=20)
    close_code: str = Field(default="Solution provided", max_length=100)


CONFIG_MODELS: Dict[str, Type[_Common]] = {
    "slack": SlackConfig,
    "teams": TeamsConfig,
    "email": EmailConfig,
    "webhook": WebhookConfig,
    "jira": JiraConfig,
    "servicenow": ServiceNowConfig,
}


# ------------------------------------------------------------------ secrets


class SlackSecret(_Model):
    webhook_url: Optional[str] = Field(default=None, max_length=512)
    bot_token: Optional[str] = Field(default=None, max_length=512)
    signing_secret: Optional[str] = Field(default=None, max_length=256)


class TeamsSecret(_Model):
    webhook_url: Optional[str] = Field(default=None, max_length=2048)


class EmailSecret(_Model):
    pass


class WebhookSecret(_Model):
    signing_secret: Optional[str] = Field(default=None, max_length=256)


class JiraSecret(_Model):
    api_token: Optional[str] = Field(default=None, max_length=1024)


class ServiceNowSecret(_Model):
    password: Optional[str] = Field(default=None, max_length=1024)


SECRET_MODELS: Dict[str, Type[_Model]] = {
    "slack": SlackSecret,
    "teams": TeamsSecret,
    "email": EmailSecret,
    "webhook": WebhookSecret,
    "jira": JiraSecret,
    "servicenow": ServiceNowSecret,
}
REQUIRED_SECRETS: Dict[str, Tuple[str, ...]] = {
    "slack": ("webhook_url",),
    "teams": ("webhook_url",),
    "email": (),
    "webhook": ("signing_secret",),
    "jira": ("api_token",),
    "servicenow": ("password",),
}


def secret_fields(kind: str) -> Tuple[str, ...]:
    return tuple(SECRET_MODELS[kind].model_fields)


def _problems(exc: ValidationError, prefix: str) -> List[str]:
    out = []
    for err in exc.errors()[:10]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        out.append(f"{prefix}{'.' + loc if loc else ''}: {err.get('msg', 'invalid')}"[:300])
    return out


def validate_config(kind: str, config: Mapping[str, Any], *, require_https: bool) -> Dict[str, Any]:
    """The normalised config for ``kind``; raises :class:`IntegrationConfigError` listing the problems."""
    model = CONFIG_MODELS.get(kind)
    if model is None:
        raise IntegrationConfigError(f"unknown integration kind {str(kind)[:32]!r}")
    try:
        parsed = model.model_validate(dict(config))
    except ValidationError as exc:
        raise IntegrationConfigError("; ".join(_problems(exc, "config"))) from None
    try:
        if isinstance(parsed, WebhookConfig):
            check_http_url(parsed.url, require_https=require_https, what="config.url")
        elif isinstance(parsed, JiraConfig):
            check_http_url(parsed.base_url, require_https=require_https, what="config.base_url")
            if parsed.deployment == "cloud" and not (parsed.email and _EMAIL.fullmatch(parsed.email)):
                raise ValueError("config.email (the account's email) is required for Jira Cloud")
        elif isinstance(parsed, ServiceNowConfig):
            check_http_url(parsed.instance_url, require_https=require_https, what="config.instance_url")
    except ValueError as exc:
        raise IntegrationConfigError(str(exc)) from None
    return parsed.model_dump(exclude_none=True)


def validate_secret(kind: str, secret: Mapping[str, Any], *, require_https: bool) -> Dict[str, str]:
    """Validate a complete secret object for ``kind`` (required fields present, URLs well formed)."""
    model = SECRET_MODELS.get(kind)
    if model is None:
        raise IntegrationConfigError(f"unknown integration kind {str(kind)[:32]!r}")
    try:
        parsed = model.model_validate(dict(secret))
    except ValidationError as exc:
        raise IntegrationConfigError("; ".join(_problems(exc, "secret"))) from None
    values: Dict[str, str] = {k: v for k, v in parsed.model_dump().items() if isinstance(v, str) and v}
    missing = [f for f in REQUIRED_SECRETS[kind] if f not in values]
    if missing:
        raise IntegrationConfigError(f"secret.{missing[0]} is required for a {kind} integration")
    try:
        if "webhook_url" in values:
            check_http_url(values["webhook_url"], require_https=True, what="secret.webhook_url")
            if kind == "slack" and httpx.URL(values["webhook_url"]).host not in SLACK_WEBHOOK_HOSTS:
                raise ValueError("secret.webhook_url must be a Slack incoming webhook (https://hooks.slack.com/...)")
    except ValueError as exc:
        raise IntegrationConfigError(str(exc)) from None
    for name in ("signing_secret",):
        if name in values and len(values[name].encode("utf-8")) < MIN_SIGNING_SECRET_BYTES:
            raise IntegrationConfigError(f"secret.{name} must be at least {MIN_SIGNING_SECRET_BYTES} bytes")
    return values


def validate_events(kind: str, events: List[str]) -> List[str]:
    allowed = TICKETING_EVENTS if kind in TICKETING_KINDS else EVENT_TYPES
    unknown = [e for e in events if e not in allowed]
    if unknown:
        raise IntegrationConfigError(
            f"event {unknown[0][:64]!r} is not available for {kind} integrations (allowed: {', '.join(allowed)})"
        )
    return list(dict.fromkeys(events))


def merge_secret(current: Mapping[str, str], patch: Mapping[str, Any]) -> Dict[str, Any]:
    """Merge-patch semantics for secrets: a value replaces, ``null`` removes, absent keys are kept."""
    merged: Dict[str, Any] = dict(current)
    for key, value in patch.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def encrypt_secret(box: SecretBox, tenant_id: str, integration_id: UUID, values: Mapping[str, str]) -> Optional[str]:
    if not values:
        return None
    return box.encrypt_json(dict(values), context=secret_context(tenant_id, integration_id))


def decrypt_secret(
    box: Optional[SecretBox], tenant_id: str, integration_id: UUID, ciphertext: Optional[str]
) -> Dict[str, str]:
    """The integration's credentials; raises :class:`IntegrationConfigError` when they cannot be read."""
    if not ciphertext:
        return {}
    if box is None:
        raise IntegrationConfigError("integration credentials cannot be decrypted: encryption keys are not configured")
    try:
        data = box.decrypt_json(ciphertext, context=secret_context(tenant_id, integration_id))
    except DecryptionError as exc:
        raise IntegrationConfigError("integration credentials cannot be decrypted") from exc
    if not isinstance(data, dict):
        raise IntegrationConfigError("integration credentials are malformed")
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def rate_limit_per_minute(kind: str, config: Mapping[str, Any]) -> int:
    value = config.get("rate_limit_per_minute")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return DEFAULT_RATE_LIMITS.get(kind, 60)


__all__ = [
    "CONFIG_MODELS",
    "IntegrationConfigError",
    "KINDS",
    "LEVELS",
    "NOTIFY_KINDS",
    "SECRET_MODELS",
    "TICKETING_KINDS",
    "decrypt_secret",
    "encrypt_secret",
    "merge_secret",
    "rate_limit_per_minute",
    "secret_context",
    "secret_fields",
    "validate_config",
    "validate_events",
    "validate_secret",
]
