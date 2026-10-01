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

The ``microsoft`` kind is the direct response connector
(:mod:`lg_sotf.integrations.microsoft`): at most one per tenant, no events,
no URL anywhere in its config (the hosts are fixed per cloud). Its config
names the cloud, the app registration (directory and client GUIDs), the
credential type and the public certificate, and enables capabilities one by
one (``enabled``, then ``live``); the client secret or the certificate's
private key are its secret.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, Type, Union
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from lg_sotf.integrations.events import EVENT_TYPES, LEVELS, SEVERITIES, TICKETING_EVENTS
from lg_sotf.security.crypto import DecryptionError, SecretBox

Kind = Literal["slack", "teams", "email", "webhook", "jira", "servicenow", "microsoft"]
KINDS: Tuple[str, ...] = ("slack", "teams", "email", "webhook", "jira", "servicenow", "microsoft")
NOTIFY_KINDS: Tuple[str, ...] = ("slack", "teams", "email", "webhook")
TICKETING_KINDS: Tuple[str, ...] = ("jira", "servicenow")
MICROSOFT_KIND = "microsoft"
MAX_MICROSOFT_CAPABILITIES = 64
MIN_RSA_BITS = 2048
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
    # Not an outbox channel: the Microsoft connector has its own per-API limits (lg_sotf.integrations.microsoft.http).
    "microsoft": 60,
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


class _Tls(_Common):
    ca_cert_pem: Optional[str] = Field(default=None, max_length=20_000, description="Private CA (PEM) of the receiver.")


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


class WebhookConfig(_Tls):
    url: str = Field(min_length=8, max_length=2048)


class _Ticketing(_Tls):
    response_actions: bool = Field(default=True, description="Use this integration for the create_ticket response action.")


class JiraConfig(_Ticketing):
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


class ServiceNowConfig(_Ticketing):
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


MicrosoftCloud = Literal["global", "usgov_gcc_high", "usgov_dod"]
DefenderGeo = Literal["us", "eu", "uk", "au", "swa", "ina", "aea"]


class MicrosoftCapabilityConfig(_Model):
    """One capability of a Microsoft integration: ``enabled`` rehearses, ``enabled`` + ``live`` acts."""

    enabled: bool = False
    live: bool = False
    options: Dict[str, Any] = Field(default_factory=dict)


class MicrosoftConfig(_Model):
    """A Microsoft integration (no URL anywhere: hosts are fixed per ``cloud``)."""

    cloud: MicrosoftCloud = "global"
    directory_tenant_id: str = Field(max_length=36, description="The customer directory's tenant id (GUID).")
    client_id: str = Field(max_length=36, description="The app registration's application (client) id (GUID).")
    credential: Literal["certificate", "client_secret"] = "certificate"
    certificate_pem: Optional[str] = Field(
        default=None, max_length=20_000, description="The app's public certificate (PEM); not a secret."
    )
    defender_geo: Optional[DefenderGeo] = Field(default=None, description="Defender API geo host (global cloud only).")
    capabilities: Dict[str, MicrosoftCapabilityConfig] = Field(default_factory=dict)


CONFIG_MODELS: Dict[str, Type[_Model]] = {
    "slack": SlackConfig,
    "teams": TeamsConfig,
    "email": EmailConfig,
    "webhook": WebhookConfig,
    "jira": JiraConfig,
    "servicenow": ServiceNowConfig,
    "microsoft": MicrosoftConfig,
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


class MicrosoftSecret(_Model):
    client_secret: Optional[str] = Field(default=None, max_length=1024)
    private_key_pem: Optional[str] = Field(
        default=None, max_length=20_000, description="Unencrypted PKCS#8 or PKCS#1 RSA private key of the certificate."
    )


SECRET_MODELS: Dict[str, Type[_Model]] = {
    "slack": SlackSecret,
    "teams": TeamsSecret,
    "email": EmailSecret,
    "webhook": WebhookSecret,
    "jira": JiraSecret,
    "servicenow": ServiceNowSecret,
    "microsoft": MicrosoftSecret,
}
# Microsoft: the required field depends on config.credential (validate_secret checks it).
REQUIRED_SECRETS: Dict[str, Tuple[str, ...]] = {
    "slack": ("webhook_url",),
    "teams": ("webhook_url",),
    "email": (),
    "webhook": ("signing_secret",),
    "jira": ("api_token",),
    "servicenow": ("password",),
    "microsoft": (),
}
MICROSOFT_SECRET_FIELD: Dict[str, str] = {"certificate": "private_key_pem", "client_secret": "client_secret"}

# Config fields that decide where, or as whom, a separately stored credential is used (the signing secret signs
# what goes to the webhook URL; the Jira token and ServiceNow password are sent to the instance). Changing one
# requires the credential again in the same update, so a stored credential never follows a new destination.
# Slack and Teams webhook URLs are themselves the credential; the Slack bot token only goes to slack.com.
# Microsoft: a new cloud, directory, app, credential type or certificate needs the credential again (the one
# config.credential names).
SECRET_BOUND_CONFIG: Dict[str, Tuple[Tuple[str, ...], Union[str, Tuple[str, ...]]]] = {
    "webhook": (("url", "ca_cert_pem"), "signing_secret"),
    "jira": (("base_url", "deployment", "email", "ca_cert_pem"), "api_token"),
    "servicenow": (("instance_url", "username", "ca_cert_pem"), "password"),
    "microsoft": (
        ("cloud", "directory_tenant_id", "client_id", "credential", "certificate_pem"),
        ("client_secret", "private_key_pem"),
    ),
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
    if isinstance(parsed, MicrosoftConfig):
        return _microsoft_config(parsed)
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


def validate_secret(
    kind: str, secret: Mapping[str, Any], *, require_https: bool, config: Optional[Mapping[str, Any]] = None
) -> Dict[str, str]:
    """Validate a complete secret object for ``kind`` (required fields present, URLs well formed).

    ``config`` (the normalised config) is required for ``microsoft``: the
    credential type decides which secret field is needed, and a private key
    must match the configured certificate.
    """
    model = SECRET_MODELS.get(kind)
    if model is None:
        raise IntegrationConfigError(f"unknown integration kind {str(kind)[:32]!r}")
    try:
        parsed = model.model_validate(dict(secret))
    except ValidationError as exc:
        raise IntegrationConfigError("; ".join(_problems(exc, "secret"))) from None
    values: Dict[str, str] = {k: v for k, v in parsed.model_dump().items() if isinstance(v, str) and v}
    if kind == MICROSOFT_KIND:
        return _microsoft_secret(values, config)
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
    allowed: Tuple[str, ...] = TICKETING_EVENTS if kind in TICKETING_KINDS else EVENT_TYPES
    if kind == MICROSOFT_KIND:
        allowed = ()
    unknown = [e for e in events if e not in allowed]
    if unknown:
        raise IntegrationConfigError(
            f"event {unknown[0][:64]!r} is not available for {kind} integrations "
            f"(allowed: {', '.join(allowed) or 'none'})"
        )
    return list(dict.fromkeys(events))


def check_secret_binding(
    kind: str, current: Mapping[str, Any], config: Mapping[str, Any], secret_patch: Mapping[str, Any]
) -> None:
    """Refuse a config change that would send the stored credential to a new destination or identity."""
    bound = SECRET_BOUND_CONFIG.get(kind)
    if bound is None:
        return
    fields, secrets = bound
    if isinstance(secrets, tuple):
        # Several credential fields: the one the (new) config's credential type uses must be supplied.
        credential = str(config.get("credential") or "certificate")
        secret = MICROSOFT_SECRET_FIELD.get(credential, secrets[0])
    else:
        secret = secrets
    changed = [f for f in fields if current.get(f) != config.get(f)]
    value = secret_patch.get(secret)
    if changed and not (isinstance(value, str) and value.strip()):
        raise IntegrationConfigError(
            f"changing config.{', config.'.join(changed)} requires secret.{secret} in the same request "
            "(a stored credential is never sent to a new destination)"
        )


_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _load_certificate(pem: str) -> Any:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise IntegrationConfigError("config.certificate_pem is not a PEM X.509 certificate") from exc
    key = certificate.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_RSA_BITS:
        raise IntegrationConfigError(f"config.certificate_pem must hold an RSA key of at least {MIN_RSA_BITS} bits")
    return certificate


def certificate_details(pem: str) -> Dict[str, Any]:
    """Thumbprints and expiry of a public certificate: ``{thumbprint_sha1, thumbprint_sha256, not_after, days_left}``.

    The SHA-1 thumbprint is what the Entra portal shows under Certificates & secrets.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    certificate = _load_certificate(pem)
    der = certificate.public_bytes(serialization.Encoding.DER)
    not_after = certificate.not_valid_after_utc
    return {
        "thumbprint_sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest().upper(),
        "thumbprint_sha256": hashlib.sha256(der).hexdigest().upper(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(UTC)).days,
    }


def _microsoft_config(parsed: MicrosoftConfig) -> Dict[str, Any]:
    """Cross-field checks of a Microsoft config; returns it normalised (options parsed with their schema)."""
    from lg_sotf.integrations.microsoft.catalog import capabilities

    problems: List[str] = []
    for name in ("directory_tenant_id", "client_id"):
        if not _GUID.match(getattr(parsed, name)):
            problems.append(f"config.{name} must be a GUID (common, organizations, consumers and domains are refused)")
    if parsed.defender_geo is not None and parsed.cloud != "global":
        problems.append("config.defender_geo applies to the global cloud only")
    if parsed.credential == "certificate":
        if not parsed.certificate_pem:
            problems.append("config.certificate_pem is required with credential=certificate")
        else:
            try:
                certificate = _load_certificate(parsed.certificate_pem)
            except IntegrationConfigError as exc:
                problems.append(str(exc))
            else:
                now = datetime.now(UTC)
                if certificate.not_valid_after_utc <= now:
                    problems.append("config.certificate_pem has expired")
                elif certificate.not_valid_before_utc > now:
                    problems.append("config.certificate_pem is not valid yet")
    if len(parsed.capabilities) > MAX_MICROSOFT_CAPABILITIES:
        problems.append(f"config.capabilities may name at most {MAX_MICROSOFT_CAPABILITIES} capabilities")
    catalog = capabilities()
    normalised: Dict[str, Dict[str, Any]] = {}
    enabled: List[str] = []
    for key, entry in parsed.capabilities.items():
        spec = catalog.get(key)
        if spec is None:
            problems.append(f"config.capabilities.{key[:64]}: unknown capability")
            continue
        if entry.live and not entry.enabled:
            problems.append(f"config.capabilities.{key}: live requires enabled")
        try:
            options = spec.options.model_validate(dict(entry.options))
        except ValidationError as exc:
            problems.extend(_problems(exc, f"config.capabilities.{key}.options"))
            continue
        if entry.enabled:
            enabled.append(key)
            if parsed.cloud not in spec.clouds:
                problems.append(f"config.capabilities.{key}: not supported in the {parsed.cloud} cloud")
            problems.extend(f"config.capabilities.{key}.options: {p}"[:300] for p in options.problems(parsed.cloud))
        normalised[key] = {"enabled": entry.enabled, "live": entry.live, "options": options.model_dump(mode="json")}
    for key in enabled:
        for other in enabled:
            if other != key and (other in catalog[key].excludes or key in catalog[other].excludes) and key < other:
                problems.append(f"config.capabilities: {key} and {other} cannot be enabled together")
    if problems:
        raise IntegrationConfigError("; ".join(problems[:10]))
    out = parsed.model_dump(exclude_none=True)
    out["capabilities"] = normalised
    return out


def parse_microsoft_config(config: Mapping[str, Any]) -> MicrosoftConfig:
    """A stored Microsoft config, validated again (raises :class:`IntegrationConfigError`)."""
    return MicrosoftConfig.model_validate(validate_config(MICROSOFT_KIND, config, require_https=True))


def _microsoft_secret(values: Dict[str, str], config: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if config is None:
        raise IntegrationConfigError("a Microsoft credential is validated against its config")
    credential = str(config.get("credential") or "certificate")
    needed = MICROSOFT_SECRET_FIELD.get(credential, "private_key_pem")
    other = next(f for f in MICROSOFT_SECRET_FIELD.values() if f != needed)
    if needed not in values:
        raise IntegrationConfigError(f"secret.{needed} is required with credential={credential}")
    if other in values:
        raise IntegrationConfigError(
            f"secret.{other} is not used with credential={credential}: remove it (set it to null)"
        )
    if credential == "certificate":
        pem = config.get("certificate_pem")
        try:
            key = serialization.load_pem_private_key(values[needed].encode("ascii"), password=None)
        except (ValueError, TypeError, UnicodeEncodeError) as exc:
            raise IntegrationConfigError(
                "secret.private_key_pem must be an unencrypted PKCS#8 or PKCS#1 RSA private key (PEM)"
            ) from exc
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_BITS:
            raise IntegrationConfigError(f"secret.private_key_pem must be an RSA key of at least {MIN_RSA_BITS} bits")
        if not isinstance(pem, str) or not pem:
            raise IntegrationConfigError("config.certificate_pem is required with credential=certificate")
        certificate = _load_certificate(pem)
        if key.public_key().public_numbers() != certificate.public_key().public_numbers():
            raise IntegrationConfigError("secret.private_key_pem does not match config.certificate_pem")
    elif len(values[needed]) < 8:
        raise IntegrationConfigError("secret.client_secret is too short to be an Entra client secret")
    return values


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
    "MICROSOFT_KIND",
    "MicrosoftCapabilityConfig",
    "MicrosoftConfig",
    "MicrosoftSecret",
    "NOTIFY_KINDS",
    "SECRET_BOUND_CONFIG",
    "SECRET_MODELS",
    "TICKETING_KINDS",
    "certificate_details",
    "check_secret_binding",
    "decrypt_secret",
    "encrypt_secret",
    "merge_secret",
    "parse_microsoft_config",
    "rate_limit_per_minute",
    "secret_context",
    "secret_fields",
    "validate_config",
    "validate_events",
    "validate_secret",
]
