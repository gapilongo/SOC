"""The tenant's response policy: the ``response`` settings schema, autonomy and the approval rules.

:class:`ResponsePolicySettings` is the schema of ``tenants.settings["response"]``;
the settings API validates writes with :func:`validate_response_settings`.
:meth:`ResponsePolicy.resolve` merges tenant and install settings into the
effective policy, failing closed (``problems``) when the guardrail keys are
malformed. :func:`approval_allowed` and :func:`preapproval_allowed` say which
role may approve which risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from lg_sotf.domain.actions import ACTION_CATALOG, DEFAULT_BLAST_RADIUS
from lg_sotf.models import vocabulary
from lg_sotf.models.vocabulary import RISK_LEVELS, RiskLevel
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.connectors import CONNECTOR_NAMES, ROUTE_NAMES, tenant_response_settings
from lg_sotf.services.response.protected import (
    LEGACY_ASSETS,
    LEGACY_CIDRS,
    MAX_POLICY_PROBLEMS,
    ProtectedAssets,
    ProtectedAssetsSettings,
    problem_list,
)
from lg_sotf.services.response.targets import domain_key
from lg_sotf.settings import Settings

log = get_logger(__name__)


ANALYST_APPROVAL_RISKS = frozenset({"low", "medium"})
ANALYST_PREAPPROVAL_RISKS = ANALYST_APPROVAL_RISKS
MAX_BLAST_RADIUS = 10_000
MAX_TENANT_HOURLY_CAP = 100_000
# create_ticket runs through the tenant's ticketing integration when one is enabled (lg_sotf.integrations).
TICKET_ACTION = "create_ticket"
TICKET_CONNECTOR_NAME = "ticketing"
MICROSOFT_CONNECTOR_NAME = "microsoft"
MAX_ROUTES = 64


def _catalog_actions(values: Optional[List[str]]) -> Optional[List[str]]:
    unknown = [v for v in values or [] if v not in ACTION_CATALOG]
    if unknown:
        raise ValueError(f"unknown action types: {', '.join(sorted(unknown)[:5])[:120]}")
    return values


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
AutonomyMap = Dict[RiskLevel, vocabulary.AutonomyMode]


class ResponsePolicySettings(BaseModel):
    """Schema of ``tenants.settings["response"]`` (connector keys: :mod:`lg_sotf.services.connectors.registry`)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector: Optional[StrictStr] = None
    dry_run: Optional[StrictBool] = None
    webhook_url: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=2_048)]] = None
    webhook_secret_ciphertext: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=8_192)]] = None
    ca_cert_pem: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=65_536)]] = None
    tls_verify: Optional[StrictBool] = None
    allow_internal_ip_blocks: Optional[StrictBool] = None
    allowed_actions: Optional[List[StrictStr]] = Field(default=None, max_length=64)
    max_actions_per_hour: Optional[Annotated[StrictInt, Field(ge=0, le=MAX_TENANT_HOURLY_CAP)]] = None
    blast_radius: Optional[Dict[StrictStr, Annotated[StrictInt, Field(ge=0, le=MAX_BLAST_RADIUS)]]] = None
    autonomy: Optional[AutonomyMap] = None
    # Per action type, which connector executes it (lg_sotf.services.connectors.routing).
    routes: Optional[Dict[StrictStr, StrictStr]] = Field(default=None, max_length=MAX_ROUTES)

    @field_validator("connector")
    @classmethod
    def _connector(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in CONNECTOR_NAMES:
            raise ValueError(f"connector must be one of {', '.join(CONNECTOR_NAMES)}")
        return value

    @field_validator("webhook_url")
    @classmethod
    def _url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        try:
            parts = urlsplit(value)
        except ValueError as exc:
            raise ValueError("webhook_url is not a URL") from exc
        if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
            raise ValueError("webhook_url must be an http(s) URL with a host and no credentials")
        return value

    @field_validator("tls_verify")
    @classmethod
    def _tls(cls, value: Optional[bool]) -> Optional[bool]:
        if value is False:
            raise ValueError("TLS verification cannot be disabled for response webhooks (use ca_cert_pem)")
        return value

    @field_validator("allowed_actions")
    @classmethod
    def _allowed(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        return _catalog_actions(value)

    @field_validator("blast_radius")
    @classmethod
    def _blast(cls, value: Optional[Dict[str, int]]) -> Optional[Dict[str, int]]:
        _catalog_actions(list(value or {}))
        return value

    @field_validator("routes")
    @classmethod
    def _routes(cls, value: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        for action_type, route in (value or {}).items():
            problem = route_problem(action_type, route)
            if problem:
                raise ValueError(problem)
        return value


def route_problem(action_type: str, route: Any) -> Optional[str]:
    """Why ``response.routes[action_type] = route`` is not allowed, or ``None``."""
    if action_type not in ACTION_CATALOG:
        return f"routes: unknown action type {str(action_type)[:64]!r}"
    if route not in ROUTE_NAMES:
        return f"routes.{action_type}: must be one of {', '.join(ROUTE_NAMES)}"
    if route == TICKET_CONNECTOR_NAME and action_type != TICKET_ACTION:
        return f"routes.{action_type}: ticketing executes create_ticket only"
    if route == MICROSOFT_CONNECTOR_NAME:
        from lg_sotf.integrations.microsoft.catalog import executes

        if not executes(action_type):
            return f"routes.{action_type}: no Microsoft capability executes {action_type}"
    return None


# The response keys the guardrails read; malformed values fail closed when a policy is resolved.
GUARDRAIL_KEYS = ("allow_internal_ip_blocks", "allowed_actions", "max_actions_per_hour", "blast_radius", "autonomy")
_AUTONOMY: TypeAdapter[Dict[str, str]] = TypeAdapter(AutonomyMap)


class ResponsePolicyError(ValueError):
    """Tenant response settings do not match the schema (message lists the problems; safe to return)."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = list(problems)


def validate_response_settings(tenant_settings: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the response sections of a tenant settings document (for the settings API).

    Checks ``response``, ``protected_assets`` (object form, or the legacy flat
    list), ``protected_cidrs``, ``autonomy`` and the legacy top-level
    ``connector``/``dry_run`` when present, and returns them normalised
    (whitespace stripped, unset keys dropped). Raises
    :class:`ResponsePolicyError` listing every problem found.
    """
    problems: List[str] = []
    out: Dict[str, Any] = {}
    if "response" in tenant_settings:
        try:
            out["response"] = ResponsePolicySettings.model_validate(tenant_settings["response"]).model_dump(
                exclude_none=True
            )
        except ValidationError as exc:
            problems += problem_list("response", exc)
    if "protected_assets" in tenant_settings:
        raw = tenant_settings["protected_assets"]
        try:
            if isinstance(raw, Mapping):
                out["protected_assets"] = ProtectedAssetsSettings.model_validate(dict(raw)).model_dump()
            else:
                out["protected_assets"] = LEGACY_ASSETS.validate_python(raw)
        except ValidationError as exc:
            problems += problem_list("protected_assets", exc)
    if "protected_cidrs" in tenant_settings:
        try:
            out["protected_cidrs"] = LEGACY_CIDRS.validate_python(tenant_settings["protected_cidrs"])
        except ValidationError as exc:
            problems += problem_list("protected_cidrs", exc)
    if "autonomy" in tenant_settings:
        try:
            out["autonomy"] = _AUTONOMY.validate_python(tenant_settings["autonomy"])
        except ValidationError as exc:
            problems += problem_list("autonomy", exc)
    if "connector" in tenant_settings or "dry_run" in tenant_settings:
        legacy = {k: tenant_settings[k] for k in ("connector", "dry_run") if k in tenant_settings}
        try:
            out.update(ResponsePolicySettings.model_validate(legacy).model_dump(exclude_none=True))
        except ValidationError as exc:
            problems += problem_list("settings", exc)
    if problems:
        raise ResponsePolicyError(problems)
    return out


def resolve_autonomy(risk: str, tenant_settings: Mapping[str, Any], settings: Settings) -> vocabulary.AutonomyMode:
    """Tenant autonomy (``response.autonomy`` over top-level ``autonomy``) over the install default.

    A value outside ``auto``/``approval``/``disabled`` means ``disabled``: a
    typo never loosens the policy.
    """
    policy: Dict[str, Any] = dict(settings.response.default_autonomy)
    for override in (tenant_settings.get("autonomy"), tenant_response_settings(tenant_settings).get("autonomy")):
        if isinstance(override, Mapping):
            policy.update({k: v for k, v in override.items() if k in RISK_LEVELS})
    mode = policy.get(risk, "approval")
    return mode if mode in vocabulary.AUTONOMY_MODES else "disabled"


@dataclass(frozen=True)
class ResponsePolicy:
    """The effective response policy for one tenant (tenant settings over install settings).

    ``problems`` non-empty means the tenant's guardrail settings are
    malformed: every action is blocked (``response_policy_invalid``).
    """

    autonomy: Mapping[str, vocabulary.AutonomyMode]
    protected: ProtectedAssets
    allow_internal_ip_blocks: bool = False
    allowed_actions: Optional[FrozenSet[str]] = None
    max_actions_per_hour: int = 50
    blast_radius: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_BLAST_RADIUS))
    problems: Tuple[str, ...] = ()
    # The tenant's own mail domains (tools.internal_domains, tenant and install): never blocked as senders.
    internal_domains: Tuple[str, ...] = ()

    @classmethod
    def resolve(cls, tenant_settings: Mapping[str, Any], settings: Settings) -> ResponsePolicy:
        rs = tenant_response_settings(tenant_settings)
        install_cap = int(settings.response.max_actions_per_hour_per_tenant)
        problems: List[str] = []
        parsed = ResponsePolicySettings()
        try:
            parsed = ResponsePolicySettings.model_validate({k: rs[k] for k in GUARDRAIL_KEYS if k in rs})
        except ValidationError as exc:
            problems += problem_list("response", exc)
        if tenant_settings.get("autonomy") is not None:
            try:
                _AUTONOMY.validate_python(tenant_settings["autonomy"])
            except ValidationError as exc:
                problems += problem_list("autonomy", exc)
        if problems:
            log.warning("response.policy_invalid", problems=problems[:MAX_POLICY_PROBLEMS])
        blast = dict(DEFAULT_BLAST_RADIUS)
        blast.update(parsed.blast_radius or {})
        tenant_cap = parsed.max_actions_per_hour
        return cls(
            autonomy={risk: resolve_autonomy(risk, tenant_settings, settings) for risk in RISK_LEVELS},
            protected=ProtectedAssets.from_tenant_settings(tenant_settings),
            allow_internal_ip_blocks=parsed.allow_internal_ip_blocks is True,
            allowed_actions=frozenset(parsed.allowed_actions) if parsed.allowed_actions is not None else None,
            max_actions_per_hour=install_cap if tenant_cap is None else min(tenant_cap, install_cap),
            blast_radius=blast,
            problems=tuple(problems[:MAX_POLICY_PROBLEMS]),
            internal_domains=_internal_domains(tenant_settings, settings),
        )

    def internal_sender(self, address: str) -> bool:
        domain = domain_key(address.rsplit("@", 1)[-1])
        return any(domain == d or domain.endswith("." + d) for d in self.internal_domains)


def _internal_domains(tenant_settings: Mapping[str, Any], settings: Settings) -> Tuple[str, ...]:
    tools = tenant_settings.get("tools")
    values: List[Any] = []
    for source in (tools if isinstance(tools, Mapping) else {}, settings.tools or {}):
        entries = source.get("internal_domains")
        if isinstance(entries, list):
            values.extend(entries)
    domains = (domain_key(v.strip().lstrip("*.")) for v in values if isinstance(v, str) and v.strip())
    return tuple(dict.fromkeys(d for d in domains if d))


def approval_allowed(risk: str, role: Optional[str], autonomy: Optional[str] = None) -> bool:
    """Role vs risk: analysts approve low/medium, admins also high and critical; nothing whose autonomy is disabled."""
    if autonomy == "disabled":
        return False
    if role == "admin":
        return risk in RISK_LEVELS
    if role == "analyst":
        return risk in ANALYST_APPROVAL_RISKS
    return False


def preapproval_allowed(risk: str, approver_role: Optional[str]) -> bool:
    """Analysts may pre-approve low/medium actions; high and critical need an admin."""
    return risk in ANALYST_PREAPPROVAL_RISKS or approver_role == "admin"
