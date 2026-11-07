"""The Microsoft connection test (``POST /integrations/{id}/test``): token requests and GETs only.

What it does:

1. Requests a fresh token for Microsoft Graph (always: it proves the
   credential, the directory and the cloud) and for Defender when an enabled
   capability needs it, and decodes each token's ``roles`` claim.
2. For **every** catalog capability, reports each permission: application
   permissions from the ``roles`` claim (``granted`` / ``missing``, or
   ``unknown`` without a readable claim); Entra directory roles and Exchange
   RBAC for Applications roles are never visible in tokens, so they are
   always ``unknown`` with guidance. An application permission the
   capability may get through Exchange RBAC for Applications
   (``Permission.exchange_rbac``) is ``unknown``, not ``missing``, when the
   token lacks it: the least-privilege setup grants it only there. Nothing
   the test can do proves that grant (a GET probe passes on a read-only
   grant while every write gets a 403), so the capability stays
   ``unverified``, with guidance to check the scope with
   ``Test-ServicePrincipalAuthorization``. When the token *does* carry it,
   the grant is tenant-wide Entra consent, which overrides the Exchange
   scope: it is reported ``granted`` with a ``warning`` and is not counted
   as evidence. A conditional permission (``when``) is required exactly
   when its condition holds for the capability's options.
3. Runs the ``probe()`` GETs of every *enabled* capability through a
   read-only client (a write is refused before it is sent).

Capability status: ``ok`` when its probes pass and no required,
token-visible permission is missing; ``unverified`` when a required
Exchange RBAC permission is not in the token, or when the only evidence is
``unknown`` (or a tenant-wide grant that carries a warning); otherwise
``missing_permission``, ``not_licensed``, ``unsupported_cloud``, ``error``
or ``not_enabled``.

The report holds no token, secret or Microsoft free text; it is stored with
the test delivery and audited as ``integration.tested``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Set

from pydantic import BaseModel, Field

from lg_sotf.integrations.microsoft.auth import AppCredentials, MicrosoftAuthError, TokenProvider
from lg_sotf.integrations.microsoft.capability import CapabilitySpec, HandlerContext, Permission, ProbeCheck
from lg_sotf.integrations.microsoft.catalog import capabilities, is_enabled, is_live
from lg_sotf.integrations.microsoft.clouds import Api
from lg_sotf.integrations.microsoft.http import MicrosoftApiError, ReadOnlyViolation
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from lg_sotf.observability.logging import get_logger, log_failure

log = get_logger(__name__)

CapabilityStatus = Literal[
    "ok", "missing_permission", "not_licensed", "unsupported_cloud", "error", "not_enabled", "unverified"
]
TEST_DEADLINE_S = 60.0
PROBE_TIMEOUT_S = 20.0
DIRECTORY_ROLE_GUIDANCE = (
    "assign this Microsoft Entra role to the app's service principal (Roles and administrators); "
    "tokens do not show it"
)
EXCHANGE_RBAC_GUIDANCE = (
    "assign this Exchange RBAC for Applications role to the app's service principal "
    "(New-ManagementRoleAssignment -App ...); tokens do not show it"
)
RBAC_ONLY_GUIDANCE = (
    "not in the token, as expected when it is granted only through Exchange RBAC for Applications "
    "(the recommended setup); neither the token nor a read-only probe shows that grant: check it with "
    "Test-ServicePrincipalAuthorization -Identity <app> -Resource <mailbox>"
)
RBAC_UNVERIFIED_DETAIL = (
    "a required mailbox permission is granted, if at all, through Exchange RBAC for Applications, which this "
    "test cannot see (a passing read probe does not prove a write role): check each role and mailbox with "
    "Test-ServicePrincipalAuthorization -Identity <app> -Resource <mailbox>"
)
TENANT_WIDE_WARNING = (
    "granted tenant-wide by Entra admin consent: this overrides the Exchange RBAC for Applications scope and "
    "reaches every mailbox; remove the consent and keep the scoped role assignment"
)


class TokenCheck(BaseModel):
    status: Literal["ok", "failed", "not_needed"]
    error: Optional[str] = None
    aadsts: Optional[int] = None
    hint: Optional[str] = None
    roles: Optional[List[str]] = None


class PermissionCheck(BaseModel):
    role: str
    api: str
    status: Literal["granted", "missing", "unknown"]
    via: Literal["token", "probe", "exchange_rbac", "directory_role"]
    required: bool = True
    guidance: str = ""
    warning: str = ""


class CapabilityCheck(BaseModel):
    status: CapabilityStatus
    enabled: bool = False
    live: bool = False
    permissions: List[PermissionCheck] = Field(default_factory=list)
    checks: List[ProbeCheck] = Field(default_factory=list)
    detail: str = ""


class CertificateInfo(BaseModel):
    thumbprint_sha1: str
    thumbprint_sha256: str
    not_after: datetime
    days_left: int


class MicrosoftTestReport(BaseModel):
    """What ``POST /integrations/{id}/test`` reports for a Microsoft integration (no tokens, no secrets)."""

    ok: bool = False
    tokens: Dict[str, TokenCheck] = Field(default_factory=dict)
    capabilities: Dict[str, CapabilityCheck] = Field(default_factory=dict)
    certificate: Optional[CertificateInfo] = None


@dataclass(frozen=True)
class ProbeTarget:
    """What the test needs from the integration (the connector builds it)."""

    creds: AppCredentials
    config: Any  # MicrosoftConfig
    context_for: Callable[[CapabilitySpec, float], HandlerContext]


def _applies(permission: Permission, options: Mapping[str, Any]) -> bool:
    """Whether a conditional permission (``when="option=value[,option=value]"``) applies to these options."""
    if not permission.when:
        return True
    for condition in permission.when.split(","):
        name, _, value = condition.strip().partition("=")
        current = options.get(name.strip())
        text = str(current).lower() if isinstance(current, bool) else str(current)
        if text != value.strip():
            return False
    return True


def _options(config: Any, key: str) -> Mapping[str, Any]:
    caps = getattr(config, "capabilities", None) or {}
    entry = caps.get(key)
    options = getattr(entry, "options", None) if entry is not None else None
    return options if isinstance(options, Mapping) else {}


def _permission_checks(
    spec: CapabilitySpec, roles: Mapping[str, Optional[Set[str]]], options: Mapping[str, Any]
) -> List[PermissionCheck]:
    out: List[PermissionCheck] = []
    for permission in spec.permissions:
        # A conditional permission is needed exactly when its condition holds (``required`` is its default).
        required = _applies(permission, options) if permission.when else permission.required
        granted = roles.get(permission.api)
        guidance = warning = ""
        if granted is None:
            status: Literal["granted", "missing", "unknown"] = "unknown"
        elif permission.role in granted:
            status = "granted"
            if permission.exchange_rbac:
                warning = TENANT_WIDE_WARNING
        elif permission.exchange_rbac:
            status, guidance = "unknown", RBAC_ONLY_GUIDANCE
        else:
            status = "missing"
        out.append(PermissionCheck(role=permission.role, api=permission.api, status=status, via="token",
                                   required=required, guidance=guidance, warning=warning))
        if permission.directory_role:
            out.append(PermissionCheck(role=permission.directory_role, api=permission.api, status="unknown",
                                       via="directory_role", required=required, guidance=DIRECTORY_ROLE_GUIDANCE))
        if permission.exchange_rbac:
            out.append(PermissionCheck(role=permission.exchange_rbac, api=permission.api, status="unknown",
                                       via="exchange_rbac", required=required, guidance=EXCHANGE_RBAC_GUIDANCE))
    return out


def _probe_failure(exc: BaseException) -> ProbeCheck:
    if isinstance(exc, MicrosoftAuthError):
        return ProbeCheck("probe", "error", detail=f"token: {exc.ledger_error}"[:300])
    if isinstance(exc, MicrosoftApiError):
        if exc.kind == "forbidden":
            detail = f"HTTP {exc.status} {exc.code}".strip()[:300]
            if exc.ledger_error == "not_licensed":
                return ProbeCheck("probe", "not_licensed", detail=detail)
            return ProbeCheck("probe", "forbidden", detail=detail)
        if exc.kind == "not_found":
            return ProbeCheck("probe", "not_found", detail=f"HTTP {exc.status} {exc.code}".strip()[:300])
        return ProbeCheck("probe", "error", detail=f"{exc.ledger_error} (HTTP {exc.status})"[:300])
    if isinstance(exc, ReadOnlyViolation):
        return ProbeCheck("probe", "error", detail="the probe attempted a write (refused, not sent)")
    if isinstance(exc, InvalidTarget):
        return ProbeCheck("probe", "error", detail=str(exc)[:300])
    if isinstance(exc, TimeoutError):
        return ProbeCheck("probe", "error", detail="the probe timed out")
    return ProbeCheck("probe", "error", detail=f"probe failed ({type(exc).__name__})")


def _rbac_unproven(spec: CapabilitySpec, permissions: Sequence[PermissionCheck]) -> bool:
    """Whether a required permission meant for Exchange RBAC for Applications is not in the token."""
    scoped = {(p.api, p.role) for p in spec.permissions if p.exchange_rbac}
    return any(
        p.required and p.via == "token" and p.status == "unknown" and (p.api, p.role) in scoped for p in permissions
    )


def _status(
    spec: CapabilitySpec, permissions: Sequence[PermissionCheck], checks: Sequence[ProbeCheck], token: TokenCheck
) -> CapabilityStatus:
    if token.status == "failed":
        return "error"
    required = [p for p in permissions if p.required]
    if any(p.status == "missing" for p in required):
        return "missing_permission"
    statuses = {c.status for c in checks}
    if "forbidden" in statuses:
        return "missing_permission"
    if "not_licensed" in statuses:
        return "not_licensed"
    if statuses & {"error", "not_found"}:
        return "error"
    # The probes are GETs: they pass on a read-only grant, so they never prove an Exchange RBAC role the token
    # does not show (a send or a purge would still get a 403).
    if _rbac_unproven(spec, permissions):
        return "unverified"
    # Passing probes or granted token roles are evidence; unknown entries alone are not, and neither is a
    # tenant-wide grant of a permission meant to be scoped by Exchange RBAC (it carries a warning).
    evidence = "ok" in statuses or any(
        p.status == "granted" and p.via == "token" and not p.warning for p in required
    )
    return "ok" if evidence else "unverified"


async def _probe(target: ProbeTarget, spec: CapabilitySpec, deadline: float, probe_timeout_s: float) -> List[ProbeCheck]:
    """One capability's read-only probe, bounded by the test deadline; a failure becomes a check."""
    loop = asyncio.get_running_loop()
    try:
        handler = spec.handler(target.context_for(spec, min(deadline, loop.time() + probe_timeout_s)))
        async with asyncio.timeout(max(0.1, min(probe_timeout_s, deadline - loop.time()))):
            return list(await handler.probe())
    except Exception as exc:  # noqa: BLE001 - a failing probe is a test result, not an API error
        log_failure(
            log, "microsoft.probe_failed", exc, level="warning", capability=spec.key, error_type=type(exc).__name__
        )
        return [_probe_failure(exc)]


async def run_connection_test(
    target: ProbeTarget,
    tokens: TokenProvider,
    *,
    deadline_s: float = TEST_DEADLINE_S,
    probe_timeout_s: float = PROBE_TIMEOUT_S,
) -> MicrosoftTestReport:
    """Run the test (module docstring) and return the report; never raises for Microsoft-side failures."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_s
    creds, config = target.creds, target.config
    catalog = capabilities()
    enabled = [spec for spec in catalog.values() if is_enabled(config, spec.key) and creds.cloud.name in spec.clouds]
    needed: Set[Api] = {"graph"}
    for spec in enabled:
        needed.add(spec.api)
        needed.update(p.api for p in spec.permissions)
    token_checks: Dict[str, TokenCheck] = {}
    roles: Dict[str, Optional[Set[str]]] = {}
    for api in ("graph", "defender"):
        if api not in needed or (api == "defender" and not creds.cloud.defender_supported):
            token_checks[api] = TokenCheck(status="not_needed")
            roles[api] = None
            continue
        tokens.invalidate(creds, api)  # test the credential as it is now, not a cached token
        try:
            token = await tokens.token(creds, api, deadline=deadline)
        except MicrosoftApiError as exc:
            auth = exc if isinstance(exc, MicrosoftAuthError) else None
            token_checks[api] = TokenCheck(
                status="failed",
                error=auth.ledger_error if auth else exc.ledger_error,
                aadsts=auth.aadsts if auth else None,
                hint=auth.hint if auth else None,
            )
            roles[api] = None
            continue
        claim = tokens.roles(token)
        roles[api] = set(claim) if claim is not None else None
        token_checks[api] = TokenCheck(status="ok", roles=sorted(claim) if claim is not None else None)
    results: Dict[str, CapabilityCheck] = {}
    for spec in sorted(catalog.values(), key=lambda s: s.key):
        options = _options(config, spec.key)
        permissions = _permission_checks(spec, roles, options)
        on, live = is_enabled(config, spec.key), is_live(config, spec.key)
        if creds.cloud.name not in spec.clouds:
            results[spec.key] = CapabilityCheck(status="unsupported_cloud", enabled=on, live=live,
                                                permissions=permissions,
                                                detail=f"not available in the {creds.cloud.name} cloud")
            continue
        if not on:
            results[spec.key] = CapabilityCheck(status="not_enabled", permissions=permissions)
            continue
        checks: List[ProbeCheck] = []
        api_token = token_checks.get(spec.api) or TokenCheck(status="not_needed")
        if api_token.status == "ok":
            checks = await _probe(target, spec, deadline, probe_timeout_s)
        status = _status(spec, permissions, checks, api_token)
        detail = ""
        if api_token.status == "failed":
            detail = f"{spec.api} token: {api_token.error}"
        elif status == "unverified" and _rbac_unproven(spec, permissions):
            detail = RBAC_UNVERIFIED_DETAIL
        results[spec.key] = CapabilityCheck(status=status, enabled=True, live=live, permissions=permissions,
                                            checks=checks, detail=detail)
    certificate: Optional[CertificateInfo] = None
    pem = getattr(config, "certificate_pem", None)
    if pem:
        from lg_sotf.integrations.config import IntegrationConfigError, certificate_details

        try:
            certificate = CertificateInfo.model_validate(certificate_details(pem))
        except (IntegrationConfigError, ValueError):
            certificate = None
    ok = all(t.status != "failed" for t in token_checks.values()) and all(
        c.status in ("ok", "unverified", "not_enabled", "unsupported_cloud") for c in results.values()
    )
    return MicrosoftTestReport(ok=ok, tokens=token_checks, capabilities=results, certificate=certificate)


__all__ = [
    "CapabilityCheck",
    "CertificateInfo",
    "MicrosoftTestReport",
    "PermissionCheck",
    "ProbeTarget",
    "TokenCheck",
    "run_connection_test",
]
