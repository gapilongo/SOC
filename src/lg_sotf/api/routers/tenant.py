# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/tenant/settings`` (admin): the tenant's policy sections.

Autonomy, protected assets, LLM budget, review policy, tool keys, retention,
sign-in security, reporting assumptions and phishing context.

``POST /tenant/llm/test`` (admin) sends a tiny structured probe to the fast
and deep model tiers and reports provider, model, latency and a sanitized
error per tier (:mod:`lg_sotf.services.llm_check`). It is rate limited per
tenant, metered to the tenant as agent ``llm_test`` and audited.

``GET /tenant/response/routes`` (admin) shows, per action type, which
connector executes it now and why (:mod:`lg_sotf.services.connectors.routing`),
and whether dry run is forced; ``response.routes`` overrides the route of an
action type (``dry_run``, ``webhook``, ``microsoft``, ``ticketing``).

``PATCH`` is a JSON merge patch over the stored settings: top-level keys
replace (``null`` removes), and inside ``response`` and ``tools.<provider>``
keys merge so a patch does not drop stored secrets. Secrets are write-only:

* ``response.webhook_secret`` is stored encrypted as
  ``response.webhook_secret_ciphertext``;
* ``tools.<provider>.api_key`` is stored encrypted as
  ``tools.<provider>.api_key_ciphertext``.

``security.require_mfa`` (boolean) makes TOTP MFA mandatory for the
tenant's local accounts: users without it can only enroll after their
password until they have.

Ciphertext fields cannot be written directly and are never returned; ``GET``
shows ``<name>_configured: true`` in their place. The response policy is
validated with :func:`~lg_sotf.services.response.validate_response_settings`
and the review policy with :class:`~lg_sotf.services.escalation.ReviewPolicy`,
the ``phishing`` section (protected brands, executives, trusted
``authserv-id`` values) with :class:`~lg_sotf.domain.phishing.PhishingSettings`;
problems come back as 422 with ``details``.

``retention`` (``alerts_days``, ``indicators_days``) merges key by key and
must stay within the install's ``retention.tenant_min_days`` ..
``retention.tenant_max_days``; responses carry those bounds as
``retention_limits``. Saving the settings marks the first-run checklist's
"autonomy reviewed" step.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Mapping, Optional

from fastapi import APIRouter, Body, Depends, Request
from pydantic import ValidationError

from lg_sotf.api.auth.deps import ADMIN, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.ratelimit import rate_limited
from lg_sotf.api.schemas import (
    LLMTestOut,
    LLMTierCheckOut,
    RetentionLimitsOut,
    TenantSettingsOut,
    VerdictCacheClearedOut,
)
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import LLMUsageDelta, Tenant
from lg_sotf.domain.connectors import ConnectorConfigError
from lg_sotf.domain.phishing import validate_phishing_settings
from lg_sotf.llm.usage import LLMUsageRow, get_usage_recorder
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services import tenancy
from lg_sotf.services.connectors.registry import encrypt_webhook_secret
from lg_sotf.services.escalation import ReviewPolicy
from lg_sotf.services.llm_check import check_llm
from lg_sotf.services.reporting import ReportingPolicy
from lg_sotf.services.response import ResponsePolicyError, validate_response_settings
from lg_sotf.tools.enrichment.service import encrypt_tool_secret

router = APIRouter(prefix="/tenant", tags=["tenant"])
log = get_logger(__name__)

EDITABLE_KEYS = frozenset(
    {
        "response",
        "protected_assets",
        "protected_cidrs",
        "autonomy",
        "llm_daily_token_budget",
        "review",
        "tools",
        "retention",
        "security",
        "reporting",
        "phishing",
    }
)
RETENTION_KEYS = ("alerts_days", "indicators_days")
RESPONSE_KEYS = frozenset(
    {
        "connector",
        "dry_run",
        "webhook_url",
        "webhook_secret",
        "ca_cert_pem",
        "tls_verify",
        "allow_internal_ip_blocks",
        "allowed_actions",
        "max_actions_per_hour",
        "blast_radius",
        "autonomy",
        "routes",
    }
)
TOOL_KEYS = frozenset({"enabled", "api_key"})
SECURITY_KEYS = frozenset({"require_mfa"})
CIPHERTEXT_SUFFIX = "_ciphertext"
MAX_TOKEN_BUDGET = 10_000_000_000
MAX_TOOL_PROVIDERS = 32
MAX_INTERNAL_DOMAINS = 256
LLM_TEST_BUCKET = "llm_test"
LLM_TEST_PER_MINUTE = 6


def redact_ciphertexts(value: Any) -> Any:
    """Replace every ``<name>_ciphertext`` with ``<name>_configured: true``."""
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.endswith(CIPHERTEXT_SUFFIX):
                if item:
                    out[key[: -len(CIPHERTEXT_SUFFIX)] + "_configured"] = True
                continue
            out[key] = redact_ciphertexts(item)
        return out
    if isinstance(value, list):
        return [redact_ciphertexts(v) for v in value]
    return value


def _out(tenant: Tenant) -> TenantSettingsOut:
    return TenantSettingsOut(
        tenant_id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        settings=redact_ciphertexts(tenant.settings),
        updated_at=tenant.updated_at,
    )


def retention_limits(ctx: ApiContext) -> RetentionLimitsOut:
    r = ctx.settings.retention
    return RetentionLimitsOut(
        min_days=r.tenant_min_days,
        max_days=r.tenant_max_days,
        alerts_days=r.alerts_days,
        indicators_days=r.indicators_days,
    )


def _invalid(problems: List[str]) -> ApiError:
    return ApiError(422, "invalid_settings", "tenant settings are invalid", details=problems)


def _merge(current: Mapping[str, Any], patch: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(current)
    for key, value in patch.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def _box(ctx: ApiContext) -> SecretBox:
    if ctx.secret_box is None:
        raise ApiError(503, "encryption_unavailable", "secret encryption is not configured on this server")
    return ctx.secret_box


def _response_section(
    ctx: ApiContext, tenant_id: str, current: Any, patch: Any, problems: List[str]
) -> Optional[Dict[str, Any]]:
    if patch is None:
        return None
    if not isinstance(patch, Mapping):
        problems.append("response: must be an object")
        return None
    unknown = sorted(set(patch) - RESPONSE_KEYS)
    if unknown:
        problems.append(f"response: unknown or read-only keys: {', '.join(unknown[:10])}")
        return None
    section = _merge(
        current if isinstance(current, Mapping) else {}, {k: v for k, v in patch.items() if k != "webhook_secret"}
    )
    if "webhook_secret" in patch:
        secret = patch["webhook_secret"]
        if secret is None:
            section.pop("webhook_secret_ciphertext", None)
        elif not isinstance(secret, str):
            problems.append("response.webhook_secret: must be a string")
        else:
            try:
                section["webhook_secret_ciphertext"] = encrypt_webhook_secret(_box(ctx), tenant_id, secret)
            except ConnectorConfigError as exc:
                problems.append(f"response.webhook_secret: {exc}")
    return section


def _tools_section(
    ctx: ApiContext, tenant_id: str, current: Any, patch: Any, problems: List[str]
) -> Optional[Dict[str, Any]]:
    if patch is None:
        return None
    if not isinstance(patch, Mapping):
        problems.append("tools: must be an object")
        return None
    tools: Dict[str, Any] = copy.deepcopy(dict(current)) if isinstance(current, Mapping) else {}
    for provider, value in patch.items():
        if provider == "internal_domains":
            if value is None:
                tools.pop(provider, None)
            elif (
                not isinstance(value, list)
                or len(value) > MAX_INTERNAL_DOMAINS
                or not all(isinstance(d, str) and 0 < len(d) <= 253 for d in value)
            ):
                problems.append(
                    f"tools.internal_domains: must be a list of at most {MAX_INTERNAL_DOMAINS} domain names"
                )
            else:
                tools[provider] = value
            continue
        if not isinstance(provider, str) or not provider.isidentifier() or len(provider) > 64:
            problems.append("tools: provider names must be identifiers")
            continue
        if value is None:
            tools.pop(provider, None)
            continue
        if not isinstance(value, Mapping):
            problems.append(f"tools.{provider}: must be an object")
            continue
        unknown = sorted(set(value) - TOOL_KEYS)
        if unknown:
            problems.append(f"tools.{provider}: unknown or read-only keys: {', '.join(unknown[:10])}")
            continue
        entry = dict(tools.get(provider) or {}) if isinstance(tools.get(provider), Mapping) else {}
        if "enabled" in value:
            if value["enabled"] is None:
                entry.pop("enabled", None)
            elif not isinstance(value["enabled"], bool):
                problems.append(f"tools.{provider}.enabled: must be true or false")
            else:
                entry["enabled"] = value["enabled"]
        if "api_key" in value:
            key = value["api_key"]
            if key is None:
                entry.pop("api_key_ciphertext", None)
            elif not isinstance(key, str) or not key.strip() or len(key) > 4_096:
                problems.append(f"tools.{provider}.api_key: must be a non-empty string")
            else:
                entry["api_key_ciphertext"] = encrypt_tool_secret(_box(ctx), tenant_id, provider, key.strip())
        tools[provider] = entry
    if len([k for k in tools if k != "internal_domains"]) > MAX_TOOL_PROVIDERS:
        problems.append(f"tools: at most {MAX_TOOL_PROVIDERS} providers")
    return tools


def _retention_section(ctx: ApiContext, current: Any, patch: Any, problems: List[str]) -> Optional[Dict[str, Any]]:
    """Per-tenant retention overrides, merged key by key (``null`` removes one; an empty section is dropped)."""
    if patch is None:
        return None
    if not isinstance(patch, Mapping):
        problems.append("retention: must be an object")
        return None
    unknown = sorted(str(k)[:64] for k in set(patch) - set(RETENTION_KEYS))
    if unknown:
        problems.append(f"retention: unknown keys: {', '.join(unknown[:10])}")
        return None
    section = _merge(current if isinstance(current, Mapping) else {}, patch)
    section = {k: v for k, v in section.items() if k in RETENTION_KEYS}
    low, high = ctx.settings.retention.tenant_min_days, ctx.settings.retention.tenant_max_days
    # Only the keys being set are checked: a value stored before the bounds changed is clamped at purge time
    # and must not block edits of the other key.
    for key in patch:
        value = section.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high):
            problems.append(f"retention.{key}: must be a whole number of days from {low} to {high}")
    return section or None


def _security_section(current: Any, patch: Any, problems: List[str]) -> Optional[Dict[str, Any]]:
    if patch is None:
        return None
    if not isinstance(patch, Mapping):
        problems.append("security: must be an object")
        return None
    unknown = sorted(set(patch) - SECURITY_KEYS)
    if unknown:
        problems.append(f"security: unknown keys: {', '.join(str(k)[:64] for k in unknown[:10])}")
        return None
    section = _merge(current if isinstance(current, Mapping) else {}, patch)
    if "require_mfa" in section and not isinstance(section["require_mfa"], bool):
        problems.append("security.require_mfa: must be true or false")
    return section


def _reporting_section(current: Any, patch: Any, problems: List[str]) -> Optional[Dict[str, Any]]:
    """``reporting`` (value report assumptions): keys merge; ``null`` removes one (back to the default)."""
    if patch is None:
        return None
    if not isinstance(patch, Mapping):
        problems.append("reporting: must be an object")
        return None
    section = _merge(current if isinstance(current, Mapping) else {}, patch)
    try:
        ReportingPolicy.model_validate(section)
    except ValidationError as exc:
        for error in exc.errors()[:5]:
            where = ".".join(str(p) for p in error["loc"]) or "reporting"
            problems.append(f"reporting.{where}: {error['msg']}"[:200])
    return section


def _phishing_section(value: Any, problems: List[str]) -> Optional[Dict[str, Any]]:
    """The whole ``phishing`` section is replaced (it holds no secrets); ``null`` removes it."""
    if value is None:
        return None
    try:
        return validate_phishing_settings(value)
    except ValueError as exc:
        problems.append(str(exc))
        return None


def build_patch(ctx: ApiContext, tenant: Tenant, body: Mapping[str, Any]) -> Dict[str, Any]:
    """The validated top-level merge patch to store (raises 422 listing every problem)."""
    problems: List[str] = []
    unknown = sorted(set(body) - EDITABLE_KEYS)
    if unknown:
        raise _invalid([f"unknown settings keys: {', '.join(str(k)[:64] for k in unknown[:10])}"])
    current = tenant.settings or {}
    patch: Dict[str, Any] = {}
    for key, value in body.items():
        if key == "response":
            patch[key] = _response_section(ctx, tenant.id, current.get("response"), value, problems)
        elif key == "tools":
            patch[key] = _tools_section(ctx, tenant.id, current.get("tools"), value, problems)
        elif key == "retention":
            patch[key] = _retention_section(ctx, current.get("retention"), value, problems)
        elif key == "security":
            patch[key] = _security_section(current.get("security"), value, problems)
        elif key == "reporting":
            patch[key] = _reporting_section(current.get("reporting"), value, problems)
        elif key == "phishing":
            patch[key] = _phishing_section(value, problems)
        elif key == "llm_daily_token_budget":
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_TOKEN_BUDGET
            ):
                problems.append(f"llm_daily_token_budget: must be an integer 0..{MAX_TOKEN_BUDGET} or null")
            patch[key] = value
        elif key == "review":
            if value is not None:
                try:
                    if not isinstance(value, Mapping):
                        raise ValueError("must be an object")
                    ReviewPolicy.model_validate(dict(value))
                except (ValidationError, ValueError, TypeError) as exc:
                    problems.append(f"review: {str(exc).splitlines()[0][:200]}")
            patch[key] = value
        else:
            patch[key] = value
    if problems:
        raise _invalid(problems)
    candidate = _merge(current, patch)
    response_view: Dict[str, Any] = {
        k: candidate[k] for k in ("response", "protected_assets", "protected_cidrs", "autonomy") if k in candidate
    }
    try:
        normalized = validate_response_settings(response_view)
    except ResponsePolicyError as exc:
        raise _invalid(exc.problems) from exc
    for key in ("response", "protected_assets", "protected_cidrs", "autonomy"):
        if key in patch and patch[key] is not None and key in normalized:
            patch[key] = normalized[key]
    return patch


@router.get("/settings", response_model=TenantSettingsOut, summary="Tenant settings (secrets redacted)")
async def get_settings(request: Request, principal: Principal = Depends(require(ADMIN))) -> TenantSettingsOut:
    ctx = get_ctx(request)
    out = _out(await ctx.repos.tenants.get(principal.tenant_id))
    return out.model_copy(update={"retention_limits": retention_limits(ctx)})


@router.patch("/settings", response_model=TenantSettingsOut, summary="Merge-patch tenant settings")
async def patch_settings(
    request: Request,
    body: Dict[str, Any] = Body(..., examples=[{"autonomy": {"low": "auto"}, "llm_daily_token_budget": 2_000_000}]),
    principal: Principal = Depends(require(ADMIN)),
) -> TenantSettingsOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    updated = await tenancy.update_settings(
        ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, lambda tenant: build_patch(ctx, tenant, body)
    )
    ctx.tenants.invalidate(tenant_id)
    return _out(updated).model_copy(update={"retention_limits": retention_limits(ctx)})


@router.get("/response/routes", summary="Which connector executes each action type, and why")
async def response_routes(request: Request, principal: Principal = Depends(require(ADMIN))) -> Dict[str, Any]:
    """``{dry_run_forced, routes: {action_type: {connector, source, capability, live, problem}}}``."""
    ctx = get_ctx(request)
    tenant = await ctx.repos.tenants.get(principal.tenant_id)
    snapshot = await ctx.review.responses.routing(principal.tenant_id, tenant.settings)
    return {
        "dry_run_forced": snapshot.dry_run_forced,
        "routes": {action_type: route.as_dict() for action_type, route in snapshot.routes().items()},
    }


@router.delete(
    "/verdict-cache",
    response_model=VerdictCacheClearedOut,
    summary="Forget every cached analyst-benign verdict of the tenant",
)
async def clear_verdict_cache(request: Request, principal: Principal = Depends(require(ADMIN))) -> VerdictCacheClearedOut:
    ctx = get_ctx(request)
    removed = await VerdictCache(ctx.redis, ctx.prefix).clear_tenant(principal.tenant_id)
    await AuditLogger(ctx.repos).record_event(
        principal.tenant_id,
        "tenant.verdict_cache_cleared",
        "tenant",
        principal.tenant_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={"removed": removed},
    )
    return VerdictCacheClearedOut(removed=removed)


async def _flush_usage(ctx: ApiContext) -> None:
    """Write the probe's metering now: the API process has no periodic usage flush of its own."""

    async def sink(rows: List[LLMUsageRow]) -> None:
        await ctx.repos.llm_usage.upsert_daily([LLMUsageDelta(**row) for row in rows])

    try:
        await get_usage_recorder().flush(sink)
    except Exception as exc:  # noqa: BLE001 - the rows stay buffered for the next flush
        log.warning("api.usage_flush_failed", error_type=type(exc).__name__)


@router.post("/llm/test", response_model=LLMTestOut, summary="Send a tiny probe to the fast and deep model tiers")
async def test_llm(request: Request, principal: Principal = Depends(require(ADMIN))) -> LLMTestOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    # Each test costs up to two model calls on the shared provider account: keep it a manual action.
    decision = await ctx.limiter.hit(LLM_TEST_BUCKET, tenant_id, LLM_TEST_PER_MINUTE, tenant_id=tenant_id)
    if not decision.allowed:
        raise rate_limited(decision)
    report = await check_llm(ctx.settings, tenant_id)
    await _flush_usage(ctx)
    await AuditLogger(ctx.repos).record_event(
        tenant_id,
        "tenant.llm_tested",
        "tenant",
        tenant_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={
            "provider": report.provider,
            "ok": report.ok,
            "tiers": {t.tier: {"model": t.model, "ok": t.ok, "error_code": t.error_code} for t in report.tiers},
        },
    )
    return LLMTestOut(
        provider=report.provider,
        enabled=report.enabled,
        ok=report.ok,
        tiers=[
            LLMTierCheckOut(
                tier=t.tier,
                model=t.model,
                ok=t.ok,
                latency_ms=t.latency_ms,
                structured_output=t.method,
                error_code=t.error_code,
                error=t.error,
            )
            for t in report.tiers
        ],
    )
