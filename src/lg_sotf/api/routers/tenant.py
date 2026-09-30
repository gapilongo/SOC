# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/tenant/settings`` (admin): autonomy policy, protected assets, LLM budget, review policy, tool keys, retention.

``PATCH`` is a JSON merge patch over the stored settings: top-level keys
replace (``null`` removes), and inside ``response`` and ``tools.<provider>``
keys merge so a patch does not drop stored secrets. Secrets are write-only:

* ``response.webhook_secret`` is stored encrypted as
  ``response.webhook_secret_ciphertext``;
* ``tools.<provider>.api_key`` is stored encrypted as
  ``tools.<provider>.api_key_ciphertext``.

Ciphertext fields cannot be written directly and are never returned; ``GET``
shows ``<name>_configured: true`` in their place. The response policy is
validated with :func:`~lg_sotf.services.response.validate_response_settings`
and the review policy with :class:`~lg_sotf.services.escalation.ReviewPolicy`;
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
from lg_sotf.api.schemas import RetentionLimitsOut, TenantSettingsOut, VerdictCacheClearedOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import Tenant
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.connectors.base import ConnectorConfigError
from lg_sotf.services.connectors.registry import encrypt_webhook_secret
from lg_sotf.services.escalation import ReviewPolicy
from lg_sotf.services.response import ResponsePolicyError, validate_response_settings
from lg_sotf.tools.enrichment.service import encrypt_tool_secret

router = APIRouter(prefix="/tenant", tags=["tenant"])

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
    }
)
TOOL_KEYS = frozenset({"enabled", "api_key"})
CIPHERTEXT_SUFFIX = "_ciphertext"
MAX_TOKEN_BUDGET = 10_000_000_000
MAX_TOOL_PROVIDERS = 32
MAX_INTERNAL_DOMAINS = 256


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
    for key in RETENTION_KEYS:
        value = section.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high):
            problems.append(f"retention.{key}: must be a whole number of days from {low} to {high}")
    return section or None


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
    async with ctx.db.tenant_tx(tenant_id) as conn:
        # Lock the row: nested sections (response, tools) are merged from this snapshot, so two
        # concurrent PATCHes of different sub-keys would otherwise silently drop one of them.
        tenant = await ctx.repos.tenants.get(tenant_id, for_update=True, conn=conn)
        patch = build_patch(ctx, tenant, body)
        updated = await ctx.repos.tenants.update_settings(tenant_id, patch, conn=conn)
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "tenant.settings_updated",
            "tenant",
            tenant_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"keys": sorted(patch)},
            conn=conn,
        )
        await ctx.repos.tenants.mark_onboarding(tenant_id, "autonomy_reviewed_at", conn=conn)
    ctx.tenants.invalidate(tenant_id)
    return _out(updated).model_copy(update={"retention_limits": retention_limits(ctx)})


@router.delete(
    "/verdict-cache",
    response_model=VerdictCacheClearedOut,
    summary="Forget every cached analyst-benign verdict of the tenant",
)
async def clear_verdict_cache(request: Request, principal: Principal = Depends(require(ADMIN))) -> VerdictCacheClearedOut:
    ctx = get_ctx(request)
    removed = await VerdictCache(ctx.redis, ctx.prefix).clear_tenant(principal.tenant_id)
    await AuditLogger(ctx.repos).record(
        principal.tenant_id,
        "tenant.verdict_cache_cleared",
        "tenant",
        principal.tenant_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={"removed": removed},
    )
    return VerdictCacheClearedOut(removed=removed)
