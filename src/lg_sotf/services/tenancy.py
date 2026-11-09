"""Tenant lifecycle for MSSPs: provisioning, settings templates, quotas and their enforcement.

Provisioning (:func:`provision_tenant`, used by ``POST /platform/tenants``
and ``lg-sotf create-tenant``) is one transaction: the tenant row, its
seeded settings, its first admin and every audit entry (in the new tenant,
the platform admin's home tenant and a copied tenant) commit together or
not at all, so a failure leaves nothing behind and a retry succeeds.

Templates seed a new tenant's settings:

* ``profile``: one of :data:`PROFILES`. Every profile keeps response actions
  in dry-run; live execution is switched on per tenant once its connector is
  configured, never by a template. ``conservative`` also requires MFA for
  local sign-in (``security.require_mfa``).
* ``copy_settings_from``: the policy of an existing tenant (autonomy, review,
  LLM budget, retention, ``security.require_mfa``, reporting assumptions,
  the non-destination parts of ``response`` and which enrichment tools are
  enabled). Secrets are never copied, nor is anything that identifies the
  source customer or points at its systems (webhook URL and CA, protected
  assets, internal domains, the ``phishing`` brands, executives and trusted
  mail servers): copying those would send one customer's actions to
  another's endpoint or leak its asset names.

Quotas (``tenants.max_*``, ``NULL`` = unlimited) are set by platform admins:

* ``max_alerts_per_day``: alerts stored per UTC day (``usage_daily``);
  ingest over it is refused with 429 and pull sources wait for the next day;
* ``max_sources`` and ``max_users`` (active accounts): creating one more is
  refused with 409. The count and the insert run in one transaction holding
  the tenant row lock, so concurrent requests cannot overshoot.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db import Connection
from lg_sotf.db.repos import Repositories, Tenant, User
from lg_sotf.db.repos.escalations import ESCALATION_LEVELS
from lg_sotf.db.tenancy import switch_tenant
from lg_sotf.domain import closure
from lg_sotf.models.tenant_settings import COPIED_KEYS, TenantSettingsDoc
from lg_sotf.services.escalation import resolve_review_policy
from lg_sotf.settings import Settings

Profile = Literal["conservative", "balanced", "autonomous"]

# Saving either settings section counts as the onboarding "autonomy reviewed" step.
AUTONOMY_REVIEW_KEYS = frozenset({"autonomy", "response"})

PROFILES: Dict[str, TenantSettingsDoc] = {
    # Nothing runs without a person; high-risk and critical actions are never proposed for execution.
    "conservative": {
        "autonomy": {"low": "approval", "medium": "approval", "high": "disabled", "critical": "disabled"},
        "response": {"dry_run": True, "max_actions_per_hour": 10},
        "review": {"sla_minutes": {"L1": 30, "L2": 60, "L3": 120}, "suggest_suppressions": True},
        # Local accounts enrol a TOTP factor at their first sign-in (SSO users get MFA from their IdP).
        "security": {"require_mfa": True},
    },
    # Low-risk containment runs on its own; everything else waits for approval.
    "balanced": {
        "autonomy": {"low": "auto", "medium": "approval", "high": "approval", "critical": "disabled"},
        "response": {"dry_run": True, "max_actions_per_hour": 25},
        "review": {"sla_minutes": {"L1": 30, "L2": 60, "L3": 120}, "suggest_suppressions": True},
    },
    # Low and medium risk run on their own; high and critical need approval.
    "autonomous": {
        "autonomy": {"low": "auto", "medium": "auto", "high": "approval", "critical": "approval"},
        "response": {"dry_run": True, "max_actions_per_hour": 50},
        "review": {"sla_minutes": {"L1": 15, "L2": 30, "L3": 60}, "suggest_suppressions": True},
    },
}

COPIED_SECURITY_KEYS = ("require_mfa",)
COPIED_RESPONSE_KEYS = (
    "dry_run",
    "allowed_actions",
    "max_actions_per_hour",
    "blast_radius",
    "autonomy",
    "allow_internal_ip_blocks",
)
CIPHERTEXT_SUFFIX = "_ciphertext"


def profile_settings(profile: str) -> Dict[str, Any]:
    """The settings a profile seeds (a fresh copy); ``KeyError`` for an unknown profile."""
    return dict(copy.deepcopy(PROFILES[profile]))


def _without_ciphertexts(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            k: _without_ciphertexts(v)
            for k, v in value.items()
            if not (isinstance(k, str) and k.endswith(CIPHERTEXT_SUFFIX))
        }
    if isinstance(value, list):
        return [_without_ciphertexts(v) for v in value]
    return value


def copyable_settings(source: Mapping[str, Any]) -> Dict[str, Any]:
    """The policy part of another tenant's settings (see the module docstring); never secrets."""
    out: Dict[str, Any] = {}
    for key in COPIED_KEYS:
        if source.get(key) is not None:
            out[key] = copy.deepcopy(source[key])
    security = source.get("security")
    if isinstance(security, Mapping):
        policy_flags = {k: security[k] for k in COPIED_SECURITY_KEYS if isinstance(security.get(k), bool)}
        if policy_flags:
            out["security"] = policy_flags
    response = source.get("response")
    if isinstance(response, Mapping):
        policy = {k: copy.deepcopy(response[k]) for k in COPIED_RESPONSE_KEYS if response.get(k) is not None}
        if policy:
            out["response"] = policy
    tools = source.get("tools")
    if isinstance(tools, Mapping):
        enabled = {
            provider: {"enabled": entry["enabled"]}
            for provider, entry in tools.items()
            if provider != "internal_domains" and isinstance(entry, Mapping) and isinstance(entry.get("enabled"), bool)
        }
        if enabled:
            out["tools"] = enabled
    cleaned: Dict[str, Any] = _without_ciphertexts(out)
    return cleaned


class QuotaExceeded(Exception):
    """A tenant quota would be exceeded."""

    def __init__(self, quota: str, limit: int, used: int) -> None:
        super().__init__(f"{quota} quota reached ({used} of {limit})")
        self.quota = quota
        self.limit = limit
        self.used = used


def quotas_of(tenant: Tenant) -> Dict[str, Optional[int]]:
    return {
        "max_alerts_per_day": tenant.max_alerts_per_day,
        "max_sources": tenant.max_sources,
        "max_users": tenant.max_users,
    }


async def alert_quota_exceeded(repos: Repositories, tenant: Tenant) -> Optional[QuotaExceeded]:
    """The refusal when today's stored alerts already reached ``max_alerts_per_day``, else ``None``.

    A request that starts under the quota is accepted whole, so the day can
    end above it by at most the batches in flight at that moment.
    """
    limit = tenant.max_alerts_per_day
    if limit is None:
        return None
    used = await repos.usage.ingested_on(tenant.id)
    return QuotaExceeded("max_alerts_per_day", limit, used) if used >= limit else None


async def ensure_capacity(repos: Repositories, tenant_id: str, quota: str, *, conn: Connection) -> None:
    """Raise :class:`QuotaExceeded` when one more source/active user would pass the quota.

    Must run inside ``db.tenant_tx(tenant_id)`` together with the insert:
    the tenant row lock taken here serialises concurrent creations.
    """
    tenant = await repos.tenants.get(tenant_id, for_update=True, conn=conn)
    if quota == "max_sources":
        limit, count = tenant.max_sources, repos.sources.count
    elif quota == "max_users":
        limit, count = tenant.max_users, repos.users.count_active
    else:
        raise ValueError(f"unknown quota: {quota!r}")
    if limit is None:
        return
    used = await count(tenant_id, conn=conn)
    if used >= limit:
        raise QuotaExceeded(quota, limit, used)


@dataclass(frozen=True)
class TenantRequest:
    """A validated provisioning request; hashing and template resolution happen before it is built.

    ``audit_details`` is merged into every audit entry: the platform admin's
    ``home_tenant_id`` for the API, ``{"via": "cli"}`` for the CLI.
    ``admin_audit_details`` is added to the first admin's ``user.created``.
    """

    tenant_id: str
    name: str
    actor: Actor
    settings: Mapping[str, Any] = field(default_factory=dict)
    template: Mapping[str, Any] = field(default_factory=dict)
    copied_from: Optional[str] = None
    home_tenant_id: Optional[str] = None
    admin_email: Optional[str] = None
    admin_password_hash: Optional[str] = None
    audit_details: Mapping[str, Any] = field(default_factory=dict)
    admin_audit_details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProvisionedTenant:
    tenant: Tenant
    admin: Optional[User]
    settings_keys: List[str]


async def provision_tenant(repos: Repositories, audit: AuditLogger, request: TenantRequest) -> ProvisionedTenant:
    """Create the tenant, its seeded settings, its first admin and every audit entry in one transaction.

    Raises :class:`~lg_sotf.db.errors.Conflict` when the id exists (also when
    a concurrent request for the same id commits first). Any failure leaves
    nothing behind, so the request can be retried. Works for the runtime role:
    the row is inserted by ``lgsotf_create_tenant`` on this transaction, and
    the platform-level entries are written after :func:`switch_tenant` to the
    home tenant and the copied tenant.
    """
    keys = sorted(request.settings)
    who: Dict[str, Any] = {"actor_type": request.actor.type, "actor_id": request.actor.id}
    async with repos.db.tenant_tx(request.tenant_id) as conn:
        tenant = await repos.tenants.provision(request.tenant_id, request.name, conn=conn)
        if request.settings:
            tenant = await repos.tenants.update_settings(tenant.id, request.settings, conn=conn)
        details = {
            "name": tenant.name,
            "with_admin": request.admin_email is not None,
            **request.template,
            "settings_keys": keys,
            **request.audit_details,
        }
        await audit.record(tenant.id, "tenant.created", "tenant", tenant.id, **who, details=details, conn=conn)
        admin = await _first_admin(repos, audit, tenant.id, request, conn)
        if request.home_tenant_id is not None:
            await switch_tenant(conn, request.home_tenant_id)
            await audit.record(
                request.home_tenant_id, "platform.tenant_created", "tenant", tenant.id, **who, details=details, conn=conn
            )
        if request.copied_from is not None:
            # Reading another tenant's configuration is cross-tenant access: that tenant's log shows it.
            await switch_tenant(conn, request.copied_from)
            await audit.record(
                request.copied_from,
                "platform.settings_copied",
                "tenant",
                tenant.id,
                **who,
                details={"to_tenant": tenant.id, "keys": keys, **request.audit_details},
                conn=conn,
            )
    return ProvisionedTenant(tenant=tenant, admin=admin, settings_keys=keys)


async def _first_admin(
    repos: Repositories, audit: AuditLogger, tenant_id: str, request: TenantRequest, conn: Connection
) -> Optional[User]:
    if request.admin_email is None:
        return None
    user = await repos.users.create(
        tenant_id, request.admin_email, "admin", password_hash=request.admin_password_hash, conn=conn
    )
    await audit.record(
        tenant_id,
        "user.created",
        "user",
        str(user.id),
        actor_type=request.actor.type,
        actor_id=request.actor.id,
        details={
            "role": user.role,
            "sso_only": request.admin_password_hash is None,
            **request.audit_details,
            **request.admin_audit_details,
        },
        conn=conn,
    )
    return user


# ---------------------------------------------------------- platform administration


@dataclass(frozen=True)
class TenantChange:
    tenant: Tenant
    status_changed: bool


async def update_tenant(
    repos: Repositories,
    audit: AuditLogger,
    settings: Settings,
    tenant_id: str,
    actor: Actor,
    *,
    home_tenant_id: str,
    changes: Mapping[str, Any],
) -> TenantChange:
    """Rename, suspend or reactivate a tenant or set its quotas (``changes``: column values), in one transaction.

    Audited in the tenant (``tenant.suspended``, ``tenant.reactivated`` or
    ``tenant.updated``, with the changed values) and in the platform admin's
    home tenant (``platform.tenant_updated``). Reactivation restarts the SLA
    clock of the tenant's open escalations. Cache invalidation and requeueing
    the tenant's queued runs are the caller's, after the commit.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        before = await repos.tenants.get(tenant_id, for_update=True, conn=conn)
        updated = await repos.tenants.update_admin(tenant_id, **changes, conn=conn)
        diff = {k: {"from": getattr(before, k), "to": v} for k, v in changes.items() if getattr(before, k) != v}
        status_changed = before.status != updated.status
        action = (
            ("tenant.suspended" if updated.status == "suspended" else "tenant.reactivated")
            if status_changed
            else "tenant.updated"
        )
        extra: Dict[str, Any] = {}
        if status_changed and updated.is_active:
            extra["sla_deadlines_reset"] = await _reset_sla_deadlines(repos, settings, updated, conn)
        who: Dict[str, Any] = {"actor_type": actor.type, "actor_id": actor.id}
        details = {"home_tenant_id": home_tenant_id, "changes": diff}
        await audit.record(tenant_id, action, "tenant", tenant_id, **who, details={**details, **extra}, conn=conn)
        await switch_tenant(conn, home_tenant_id)
        await audit.record(
            home_tenant_id,
            "platform.tenant_updated",
            "tenant",
            tenant_id,
            **who,
            details={**details, "tenant_action": action},
            conn=conn,
        )
    return TenantChange(tenant=updated, status_changed=status_changed)


async def _reset_sla_deadlines(repos: Repositories, settings: Settings, tenant: Tenant, conn: Connection) -> int:
    """Restart the SLA clock of a reactivated tenant's open escalations (now + the level's SLA).

    The sweep skips suspended tenants, so without this every escalation whose
    deadline passed during the suspension would jump a level on the next
    sweep. Deadlines are only ever pushed out, never shortened.
    """
    policy = resolve_review_policy(tenant.settings, settings)
    now = datetime.now(UTC)
    deadlines: Dict[str, datetime] = {
        level: now + timedelta(minutes=policy.sla_minutes[level]) for level in ESCALATION_LEVELS
    }
    return await repos.escalations.extend_sla_deadlines(tenant.id, deadlines, conn=conn)


async def update_settings(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    build_patch: Callable[[Tenant], Dict[str, Any]],
) -> Tenant:
    """Merge the top-level settings patch that ``build_patch`` makes from the locked current tenant.

    The row is locked first: nested sections are merged from this snapshot,
    so two concurrent changes to different sub-keys cannot drop one another.
    ``build_patch`` validates and may raise, and then nothing changes.
    Audited ``tenant.settings_updated`` with the patched keys (never their
    values), plus the model-led closure tier when ``ai_closure`` changes;
    saving ``autonomy`` or ``response`` also marks the onboarding
    "autonomy reviewed" step. Cache invalidation is the caller's.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        tenant = await repos.tenants.get(tenant_id, for_update=True, conn=conn)
        patch = build_patch(tenant)
        updated = await repos.tenants.update_settings(tenant_id, patch, conn=conn)
        details: Dict[str, Any] = {"keys": sorted(patch)}
        if closure.SETTING in patch:
            details["ai_closure_tier"] = closure.autonomy_tier(updated.settings)
        await audit.record(
            tenant_id,
            "tenant.settings_updated",
            "tenant",
            tenant_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
        if AUTONOMY_REVIEW_KEYS & patch.keys():
            await repos.tenants.mark_onboarding(tenant_id, "autonomy_reviewed_at", conn=conn)
    return updated


async def record_platform_access(
    audit: AuditLogger, actor: Actor, home_tenant_id: str, action: str, resource_id: Optional[str], **details: Any
) -> None:
    """Audit a platform admin's cross-tenant read (``platform.*``) in their home tenant."""
    await audit.record_event(
        home_tenant_id,
        action,
        "tenant",
        resource_id,
        actor_type=actor.type,
        actor_id=actor.id,
        details={"home_tenant_id": home_tenant_id, **details},
    )


__all__ = [
    "AUTONOMY_REVIEW_KEYS",
    "COPIED_KEYS",
    "PROFILES",
    "Profile",
    "ProvisionedTenant",
    "QuotaExceeded",
    "TenantChange",
    "TenantRequest",
    "alert_quota_exceeded",
    "copyable_settings",
    "ensure_capacity",
    "profile_settings",
    "provision_tenant",
    "quotas_of",
    "record_platform_access",
    "update_settings",
    "update_tenant",
]
