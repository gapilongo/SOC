"""Tenant lifecycle for MSSPs: settings templates, quotas and their enforcement.

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
from typing import Any, Dict, Literal, Mapping, Optional

from lg_sotf.db.repos import Repositories, Tenant
from lg_sotf.db.repos._base import Connection

Profile = Literal["conservative", "balanced", "autonomous"]

PROFILES: Dict[str, Dict[str, Any]] = {
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

# Never "phishing": its brands, executives and mail servers identify the customer.
COPIED_KEYS = ("autonomy", "review", "llm_daily_token_budget", "retention", "reporting")
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
    return copy.deepcopy(PROFILES[profile])


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
        limit = tenant.max_sources
        sql = "SELECT count(*) FROM sources WHERE tenant_id = $1"
    elif quota == "max_users":
        limit = tenant.max_users
        sql = "SELECT count(*) FROM users WHERE tenant_id = $1 AND is_active"
    else:
        raise ValueError(f"unknown quota: {quota!r}")
    if limit is None:
        return
    used = int(await conn.fetchval(sql, tenant_id))
    if used >= limit:
        raise QuotaExceeded(quota, limit, used)


__all__ = [
    "COPIED_KEYS",
    "PROFILES",
    "Profile",
    "QuotaExceeded",
    "alert_quota_exceeded",
    "copyable_settings",
    "ensure_capacity",
    "profile_settings",
    "quotas_of",
]
