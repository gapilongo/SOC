"""The tenant settings document (``tenants.settings``): its keys and typed readers (roadmap T5).

``PATCH /tenant/settings`` writes the :data:`EDITABLE_KEYS`, tenant templates
copy the :data:`COPIED_KEYS`, and every reader of the daily LLM token budget
goes through :func:`token_budget`, so the rule is declared once.

The sections (``response``, ``phishing``, ``review``, ...) keep their own
fail-closed parsing in the modules that own them; this module only names the
top-level keys. Nothing here validates a document at runtime: stored
settings written by an older release may hold other shapes.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple, TypedDict

__all__ = [
    "COPIED_KEYS",
    "EDITABLE_KEYS",
    "LLM_BUDGET_SETTING",
    "MAX_TOKEN_BUDGET",
    "TenantSettingsDoc",
    "as_token_budget",
    "token_budget",
    "token_budget_problem",
]


class TenantSettingsDoc(TypedDict, total=False):
    """The top-level keys of ``tenants.settings``."""

    # Response policy (lg_sotf.services.response.policy).
    response: Dict[str, Any]
    #: An object of asset lists, or a legacy list of names.
    protected_assets: Any
    protected_cidrs: List[str]
    autonomy: Dict[str, str]
    #: Daily LLM tokens for the tenant's runs; ``null`` (or absent) = the install default.
    llm_daily_token_budget: Optional[int]
    review: Dict[str, Any]
    #: Enrichment providers ({provider: {enabled, api_key_ciphertext}}) and ``internal_domains``.
    tools: Dict[str, Any]
    retention: Dict[str, Any]
    security: Dict[str, Any]
    reporting: Dict[str, Any]
    #: Blind audit sampling of auto-closed alerts (lg_sotf.services.blind_audit).
    blind_audit: Dict[str, Any]
    phishing: Dict[str, Any]
    #: Triage context (``known_scanners``; lg_sotf.domain.benign_evidence).
    triage: Dict[str, Any]
    #: Set when the tenant's data was erased (compliance.tenant_data); never editable.
    erased_at: str


LLM_BUDGET_SETTING = "llm_daily_token_budget"
MAX_TOKEN_BUDGET = 10_000_000_000

#: The keys ``PATCH /tenant/settings`` accepts.
EDITABLE_KEYS: FrozenSet[str] = frozenset(
    {
        "response",
        "protected_assets",
        "protected_cidrs",
        "autonomy",
        LLM_BUDGET_SETTING,
        "review",
        "tools",
        "retention",
        "security",
        "reporting",
        "blind_audit",
        "phishing",
        "triage",
    }
)

#: The policy keys a new tenant copies whole from another tenant (``copy_settings_from``).
#: Never "phishing": its brands, executives and mail servers identify the customer.
COPIED_KEYS: Tuple[str, ...] = (
    "autonomy", "review", LLM_BUDGET_SETTING, "retention", "reporting", "blind_audit",
)


def as_token_budget(value: object) -> Optional[int]:
    """A stored ``llm_daily_token_budget`` as the platform honours it: an ``int`` that is not a ``bool``, else ``None``."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def token_budget(doc: Optional[Mapping[str, Any]]) -> Optional[int]:
    """The tenant's daily LLM token budget; ``None`` means the install default."""
    return as_token_budget(doc.get(LLM_BUDGET_SETTING)) if isinstance(doc, Mapping) else None


def token_budget_problem(value: object) -> Optional[str]:
    """Why ``value`` cannot be stored as ``llm_daily_token_budget`` (``None`` when it can: null or 0..max)."""
    if value is None:
        return None
    budget = as_token_budget(value)
    if budget is None or not 0 <= budget <= MAX_TOKEN_BUDGET:
        return f"{LLM_BUDGET_SETTING}: must be an integer 0..{MAX_TOKEN_BUDGET} or null"
    return None
