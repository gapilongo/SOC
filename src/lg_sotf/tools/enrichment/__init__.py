"""Indicator enrichment: provider interface, VirusTotal, AbuseIPDB, internal history, and the service.

Nothing here simulates intelligence: a provider without credentials answers
``not_configured``.
"""

from lg_sotf.tools.enrichment.base import (
    EnrichmentProvider,
    EnrichmentResult,
    LookupRequest,
    ProviderCredentials,
    compact,
)
from lg_sotf.tools.enrichment.history import HistoryProvider, confirmed_outcome
from lg_sotf.tools.enrichment.http import JsonHttpClient
from lg_sotf.tools.enrichment.providers import (
    AbuseIPDBProvider,
    VirusTotalProvider,
    normal_hash,
    public_domain,
    public_ip,
    public_url,
    secret_like_segment,
)
from lg_sotf.tools.enrichment.service import (
    CredentialResolver,
    EnrichmentService,
    RateLimiter,
    TenantTTLCache,
    encrypt_tool_secret,
    is_internal_domain,
    limit_scope,
    tool_secret_context,
)

__all__ = [
    "AbuseIPDBProvider",
    "CredentialResolver",
    "EnrichmentProvider",
    "EnrichmentResult",
    "EnrichmentService",
    "HistoryProvider",
    "JsonHttpClient",
    "LookupRequest",
    "ProviderCredentials",
    "RateLimiter",
    "TenantTTLCache",
    "VirusTotalProvider",
    "compact",
    "confirmed_outcome",
    "encrypt_tool_secret",
    "is_internal_domain",
    "limit_scope",
    "normal_hash",
    "public_domain",
    "public_ip",
    "public_url",
    "secret_like_segment",
    "tool_secret_context",
]
