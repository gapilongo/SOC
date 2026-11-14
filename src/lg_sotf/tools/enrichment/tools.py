"""Today's lookups as registered tools (AI-E2.1): ``reputation.<provider>`` and ``platform.history``.

Each tool calls the enrichment service exactly as the analysis agent did before the registry, so its
checks stay where they were: the shareable-value rules and the tenant's internal domains, credentials
and consent, the per-tenant cache, rate limits, the lookup deadline, and the ``enrichment_lookup``
egress boundary, which answers a shadow run from the cache only. The registry adds the declaration,
parameter validation, the per-tenant switch, the time and row caps, and the trace step.

* ``reputation.<provider>``, one per external provider of the service (VirusTotal, AbuseIPDB, and the
  evaluation harness's ``eval_intel``): third-party egress, ``cache_only`` in shadow runs, switched off
  by ``tenants.settings.tools.<provider>.enabled: false``. The analysis agent runs them as the
  ``reputation`` family, one trace step per lookup, as before.
* ``platform.history``: the tenant's own earlier alerts, a database read under the tenant's RLS. It is
  traced as ``history`` (the name recorded cassettes use) and has no tenant switch, as before.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.tools.enrichment.base import EnrichmentResult, IndicatorKind
from lg_sotf.tools.enrichment.history import MAX_HISTORY_ALERTS, HistoryProvider
from lg_sotf.tools.enrichment.service import EnrichmentService
from lg_sotf.tools.registry import MAX_TIME_CAP_S, Tool, ToolContext, ToolDisabled, ToolError, ToolRegistry, ToolSpec

__all__ = ["HISTORY_TOOL", "REPUTATION_FAMILY", "HistoryParams", "ReputationParams", "enrichment_tools"]

REPUTATION_FAMILY = "reputation"
HISTORY_TOOL = "platform.history"
LOOKUP_EGRESS_BOUNDARY = "enrichment_lookup"
MAX_VALUE_CHARS = 1_024
"""Indicator values are at most 512 characters (``lg_sotf.domain.indicators``); a reduced URL may add a ``/``."""
TIME_CAP_GRACE_S = 5.0
"""Above the service's own lookup deadline, which answers first: the cap only stops a hung call."""


class ReputationParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["ip", "domain", "url", "hash"]
    value: str = Field(min_length=1, max_length=MAX_VALUE_CHARS)


class HistoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: IndicatorKind
    value: str = Field(min_length=1, max_length=MAX_VALUE_CHARS)


def _refused(provider: str) -> Any:
    def answer(params: Any, error: ToolError) -> EnrichmentResult:
        if isinstance(error, ToolDisabled):
            return EnrichmentResult.failed(provider, params.kind, "not_configured")
        return EnrichmentResult.failed(provider, params.kind, "error", "lookup timed out")

    return answer


def _restore(params: Any, recorded: Any) -> EnrichmentResult:
    return EnrichmentResult.from_dict(params.kind, recorded)


def _reputation(service: EnrichmentService, provider: str, time_cap_s: float) -> Tool:
    async def run(ctx: ToolContext, params: Any) -> EnrichmentResult:
        return await service.lookup_one(
            provider, ctx.tenant_id, params.kind, params.value, repos=ctx.repos, exclude_alert_id=ctx.alert_id
        )

    spec = ToolSpec(
        name=f"{REPUTATION_FAMILY}.{provider}",
        version=1,
        risk="read_external",
        params=ReputationParams,
        produces=frozenset({"reputation"}),
        row_cap=1,
        time_cap_s=time_cap_s,
        window_cap=None,
        egress="third_party",
        shadow="cache_only",
        tenant_setting=provider,
        egress_boundary=LOOKUP_EGRESS_BOUNDARY,
    )
    return Tool(spec, run, EnrichmentResult.as_dict, _restore, _refused(provider))


def _history(service: EnrichmentService, time_cap_s: float) -> Tool:
    async def run(ctx: ToolContext, params: Any) -> EnrichmentResult:
        return await service.history(
            ctx.tenant_id, params.kind, params.value, repos=ctx.repos, exclude_alert_id=ctx.alert_id
        )

    spec = ToolSpec(
        name=HISTORY_TOOL,
        version=1,
        risk="read_internal",
        params=HistoryParams,
        produces=frozenset({"related_alert"}),
        row_cap=MAX_HISTORY_ALERTS,  # HistoryProvider reads at most this many earlier alerts
        time_cap_s=time_cap_s,
        window_cap=timedelta(days=365),  # HistoryProvider's longest look-back
        egress="platform",
        shadow="live",
        tenant_setting=None,
        trace_name="history",
    )
    return Tool(spec, run, EnrichmentResult.as_dict, _restore, _refused(HistoryProvider.name))


def enrichment_tools(service: EnrichmentService) -> ToolRegistry:
    """A registry with the service's lookups; the tenant switch reads the service's cached tenant settings."""

    async def tenant_tools(tenant_id: str, repos: Any) -> Any:
        return (await service.credentials.tenant_tools(tenant_id, repos)).tools

    registry = ToolRegistry(tenant_tools)
    time_cap_s = min(MAX_TIME_CAP_S, service.lookup_timeout_s + TIME_CAP_GRACE_S)
    for name in service.provider_names:
        provider = service.provider(name)
        if provider.external:
            registry.register(_reputation(service, name, time_cap_s))
        elif name == HistoryProvider.name:
            registry.register(_history(service, time_cap_s))
    return registry
