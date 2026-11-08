"""Canned tool answers for evaluation items (tool-output injection).

A dataset item can carry ``tool_fixtures``: what the threat-intelligence
lookup and the tenant-history lookup answer for its indicators. The
evaluation engine then runs with two extra providers:

* :class:`FixtureIntelProvider` (``eval_intel``), an external provider that
  needs no credentials, so the item's public indicators become ReAct lookup
  candidates exactly as with a configured VirusTotal or AbuseIPDB key;
  indicators without a fixture answer ``not_found``;
* :class:`FixtureHistoryProvider`, which takes the place of the history
  provider: a fixture answers for its indicator, every other lookup goes to
  the real (database-backed) history provider.

Answers go through the real enrichment service (shareable-value checks,
per-tenant cache, compaction and redaction), the real ReAct loop and the
real prompt (``<tool_data>`` and the alert block's ``history``). Only the
evaluation harness builds these providers, and only for a dataset that has
fixtures; the product's providers never simulate data.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Iterable, Optional, Tuple

from lg_sotf.eval.dataset import EXTERNAL_FIXTURE_KINDS, Dataset, EvalItem, ToolFixture
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import normalize_indicator
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import (
    EnrichmentProvider,
    EnrichmentResult,
    EnrichmentService,
    HistoryProvider,
    LookupRequest,
)

FIXTURE_INTEL_PROVIDER = "eval_intel"
FixtureTable = Dict[Tuple[str, str], ToolFixture]


def fixture_tables(items: Iterable[EvalItem]) -> Tuple[FixtureTable, FixtureTable]:
    """``(threat_intel, history)`` answers keyed by ``(kind, normalised value)``."""
    intel: FixtureTable = {}
    history: FixtureTable = {}
    for item in items:
        if item.tool_fixtures is None:
            continue
        for tool, fixture in item.tool_fixtures.entries():
            (intel if tool == "threat_intel" else history)[fixture.key()] = fixture
    return intel, history


def _answer(provider: str, fixture: ToolFixture) -> EnrichmentResult:
    return EnrichmentResult.ok(provider, fixture.kind, fixture.verdict, fixture.data)


class FixtureIntelProvider:
    """A threat-intelligence provider that answers from the dataset's ``tool_fixtures.threat_intel``."""

    name = FIXTURE_INTEL_PROVIDER
    kinds: FrozenSet[str] = frozenset(EXTERNAL_FIXTURE_KINDS)
    external = True
    cache_ttl_s = 60.0

    def __init__(self, table: FixtureTable) -> None:
        self._table = dict(table)

    def requires_credentials(self) -> bool:
        return False

    async def aclose(self) -> None:
        return None

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        fixture = self._table.get((request.kind, normalize_indicator(request.kind, request.value)))
        if fixture is None:
            return EnrichmentResult(self.name, request.kind, "not_found", "unknown", {})
        return _answer(self.name, fixture)


class FixtureHistoryProvider:
    """The history provider with the dataset's ``tool_fixtures.history`` answers in front of it."""

    name = HistoryProvider.name
    external = False

    def __init__(self, table: FixtureTable, real: EnrichmentProvider) -> None:
        self._table = dict(table)
        self._real = real
        self.kinds: FrozenSet[str] = real.kinds
        self.cache_ttl_s = real.cache_ttl_s

    def requires_credentials(self) -> bool:
        return False

    async def aclose(self) -> None:
        await self._real.aclose()

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        fixture = self._table.get((request.kind, normalize_indicator(request.kind, request.value)))
        if fixture is None:
            return await self._real.lookup(request)
        return _answer(self.name, fixture)


def fixture_enrichment(
    settings: Settings, dataset: Dataset, *, secret_box: Optional[SecretBox] = None
) -> EnrichmentService:
    """The product's enrichment service with the dataset's fixture providers added."""
    real = EnrichmentService.from_settings(settings, secret_box=secret_box)
    intel, history = fixture_tables(dataset.items)
    providers = [
        FixtureHistoryProvider(history, real.provider(name)) if name == HistoryProvider.name else real.provider(name)
        for name in real.provider_names
    ]
    providers.append(FixtureIntelProvider(intel))
    return EnrichmentService(providers, settings, credentials=real.credentials)

