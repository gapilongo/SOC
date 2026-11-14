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

:class:`EventStore` (AI-E1.10) holds the telemetry around a dataset's alerts
(the alerts themselves plus the context events of
``tests/fixtures/eval/corpus_v1_events.jsonl.gz``) and answers the questions
the Wazuh evidence templates ask the indexer: filter by agent, time range,
event id and field equality; counts, distinct counts, first and last time.
Every query runs *as of* a moment, so an investigation replayed on event time
never sees what happened after ``occurred_at + settle``.
"""

from __future__ import annotations

import bisect
import gzip
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

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


# ---------------------------------------------------------------------------------------------------------------------
# Event store: the telemetry the Wazuh evidence templates query (AI-E1.10)
# ---------------------------------------------------------------------------------------------------------------------

#: The Windows event id of a Wazuh document, the field the templates' ``event_ids`` filter reads.
EVENT_ID_FIELD = "data.win.system.eventID"
FieldMatch = Union[str, Sequence[str]]


def event_time(doc: Mapping[str, Any]) -> datetime:
    """The manager's ``timestamp`` of a Wazuh document (``2026-10-19T07:28:01.928+0000``)."""
    return datetime.strptime(str(doc["timestamp"]), "%Y-%m-%dT%H:%M:%S.%f%z")


def field_values(doc: Mapping[str, Any], path: str) -> List[str]:
    """The values at a dotted ``path``, as strings; a list field gives each element (an indexer ``term`` matches any)."""
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return []
        node = node[part]
    if node is None:
        return []
    items = node if isinstance(node, list) else [node]
    return [str(v) for v in items if v is not None and not isinstance(v, (dict, list))]


@dataclass(frozen=True)
class EventQuery:
    """One filter: every given condition must hold (``where`` maps a dotted field to one value or any of several)."""

    agent: Optional[str] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    event_ids: Tuple[str, ...] = ()
    rule_ids: Tuple[str, ...] = ()
    where: Mapping[str, FieldMatch] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for bound in (self.start, self.end):
            if bound is not None and bound.tzinfo is None:
                raise ValueError("query times must be timezone-aware")

    def matches(self, doc: Mapping[str, Any]) -> bool:
        if self.agent is not None and self.agent not in field_values(doc, "agent.name"):
            return False
        if self.event_ids and not set(self.event_ids) & set(field_values(doc, EVENT_ID_FIELD)):
            return False
        if self.rule_ids and not set(self.rule_ids) & set(field_values(doc, "rule.id")):
            return False
        for path, wanted in self.where.items():
            accepted = {wanted} if isinstance(wanted, str) else set(wanted)
            if not accepted & set(field_values(doc, path)):
                return False
        return True


class EventStore:
    """Wazuh documents in time order; read them through :meth:`as_of`, never directly."""

    def __init__(self, docs: Iterable[Mapping[str, Any]]) -> None:
        keyed = sorted(((event_time(d), str(d.get("id", "")), dict(d)) for d in docs), key=lambda e: (e[0], e[1]))
        self._times: List[datetime] = [t for t, _, _ in keyed]
        self._docs: List[Dict[str, Any]] = [d for _, _, d in keyed]

    @classmethod
    def load(cls, *paths: Union[str, Path]) -> EventStore:
        """Read ``.jsonl`` or ``.jsonl.gz`` files of Wazuh documents or dataset items (their ``alert``); ``_meta`` is skipped."""
        docs: List[Mapping[str, Any]] = []
        for path in paths:
            p = Path(path)
            raw = p.read_bytes()
            text = (gzip.decompress(raw) if p.suffix == ".gz" else raw).decode("utf-8")
            for line in text.splitlines():
                if not line.strip():
                    continue
                data = json.loads(line)
                if "_meta" in data:
                    continue
                docs.append(data["alert"] if "alert" in data and "rule" not in data else data)
        return cls(docs)

    def __len__(self) -> int:
        return len(self._docs)

    def as_of(self, when: datetime) -> EventView:
        """What the indexer held at ``when``: nothing later is ever returned."""
        if when.tzinfo is None:
            raise ValueError("the as-of time must be timezone-aware")
        return EventView(self, when)

    def window(self, start: Optional[datetime], end: datetime) -> List[Dict[str, Any]]:
        """Documents with ``start <= time <= end`` (no other filter); :class:`EventView` applies the as-of bound."""
        lo = 0 if start is None else bisect.bisect_left(self._times, start)
        hi = bisect.bisect_right(self._times, end)
        return self._docs[lo:hi]


class EventView:
    """An :class:`EventStore` as of one moment: the queries the evidence templates need."""

    def __init__(self, store: EventStore, as_of: datetime) -> None:
        self._store = store
        self.as_of = as_of

    def select(self, query: EventQuery, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Matching documents in time order (the first ``limit``), none after the as-of time."""
        end = self.as_of if query.end is None else min(query.end, self.as_of)
        if query.start is not None and query.start > end:
            return []
        found = [d for d in self._store.window(query.start, end) if query.matches(d)]
        return found if limit is None else found[: max(0, limit)]

    def count(self, query: EventQuery) -> int:
        return len(self.select(query))

    def distinct(self, query: EventQuery, path: str) -> List[str]:
        """The distinct values of ``path`` among the matches, sorted."""
        return sorted({v for d in self.select(query) for v in field_values(d, path)})

    def distinct_count(self, query: EventQuery, path: str) -> int:
        return len(self.distinct(query, path))

    def first_time(self, query: EventQuery) -> Optional[datetime]:
        found = self.select(query)
        return event_time(found[0]) if found else None

    def last_time(self, query: EventQuery) -> Optional[datetime]:
        found = self.select(query)
        return event_time(found[-1]) if found else None
