"""A dataset's telemetry behind the Wazuh evidence tools: the offline backend (INT3.4).

:class:`EventStoreBackend` answers the search bodies of ``lg_sotf.tools.wazuh.templates`` from an
:class:`~lg_sotf.eval.tool_fixtures.EventView`, in the shape a Wazuh indexer (OpenSearch) answers them, so
the same tool code and the same mappers produce facts from the corpus telemetry. It understands exactly
what :func:`lg_sotf.tools.wazuh.dsl.check_search` allows and refuses anything else, like the indexer client.

Every read goes through the view: no document later than its as-of time is counted, listed or
aggregated, whatever window a query asks for. The store receives an event at its own time (no ingest
lag), and its answers are never partial.

``tests/live/wazuh/test_evidence_tools.py`` loads the same documents into a Wazuh 4.14 indexer and checks
that both backends give the same facts.

:class:`TelemetryBackends` resolves that backend for a workflow run, when the install's settings name the
event store as the evidence backend (:func:`telemetry_backends`).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.db.errors import NotFound
from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, EventView, event_time, field_values, load_documents
from lg_sotf.settings import Settings
from lg_sotf.tools.registry import ToolContext
from lg_sotf.tools.wazuh import dsl
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable

Doc = Mapping[str, Any]


def _instant(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _matches(doc: Doc, clause: Mapping[str, Any]) -> bool:
    ((kind, spec),) = clause.items()
    if kind == "bool":
        return all(_matches(doc, inner) for inner in spec["filter"])
    ((field, value),) = spec.items()
    if kind == "range":
        at = event_time(doc)
        return ("gte" not in value or at >= _instant(value["gte"])) and ("lte" not in value or at <= _instant(value["lte"]))
    if isinstance(value, Mapping):  # a name matched without case
        return value["value"].casefold() in {found.casefold() for found in field_values(doc, field)}
    wanted = set(value) if kind == "terms" else {value}
    return bool(wanted & set(field_values(doc, field)))


def _bounds(filters: Sequence[Mapping[str, Any]]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """The time range the query's own filters give (the view reads only that part of the store)."""
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    for clause in filters:
        bounds = clause.get("range", {}).get(dsl.TIME, {})
        if "gte" in bounds:
            start = max(start, _instant(bounds["gte"])) if start else _instant(bounds["gte"])
        if "lte" in bounds:
            end = min(end, _instant(bounds["lte"])) if end else _instant(bounds["lte"])
    return start, end


def _number(field: str, value: str) -> float:
    if field == dsl.TIME:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() * 1000
    return float(value)


def _aggregate(docs: Sequence[Doc], agg: Mapping[str, Any]) -> Dict[str, Any]:
    kind = next(key for key in agg if key != "aggs")
    spec = agg[kind]
    if kind == "filters":
        buckets: Dict[str, Any] = {}
        for name, clause in spec["filters"].items():
            inside = [doc for doc in docs if _matches(doc, clause)]
            inner = {sub: _aggregate(inside, sub_agg) for sub, sub_agg in agg.get("aggs", {}).items()}
            buckets[name] = {"doc_count": len(inside), **inner}
        return {"buckets": buckets}
    field = spec["field"]
    if kind == "terms":
        counts = Counter(value for doc in docs for value in set(field_values(doc, field)))
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        listed, rest = ordered[: spec["size"]], ordered[spec["size"] :]
        return {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum(n for _, n in rest),
            "buckets": [{"key": key, "doc_count": n} for key, n in listed],
        }
    found = [value for doc in docs for value in field_values(doc, field)]
    if kind == "cardinality":
        return {"value": len(set(found))}
    if kind == "value_count":
        return {"value": len(found)}
    numbers = [_number(field, value) for value in found]
    return {"value": (min(numbers) if kind == "min" else max(numbers)) if numbers else None}


def _sort_key(doc: Doc, field: str) -> Any:
    found = field_values(doc, field)
    if field == dsl.TIME:
        return event_time(doc)
    if field == dsl.RULE_LEVEL:
        return int(found[0]) if found else -1
    return found[0] if found else ""


def _project(doc: Doc, fields: Sequence[str]) -> Dict[str, Any]:
    """``doc`` with only ``fields`` (dotted paths), as ``_source`` filtering returns it."""
    out: Dict[str, Any] = {}
    for path in fields:
        node: Any = doc
        parts = path.split(".")
        for part in parts:
            node = node.get(part) if isinstance(node, Mapping) else None
        if node is None:
            continue
        target = out
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = node
    return out


_ID_SUFFIX = re.compile(r"-[0-9]{1,20}$")
MAX_SHIFTED_STORES = 8


class TelemetryBackends:
    """``await backends(ctx)``: a dataset's telemetry as the evidence backend of a run (evaluation and development).

    Chosen by configuration only (``investigation.evidence_backend: event_store``), never as a fallback, and
    never in staging or production: the documents are synthetic. The run's alert is read under the run's own
    tenant; the store answers as of the alert's own time, so nothing that happened after it is ever seen
    (the investigation does not wait for windows to close).

    The alert must be one of the dataset's documents: its source alert id is the document's ``id``, as it
    is, or followed by ``-<digits>`` (how the development sender marks a re-sent copy). An alert that was
    re-sent with its time moved gets the whole store moved by the same amount, so its context keeps its
    distance from it. An alert the dataset does not hold has no telemetry: the call fails with
    ``no_telemetry``, it never reads as "nothing found".

    The store is one dataset for the whole install. It holds no tenant's data; a tenant reads it only once
    it switched the evidence tools on.
    """

    def __init__(self, documents: Sequence[Doc]) -> None:
        self._documents = list(documents)
        self._times = {str(doc.get("id")): event_time(doc) for doc in self._documents if doc.get("id")}
        self._stores: Dict[timedelta, EventStore] = {timedelta(0): EventStore(self._documents)}

    @classmethod
    def load(cls, files: Sequence[str]) -> TelemetryBackends:
        return cls(load_documents(*files))

    def __len__(self) -> int:
        return len(self._documents)

    def _store(self, delta: timedelta) -> EventStore:
        store = self._stores.get(delta)
        if store is None:
            while len(self._stores) >= MAX_SHIFTED_STORES:
                self._stores.pop(next(key for key in self._stores if key))
            store = self._stores[delta] = EventStore(_moved(doc, delta) for doc in self._documents)
        return store

    async def __call__(self, ctx: ToolContext) -> EventStoreBackend:
        if ctx.repos is None:
            raise IndexerUnavailable("not_configured")
        try:
            alert = await ctx.repos.alerts.get(ctx.tenant_id, ctx.alert_id)
        except NotFound:
            raise IndexerUnavailable("no_telemetry") from None
        known = str(alert.source_alert_id)
        original = self._times.get(known) or self._times.get(_ID_SUFFIX.sub("", known))
        if original is None:
            raise IndexerUnavailable("no_telemetry")
        return EventStoreBackend(self._store(alert.occurred_at - original).as_of(alert.occurred_at))


def _moved(doc: Doc, delta: timedelta) -> Dict[str, Any]:
    """``doc`` with its time moved by ``delta`` (the fields a query filters on and reads back)."""
    at = (event_time(doc) + delta).astimezone(UTC)
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}"
    return {**doc, "timestamp": stamp + "+0000", "@timestamp": stamp + "Z"}


def telemetry_backends(settings: Settings) -> Optional[TelemetryBackends]:
    """The telemetry store ``settings`` ask for, or ``None`` when the evidence tools read the tenants' indexers.

    Built by a process's composition root (``lg-sotf worker``, ``lg-sotf eval``) and handed to the engine.
    """
    if settings.investigation.evidence_backend != "event_store":
        return None
    if settings.is_production:
        raise ValueError("investigation.evidence_backend=event_store is for evaluation and development only")
    return TelemetryBackends.load(settings.investigation.event_store_files)


class EventStoreBackend:
    """An :class:`EventView` as an evidence backend: what the indexer held at the view's as-of time."""

    lag = timedelta(0)

    def __init__(self, view: EventView) -> None:
        self._view = view

    def now(self) -> datetime:
        return self._view.as_of

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        dsl.check_search(body)
        filters: List[Mapping[str, Any]] = body["query"]["bool"]["filter"]
        start, end = _bounds(filters)
        docs: List[Doc] = [
            doc for doc in self._view.select(EventQuery(start=start, end=end)) if all(_matches(doc, c) for c in filters)
        ]
        ranked = docs
        for key in reversed(body.get("sort", [])):
            ((field, order),) = key.items()
            ranked = sorted(ranked, key=partial(_sort_key, field=field), reverse=order["order"] == "desc")
        source = body["_source"]
        hits = [{"_source": _project(doc, source)} if source else {} for doc in ranked[: body["size"]]]
        return {
            "timed_out": False,
            "terminated_early": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"hits": hits},
            "aggregations": {name: _aggregate(docs, agg) for name, agg in body.get("aggs", {}).items()},
        }
