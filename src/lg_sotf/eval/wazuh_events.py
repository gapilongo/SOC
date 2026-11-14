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
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.eval.tool_fixtures import EventQuery, EventView, event_time, field_values
from lg_sotf.tools.wazuh import dsl

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
