"""What an evidence query may contain: the one shape every search body has, and the check that holds it (INT3.4).

A template (:mod:`lg_sotf.tools.wazuh.templates`) builds a body with :func:`search` and the clause helpers
below. :func:`check_search` walks a body before it is run, in the indexer client and in the offline event
store alike, and refuses anything else, so a query that is not on this page is never sent:

* a body has only ``size`` (at most :data:`MAX_HITS`), the fixed ``timeout``, ``terminate_after`` and
  ``track_total_hits: false``, ``_source`` (``false`` or allow-listed fields), ``sort`` on allow-listed
  fields, ``query`` and ``aggs``;
* the query is ``bool`` / ``filter`` over ``term``, ``terms`` and ``range`` clauses. ``range`` is on the
  alert time only. There is no ``should``, ``must_not``, ``script``, ``query_string``, ``wildcard``,
  ``regexp``, ``prefix``, ``fuzzy`` or ``match``: a value is compared whole, so ``*`` or a quote in it is a
  character like any other. A ``term`` on one of the :data:`NAMES` fields (a Windows user or host name,
  which Windows compares without case and logs as the client typed it) may ask for ``case_insensitive``;
  no other option exists;
* an aggregation is ``terms`` (at most :data:`MAX_BUCKETS` buckets), ``cardinality``, ``min``, ``max``,
  ``value_count`` or ``filters`` over the same clauses;
* every field is in :data:`FIELDS`, and every value is a string (the keys and the structure never come
  from a parameter).

The index is not part of a body: the client sends every search to the tenant's configured index pattern.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

Clause = Dict[str, Any]

TIME = "timestamp"
DOC_ID = "id"
AGENT = "agent.name"
RULE_ID = "rule.id"
RULE_LEVEL = "rule.level"
RULE_GROUPS = "rule.groups"
TECHNIQUES = "rule.mitre.id"
DECODER = "decoder.name"
SSH_SOURCE = "data.srcip"
SSH_USER = "data.dstuser"
FILE_SHA256 = "syscheck.sha256_after"
EVENT_ID = "data.win.system.eventID"
PROVIDER = "data.win.system.providerName"
_ED = "data.win.eventdata."
TARGET_USER = _ED + "targetUserName"
SOURCE_IP = _ED + "ipAddress"
WORKSTATION = _ED + "workstationName"
CALLER = _ED + "callerComputerName"
LOGON_TYPE = _ED + "logonType"
SUB_STATUS = _ED + "subStatus"
PROCESS_USER = _ED + "user"
IMAGE = _ED + "image"
COMMAND_LINE = _ED + "commandLine"
PROCESS_GUID = _ED + "processGuid"
PROCESS_ID = _ED + "processId"
PARENT_GUID = _ED + "parentProcessGuid"
PARENT_ID = _ED + "parentProcessId"
PARENT_IMAGE = _ED + "parentImage"
PARENT_COMMAND_LINE = _ED + "parentCommandLine"
PARENT_USER = _ED + "parentUser"
SERVICE_IMAGE_PATH = _ED + "imagePath"
SERVICE_NAME = _ED + "serviceName"

FIELDS: FrozenSet[str] = frozenset({
    TIME, DOC_ID, AGENT, RULE_ID, RULE_LEVEL, RULE_GROUPS, TECHNIQUES, DECODER, SSH_SOURCE, SSH_USER, FILE_SHA256,
    EVENT_ID, PROVIDER, TARGET_USER, SOURCE_IP, WORKSTATION, CALLER, LOGON_TYPE, SUB_STATUS, PROCESS_USER, IMAGE,
    COMMAND_LINE, PROCESS_GUID, PROCESS_ID, PARENT_GUID, PARENT_ID, PARENT_IMAGE, PARENT_COMMAND_LINE, PARENT_USER,
    SERVICE_IMAGE_PATH, SERVICE_NAME,
})
"""Every field a query may filter, sort, aggregate on or read back. Nothing else leaves the indexer."""
NAMES: FrozenSet[str] = frozenset({TARGET_USER, WORKSTATION, CALLER, AGENT})
"""Fields a ``term`` may match without case: ``Administrator`` and ``ADMINISTRATOR`` are one account."""

MAX_HITS = 50
MAX_BUCKETS = 50
MAX_TERMS = 64
MAX_VALUE_CHARS = 1_024
MAX_FILTER_BUCKETS = 8
TIMEOUT = "5s"
TERMINATE_AFTER = 100_000
"""Documents one shard reads for a search; a search that stops there answers ``terminated_early``."""
PRECISION = 1_000
"""Distinct counts are exact up to here (``precision_threshold``)."""

_REQUIRED = frozenset({"size", "timeout", "terminate_after", "track_total_hits", "_source", "query"})
_OPTIONAL = frozenset({"sort", "aggs"})
_METRICS = frozenset({"min", "max", "value_count"})
_NAME = re.compile(r"^[a-z][a-z_]{0,31}$")
_INSTANT = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


class QueryNotAllowed(Exception):
    """A search body is not one the templates may send. The message names the part, never a value."""


def instant(when: datetime) -> str:
    utc = when.astimezone(UTC)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond // 1000:03d}Z"


def term(field: str, value: str) -> Clause:
    return {"term": {field: value}}


def named(field: str, value: str) -> Clause:
    """A user or host name, whatever case it was typed in (``field`` must be one of :data:`NAMES`)."""
    return {"term": {field: {"value": value, "case_insensitive": True}}}


def terms(field: str, values: Sequence[str]) -> Clause:
    return {"terms": {field: list(values)}}


def between(start: datetime, end: datetime) -> Clause:
    """Alerts raised from ``start`` to ``end``, both included."""
    return {"range": {TIME: {"gte": instant(start), "lte": instant(end)}}}


def all_of(*clauses: Clause) -> Clause:
    return {"bool": {"filter": list(clauses)}}


def search(
    filters: Sequence[Clause],
    *,
    size: int = 0,
    source: Sequence[str] = (),
    sort: Sequence[Tuple[str, str]] = (),
    aggs: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """A search body: the caps are fixed here, so no template can leave one out."""
    body: Dict[str, Any] = {
        "size": size,
        "timeout": TIMEOUT,
        "terminate_after": TERMINATE_AFTER,
        "track_total_hits": False,
        "_source": list(source) if source else False,
        "query": all_of(*filters),
    }
    if sort:
        body["sort"] = [{field: {"order": order}} for field, order in sort]
    if aggs:
        body["aggs"] = dict(aggs)
    return body


def _refuse(part: str) -> QueryNotAllowed:
    return QueryNotAllowed(f"evidence query refused: {part}")


def _value(value: Any) -> bool:
    return type(value) is str and len(value) <= MAX_VALUE_CHARS


def _field(field: Any) -> bool:
    return type(field) is str and field in FIELDS


def _clause(clause: Any, depth: int = 0) -> None:
    if type(clause) is not dict or len(clause) != 1:
        raise _refuse("clause")
    ((kind, spec),) = clause.items()
    if kind == "bool":
        if depth or type(spec) is not dict or set(spec) != {"filter"} or type(spec["filter"]) is not list:
            raise _refuse("clause")
        for inner in spec["filter"]:
            _clause(inner, depth + 1)
        return
    if kind not in ("term", "terms", "range") or type(spec) is not dict or len(spec) != 1:
        raise _refuse("clause")
    ((field, value),) = spec.items()
    if kind == "range":
        bounds = value if type(value) is dict else {}
        if field != TIME or not bounds or not set(bounds) <= {"gte", "lte"}:
            raise _refuse("range")
        if not all(type(bound) is str and _INSTANT.fullmatch(bound) for bound in bounds.values()):
            raise _refuse("range")
        return
    if not _field(field):
        raise _refuse("field")
    if kind == "term" and type(value) is dict:  # the one option: a name matched without case
        if field not in NAMES or set(value) != {"value", "case_insensitive"} or value["case_insensitive"] is not True:
            raise _refuse("value")
        value = value["value"]
    if kind == "terms" and type(value) is not list:
        raise _refuse("value")
    values: List[Any] = value if kind == "terms" else [value]
    if not 1 <= len(values) <= MAX_TERMS or not all(_value(v) for v in values):
        raise _refuse("value")


def _aggregation(name: Any, agg: Any, *, nested: bool = False) -> None:
    if type(name) is not str or not _NAME.fullmatch(name) or type(agg) is not dict:
        raise _refuse("aggregation")
    kinds = set(agg) - {"aggs"}
    kind = next(iter(kinds)) if len(kinds) == 1 else ""
    spec = agg.get(kind)
    if type(spec) is not dict:
        raise _refuse("aggregation")
    if kind == "filters" and not nested:
        buckets = spec.get("filters")
        if set(spec) != {"filters"} or type(buckets) is not dict or not 1 <= len(buckets) <= MAX_FILTER_BUCKETS:
            raise _refuse("aggregation")
        for bucket, clause in buckets.items():
            if type(bucket) is not str or not _NAME.fullmatch(bucket):
                raise _refuse("aggregation")
            _clause(clause)
        inner = agg.get("aggs", {})
        if type(inner) is not dict:
            raise _refuse("aggregation")
        for inner_name, inner_agg in inner.items():
            _aggregation(inner_name, inner_agg, nested=True)
        return
    allowed = {
        "terms": {"field", "size"},
        "cardinality": {"field", "precision_threshold"},
        **{metric: {"field"} for metric in _METRICS},
    }.get(kind)
    if allowed is None or "aggs" in agg or set(spec) != allowed or not _field(spec["field"]):
        raise _refuse("aggregation")
    if kind == "terms" and (type(spec["size"]) is not int or not 1 <= spec["size"] <= MAX_BUCKETS):
        raise _refuse("aggregation")
    if kind == "cardinality" and spec["precision_threshold"] != PRECISION:
        raise _refuse("aggregation")


def check_search(body: Any) -> None:
    """Raise :class:`QueryNotAllowed` unless ``body`` is a search the templates may send (see the module docs)."""
    if type(body) is not dict or not _REQUIRED <= set(body) <= _REQUIRED | _OPTIONAL:
        raise _refuse("search")
    size, source = body["size"], body["_source"]
    if type(size) is not int or not 0 <= size <= MAX_HITS:
        raise _refuse("size")
    if body["timeout"] != TIMEOUT or body["terminate_after"] != TERMINATE_AFTER or body["track_total_hits"] is not False:
        raise _refuse("caps")
    if source is not False and (type(source) is not list or not source or not all(_field(f) for f in source)):
        raise _refuse("field")
    query = body["query"]
    if type(query) is not dict or set(query) != {"bool"}:
        raise _refuse("query")
    _clause(query)
    sort = body.get("sort", [])
    if type(sort) is not list:
        raise _refuse("sort")
    for key in sort:
        if type(key) is not dict or len(key) != 1:
            raise _refuse("sort")
        ((field, order),) = key.items()
        if not _field(field) or order not in ({"order": "asc"}, {"order": "desc"}):
            raise _refuse("sort")
    aggs = body.get("aggs", {})
    if type(aggs) is not dict:
        raise _refuse("aggregation")
    for name, agg in aggs.items():
        _aggregation(name, agg)
