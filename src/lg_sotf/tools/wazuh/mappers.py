"""From a search response to the typed value of a fact (INT3.4, ADR 0014 section 3.3).

Rows never leave this module: a mapper reads the allow-listed fields of a response and returns the typed
value of one evidence fact (:mod:`lg_sotf.models.evidence_fact`, schema 1.1), with

* ``whole``: false when something the value lists was cut (more alerts than the 50 returned, more
  buckets than the 50 listed, a distinct count above the exact range, an event that could not be read);
* ``redactions``: where a command line was masked (a secret) or cut to the schema's length.

Every string a fact holds is one the indexer returned, so one an attacker may have chosen: it is cut to
the schema's bound and never interpreted. A response that is not a search response raises
:class:`Malformed`, which the tool reports as a failed call, never as "nothing found".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Generic, List, Mapping, Optional, Sequence, Tuple, TypeVar

from lg_sotf.models.evidence_fact import (
    MAX_COMMAND_LINE_CHARS,
    MAX_LIST_ITEMS,
    MAX_NAME_CHARS,
    MAX_RULE_LEVEL,
    MAX_TEXT_CHARS,
    MAX_TOKEN_CHARS,
    GroupCount,
    HostActivityValue,
    HostEvent,
    LogonFanoutValue,
    PrevalenceValue,
    ProcessLineageValue,
    ProcessNode,
    Redaction,
)
from lg_sotf.security.redaction import redact_text
from lg_sotf.tools.wazuh import dsl
from lg_sotf.tools.wazuh.templates import LogonFanoutParams

V = TypeVar("V")
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_NUMBER = re.compile(r"(?<![\w.])\d+(?![\w.])")


class Malformed(Exception):
    """The indexer's answer is not a search response."""


@dataclass(frozen=True)
class Answer:
    """One search response: the hits' sources, the aggregations, and whether the indexer finished the search."""

    hits: Tuple[Mapping[str, Any], ...]
    aggs: Mapping[str, Any]
    partial: bool
    """It timed out, stopped at ``terminate_after`` or a shard failed: what it shows is a lower bound."""


@dataclass(frozen=True)
class Mapped(Generic[V]):
    value: V
    whole: bool
    redactions: Tuple[Redaction, ...] = ()


def read(response: Any) -> Answer:
    if not isinstance(response, Mapping):
        raise Malformed("not a search response")
    outer, shards = response.get("hits"), response.get("_shards")
    hits = outer.get("hits") if isinstance(outer, Mapping) else None
    if not isinstance(hits, list) or not isinstance(shards, Mapping):
        raise Malformed("not a search response")
    sources = tuple(hit["_source"] for hit in hits if isinstance(hit, Mapping) and isinstance(hit.get("_source"), Mapping))
    aggs = response.get("aggregations")
    partial = bool(response.get("timed_out") or response.get("terminated_early") or shards.get("failed"))
    return Answer(sources, aggs if isinstance(aggs, Mapping) else {}, partial or len(sources) != len(hits))


# ---- reading a document and an aggregation ---------------------------------------------------------------


def values(doc: Mapping[str, Any], path: str) -> List[str]:
    """The values at a dotted ``path`` as text (a list field gives each element; an object is not a value)."""
    node: Any = doc
    for part in path.split("."):
        node = node.get(part) if isinstance(node, Mapping) else None
    items = node if isinstance(node, list) else [node]
    return [str(item) for item in items if item is not None and not isinstance(item, (Mapping, list))]


def first(doc: Mapping[str, Any], path: str) -> Optional[str]:
    """The value at ``path``, with the Wazuh 4.x doubled backslashes of Windows event data undone."""
    found = values(doc, path)
    return found[0].replace("\\\\", "\\") if found and found[0] else None


def clip(text: Optional[str], limit: int) -> Optional[str]:
    return text[:limit] if text else None


def when(text: Optional[str]) -> Optional[datetime]:
    """An alert's ``timestamp`` (``2026-10-19T07:28:01.928+0000``); ``None`` when it is not an aware time."""
    try:
        parsed = datetime.fromisoformat(text) if text else None
    except ValueError:
        return None
    return parsed if parsed is not None and parsed.tzinfo is not None else None


def _number(aggs: Mapping[str, Any], name: str) -> Optional[float]:
    agg = aggs.get(name)
    value = agg.get("value") if isinstance(agg, Mapping) else None
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def count(aggs: Mapping[str, Any], name: str) -> int:
    """A count the search must carry; its absence means the answer is not the one asked for."""
    value = _number(aggs, name)
    if value is None or value < 0:
        raise Malformed("an aggregation is missing")
    return int(value)


def instant(aggs: Mapping[str, Any], name: str) -> Optional[datetime]:
    """A ``min`` or ``max`` over the alert time (epoch milliseconds), ``None`` when nothing matched."""
    millis = _number(aggs, name)
    return None if millis is None else datetime.fromtimestamp(millis / 1000, UTC)


def buckets(aggs: Mapping[str, Any], name: str) -> Tuple[List[Tuple[str, int]], bool]:
    """``(key, count)`` of a ``terms`` aggregation, and whether it lists every value (nothing under "other")."""
    agg = aggs.get(name)
    if not isinstance(agg, Mapping) or not isinstance(agg.get("buckets"), list):
        return [], True
    rows = agg["buckets"]
    found = [(str(row["key"]), int(row.get("doc_count", 0))) for row in rows if isinstance(row, Mapping) and "key" in row]
    return found[:MAX_LIST_ITEMS], not agg.get("sum_other_doc_count") and len(found) <= MAX_LIST_ITEMS


def _keys(aggs: Mapping[str, Any], name: str, limit: int = MAX_TEXT_CHARS) -> Tuple[List[str], bool]:
    rows, whole = buckets(aggs, name)
    return [key[:limit] for key, _ in rows if key], whole


def image_name(path: Optional[str]) -> Optional[str]:
    return clip(path.replace("/", "\\").rsplit("\\", 1)[-1], MAX_NAME_CHARS) if path else None


def command_template(command: str) -> Optional[str]:
    """A command line in lower case with single spaces and its bare numbers as ``<n>``.

    The recipe the corpus's routine-command lists are written in; AI-E4.2 replaces it with the shared
    ``lg_sotf.domain.patterns.command_template`` when that lands.
    """
    return _NUMBER.sub("<n>", " ".join(command.lower().split())) or None


def _command(raw: Optional[str], path: str, notes: List[Redaction]) -> Optional[str]:
    """A command line as a fact may hold it: secrets masked, cut to the schema's length, both noted at ``path``."""
    if not raw:
        return None
    text, masked = redact_text(raw)
    if masked:
        notes.append(Redaction(path=path, reason="secret"))
    if len(text) > MAX_COMMAND_LINE_CHARS:
        notes.append(Redaction(path=path, reason="truncated"))
    return text[:MAX_COMMAND_LINE_CHARS]


def _noted(notes: List[Redaction]) -> Tuple[Redaction, ...]:
    return tuple(notes[:MAX_LIST_ITEMS])


# ---- host activity ------------------------------------------------------------------------------------------


def _level(doc: Mapping[str, Any]) -> Optional[int]:
    level = first(doc, dsl.RULE_LEVEL)
    return int(level) if level and level.isdigit() and int(level) <= MAX_RULE_LEVEL else None


def _host_event(doc: Mapping[str, Any], path: str, notes: List[Redaction]) -> Optional[HostEvent]:
    at = when(first(doc, dsl.TIME))
    if at is None:
        return None
    line = _command(first(doc, dsl.COMMAND_LINE), f"{path}/command_template", notes)
    return HostEvent(
        at=at,
        rule_id=clip(first(doc, dsl.RULE_ID), MAX_TOKEN_CHARS),
        level=_level(doc),
        groups=[group[:MAX_TOKEN_CHARS] for group in values(doc, dsl.RULE_GROUPS) if group][:MAX_LIST_ITEMS],
        event_id=clip(first(doc, dsl.EVENT_ID), MAX_TOKEN_CHARS),
        user=clip(first(doc, dsl.PROCESS_USER) or first(doc, dsl.TARGET_USER), MAX_TEXT_CHARS),
        image_name=image_name(first(doc, dsl.IMAGE)),
        command_template=command_template(line) if line else None,
    )


def host_activity(answer: Answer, start: datetime, end: datetime) -> Optional[Mapped[HostActivityValue]]:
    """``None`` when the host raised nothing in the window."""
    total = count(answer.aggs, "total")
    if not total and not answer.hits:
        return None
    notes: List[Redaction] = []
    events: List[HostEvent] = []
    for doc in answer.hits[:MAX_LIST_ITEMS]:
        event = _host_event(doc, f"/value/events/{len(events)}", notes)
        if event is not None:
            events.append(event)
    groups, all_groups = buckets(answer.aggs, "groups")
    techniques, all_techniques = _keys(answer.aggs, "techniques")
    level = _number(answer.aggs, "max_level")
    value = HostActivityValue(
        window_start=start,
        window_end=end,
        total=max(total, len(events)),
        max_level=int(level) if level is not None and 0 <= level <= MAX_RULE_LEVEL else None,
        by_group=[GroupCount(group=group[:MAX_TOKEN_CHARS], count=n) for group, n in groups if group],
        techniques=[t for t in techniques if _TECHNIQUE.fullmatch(t)],
        events=events,
    )
    return Mapped(value, all_groups and all_techniques and total == len(events), _noted(notes))


# ---- logon fan-out ------------------------------------------------------------------------------------------


def _outcome(aggs: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    outcomes = aggs.get("outcomes")
    found = outcomes.get("buckets", {}).get(name) if isinstance(outcomes, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def first_failure_and_success(answer: Answer) -> Tuple[Optional[datetime], Optional[datetime]]:
    return instant(_outcome(answer.aggs, "failure"), "first"), instant(_outcome(answer.aggs, "success"), "first")


def logon_fanout(
    params: LogonFanoutParams,
    answer: Answer,
    *,
    start: datetime,
    end: datetime,
    lockouts: Optional[int],
    success_after_failure: Optional[datetime],
) -> Optional[Mapped[LogonFanoutValue]]:
    """``None`` when no logon matched. ``lockouts`` is the count read apart, when the pivot needed it."""
    aggs = answer.aggs
    doc_count = {name: int(_outcome(aggs, name).get("doc_count", 0)) for name in ("failure", "success", "lockout", "unknown_user")}
    locked = doc_count["lockout"] if lockouts is None else lockouts
    if not doc_count["failure"] + doc_count["success"] + locked:
        return None
    failed_users, all_failed = _keys(_outcome(aggs, "failure"), "users")
    success_users, all_successes = _keys(_outcome(aggs, "success"), "users")
    sources, all_sources = _keys(aggs, "source_list")
    source_hosts, all_source_hosts = _keys(aggs, "source_hosts")
    logon_types, all_types = _keys(aggs, "logon_types", MAX_TOKEN_CHARS)
    distinct = {name: count(aggs, name) for name in ("users", "sources", "hosts")}
    first_failure, _ = first_failure_and_success(answer)
    after: Optional[int] = None
    if first_failure is not None and success_after_failure is not None and success_after_failure >= first_failure:
        after = int((success_after_failure - first_failure).total_seconds())
    value = LogonFanoutValue(
        pivot=params.pivot,
        family=params.family,
        window_start=start,
        window_end=end,
        failures=doc_count["failure"],
        successes=doc_count["success"],
        lockouts=locked,
        unknown_user_failures=doc_count["unknown_user"],
        distinct_target_users=distinct["users"],
        distinct_sources=distinct["sources"],
        distinct_target_hosts=distinct["hosts"],
        first_success_after_failure_s=after,
        success_users=success_users,
        failed_users=failed_users,
        sources=sources,
        source_hosts=source_hosts,
        logon_types=logon_types,
    )
    whole = all_failed and all_successes and all_sources and all_source_hosts and all_types
    return Mapped(value, whole and max(distinct.values()) <= dsl.PRECISION)


# ---- process lineage ----------------------------------------------------------------------------------------


def guid(doc: Mapping[str, Any]) -> Optional[str]:
    return first(doc, dsl.PROCESS_GUID)


def parent_guid(doc: Mapping[str, Any]) -> Optional[str]:
    return first(doc, dsl.PARENT_GUID)


def _node(
    doc: Mapping[str, Any], path: str, notes: List[Redaction], *, parent: bool = False
) -> Optional[ProcessNode]:
    """The process a creation event is about, or (``parent``) the process that event names as its parent."""
    image, line, user, pid, process_guid = (
        (dsl.PARENT_IMAGE, dsl.PARENT_COMMAND_LINE, dsl.PARENT_USER, dsl.PARENT_ID, dsl.PARENT_GUID)
        if parent
        else (dsl.IMAGE, dsl.COMMAND_LINE, dsl.PROCESS_USER, dsl.PROCESS_ID, dsl.PROCESS_GUID)
    )
    name = first(doc, image)
    if not name:
        return None
    command = _command(first(doc, line), f"{path}/command_line", notes)
    number = first(doc, pid)
    return ProcessNode(
        name=name[:MAX_TEXT_CHARS],
        pid=int(number) if number and number.isdigit() else None,
        command_line=command,
        user=clip(first(doc, user), MAX_TEXT_CHARS),
        started_at=None if parent else when(first(doc, dsl.TIME)),
        command_template=command_template(command) if command else None,
        image_name=image_name(name),
        process_guid=clip(first(doc, process_guid), MAX_TOKEN_CHARS),
    )


def process_lineage(
    ancestry: Sequence[Mapping[str, Any]], named_parent: Optional[Mapping[str, Any]], children: Sequence[Mapping[str, Any]]
) -> Optional[Mapped[ProcessLineageValue]]:
    """The lineage fact's value from creation events.

    ``ancestry`` is oldest first, the subject process last. ``named_parent`` is the event whose *parent
    fields* describe the process above the oldest one found (its own event was not in the index).
    ``None`` when there is no process to name.
    """
    notes: List[Redaction] = []
    chain: List[ProcessNode] = []
    whole = len(children) <= MAX_LIST_ITEMS
    for doc, as_parent in [(named_parent, True), *((event, False) for event in ancestry)]:
        node = _node(doc, f"/value/chain/{len(chain)}", notes, parent=as_parent) if doc is not None else None
        if node is not None:
            chain.append(node)
    started: List[ProcessNode] = []
    for doc in children[:MAX_LIST_ITEMS]:
        node = _node(doc, f"/value/children/{len(started)}", notes)
        if node is not None:
            started.append(node)
    whole = whole and len(started) == min(len(children), MAX_LIST_ITEMS)
    if not chain:
        return None
    return Mapped(ProcessLineageValue(chain=chain, children=started), whole, _noted(notes))


# ---- prevalence ---------------------------------------------------------------------------------------------


def prevalence(answer: Answer, start: datetime, end: datetime) -> Optional[Mapped[PrevalenceValue]]:
    """``None`` when the value was not seen in the window."""
    total = count(answer.aggs, "total")
    if not total:
        return None
    hosts = count(answer.aggs, "hosts")
    value = PrevalenceValue(
        scope="tenant_fleet",
        window_start=start,
        window_end=end,
        first_seen_at=instant(answer.aggs, "first"),
        last_seen_at=instant(answer.aggs, "last"),
        host_count=hosts,
        event_count=total,
    )
    return Mapped(value, hosts <= dsl.PRECISION)
