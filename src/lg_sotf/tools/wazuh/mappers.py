"""From a search response to the typed value of a fact (INT3.4, ADR 0014 section 3.3).

Rows never leave this module: a mapper reads the allow-listed fields of a response and returns the typed
value of one evidence fact (:mod:`lg_sotf.models.evidence_fact`, schema 1.2), with

* ``whole``: false when something the value lists was cut (more alerts than the 50 listed, more
  buckets than the 50 listed, a distinct count above the exact range, an event that could not be read);
* ``redactions``: where a command line was masked (a secret) or cut to the schema's length.

Every string a fact holds is one the indexer returned, so one an attacker may have chosen: it is cut to
the schema's bound and never interpreted. A response that is not a search response raises
:class:`Malformed`, which the tool reports as a failed call, never as "nothing found".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Generic, Iterable, List, Mapping, Optional, Sequence, Tuple, TypeVar

from lg_sotf.domain.closure import NEVER_CLOSE_TECHNIQUES
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
    ListedFor,
    LogonFanoutValue,
    PrevalenceValue,
    ProcessLineageValue,
    ProcessNode,
    Redaction,
)
from lg_sotf.security.redaction import redact_text
from lg_sotf.tools.wazuh import dsl
from lg_sotf.tools.wazuh.templates import (
    LOGONS,
    NEAREST_SHARE,
    NEVER_CLOSE_SHARE,
    RARE_SHARE,
    LogonFanoutParams,
    counted,
)

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
    """It timed out, stopped at ``terminate_after``, or not every shard answered: what it shows is a lower bound."""


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
    # A shard that is not allocated is neither successful nor failed: only "every shard answered" is a whole search.
    total, answered = shards.get("total"), shards.get("successful")
    every_shard = type(total) is int and type(answered) is int and answered >= total and not shards.get("failed")
    partial = bool(response.get("timed_out") or response.get("terminated_early")) or not every_shard
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


def asked(aggs: Mapping[str, Any], name: str, key: str = "value") -> Any:
    """What an aggregation the template asked for answered. Its absence is not "nothing found": it is not the answer."""
    agg = aggs.get(name)
    if not isinstance(agg, Mapping) or key not in agg:
        raise Malformed("an aggregation is missing")
    return agg[key]


def _number(aggs: Mapping[str, Any], name: str) -> Optional[float]:
    value = asked(aggs, name)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def count(aggs: Mapping[str, Any], name: str) -> int:
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
    rows = asked(aggs, name, "buckets")
    if not isinstance(rows, list):
        raise Malformed("an aggregation is missing")
    found = [(str(row["key"]), int(row.get("doc_count", 0))) for row in rows if isinstance(row, Mapping) and "key" in row]
    return found[:MAX_LIST_ITEMS], not aggs[name].get("sum_other_doc_count") and len(found) <= MAX_LIST_ITEMS


def _keys(aggs: Mapping[str, Any], name: str, limit: int = MAX_TEXT_CHARS, *, fold: bool = False) -> Tuple[List[str], bool]:
    """The values a ``terms`` aggregation lists, most frequent first.

    ``fold``: a Windows user or host name, which is one name whatever its case. The spellings are counted
    together and the name is given in lower case.
    """
    rows, whole = buckets(aggs, name)
    counts: Dict[str, int] = {}
    for key, n in rows:
        name_ = (key.casefold() if fold else key)[:limit]
        if name_:
            counts[name_] = counts.get(name_, 0) + n
    return [key for key, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))], whole


def image_name(path: Optional[str]) -> Optional[str]:
    return clip(path.replace("/", "\\").rsplit("\\", 1)[-1], MAX_NAME_CHARS) if path else None


def command_template(command: str) -> Optional[str]:
    """A command line in lower case with single spaces and its bare numbers as ``<n>``.

    The recipe the corpus's routine-command lists are written in; AI-E4.2 replaces it with the shared
    ``lg_sotf.domain.patterns.command_template`` when that lands.
    """
    # ``<n>`` is longer than a digit: a line of bare numbers would outgrow the schema's length and fail the fact.
    return _NUMBER.sub("<n>", " ".join(command.lower().split()))[:MAX_COMMAND_LINE_CHARS] or None


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


MAX_EVENT_COMMAND_CHARS = 400
MAX_EVENT_NAME_CHARS = 100
"""What one listed host event holds of a command line, and of a user or an image name, counted as the fact's
JSON holds them (an escaped character counts whole). The text is the attacker's: with these caps fifty events
at their largest stay under what a prompt may show of one fact (``lg_sotf.domain.ledger.MAX_PLANNER_CHARS``),
so one event's text can neither fail the lookup nor make the prompt leave the host's observation out."""


def _short(text: Optional[str], limit: int, path: str, notes: List[Redaction]) -> Optional[str]:
    """``text`` cut to what takes at most ``limit`` characters in JSON; a cut is noted at ``path``."""
    kept = (text or "")[:limit]
    while (over := len(json.dumps(kept, ensure_ascii=False)) - 2 - limit) > 0:
        kept = kept[: -max(1, over // 6)]
    if kept != (text or "") and Redaction(path=path, reason="truncated") not in notes:
        notes.append(Redaction(path=path, reason="truncated"))
    return kept or None


def _host_event(
    doc: Mapping[str, Any], path: str, notes: List[Redaction], listed_for: Optional[ListedFor] = None
) -> Optional[HostEvent]:
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
        user=_short(first(doc, dsl.PROCESS_USER) or first(doc, dsl.TARGET_USER), MAX_EVENT_NAME_CHARS, f"{path}/user", notes),
        image_name=_short(image_name(first(doc, dsl.IMAGE)), MAX_EVENT_NAME_CHARS, f"{path}/image_name", notes),
        command_template=_short(command_template(line) if line else None, MAX_EVENT_COMMAND_CHARS, f"{path}/command_template", notes),
        listed_for=listed_for,
    )


def _less(rows: List[Tuple[str, int]], own: Mapping[str, int]) -> List[Tuple[str, int]]:
    """``rows`` with the alert's own counts taken out; a value only the alert's own event had is gone."""
    left = [(key, n - own.get(key, 0)) for key, n in rows]
    return [(key, n) for key, n in left if n > 0]


def _own_event(doc: Mapping[str, Any], own: Answer) -> bool:
    """Whether a listed event is the alert's own: the same rule at the same instant as one of ``own``'s."""
    mine = {(first(doc_, dsl.RULE_ID), when(first(doc_, dsl.TIME))) for doc_ in own.hits}
    return (first(doc, dsl.RULE_ID), when(first(doc, dsl.TIME))) in mine


@dataclass(frozen=True)
class _Window:
    """A host's window as the level search answered it, with the alert's own event taken out of everything."""

    total: int
    groups: List[Tuple[str, int]]
    techniques: List[Tuple[str, int]]
    level: Optional[float]
    hits: Tuple[Mapping[str, Any], ...]
    all_groups: bool
    all_techniques: bool


def _window(answer: Answer, own: Optional[Answer]) -> _Window:
    total = count(answer.aggs, "total")
    groups, all_groups = buckets(answer.aggs, "groups")
    technique_rows, all_techniques = buckets(answer.aggs, "techniques")
    level = _number(answer.aggs, "max_level")
    hits = answer.hits
    if own is not None and count(own.aggs, "total") > 0:
        total = max(0, total - count(own.aggs, "total"))
        groups = _less(groups, dict(buckets(own.aggs, "groups")[0]))
        technique_rows = _less(technique_rows, dict(buckets(own.aggs, "techniques")[0]))
        hits = tuple(doc for doc in hits if not _own_event(doc, own))
        levels = [n for n in (_level(doc) for doc in hits) if n is not None]
        level = max(levels) if levels else level if total else None  # the others' highest is among the listed
    return _Window(total, groups, technique_rows, level, hits, all_groups, all_techniques)


@dataclass(frozen=True)
class HostSample:
    """The answers to :func:`lg_sotf.tools.wazuh.templates.host_sample`, by part, and the alert's time.

    ``failed``: a search of the sample did not answer. No part is used then: the events are listed by level,
    as the host search returned them, and the fact says that never-close events may be left out."""

    at: datetime
    parts: Mapping[str, Answer]
    failed: bool = False


def _never_close(technique: str) -> bool:
    return technique.split(".", 1)[0] in NEVER_CLOSE_TECHNIQUES


def host_sample_techniques(answer: Answer, own: Optional[Answer] = None) -> Optional[Tuple[List[str], List[str]]]:
    """``None`` when the level search lists every event of the window. Otherwise the list is a sample, and
    these are the technique ids part of it is kept for: the ids the host showed that are in a never-close
    class, and the ids it showed least often.

    The rare ids are the least seen first, at most :data:`RARE_SHARE` of them, and only as many as one search
    returns every event of (the rarest one always): each then has an event to list, however many decoys of
    it there are. No level or time changes either list. A never-close id counts among the rare ones only
    when there are more never-close events than their share: one of them seen once is then still listed,
    however many newer ones of another technique fill that share. With more techniques than the aggregation
    lists, the rarest are not known: none is named.
    """
    window = _window(answer, own)
    if window.total <= len(window.hits):
        return None
    rows = [row for row in window.techniques if _TECHNIQUE.fullmatch(row[0])]
    never_close = [row for row in rows if _never_close(row[0])]
    listed_anyway = never_close if sum(n for _, n in never_close) <= NEVER_CLOSE_SHARE else []
    rare: List[str] = []
    room = dsl.MAX_HITS - (count(own.aggs, "total") if own is not None else 0)  # the search returns the alert's own too
    for key, n in _rarest(row for row in rows if row not in listed_anyway) if window.all_techniques else []:
        if len(rare) == RARE_SHARE or (rare and n > room):
            break
        rare.append(key)
        room -= n
    return [key for key, _ in never_close], rare


def _rarest(rows: Iterable[Tuple[str, int]]) -> List[Tuple[str, int]]:
    return sorted(rows, key=lambda row: (row[1], row[0]))


def _one_of_each(docs: List[Mapping[str, Any]], techniques: Sequence[str], *, only: bool) -> List[Mapping[str, Any]]:
    """``docs`` (newest first) with the newest event of each of ``techniques`` in front, in their order: more
    events of one technique cannot keep every event of it, or of another, out of the part. ``only``: just
    those (the search came back full, so the rest is one technique's flood, not a rare technique's events)."""
    front: List[Mapping[str, Any]] = []
    for key in techniques:
        found = next((doc for doc in docs if key in values(doc, dsl.TECHNIQUES) and doc not in front), None)
        if found is not None:
            front.append(found)
    return front if only else front + [doc for doc in docs if doc not in front]


def _sampled(window: _Window, own: Optional[Answer], sample: HostSample) -> Tuple[List[Tuple[Mapping[str, Any], ListedFor]], bool]:
    """The events a busy host's fact lists, each with the part that kept it, in the order of the parts; and
    whether the window may hold events of a never-close technique that are not listed.

    Each part is filled from its own search, so nothing in another part (a louder alert, a closer one, any
    number of them) takes its place. An event two parts would keep is listed once, for the first. Not every
    event of a never-close technique is known to be listed when there are more than their share, when their
    search came back full (the alert's own exact duplicates may have filled it) or unfinished, when the
    techniques were cut, or when the sample's searches failed.
    """

    def pool(part: str) -> List[Mapping[str, Any]]:
        answer = sample.parts.get(part)
        return [doc for doc in answer.hits if own is None or not _own_event(doc, own)] if answer is not None else []

    def away(doc: Mapping[str, Any]) -> timedelta:
        at = when(first(doc, dsl.TIME))
        return abs(at - sample.at) if at is not None else timedelta.max

    def full(part: str) -> bool:
        answer = sample.parts.get(part)
        return answer is not None and len(answer.hits) >= dsl.MAX_HITS

    never, asked = pool("never_close"), sample.parts.get("never_close")
    unsure = full("never_close") or (asked is not None and asked.partial)
    cut = len(never) > NEVER_CLOSE_SHARE or unsure or not window.all_techniques or sample.failed
    near = {_identity(doc): doc for doc in sorted(pool("before") + pool("after"), key=away)}  # stable: closest first
    rare = _one_of_each(pool("rare"), [key for key, _ in _rarest(window.techniques)], only=full("rare"))
    parts: List[Tuple[ListedFor, Sequence[Mapping[str, Any]]]] = [
        ("never_close_class", never[:NEVER_CLOSE_SHARE]),
        ("rare_technique", rare[:RARE_SHARE]),
        ("nearest_in_time", list(near.values())[:NEAREST_SHARE]),
        ("rule_level", window.hits),
    ]
    listed: Dict[str, Tuple[Mapping[str, Any], ListedFor]] = {}
    for part, docs in parts:
        for doc in docs:
            if len(listed) < MAX_LIST_ITEMS:
                listed.setdefault(_identity(doc), (doc, part))
    return list(listed.values()), cut


def _identity(doc: Mapping[str, Any]) -> str:
    """Everything read of an event (its document id among it): what tells two searches' hits apart."""
    return json.dumps(doc, sort_keys=True, default=str)


def host_activity(
    answer: Answer, start: datetime, end: datetime, own: Optional[Answer] = None, sample: Optional[HostSample] = None
) -> Optional[Mapped[HostActivityValue]]:
    """``None`` when the host raised nothing in the window.

    ``own`` is the search for the investigated alert's own event (and its exact duplicates) with the same
    aggregations: its counts are taken out of every number, group and technique, its events are not listed,
    and the highest level is the highest of what is left. An alert alone on its host shows nothing.

    ``sample``: the window holds more events than the fact lists (:func:`host_sample_techniques`), and these
    searches choose the listed ones (:func:`_sampled`). Each event then says what it is listed for.
    """
    window = _window(answer, own)
    total, level = window.total, window.level
    techniques = [key for key, _ in sorted(window.techniques, key=lambda row: -row[1])]  # stable: the index order on a tie
    if not total and not window.hits:
        return None
    chosen: Sequence[Tuple[Mapping[str, Any], Optional[ListedFor]]] = [(doc, None) for doc in window.hits[:MAX_LIST_ITEMS]]
    truncated: Optional[bool] = None
    if sample is not None:
        chosen, cut = _sampled(window, own, sample)
        truncated = cut or answer.partial  # a search that did not finish may not have listed every technique
    notes: List[Redaction] = []
    events: List[HostEvent] = []
    for doc, part in chosen:
        event = _host_event(doc, f"/value/events/{len(events)}", notes, part)
        if event is not None:
            events.append(event)
    value = HostActivityValue(
        window_start=start,
        window_end=end,
        total=max(total, len(events)),
        max_level=int(level) if level is not None and 0 <= level <= MAX_RULE_LEVEL else None,
        by_group=[GroupCount(group=group[:MAX_TOKEN_CHARS], count=n) for group, n in window.groups if group],
        techniques=[t for t in techniques if _TECHNIQUE.fullmatch(t)],
        events=events,
        never_close_technique_truncated=truncated,
    )
    return Mapped(value, window.all_groups and window.all_techniques and total == len(events), _noted(notes))


# ---- logon fan-out ------------------------------------------------------------------------------------------


def _outcome(aggs: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    found = asked(aggs, "outcomes", "buckets")
    bucket = found.get(name) if isinstance(found, Mapping) else None
    if not isinstance(bucket, Mapping):
        raise Malformed("an aggregation is missing")
    return bucket


def _doc_count(bucket: Mapping[str, Any]) -> int:
    value = bucket.get("doc_count")
    if type(value) is not int or value < 0:
        raise Malformed("an aggregation is missing")
    return value


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
    """``None`` when no logon matched. ``lockouts`` is the count read apart, when the pivot needed it.

    Every count is over every outcome and every logon type of the pivot in the window. Windows user and
    host names are one name whatever their case: their spellings are counted together.
    """
    aggs, spec, outcomes = answer.aggs, LOGONS[params.family], counted(params)
    doc_count = {name: _doc_count(_outcome(aggs, name)) for name in [*outcomes, "unknown_user"]}
    locked = doc_count.get("lockout", lockouts or 0)
    users = {name: _keys(_outcome(aggs, name), "users", fold=spec.user in dsl.NAMES) for name in outcomes}
    sources, all_sources = _keys(aggs, "source_list")
    source_hosts, all_source_hosts = _keys(aggs, "source_hosts", fold=True) if spec.source_host else ([], True)
    logon_types, all_types = _keys(aggs, "logon_types", MAX_TOKEN_CHARS) if spec.logon_type else ([], True)
    distinct = {name: count(aggs, name) for name in ("users", "sources", "hosts")}
    first_failure, _ = first_failure_and_success(answer)
    if not doc_count["failure"] + doc_count["success"] + locked:
        return None
    all_users = all(whole for _, whole in users.values())
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
        # Every user is in one of the outcome lists: counted there, two spellings of a name are one user.
        distinct_target_users=len({name for names, _ in users.values() for name in names}) if all_users else distinct["users"],
        distinct_sources=distinct["sources"],
        distinct_target_hosts=distinct["hosts"],
        first_success_after_failure_s=after,
        success_users=users["success"][0],
        failed_users=users["failure"][0],
        sources=sources,
        source_hosts=source_hosts,
        logon_types=logon_types,
    )
    whole = all_users and all_sources and all_source_hosts and all_types
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
    ancestry: Sequence[Mapping[str, Any]],
    named_parent: Optional[Mapping[str, Any]],
    children: Sequence[Mapping[str, Any]],
    *,
    cut: bool = False,
) -> Optional[Mapped[ProcessLineageValue]]:
    """The lineage fact's value from creation events.

    ``ancestry`` is oldest first, the subject process last. ``named_parent`` is the event whose *parent
    fields* describe the process above the oldest one found (its own event was not read).
    ``cut``: the walk up stopped at the asked depth with a parent still above; the fact says so (a
    ``truncated`` redaction on the chain) and is not whole. ``None`` when there is no process to name.
    """
    notes: List[Redaction] = [Redaction(path="/value/chain", reason="truncated")] if cut else []
    chain: List[ProcessNode] = []
    whole = len(children) <= MAX_LIST_ITEMS and not cut
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
