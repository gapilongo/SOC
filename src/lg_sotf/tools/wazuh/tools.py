"""The Wazuh evidence tools (INT3.4): four query templates as registered tools.

* ``wazuh.host_activity``: what a host's alerts show around a moment;
* ``wazuh.logon_fanout``: every logon of one source address, source host, user or target host (a caller
  cannot narrow it to an outcome or a logon type, so a fact never leaves out what was not asked for);
* ``wazuh.process_lineage``: a process's parents and what it started, down to what its children started
  (one fact per process that matches; several matches are an ambiguous answer, and say so);
* ``wazuh.prevalence``: on how many of the tenant's agents a file hash, a process image, a service's image
  path or a service name was seen.

Each call answers with an :class:`Evidence`: the typed facts it observed (schema 1.1; none when nothing
matched), a tuple the registry counts itself. One call is one trace step with its own outcome and hashes;
the fact ledger (``lg_sotf.agents.investigation.ledger``) gives the facts the ids an investigation cites and
binds them to those hashes. The tools are never run as a family.

**Outcomes.** Facts came back: ``success``. The search ran and matched nothing: ``empty``. Anything else
is ``failed`` and ``Evidence.error`` says why in a fixed code (``unreachable``, ``timeout``,
``credentials_refused``, ``index_not_found``, ``not_configured``, ``disabled``, ``partial_answer``...): an
indexer that is down, refuses the credentials or answers half a search never reads as "nothing found".

**Complete.** A fact, and the call's result, is ``complete`` only when every shard answered every search,
nothing the fact lists was cut by a cap, the window had closed when it was read (its end is older than
the source's ingest lag) and the index still held alerts as old as the window's start. Otherwise what the
fact shows still counts, but no claim of absence can rest on it. An empty answer carries the same flag.

**Tenancy.** The backend is resolved from the calling run (``ctx.tenant_id``, ``ctx.alert_id``), never
from a parameter, and the tools are switched off per tenant with ``tenants.settings.tools.wazuh_indexer``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel

from lg_sotf.models.evidence_fact import EvidenceFact, FactKind, SubjectType, parse_fact
from lg_sotf.tools.registry import Tool, ToolContext, ToolError, ToolFailed, ToolRegistry, ToolSpec
from lg_sotf.tools.wazuh import dsl, mappers, templates
from lg_sotf.tools.wazuh.indexer import EGRESS_BOUNDARY, Backend, IndexerUnavailable
from lg_sotf.tools.wazuh.mappers import Answer, Malformed, Mapped
from lg_sotf.tools.wazuh.templates import (
    HostActivityParams,
    LogonFanoutParams,
    PrevalenceParams,
    ProcessLineageParams,
    minutes,
)

__all__ = [
    "HOST_ACTIVITY",
    "LOGON_FANOUT",
    "PREVALENCE",
    "PROCESS_LINEAGE",
    "TENANT_SETTING",
    "Backends",
    "Evidence",
    "register_wazuh_tools",
    "wazuh_tools",
]

HOST_ACTIVITY = "wazuh.host_activity"
LOGON_FANOUT = "wazuh.logon_fanout"
PROCESS_LINEAGE = "wazuh.process_lineage"
PREVALENCE = "wazuh.prevalence"
VERSION = 1
TENANT_SETTING = "wazuh_indexer"
TIME_CAP_S = 30.0
"""A call sends a handful of searches one after the other, each cut off by the indexer after five seconds."""
_SUBJECTS: Mapping[str, SubjectType] = {
    "source_ip": "ip", "source_host": "host", "target_user": "user", "target_host": "host",
    "sha256": "file", "process_image": "process", "service_image_path": "service", "service_name": "service",
}

Backends = Callable[[ToolContext], Awaitable[Backend]]
"""The calling run's backend: its tenant's indexer, or a dataset's telemetry. Raises ``IndexerUnavailable``."""
Document = Mapping[str, Any]


class Evidence(Tuple[EvidenceFact, ...]):
    """The facts one call observed. It is a tuple, so the registry counts the facts itself."""

    complete: bool
    """False when a cap, a window still open or the index's retention cut what was read (an empty answer too)."""
    error: Optional[str]
    """Why there is no answer (the ``failed`` outcome): a fixed code, never text from the indexer."""

    def __new__(cls, facts: Iterable[EvidenceFact] = (), *, complete: bool = True, error: Optional[str] = None) -> Evidence:
        self = super().__new__(cls, tuple(facts))
        self.complete = complete and error is None
        self.error = error
        return self


class _Reader:
    """The searches of one call: every answer is read here, and remembered when the indexer did not finish it."""

    def __init__(self, backend: Backend) -> None:
        self.backend = backend
        self.partial = False
        self._oldest: Optional[datetime] = None
        self._asked_oldest = False

    async def ask(self, body: Dict[str, Any]) -> Answer:
        answer = mappers.read(await self.backend.search(body))
        self.partial = self.partial or answer.partial
        return answer

    async def oldest(self) -> Optional[datetime]:
        """The oldest alert the index holds (one search per call). A search cut short gives a later time: the safe side."""
        if not self._asked_oldest:
            answer = mappers.read(await self.backend.search(templates.coverage()))
            self._oldest, self._asked_oldest = mappers.instant(answer.aggs, "oldest"), True
        return self._oldest


async def _evidence(
    reader: _Reader,
    name: str,
    kind: FactKind,
    subject: Tuple[SubjectType, str],
    mapped: Sequence[Mapped[Any]],
    start: datetime,
    end: datetime,
) -> Evidence:
    """The call's answer: each fact with its computed ``complete``, or an empty answer that says whether it is whole."""
    backend = reader.backend
    settled = end <= backend.now() - backend.lag
    if settled:
        oldest = await reader.oldest()
        settled = oldest is not None and oldest <= start
    if not mapped:
        if reader.partial:  # the indexer did not finish: "nothing matched" is not known
            raise IndexerUnavailable("partial_answer")
        return Evidence(complete=settled)
    facts = [
        parse_fact({
            "id": f"{name}:{n}",
            "kind": kind,
            "subject": {"type": subject[0], "value": subject[1]},
            "observed_at": backend.now(),
            "source": {"name": name, "version": str(VERSION)},
            "value": one.value,
            "complete": one.whole and not reader.partial and settled,
            "redactions": list(one.redactions),
        })
        for n, one in enumerate(mapped)
    ]
    return Evidence(facts, complete=all(fact.complete for fact in facts))


def _found(mapped: Optional[Mapped[Any]]) -> List[Mapped[Any]]:
    return [mapped] if mapped is not None else []


async def _host_activity(reader: _Reader, params: HostActivityParams) -> Evidence:
    start, end = params.at - minutes(params.before_min), params.at + minutes(params.after_min)
    mapped = mappers.host_activity(await reader.ask(templates.host_activity(params)), start, end)
    return await _evidence(reader, HOST_ACTIVITY, "host_activity", ("host", params.host), _found(mapped), start, end)


async def _logon_fanout(reader: _Reader, params: LogonFanoutParams) -> Evidence:
    start, end = params.at - minutes(params.before_min), params.at + minutes(params.after_min)
    answer = await reader.ask(templates.logons(params))
    apart = templates.lockouts(params)
    locked = mappers.count((await reader.ask(apart)).aggs, "total") if apart is not None else None
    first_failure, success = mappers.first_failure_and_success(answer)
    if first_failure is not None and success is not None and success < first_failure:
        # A success before the first failure hides the one after it: ask for that one.
        success = mappers.instant((await reader.ask(templates.first_success(params, first_failure))).aggs, "first")
    mapped = mappers.logon_fanout(params, answer, start=start, end=end, lockouts=locked, success_after_failure=success)
    subject = (_SUBJECTS[params.pivot], params.value)
    return await _evidence(reader, LOGON_FANOUT, "logon_fanout", subject, _found(mapped), start, end)


Find = Callable[[str, List[str], datetime], Awaitable[List[Document]]]


async def _descendants(find: Find, roots: Sequence[str], levels: int, since: datetime) -> List[Document]:
    """What the processes ``roots`` started, level by level: their children first, then what those started."""
    found: List[Document] = []
    parents, seen = list(roots), set(roots)
    for _ in range(levels):
        if not parents:
            break
        level = [doc for doc in await find(dsl.PARENT_GUID, parents[: dsl.MAX_TERMS], since) if mappers.guid(doc) not in seen]
        found += level
        parents = [g for g in map(mappers.guid, level) if g]
        seen.update(parents)
    return found


async def _ancestry(find: Find, subject: Document, depth: int, since: datetime) -> Tuple[List[Document], bool]:
    """The subject's creation event with its parents' in front of it, oldest first: at most ``depth`` look-ups.

    Also whether the walk was cut: it used every look-up and the oldest process found still names a parent.
    """
    chain = [subject]
    for _ in range(depth):
        above = mappers.parent_guid(chain[0])
        parents = await find(dsl.PROCESS_GUID, [above], since) if above else []
        if not parents:
            return chain, False
        chain.insert(0, parents[0])
    return chain, mappers.parent_guid(chain[0]) is not None


async def _process_lineage(reader: _Reader, params: ProcessLineageParams) -> Evidence:
    """One fact per process that matches: its ancestry, and what it started.

    A GUID names one process: use it whenever the alert carries one. An image names every process of that
    image that started around the alert, and an attacker can start a decoy seconds before: each match (at
    most ``MAX_LINEAGE_SUBJECTS``) gets its own fact, and when there is more than one, none is complete,
    because the tool cannot tell which is the alert's.

    The process above the oldest event found is named from that event's parent fields. A process given by a
    GUID whose own creation event is not in the index is named the same way, by its first child. A fact is
    complete only when the subject's own event was found (only then is the host known to report it), the
    walk up was not cut at ``depth`` and no search returned as many events as it may.
    What a process started is read from five seconds before ``at`` for an image, and over the day before
    ``at`` for a GUID (one process, which may have started well before the alert).
    """
    end = params.at + minutes(params.after_min)
    origin, cut = params.at - templates.LINEAGE_LOOKBACK, False
    start = params.at - templates.LINEAGE_SLACK if params.image is not None else origin

    async def find(field: str, values: List[str], since: datetime) -> List[Document]:
        nonlocal cut
        answer = await reader.ask(templates.processes(params.host, field, values, since, end))
        cut = cut or len(answer.hits) >= dsl.MAX_HITS
        return list(answer.hits)

    if params.image is not None:
        subjects = await find(dsl.IMAGE, templates.stored(params.image), start)
    else:
        subjects = await find(dsl.PROCESS_GUID, [str(params.process_guid)], start)
    found: List[Mapped[Any]] = []
    for subject in subjects[: templates.MAX_LINEAGE_SUBJECTS]:
        own = mappers.guid(subject)
        children = await _descendants(find, [own] if own else [], params.child_depth, start)
        ancestry, deeper = await _ancestry(find, subject, params.depth, origin)
        found += _found(mappers.process_lineage(ancestry, ancestry[0], children, cut=deeper))
    if not subjects and params.process_guid is not None:  # its own event is not there: its children name it
        children = await _descendants(find, [params.process_guid], params.child_depth, start)
        found += _found(mappers.process_lineage([], children[0] if children else None, children))
    if cut or len(subjects) != 1:
        found = [replace(one, whole=False) for one in found]
    subject_of: Tuple[SubjectType, str] = ("process", params.image or str(params.process_guid))
    return await _evidence(reader, PROCESS_LINEAGE, "process_lineage", subject_of, found, start, end)


async def _prevalence(reader: _Reader, params: PrevalenceParams) -> Evidence:
    """The window ends where the index is settled (now less the source's ingest lag) and reaches back ``days``."""
    end = reader.backend.now() - reader.backend.lag
    start = end - timedelta(days=params.days)
    answer = await reader.ask(templates.prevalence(params, end))
    oldest = await reader.oldest()
    mapped = mappers.prevalence(answer, max(start, oldest) if oldest is not None else start, end)
    value = params.value.lower() if params.kind == "sha256" else params.value
    return await _evidence(reader, PREVALENCE, "prevalence", (_SUBJECTS[params.kind], value), _found(mapped), start, end)


def _failed(evidence: Evidence) -> bool:
    return evidence.error is not None


def _whole(evidence: Evidence) -> bool:
    return evidence.complete


def _record(evidence: Evidence) -> Dict[str, Any]:
    facts = [fact.model_dump(mode="json", exclude_none=True) for fact in evidence]
    return {"facts": facts, "complete": evidence.complete, "error": evidence.error}


def _restore(params: BaseModel, recorded: Mapping[str, Any]) -> Evidence:
    facts = [parse_fact(fact) for fact in recorded["facts"]]
    return Evidence(facts, complete=recorded["complete"] is True, error=recorded.get("error"))


def _refused(params: BaseModel, error: ToolError) -> Evidence:
    return Evidence(error="error" if isinstance(error, ToolFailed) else error.reason)


def _tool(
    name: str,
    kind: FactKind,
    params: type[BaseModel],
    answer: Callable[[_Reader, Any], Awaitable[Evidence]],
    window: Callable[[Any], timedelta],
    window_cap: timedelta,
    backends: Backends,
    row_cap: int = 1,
) -> Tool[Any, Evidence]:
    async def run(ctx: ToolContext, valid: Any) -> Evidence:
        try:
            return await answer(_Reader(await backends(ctx)), valid)
        except IndexerUnavailable as exc:
            return Evidence(error=exc.reason)
        except Malformed:
            return Evidence(error="bad_response")

    spec = ToolSpec(
        name=name,
        version=VERSION,
        risk="read_internal",
        params=params,
        produces=frozenset({kind}),
        row_cap=row_cap,  # facts a call; what a fact lists is capped by the templates and the fact schema
        time_cap_s=TIME_CAP_S,
        window_cap=window_cap,
        egress="tenant_source",
        shadow="live",
        tenant_setting=TENANT_SETTING,
        egress_boundary=EGRESS_BOUNDARY,
    )
    return Tool(spec, run, len, _failed, _record, _restore, _refused, window=window, whole=_whole)


def wazuh_tools(backends: Backends) -> List[Tool[Any, Evidence]]:
    """The four tools, answering from the backend ``backends`` resolves for the calling run."""
    host = minutes(2 * templates.MAX_HOST_MINUTES)
    logon = minutes(templates.MAX_LOGON_LOOKBACK_MINUTES + templates.MAX_LOGON_AFTER_MINUTES)
    lineage = templates.LINEAGE_LOOKBACK + minutes(templates.MAX_LINEAGE_AFTER_MINUTES)
    return [
        _tool(HOST_ACTIVITY, "host_activity", HostActivityParams, _host_activity,
              lambda p: minutes(p.before_min + p.after_min), host, backends),
        _tool(LOGON_FANOUT, "logon_fanout", LogonFanoutParams, _logon_fanout,
              lambda p: minutes(p.before_min + p.after_min), logon, backends),
        _tool(PROCESS_LINEAGE, "process_lineage", ProcessLineageParams, _process_lineage,
              lambda p: templates.LINEAGE_LOOKBACK + minutes(p.after_min), lineage, backends,
              row_cap=templates.MAX_LINEAGE_SUBJECTS),
        _tool(PREVALENCE, "prevalence", PrevalenceParams, _prevalence,
              lambda p: timedelta(days=p.days), timedelta(days=templates.MAX_PREVALENCE_DAYS), backends),
    ]


def register_wazuh_tools(registry: ToolRegistry, backends: Backends) -> None:
    for tool in wazuh_tools(backends):
        registry.register(tool)
