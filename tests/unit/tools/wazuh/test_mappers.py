"""From a search response to a fact (INT3.4): completeness is computed, strings are bounded, secrets are masked.

``complete`` is the flag a claim of absence rests on (TM-EVT-12), so every way a result can be less than
whole is exercised here: a search the indexer did not finish, a list cut by a cap, a window that had
not closed, an index that does not reach back to the window's start.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

import pytest

from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, event_time
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.models.evidence_fact import MAX_COMMAND_LINE_CHARS, EvidenceFact, fact_is_complete
from lg_sotf.tools.wazuh import dsl, mappers, templates
from lg_sotf.tools.wazuh.mappers import Answer, Malformed
from lg_sotf.tools.wazuh.templates import LogonFanoutParams
from tests.fixtures.attack_corpus import gold
from tests.unit.tools._support import Ctx
from tests.unit.tools.wazuh._support import corpus, minutes, over, raw

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
PSEXESVC = "C:\\Windows\\PSEXESVC.exe"


class Indexer:
    """The corpus store as an indexer that may answer late, in part, or with a clock and a lag of its own."""

    def __init__(self, store: EventStore, as_of: datetime, *, lag: timedelta = timedelta(0), **flags: Any) -> None:
        self._inner = EventStoreBackend(store.as_of(as_of))
        self._as_of = as_of
        self.lag = lag
        self.flags = flags
        self.bodies: List[Mapping[str, Any]] = []

    def now(self) -> datetime:
        return self._as_of

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.bodies.append(body)
        answer = dict(await self._inner.search(body))
        if "failed_shards" in self.flags:
            answer["_shards"] = {"total": 3, "successful": 2, "failed": self.flags["failed_shards"]}
        return {**answer, **{k: v for k, v in self.flags.items() if k != "failed_shards"}}


async def _facts(backend: Any) -> Dict[str, Optional[EvidenceFact]]:
    """One call of each tool around the PsExec of ``cv1-0113``: every fact is complete on a settled, healthy index."""
    at = event_time(corpus("corpus_v1").items["cv1-0113"].alert)
    host = {"host": "SRV-APP-02", "at": at}
    calls = {
        "host_activity": {**host, "before_min": 30, "after_min": 15},
        "logon_fanout": {"pivot": "target_host", "value": "SRV-APP-02", "at": at, "before_min": 15, "after_min": 15},
        "process_lineage": {**host, "image": PSEXESVC, "after_min": 15},
        "prevalence": {"kind": "process_image", "value": PSEXESVC, "days": 14},
    }
    out: Dict[str, Optional[EvidenceFact]] = {}
    for tool, params in calls.items():
        result = await over(backend).call(Ctx(), f"wazuh.{tool}", params, agent="investigation")
        assert result.outcome == "success", (tool, result.value.error)
        assert result.complete is (result.value[0].complete is True), "the result and its fact say the same"
        out[tool] = result.value[0]
    return out


def _settled(**kwargs: Any) -> Indexer:
    c = corpus("corpus_v1")
    return Indexer(c.store, event_time(c.items["cv1-0113"].alert) + minutes(15), **kwargs)


@pytest.mark.parametrize(
    "flags",
    [{"timed_out": True}, {"terminated_early": True}, {"failed_shards": 1}],
    ids=["timeout", "stopped at terminate_after", "failed shards"],
)
async def test_incomplete_results_are_marked(flags: Dict[str, Any]) -> None:
    whole = await _facts(_settled())
    assert all(fact is not None and fact.complete is True for fact in whole.values())
    partial = await _facts(_settled(**flags))
    for tool, fact in partial.items():
        assert fact is not None and fact.complete is False and not fact_is_complete(fact), tool
        assert fact.value == whole[tool].value, "what the indexer did return is still shown"  # type: ignore[union-attr]


async def test_a_window_that_has_not_closed_or_is_not_covered_is_marked() -> None:
    c = corpus("corpus_v1")
    at = event_time(c.items["cv1-0113"].alert)
    end = at + minutes(15)
    # The source's ingest lag: an alert may still arrive that long after its time, so the window is open until then.
    lag = timedelta(seconds=900)
    for now, closed in ((end, False), (end + lag - timedelta(seconds=1), False), (end + lag, True)):
        facts = await _facts(Indexer(c.store, now, lag=lag))
        assert [f.complete for name, f in facts.items() if f and name != "prevalence"] == [closed] * 3, now
        # Prevalence reads up to where the index is settled, so its window is closed by construction.
        seen = facts["prevalence"]
        assert seen is not None and seen.complete is True and seen.value.window_end == now - lag
    # Retention: an index whose oldest alert is younger than the window's start cannot vouch for the window.
    oldest = {"id": "1790000000.1", "timestamp": f"{at - minutes(20):%Y-%m-%dT%H:%M:%S}.000+0000", "agent": {"name": "OTHER-01"}}
    recent = EventStore([oldest, *c.store.as_of(end).select(EventQuery(start=at - minutes(20)))])
    backend = Indexer(recent, end)
    cut = await _facts(backend)
    assert cut["host_activity"].complete is False and cut["host_activity"].value.total == 7  # type: ignore[union-attr]
    assert cut["logon_fanout"].complete is True, "its 15-minute window is inside what the index holds"  # type: ignore[union-attr]
    seen = cut["prevalence"]
    assert seen is not None and seen.complete is False and seen.value.window_start == (at - minutes(20)).replace(microsecond=0)
    # One coverage search per call, with the same caps as any other.
    coverage = [body for body in backend.bodies if set(body.get("aggs", {})) == {"oldest"}]
    assert len(coverage) == 4 and all(body == templates.coverage() for body in coverage)
    # An index with nothing in it covers nothing: an empty answer from it is not a complete one.
    nothing = await over(Indexer(EventStore([]), end)).call(
        Ctx(), "wazuh.host_activity", {"host": "SRV-APP-02", "at": at, "before_min": 30, "after_min": 15}, agent="a")
    assert (nothing.outcome, nothing.complete) == ("empty", False)


def _answer(hits: List[Mapping[str, Any]], aggs: Mapping[str, Any]) -> Answer:
    return Answer(tuple(hits), aggs, partial=False)


def _event(n: int = 0, **eventdata: Any) -> Dict[str, Any]:
    return {
        "timestamp": f"2026-11-02T09:00:{n % 60:02d}.000+0000",
        "rule": {"id": "100100", "level": 3, "groups": ["windows"], "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": {"eventID": "1"}, "eventdata": eventdata}},
    }


def _terms(*keys: str, other: int = 0) -> Dict[str, Any]:
    return {"sum_other_doc_count": other, "buckets": [{"key": key, "doc_count": 1} for key in keys]}


def test_a_list_cut_by_a_cap_is_not_whole() -> None:
    aggs = {"total": {"value": 50}, "max_level": {"value": 3.0}, "groups": _terms("windows"), "techniques": _terms("T1059.001")}
    full = mappers.host_activity(_answer([_event(n) for n in range(50)], aggs), T0, T0 + minutes(5))
    assert full is not None and full.whole and len(full.value.events) == full.value.total == 50
    # The row cap: more alerts in the window than the 50 returned.
    more = mappers.host_activity(_answer([_event(n) for n in range(50)], {**aggs, "total": {"value": 51}}), T0, T0 + minutes(5))
    assert more is not None and not more.whole and (more.value.total, len(more.value.events)) == (51, 50)
    # sum_other_doc_count: rule groups or techniques beyond the buckets listed.
    for name in ("groups", "techniques"):
        cut = mappers.host_activity(_answer([_event()], {**aggs, "total": {"value": 1}, name: _terms("T1059.001", other=4)}), T0, T0)
        assert cut is not None and not cut.whole, name
    # An alert whose time cannot be read is not listed, and the fact says it is not whole.
    unread = mappers.host_activity(_answer([{**_event(), "timestamp": "yesterday"}], {**aggs, "total": {"value": 1}}), T0, T0)
    assert unread is not None and not unread.whole and unread.value.events == [] and unread.value.total == 1
    assert mappers.host_activity(_answer([], {"total": {"value": 0}}), T0, T0) is None
    # Logons: a user or source list beyond its 50 buckets, or a distinct count above the exact range.
    params = LogonFanoutParams(pivot="source_ip", value="10.20.1.83", at=T0, before_min=30)
    bucket = {"doc_count": 2, "users": _terms("ann", "bob"), "first": {"value": 1_793_610_000_000.0}}
    logons = {"users": {"value": 2}, "sources": {"value": 1}, "hosts": {"value": 1}, "source_list": _terms("10.20.1.83"),
              "source_hosts": _terms("WS-1"), "logon_types": _terms("3"), "outcomes": {"buckets": {"failure": bucket}}}

    def fanout(aggs: Mapping[str, Any]) -> Any:
        return mappers.logon_fanout(params, _answer([], aggs), start=T0, end=T0, lockouts=None, success_after_failure=None)

    assert fanout(logons).whole and fanout(logons).value.failed_users == ["ann", "bob"]
    listed = {**bucket, "users": _terms("ann", "bob", other=7)}
    assert not fanout({**logons, "outcomes": {"buckets": {"failure": listed}}}).whole
    assert not fanout({**logons, "source_list": _terms("10.20.1.83", other=1)}).whole
    assert not fanout({**logons, "users": {"value": dsl.PRECISION + 1}}).whole
    assert fanout({**logons, "outcomes": {"buckets": {}}}) is None
    with pytest.raises(Malformed):  # a count the search must carry is missing: not the answer that was asked for
        fanout({key: value for key, value in logons.items() if key != "hosts"})
    # Prevalence: the agent count is exact only up to the precision threshold.
    seen = {"total": {"value": 9_000}, "hosts": {"value": dsl.PRECISION + 1}, "first": {"value": 1.79e12}, "last": {"value": 1.79e12}}
    assert not mappers.prevalence(_answer([], seen), T0, T0).whole  # type: ignore[union-attr]
    assert mappers.prevalence(_answer([], {**seen, "hosts": {"value": 12}}), T0, T0).whole  # type: ignore[union-attr]
    assert mappers.prevalence(_answer([], {**seen, "total": {"value": 0}}), T0, T0) is None


def test_strings_from_the_indexer_are_bounded_and_secrets_are_masked() -> None:
    long_tail = "a" * (MAX_COMMAND_LINE_CHARS + 500)
    child = _event(
        1, image="C:\\\\Tools\\\\PsExec64.exe", processGuid="{c}", processId="4242", user="CORP\\\\adm.ksmith" + "x" * 2_000,
        commandLine="psexec \\\\\\\\SRV-01 -u admin -p Winter2026! cmd.exe", parentImage="C:\\\\Windows\\\\explorer.exe",
        parentProcessGuid="{p}", parentCommandLine="explorer.exe " + long_tail, parentProcessId="not-a-number",
    )
    mapped = mappers.process_lineage([child], child, [_event(2, image="C:\\\\x\\\\" + "n" * 2_000, commandLine="mysql --password=hunter2hunter2")])
    assert mapped is not None and mapped.whole
    parent, subject = mapped.value.chain
    started = mapped.value.children[0]  # type: ignore[index]
    assert (parent.name, parent.image_name, parent.process_guid, parent.pid) == ("C:\\Windows\\explorer.exe", "explorer.exe", "{p}", None)
    assert (subject.name, subject.pid, subject.process_guid) == ("C:\\Tools\\PsExec64.exe", 4242, "{c}")
    # The password never reaches the fact, in the command line or in its template.
    assert subject.command_line == "psexec \\\\SRV-01 -u admin -p [REDACTED] cmd.exe"
    assert subject.command_template == "psexec \\\\srv-<n> -u admin -p [redacted] cmd.exe"
    assert "Winter2026" not in mapped.value.model_dump_json() and "hunter2" not in mapped.value.model_dump_json()
    assert len(subject.user or "") == 1_024 and len(parent.command_line or "") == MAX_COMMAND_LINE_CHARS
    assert len(started.name) == 1_024 and len(started.image_name or "") == 255
    assert {(r.path, r.reason) for r in mapped.redactions} == {
        ("/value/chain/1/command_line", "secret"), ("/value/chain/0/command_line", "truncated"),
        ("/value/children/0/command_line", "secret")}
    # A host event carries the template only, masked the same way.
    aggs = {"total": {"value": 1}, "max_level": {"value": 99}, "groups": _terms("windows", "g" * 500), "techniques": _terms("T1059.001", "not-a-technique")}
    host = mappers.host_activity(_answer([child], aggs), T0, T0)
    assert host is not None and host.value.events[0].command_template == subject.command_template
    assert host.value.events[0].image_name == "PsExec64.exe" and host.value.max_level is None
    assert host.value.techniques == ["T1059.001"] and [len(g.group) for g in host.value.by_group] == [7, 128]
    assert [(r.path, r.reason) for r in host.redactions] == [("/value/events/0/command_template", "secret")]
    # A process with no image has no name: it is left out, and the fact is not whole.
    nameless = mappers.process_lineage([child], None, [_event(3, processGuid="{x}")])
    assert nameless is not None and not nameless.whole and nameless.value.children == []
    assert mappers.process_lineage([], None, []) is None


def test_the_command_template_is_the_recipe_of_the_routine_command_lists() -> None:
    assert mappers.command_template("  Shutdown   /r /t 60 ") == "shutdown /r /t <n>"
    assert mappers.command_template("ping 10.0.0.1 -n 4") == "ping 10.0.0.1 -n <n>" and mappers.command_template("   ") is None
    c = corpus("corpus_v1")
    lines = {raw(doc, "commandLine") for doc in c.store.as_of(datetime(2100, 1, 1, tzinfo=UTC)).select(EventQuery())}
    lines.discard("")
    assert len(lines) > 30 and all(mappers.command_template(line) == gold.command_template(line) for line in lines)


@pytest.mark.parametrize(
    "response",
    [None, [], "error", {}, {"hits": {"hits": []}}, {"_shards": {}, "hits": []}, {"_shards": {}, "hits": {"total": 3}},
     {"error": {"type": "search_phase_execution_exception"}, "status": 400}],
)
def test_a_response_that_is_not_a_search_response_is_malformed(response: Any) -> None:
    with pytest.raises(Malformed):
        mappers.read(response)


def test_a_response_is_read_with_its_flags() -> None:
    body = {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [{"_source": {"id": "1"}}]}, "aggregations": {"n": {"value": 1}}}
    assert mappers.read(body) == Answer(({"id": "1"},), {"n": {"value": 1}}, partial=False)
    assert mappers.read({**body, "timed_out": True}).partial and mappers.read({**body, "terminated_early": True}).partial
    assert mappers.read({**body, "_shards": {"failed": 2}}).partial
    assert mappers.read({**body, "hits": {"hits": [{"_id": "no source"}]}}).partial, "a hit without its source is a hit not read"
    assert mappers.values({"a": {"b": [1, None, {"c": 1}, "x"]}}, "a.b") == ["1", "x"] and mappers.values({"a": 1}, "a.b") == []
    assert mappers.when("2026-10-19T07:28:01.928+0000") == datetime(2026, 10, 19, 7, 28, 1, 928000, tzinfo=UTC)
    assert mappers.when("2026-10-19T07:28:01") is None and mappers.when(None) is None and mappers.when("soon") is None
