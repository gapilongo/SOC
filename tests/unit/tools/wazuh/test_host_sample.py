"""Issue 452 (AI-E3.3c): the events a busy host's fact lists are chosen in parts, not by rule level alone.

A host with more than 50 events in the window gets a sample. Whoever can raise alerts on the host chooses
how many there are, how loud they are and when they happen, so each of those is exercised against the part
it cannot reach: a quiet, early event of a never-close class under louder noise, under noise closer to the
alert, and under both; more never-close events than their share; and the reviewer's own scenario, a
technique seen once among sixty failed logons.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

import pytest

from lg_sotf.domain.closure import NEVER_CLOSE_TECHNIQUES
from lg_sotf.eval.tool_fixtures import EventStore
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.models.evidence_fact import MAX_LIST_ITEMS, EvidenceFact
from lg_sotf.tools.wazuh import dsl, templates
from lg_sotf.tools.wazuh.templates import NEAREST_SHARE, NEVER_CLOSE_SHARE, RARE_SHARE
from tests.unit.tools._support import Ctx
from tests.unit.tools.wazuh._support import minutes, over

pytestmark = pytest.mark.unit

AT = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
HOST = "FIN-SRV-02"
HOUR = {"host": HOST, "at": AT, "before_min": 60, "after_min": 0}
DUMPING = "T1003.001"  # a sub-technique of a never-close class
SCRIPTING = "T1059.001"  # not one


def event(n: int, before_s: float, *, level: int = 3, technique: Optional[str] = SCRIPTING, rule: str = "100100") -> Dict[str, Any]:
    at = AT - timedelta(seconds=before_s)
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"
    rule_: Dict[str, Any] = {"id": rule, "level": level, "groups": ["sysmon"]}
    if technique is not None:
        rule_["mitre"] = {"id": [technique]}
    return {"id": f"1790000000.{n}", "timestamp": stamp, "agent": {"name": HOST}, "rule": rule_}


class Recording:
    """The store as an indexer that remembers every search it was sent (each is checked against the allow-list)."""

    lag = timedelta(0)

    def __init__(self, documents: List[Dict[str, Any]], *, unfinished: str = "") -> None:
        old = {**event(99_999, 40 * 86_400), "agent": {"name": "OLD-01"}}  # the index reaches back 40 days
        self._inner = EventStoreBackend(EventStore([old, *documents]).as_of(AT + minutes(90)))
        self.bodies: List[Mapping[str, Any]] = []
        self.unfinished = unfinished
        """A technique id: the search that asks for it times out (it answers what it has)."""

    def now(self) -> datetime:
        return AT + minutes(90)

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.bodies.append(body)
        answer = await self._inner.search(body)
        return {**answer, "timed_out": True} if self.unfinished and self.unfinished in str(body["query"]) else answer


async def host(documents: List[Dict[str, Any]], backend: Optional[Recording] = None, **params: Any) -> EvidenceFact:
    result = await over(backend or Recording(documents)).call(Ctx(), "wazuh.host_activity", {**HOUR, **params}, agent="investigation")
    assert result.outcome == "success", result.value.error
    (fact,) = result.value
    return fact


def listed(fact: EvidenceFact, part: str) -> List[Any]:
    return [e for e in fact.value.events if e.listed_for == part]  # type: ignore[union-attr]


NOISE = {
    "louder": [event(100 + n, 60 + 40 * n, level=12) for n in range(80)],
    "closer in time": [event(100 + n, 1 + n) for n in range(80)],
    "louder and closer": [event(100 + n, 1 + n, level=15) for n in range(80)],
    "a flood": [event(100 + n, 1 + n % 3000, level=3 + n % 13) for n in range(1_000)],
}


@pytest.mark.parametrize("noise", list(NOISE), ids=list(NOISE))
async def test_an_event_of_a_never_close_class_is_listed_whatever_the_noise(noise: str) -> None:
    """One level-3 credential-dumping event 55 minutes before the alert: by level and by time it is last."""
    quiet = event(1, 3_300, technique=DUMPING, rule="92900")
    fact = await host([quiet, *NOISE[noise]])
    value = fact.value
    assert value.total == len(NOISE[noise]) + 1 and len(value.events) == MAX_LIST_ITEMS and fact.complete is False  # type: ignore[union-attr]
    (kept,) = listed(fact, "never_close_class")
    assert (kept.rule_id, kept.level, kept.at) == ("92900", 3, AT - timedelta(seconds=3_300))
    assert value.never_close_class_truncated is False, "every event of a never-close class is listed, and the fact says so"  # type: ignore[union-attr]
    assert all(e.listed_for is not None for e in value.events), "a sample says what each event is listed for"  # type: ignore[union-attr]
    # The same host when the search for those events did not finish: what it returned is listed, "all of them" is not said.
    late = await host([], Recording([quiet, *NOISE[noise]], unfinished=DUMPING))
    assert len(listed(late, "never_close_class")) == 1 and late.value.never_close_class_truncated is True  # type: ignore[union-attr]


@pytest.mark.parametrize("noise", list(NOISE), ids=list(NOISE))
async def test_as_many_never_close_events_as_their_share_are_all_listed(noise: str) -> None:
    quiet = [event(n, 3_000 + n, technique=sorted(NEVER_CLOSE_TECHNIQUES)[n % len(NEVER_CLOSE_TECHNIQUES)]) for n in range(NEVER_CLOSE_SHARE)]
    fact = await host([*quiet, *NOISE[noise]])
    assert {e.at for e in listed(fact, "never_close_class")} == {AT - timedelta(seconds=3_000 + n) for n in range(NEVER_CLOSE_SHARE)}
    assert fact.value.never_close_class_truncated is False  # type: ignore[union-attr]


async def test_more_never_close_events_than_their_share_are_a_sample_of_the_newest_and_the_fact_says_so() -> None:
    """Thirty quiet credential-access events, early in the hour, under eighty louder and closer ones."""
    many = [event(n, 1_800 + 60 * n, technique="T1110.001", rule="5710") for n in range(30)]
    fact = await host([*many, *NOISE["louder and closer"]])
    kept = listed(fact, "never_close_class")
    assert [e.at for e in kept] == [AT - timedelta(seconds=1_800 + 60 * n) for n in range(NEVER_CLOSE_SHARE)], "the newest, newest first"
    assert fact.value.never_close_class_truncated is True and fact.complete is False  # type: ignore[union-attr]
    assert len(fact.value.events) == MAX_LIST_ITEMS and "T1110.001" in fact.value.techniques  # type: ignore[union-attr]
    # One credential dump before all of them is not among the newest 20: it is kept as the technique seen least.
    dump = event(900, 3_590, technique=DUMPING, rule="92900")
    flooded = await host([dump, *many, *NOISE["louder and closer"]])
    assert [e.rule_id for e in listed(flooded, "rare_technique")] == ["92900"] and len(listed(flooded, "never_close_class")) == NEVER_CLOSE_SHARE
    # More techniques on the host than the fact lists: which of them are never-close is not known, and the fact says so.
    wide = [event(n, 10 + n, technique=f"T2{n:03d}") for n in range(60)]
    assert (await host(wide)).value.never_close_class_truncated is True  # type: ignore[union-attr]
    assert listed(await host(wide), "rare_technique") == []


async def test_a_technique_seen_once_is_listed_under_sixty_louder_failed_logons() -> None:
    """The reviewer's scenario: certutil decoding a payload (T1140, level 3), then 60 failed logons anybody can cause."""
    certutil = event(1, 3_000, technique="T1140", rule="92018")
    certutil["data"] = {"win": {"eventdata": {"image": "C:\\Windows\\System32\\certutil.exe", "commandLine": "certutil.exe -decode a.b64 loader.exe"}}}
    logons = [event(100 + n, 60 + 30 * n, level=5, technique="T1531", rule="60122") for n in range(60)]
    fact = await host([certutil, *logons])
    (kept,) = listed(fact, "rare_technique")
    assert (kept.image_name, kept.command_template) == ("certutil.exe", "certutil.exe -decode a.b64 loader.exe")
    assert len(listed(fact, "never_close_class")) == NEVER_CLOSE_SHARE and fact.value.never_close_class_truncated is True  # type: ignore[union-attr]
    # Volume makes the noise's own technique frequent; it cannot make another one less rare.
    flood = [event(1_000 + n, 1 + n % 3_500, level=14, technique="T1531", rule="60122") for n in range(2_000)]
    assert [e.rule_id for e in listed(await host([certutil, *logons, *flood]), "rare_technique")] == ["92018"]
    # Louder events of rules with no technique at all are in no technique's part: they cannot take its place either.
    unmapped = [event(400 + n, 10 + n, level=9, technique=None) for n in range(60)]
    assert [e.rule_id for e in listed(await host([certutil, *unmapped]), "rare_technique")] == ["92018"]
    # Rare means whole techniques that fit in the share together, the least seen first: eleven events of one are not rare.
    eleven = [event(200 + n, 3_100 + n, technique="T1105", rule="92100") for n in range(RARE_SHARE + 1)]
    assert [e.rule_id for e in listed(await host([certutil, *eleven, *logons]), "rare_technique")] == ["92018"]
    ones = [event(300 + n, 3_200 + n, technique=f"T10{20 + n}", rule=f"93{n:03d}") for n in range(RARE_SHARE + 2)]
    rare = listed(await host([*ones, *logons]), "rare_technique")
    assert sorted(e.rule_id for e in rare) == [f"93{n:03d}" for n in range(RARE_SHARE)], "ten whole techniques, by id on a tie"


async def test_the_events_closest_in_time_are_listed_before_and_after_the_alert() -> None:
    loud = [event(100 + n, (1_200 + 20 * n) * (1 if n % 2 else -1), level=12) for n in range(80)]  # 20 minutes away and more
    near = [event(n, seconds) for n, seconds in enumerate([-200, -90, -45, -30, -2, 0, 1, 15, 40, 60, 100, 300, 600])]
    fact = await host([*loud, *near], after_min=60)
    closest = listed(fact, "nearest_in_time")
    assert [(e.at - AT).total_seconds() for e in closest] == [0, -1, 2, -15, 30, -40, 45, -60, 90, -100]
    assert len(closest) == NEAREST_SHARE and len(listed(fact, "rule_level")) == MAX_LIST_ITEMS - NEAREST_SHARE
    assert [e.level for e in listed(fact, "rule_level")] == [12] * 40, "the rest is filled by level, as before"


async def test_a_window_the_fact_lists_whole_is_read_as_before() -> None:
    backend = Recording([event(n, 10 + n, level=3 + n % 5, technique=DUMPING) for n in range(MAX_LIST_ITEMS)])
    fact = await host([], backend)
    value = fact.value
    assert len(value.events) == value.total == MAX_LIST_ITEMS and fact.complete is True  # type: ignore[union-attr]
    assert value.never_close_class_truncated is None and all(e.listed_for is None for e in value.events)  # type: ignore[union-attr]
    assert [e.level for e in value.events[:11]] == [7] * 10 + [6], "highest level first"  # type: ignore[union-attr]
    assert len(backend.bodies) == 2, "the host search and the coverage search: nothing more is asked"
    assert "listed_for" not in fact.model_dump_json(exclude_none=True)


async def test_the_sample_is_bounded_and_the_same_however_the_index_holds_the_events() -> None:
    documents = [
        *[event(n, 1 + 7 * n, level=3 + n % 13, technique=["T1003", "T1486", SCRIPTING, "T1105", None][n % 5]) for n in range(400)],
        event(900, 3_599, technique="T1140"),
    ]
    backend = Recording(documents)
    first = await host([], backend)
    shuffled = list(documents)
    random.Random(452).shuffle(shuffled)
    assert (await host(shuffled)).value == first.value == (await host(documents)).value
    events = first.value.events  # type: ignore[union-attr]
    assert len(events) == MAX_LIST_ITEMS and len({(e.at, e.rule_id, e.level) for e in events}) == MAX_LIST_ITEMS, "no event twice"
    assert [e.listed_for for e in events] == sorted(
        (e.listed_for for e in events), key=["never_close_class", "rare_technique", "nearest_in_time", "rule_level"].index)
    assert len(listed(first, "never_close_class")) == NEVER_CLOSE_SHARE and first.value.never_close_class_truncated is True  # type: ignore[union-attr]
    # Five searches (the host's, three parts, the coverage), each one the allow-list passes and none above the row cap.
    assert len(backend.bodies) == 5 and all(body["size"] <= dsl.MAX_HITS for body in backend.bodies)
    for body in backend.bodies:
        dsl.check_search(dict(body))
    asked = [v for body in backend.bodies for clause in body["query"]["bool"]["filter"] for v in clause.get("terms", {}).get(dsl.TECHNIQUES, [])]
    assert sorted(asked) == ["T1003", "T1140", "T1486"], "only technique ids the indexer itself listed are asked for"


async def test_the_alerts_own_event_is_in_no_part_of_the_sample() -> None:
    """The alert is a level-12 brute-force event: newest, loudest and never-close, so every part would keep it."""
    own = [event(n, 0, level=12, technique="T1110", rule="5710") for n in (1, 2, 3)]  # the alert and two exact duplicates
    others = [event(100 + n, 60 + n, technique=DUMPING, rule="92900") for n in range(25)]
    fact = await host([*own, *others, *NOISE["louder"]], exclude_rule_id="5710")
    assert all(e.rule_id != "5710" for e in fact.value.events) and "T1110" not in fact.value.techniques  # type: ignore[union-attr]
    assert len(listed(fact, "never_close_class")) == NEVER_CLOSE_SHARE and fact.value.total == 105  # type: ignore[union-attr]
    assert fact.value.never_close_class_truncated is True  # type: ignore[union-attr]
    # Forty-five exact duplicates of the alert fill the search for never-close events, and three of the eight
    # others are not returned. The duplicates are never listed, and the fact does not say "all of them are".
    burst = [event(2_000 + n, 0, level=12, technique="T1110", rule="5710") for n in range(45)]
    older = [event(3_000 + n, 600 + n, technique="T1110", rule="5712") for n in range(8)]
    flooded = await host([*burst, *older, *NOISE["louder"]], exclude_rule_id="5710")
    assert all(e.rule_id != "5710" for e in flooded.value.events) and flooded.value.total == 88  # type: ignore[union-attr]
    assert len(listed(flooded, "never_close_class")) == 5 and flooded.value.never_close_class_truncated is True  # type: ignore[union-attr]


def test_the_sample_searches_take_ids_only_as_terms_and_ask_nothing_for_a_part_that_is_empty() -> None:
    params = templates.HostActivityParams(**HOUR)
    assert set(templates.host_sample(params, [], [])) == {"before"}
    both = templates.HostActivityParams(**{**HOUR, "after_min": 5})
    bodies = templates.host_sample(both, ["T1003"], ["T1140", "T1105"])
    assert list(bodies) == ["never_close", "rare", "before", "after"]
    for body in bodies.values():
        dsl.check_search(body)
        assert body["size"] == dsl.MAX_HITS and "aggs" not in body and body["_source"] == list(templates.EVENT_SOURCE)
    assert bodies["rare"]["query"]["bool"]["filter"][1] == {"terms": {dsl.TECHNIQUES: ["T1140", "T1105"]}}
    assert set(templates.host_sample(templates.HostActivityParams(**{**HOUR, "before_min": 0}), [], [])) == set()
