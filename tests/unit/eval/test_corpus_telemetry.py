"""Corpus telemetry, gold evidence and the in-memory event store (AI-E1.10).

``corpus_v1`` holds alerts only; an investigation skill (ADR 0014) reads what
surrounds an alert. These tests pin the generated context events, the gold
evidence, the ``corpus_skills_v1`` dataset and the :class:`EventStore` that
serves them offline. The checks on the telemetry are written against the
store with plain queries, not with the generator's own reading
(``tests/fixtures/attack_corpus/gold.py``), so a mistake there shows here.
"""

from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import pytest

from lg_sotf.eval.dataset import Dataset, EvalItem, load_dataset
from lg_sotf.eval.tool_fixtures import EVENT_ID_FIELD, EventQuery, EventStore, EventView, event_time, field_values
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.ingestion.normalizers.wazuh import WazuhNormalizer
from tests.fixtures.attack_corpus.catalog import RULES
from tests.fixtures.attack_corpus.corpus import sha256_text
from tests.fixtures.attack_corpus.files import (
    EVENTS_SKILLS,
    EVENTS_V1,
    GOLD_SKILLS,
    GOLD_V1,
    SKILLS,
    build_files,
    file_bytes,
)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
EVAL = ROOT / "tests" / "fixtures" / "eval"
DOCS = (ROOT / "docs" / "evaluation.md", EVAL / "README.md")
SHA256 = {
    EVENTS_V1: "8e7f65e11578eb450f3e28ee1b3771b31cca4d7f3a5ae3c79724e198c143cc48",
    GOLD_V1: "d58596bf299e87b9b01127aec8219e7b4a70af01ed262a871c8eba94acf04dff",
    SKILLS: "d4833621b875b1cf6fc638c0c4a017b30a1d73e6d540d4baab5665c7f4421679",
    EVENTS_SKILLS: "caefe42378c021bfa10ba0e34cff513b4694c2fb7142eb366656877fd9e874ce",
    GOLD_SKILLS: "f21cec799900fc00bafa8517b8a6f4e0c4b39ea458b2dbfdc775a3e9e734d4e5",
}
ED = "data.win.eventdata."
IT_WORKSTATION_IP = "10.20.1.120"
ADMIN_ACCOUNTS = ("adm.ksmith", "adm.tlee")
# ADR 0014 sections 1.4 and 1.5: the ids a gold file may name.
KNOWN = {
    "windows.logon_failure": {
        "rules": ["60122", "60204", "60115"],
        "benign": ["typo_then_success", "stale_credentials"],
        "malicious": ["password_spray", "guessing", "valid_account_after_failures", "lockouts_from_one_source"],
        "never_close": ["privileged_account", "public_source", "service_account_interactive_failure"],
    },
    "windows.service_install": {
        "rules": ["61138", "92068"],
        "benign": ["sanctioned_remote_admin", "vendor_updater_service"],
        "malicious": ["binary_in_user_writable_path", "new_binary", "lateral_from_unsanctioned_source",
                      "discovery_through_the_service", "hands_on_keyboard_nearby"],
        "never_close": ["crown_jewel_or_domain_controller", "service_runs_an_interpreter"],
    },
}
SKILL_RULES = {rule: skill for skill, entry in KNOWN.items() for rule in entry["rules"]}
# Benign corpus_v1 items the v1 skills cannot prove, and why (the telemetry, not the label, decides).
UNPROVABLE_V1 = {
    "cv1-0220": "the mapped drive's owner logged on from the same workstation that morning (a success from the source)",
    "cv1-0326": "the user was a target of the password spray three hours earlier (failures from three sources)",
    "cv1-0383": "the user was a target of the password spray the day before (failures from three sources)",
}


class Corpus:
    """A dataset with its context events, its gold evidence and the store over both."""

    def __init__(self, dataset: str, events: str, gold: str):
        self.dataset: Dataset = load_dataset(EVAL / dataset)
        self.events = [row for row in _jsonl(EVAL / events) if "_meta" not in row]
        self.events_meta = _jsonl(EVAL / events)[0]["_meta"]
        self.gold = json.loads((EVAL / gold).read_text(encoding="utf-8"))
        self.store = EventStore.load(EVAL / dataset, EVAL / events)
        self.skill_items = [i for i in self.dataset.items if i.alert["rule"]["id"] in SKILL_RULES]


def _jsonl(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in gzip.decompress(path.read_bytes()).decode("utf-8").splitlines()]


@pytest.fixture(scope="module")
def v1() -> Corpus:
    return Corpus("corpus_v1.jsonl.gz", EVENTS_V1, GOLD_V1)


@pytest.fixture(scope="module")
def skills() -> Corpus:
    return Corpus(SKILLS, EVENTS_SKILLS, GOLD_SKILLS)


def tag(item: EvalItem, prefix: str) -> Optional[str]:
    return next((t.split(":", 1)[1] for t in item.tags if t.startswith(prefix + ":")), None)


def value(doc: Mapping[str, Any], name: str) -> str:
    found = field_values(doc, ED + name)
    return found[0].replace("\\\\", "\\") if found else ""


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)


# ---------------------------------------------------------------------------------------------------------------------
# The files
# ---------------------------------------------------------------------------------------------------------------------


def test_the_events_file_is_reproduced_byte_for_byte(v1: Corpus) -> None:
    files = build_files()
    assert set(files) == set(SHA256)
    for name, text in files.items():
        assert file_bytes(name, text) == (EVAL / name).read_bytes(), (
            f"{name}: run `python -m tests.fixtures.attack_corpus generate`")
        assert sha256_text(text) == SHA256[name], name
        for doc in DOCS:
            assert SHA256[name] in doc.read_text(encoding="utf-8"), f"record the sha256 of {name} in {doc.name}"
    # The events belong to the corpus as committed: corpus_v1 itself is not rewritten (its own test pins its bytes).
    assert v1.events_meta["dataset"] == {"name": "corpus_v1", "sha256": v1.dataset.sha256}
    assert v1.gold["_meta"]["dataset"]["sha256"] == v1.dataset.sha256
    assert v1.gold["_meta"]["events"]["sha256"] == SHA256[EVENTS_V1]


def test_event_ids_are_unique_and_events_are_wazuh_documents_in_time_order(v1: Corpus, skills: Corpus) -> None:
    seen: Counter[str] = Counter()
    for corpus in (v1, skills):
        times = [event_time(doc) for doc in corpus.events]
        assert times == sorted(times)
        assert corpus.events_meta["composition"]["events"] == len(corpus.events) and corpus.events_meta["synthetic"]
        seen.update(str(doc["id"]) for doc in corpus.events)
        seen.update(str(item.alert["id"]) for item in corpus.dataset.items)
        for doc in corpus.events:
            assert set(doc) <= {"timestamp", "@timestamp", "rule", "agent", "manager", "id", "decoder", "data", "location"}
            assert doc["decoder"] == {"name": "windows_eventchannel"} and doc["manager"] == {"name": "wazuh-manager"}
            local = corpus.events_meta["local_rules"].get(doc["rule"]["id"])
            if local:  # Sysmon process creations reach alerts.json only through the lab's local rule
                assert doc["rule"]["level"] == local["level"] and field_values(doc, EVENT_ID_FIELD) == ["1"]
    assert max(seen.values()) == 1, "document ids must be unique across both datasets and their events"


# ---------------------------------------------------------------------------------------------------------------------
# The context an investigation reads, per scenario
# ---------------------------------------------------------------------------------------------------------------------


def _view(corpus: Corpus, item: EvalItem, after_min: float = 15) -> EventView:
    return corpus.store.as_of(event_time(item.alert) + minutes(after_min))


def _source(item: EvalItem) -> Tuple[str, str]:
    """The address and user a logon alert is about (a lockout names the calling computer instead)."""
    return value(item.alert, "ipAddress"), value(item.alert, "targetUserName")


def _typo(corpus: Corpus, item: EvalItem) -> None:
    at, (ip, user) = event_time(item.alert), _source(item)
    ok = _view(corpus, item).select(EventQuery(start=at, end=at + minutes(10), event_ids=("4624",),
                                               where={ED + "ipAddress": ip, ED + "targetUserName": user}))
    assert ok, f"{item.id}: no success of {user} from {ip} within ten minutes"


def _stale(corpus: Corpus, item: EvalItem) -> None:
    at, (ip, user) = event_time(item.alert), _source(item)
    view = corpus.store.as_of(at + minutes(120))
    retries = view.select(EventQuery(start=at - minutes(360), event_ids=("4625",),
                                     where={ED + "ipAddress": ip, ED + "targetUserName": user}))
    span = event_time(retries[-1]) - event_time(retries[0])
    assert len(retries) >= 5 and span >= timedelta(hours=2), f"{item.id}: no retry cadence over hours"
    assert view.distinct(EventQuery(start=at - minutes(360), event_ids=("4625",), where={ED + "ipAddress": ip}),
                         ED + "targetUserName") == [user], f"{item.id}: the device retries one account only"


def _spray(corpus: Corpus, item: EvalItem) -> None:
    at = event_time(item.alert)
    ip = value(item.alert, "ipAddress") or {"SALES-WS-03": "10.20.1.83", "ENG-WS-14": "10.20.1.64"}.get(
        value(item.alert, "callerComputerName"), "")
    if not ip:  # a lockout of the skills dataset: the caller's failures are checked through its other alerts
        return
    users = _view(corpus, item, 10).distinct(
        EventQuery(start=at - minutes(1440), event_ids=("4625",), where={ED + "ipAddress": ip}), ED + "targetUserName")
    wanted = 1 if "early-stage" in item.tags else 3
    assert len(users) >= wanted, f"{item.id}: {len(users)} accounts tried from {ip}"


def _inbound(corpus: Corpus, item: EvalItem) -> List[Dict[str, Any]]:
    at = event_time(item.alert)
    found = _view(corpus, item).select(EventQuery(agent=item.alert["agent"]["name"], start=at - minutes(15), end=at,
                                                  event_ids=("4624",), where={ED + "logonType": "3"}))
    assert found, f"{item.id}: no network logon on the target in the 15 minutes before"
    return found


def _psexec(corpus: Corpus, item: EvalItem) -> List[Dict[str, Any]]:
    """The PSEXESVC process of the alert's PsExec run and what it started, linked by process guid."""
    at, host = event_time(item.alert), item.alert["agent"]["name"]
    started = _view(corpus, item).select(EventQuery(agent=host, start=at - minutes(5), event_ids=("1",)))
    if item.alert["rule"]["id"] == "92068":
        roots = [d for d in started if value(d, "processGuid") == value(item.alert, "parentProcessGuid")]
    else:
        roots = [d for d in started if value(d, "image").lower().endswith("\\psexesvc.exe") and event_time(d) >= at]
    assert roots and value(roots[0], "image") == "C:\\Windows\\PSEXESVC.exe", f"{item.id}: no PSEXESVC process"
    guid = value(roots[0], "processGuid")
    children = [d for d in started if value(d, "parentProcessGuid") == guid]
    assert children, f"{item.id}: PSEXESVC started nothing"
    grandchildren = [d for d in started if value(d, "parentProcessGuid") in {value(c, "processGuid") for c in children}]
    return [*children, *grandchildren]


def _it_admin(corpus: Corpus, item: EvalItem) -> None:
    logons = _inbound(corpus, item)
    assert {value(d, "ipAddress") for d in logons} == {IT_WORKSTATION_IP}, item.id
    assert {value(d, "targetUserName") for d in logons} <= set(ADMIN_ACCOUNTS), item.id
    for child in _psexec(corpus, item):
        assert value(child, "image").rsplit("\\", 1)[-1] in ("gpupdate.exe", "klist.exe", "shutdown.exe"), item.id


def _lateral(corpus: Corpus, item: EvalItem) -> None:
    logons = _inbound(corpus, item)
    names = {value(d, "workstationName") for d in logons}
    if tag(item, "scenario") == "campaign:lateral-ransomware":
        assert names <= {"MKT-WS-11", "ENG-WS-19"} and len(names) == 1, item.id
    elif "context-abuse" in item.tags:
        assert names == {"IT-WS-01"}, item.id
    else:
        assert "IT-WS-01" not in names, item.id
    images = {value(d, "image").rsplit("\\", 1)[-1] for d in _psexec(corpus, item)}
    if tag(item, "scenario") != "skills:psexec-two-sources":
        assert images & {"whoami.exe", "nltest.exe", "net.exe", "quser.exe", "systeminfo.exe", "ipconfig.exe"}, item.id


def _fleet(corpus: Corpus, item: EvalItem) -> None:
    at = event_time(item.alert)
    earlier = _view(corpus, item).select(EventQuery(start=at - timedelta(days=30), end=at - timedelta(days=7),
                                                    event_ids=("7045",),
                                                    where={ED + "imagePath": field_values(item.alert, ED + "imagePath")}))
    hosts = {d["agent"]["name"] for d in earlier}
    assert len(hosts) >= 10, f"{item.id}: the updater is on {len(hosts)} hosts a week before"


def _new_service(corpus: Corpus, item: EvalItem) -> None:
    at, host = event_time(item.alert), item.alert["agent"]["name"]
    view = _view(corpus, item)
    around = view.select(EventQuery(agent=host, start=at - minutes(1), end=at + minutes(1), event_ids=("1",)))
    if tag(item, "scenario") not in ("skills:service-interpreter", "skills:new-software"):
        assert any("sc.exe" in value(d, "image") and value(item.alert, "serviceName") in value(d, "commandLine")
                   for d in around), f"{item.id}: no sc.exe create"
    hosts = view.distinct(EventQuery(start=at - timedelta(days=30), event_ids=("7045",),
                                     where={ED + "imagePath": field_values(item.alert, ED + "imagePath")}), "agent.name")
    assert len(hosts) <= 3, f"{item.id}: the binary is on {len(hosts)} hosts"


def _service_account(corpus: Corpus, item: EvalItem) -> None:
    at, (ip, user) = event_time(item.alert), _source(item)
    assert value(item.alert, "logonType") == "10" and user.startswith("svc_")
    assert _view(corpus, item).select(EventQuery(start=at, event_ids=("4624",), where={
        ED + "ipAddress": ip, ED + "targetUserName": user, ED + "logonType": "10"})), f"{item.id}: no success after"


def _forgotten(corpus: Corpus, item: EvalItem) -> None:
    at, user = event_time(item.alert), value(item.alert, "targetUserName")
    view = corpus.store.as_of(at + minutes(60))
    assert view.count(EventQuery(start=at - minutes(5), event_ids=("4767",), where={ED + "targetUserName": user})) == 1
    assert view.count(EventQuery(start=at - minutes(5), event_ids=("4740",), where={ED + "targetUserName": user})) == 1


CONTEXT: Dict[str, Callable[[Corpus, EvalItem], None]] = {
    "noise:logon-typo": _typo, "skills:typo": _typo,
    "lookalike:stale-credentials": _stale, "skills:stale-phone": _stale, "skills:stale-drive": _stale,
    "campaign:password-spray": _spray, "skills:spray-burst": _spray, "skills:spray-lockouts": _spray,
    "skills:spray-from-admin-workstation": _spray, "skills:slow-spray": _spray, "skills:invented-users": _spray,
    "skills:many-sources": lambda corpus, item: None,  # one account, many sources: checked through its gold below
    "skills:service-account-interactive": _service_account,
    "skills:forgotten-password": _forgotten,
    "lookalike:it-admin": _it_admin, "skills:it-admin": _it_admin,
    "campaign:lateral-ransomware": _lateral, "skills:psexec-lateral": _lateral, "skills:psexec-two-sources": _lateral,
    "skills:psexec-admin-account-discovery": _lateral,
    "lookalike:windows-patching": _fleet, "skills:vendor-update": _fleet,
    "atomic-sweep": _new_service, "skills:service-user-writable": _new_service,
    "skills:service-masquerade": _new_service, "skills:service-interpreter": _new_service,
    "skills:service-outside-maintenance-window": _new_service, "skills:new-software": _new_service,
}


def test_every_skill_item_has_its_context_events(v1: Corpus, skills: Corpus) -> None:
    assert Counter(SKILL_RULES[i.alert["rule"]["id"]] for i in v1.skill_items) == {
        "windows.logon_failure": 34, "windows.service_install": 18}
    assert len(skills.skill_items) == len(skills.dataset.items)
    checked: Counter[str] = Counter()
    for corpus in (v1, skills):
        for item in corpus.skill_items:
            scenario = str(tag(item, "scenario"))
            CONTEXT[scenario](corpus, item)
            checked[scenario] += 1
    assert set(checked) == set(CONTEXT), "a scenario of a skill family has no context check"
    # The estate's history before the window: IT's PsExec sessions over the previous four weeks.
    first = min(event_time(i.alert) for i in v1.dataset.items)
    history = v1.store.as_of(first).select(EventQuery(event_ids=("7045",), where={ED + "serviceName": "PSEXESVC"}))
    assert len(history) == 12 and first - event_time(history[0]) <= timedelta(days=29)


# ---------------------------------------------------------------------------------------------------------------------
# The event store
# ---------------------------------------------------------------------------------------------------------------------


def test_the_event_store_never_returns_events_after_the_as_of_time(v1: Corpus, skills: Corpus) -> None:
    for corpus in (v1, skills):
        last = max(event_time(d) for d in corpus.store.as_of(datetime(2100, 1, 1, tzinfo=UTC)).select(EventQuery()))
        for item in corpus.skill_items:
            at = event_time(item.alert)
            as_of = at + minutes(10)  # occurred_at + settle
            view = corpus.store.as_of(as_of)
            everything = view.select(EventQuery())
            assert everything and all(event_time(d) <= as_of for d in everything), item.id
            assert len(everything) < len(corpus.store) or as_of >= last
            # A window that reaches past the as-of time is cut there, whatever the query asks for.
            late = EventQuery(agent=item.alert["agent"]["name"], start=at - minutes(30), end=at + timedelta(days=30))
            found = view.select(late)
            assert any(d["id"] == item.alert["id"] for d in found) and all(event_time(d) <= as_of for d in found)
            assert view.count(late) == len(found)
            assert view.last_time(late) is not None and view.last_time(late) <= as_of  # type: ignore[operator]
            assert view.first_time(late) == event_time(found[0])
            assert set(view.distinct(late, "rule.id")) == {d["rule"]["id"] for d in found}
            assert view.select(EventQuery(start=as_of + timedelta(milliseconds=1))) == []
    # The success after a typo exists in the store, and is invisible until it has happened.
    typo = next(i for i in v1.skill_items if tag(i, "scenario") == "noise:logon-typo")
    success = EventQuery(event_ids=("4624",), where={ED + "ipAddress": value(typo.alert, "ipAddress")},
                         start=event_time(typo.alert))
    assert v1.store.as_of(event_time(typo.alert)).count(success) == 0
    assert v1.store.as_of(event_time(typo.alert) + minutes(10)).count(success) == 1


def test_times_must_be_timezone_aware() -> None:
    store = EventStore([])
    with pytest.raises(ValueError, match="timezone-aware"):
        store.as_of(datetime(2026, 10, 19))
    with pytest.raises(ValueError, match="timezone-aware"):
        EventQuery(start=datetime(2026, 10, 19))
    assert len(store) == 0 and store.as_of(datetime(2026, 10, 19, tzinfo=UTC)).first_time(EventQuery()) is None
    assert store.as_of(datetime(2026, 10, 19, tzinfo=UTC)).last_time(EventQuery()) is None


def _doc(doc_id: str, at: str, agent: str, rule: str, event_id: str, **eventdata: Any) -> Dict[str, Any]:
    return {"id": doc_id, "timestamp": at, "agent": {"name": agent}, "rule": {"id": rule, "groups": ["windows", "x"]},
            "data": {"win": {"system": {"eventID": event_id}, "eventdata": eventdata}}}


def test_event_queries_filter_by_agent_time_event_id_and_field(tmp_path: Path) -> None:
    docs = [
        _doc("3", "2026-10-19T10:02:00.000+0000", "DC-01", "60106", "4624", targetUserName="ann", ipAddress="10.0.0.1"),
        _doc("1", "2026-10-19T10:00:00.000+0000", "DC-01", "60122", "4625", targetUserName="ann", ipAddress="10.0.0.1"),
        _doc("2", "2026-10-19T10:01:00.000+0000", "DC-02", "60122", "4625", targetUserName="bob", ipAddress="10.0.0.1"),
        _doc("4", "2026-10-19T10:03:00.000+0000", "DC-01", "60122", "4625", targetUserName="cy", ipAddress="10.0.0.2",
             nothing=None, nested={"a": 1}),
    ]
    plain = tmp_path / "events.jsonl"
    plain.write_text("\n".join(json.dumps(d) for d in [{"_meta": {"name": "x"}}, *docs[:2]]) + "\n\n", encoding="utf-8")
    packed = tmp_path / "items.jsonl.gz"  # dataset items: the store reads their alert
    packed.write_bytes(gzip.compress("\n".join(json.dumps({"id": f"i{n}", "alert": d, "expected": {}})
                                               for n, d in enumerate(docs[2:])).encode("utf-8")))
    store = EventStore.load(plain, str(packed))
    assert len(store) == 4
    view = store.as_of(datetime(2026, 10, 19, 10, 2, 30, tzinfo=UTC))
    assert [d["id"] for d in view.select(EventQuery())] == ["1", "2", "3"]  # time order, nothing after the as-of time
    assert [d["id"] for d in view.select(EventQuery(agent="DC-01"))] == ["1", "3"]
    assert [d["id"] for d in view.select(EventQuery(event_ids=("4625",)))] == ["1", "2"]
    assert [d["id"] for d in view.select(EventQuery(rule_ids=("60106", "99999")))] == ["3"]
    assert [d["id"] for d in view.select(EventQuery(where={ED + "targetUserName": ["ann", "bob"]}))] == ["1", "2", "3"]
    assert [d["id"] for d in view.select(EventQuery(where={ED + "targetUserName": "ann", "rule.groups": "x"}))] == ["1", "3"]
    assert view.select(EventQuery(where={"rule.groups": "y"})) == [] and view.select(EventQuery(where={"a.b.c": "1"})) == []
    assert [d["id"] for d in view.select(EventQuery(), limit=2)] == ["1", "2"] and view.select(EventQuery(), limit=-1) == []
    start = datetime(2026, 10, 19, 10, 1, tzinfo=UTC)
    assert [d["id"] for d in view.select(EventQuery(start=start, end=start))] == ["2"]  # both bounds inclusive
    failures = EventQuery(event_ids=("4625",), where={ED + "ipAddress": "10.0.0.1"})
    assert (view.count(failures), view.distinct_count(failures, ED + "targetUserName")) == (2, 2)
    assert view.distinct(failures, "agent.name") == ["DC-01", "DC-02"] and view.first_time(failures) == event_time(docs[1])
    assert view.last_time(failures) == start
    later = store.as_of(datetime(2026, 10, 20, tzinfo=UTC))
    assert later.count(EventQuery(event_ids=("4625",))) == 3 and later.as_of.tzinfo is not None
    # A null value and an object are not values; a list field matches on any element.
    assert field_values(docs[3], ED + "nothing") == [] and field_values(docs[3], ED + "nested") == []
    assert field_values(docs[3], "rule.groups") == ["windows", "x"] and field_values(docs[3], "rule.id.x") == []


# ---------------------------------------------------------------------------------------------------------------------
# Gold evidence
# ---------------------------------------------------------------------------------------------------------------------


def test_gold_evidence_names_known_hypotheses_and_indicators(v1: Corpus, skills: Corpus) -> None:
    for corpus in (v1, skills):
        gold, items = corpus.gold["items"], {i.id: i for i in corpus.skill_items}
        assert corpus.gold["_meta"]["skills"] == KNOWN and corpus.gold["_meta"]["synthetic"] is True
        assert list(gold) == list(items), "one gold entry per skill item, in dataset order"
        known_ids = {str(d["id"]) for d in corpus.events} | {str(i.alert["id"]) for i in corpus.dataset.items}
        for item_id, entry in gold.items():
            item, skill = items[item_id], KNOWN[entry["skill"]]
            assert entry["skill"] == SKILL_RULES[item.alert["rule"]["id"]] == (item.family if corpus is skills else entry["skill"])
            assert entry["disposition"] == item.expected.disposition
            assert entry["benign_hypothesis"] is None or entry["benign_hypothesis"] in skill["benign"], item_id
            assert set(entry["malicious_indicators"]) <= set(skill["malicious"]), item_id
            assert set(entry["never_close"]) <= set(skill["never_close"]), item_id
            assert set(entry["evidence"]) <= known_ids - {item.alert["id"]}, item_id
            assert entry["evidence"] == sorted(set(entry["evidence"]))
            if entry["disposition"] == "malicious":
                assert entry["benign_hypothesis"] is None, item_id
                assert entry["malicious_indicators"] or entry["never_close"] or "early-stage" in item.tags, (
                    f"{item_id}: an attack no indicator and no never-close condition catches")
                assert entry["evidence"] or entry["never_close"] or "early-stage" in item.tags, item_id
            elif entry["benign_hypothesis"] is not None:  # a proof, so nothing may speak against it
                assert not entry["malicious_indicators"] and not entry["never_close"] and entry["evidence"], item_id
    by_id = v1.gold["items"]
    unprovable = {i for i, e in by_id.items() if e["disposition"] == "benign" and e["benign_hypothesis"] is None}
    assert unprovable == set(UNPROVABLE_V1)
    assert v1.gold["_meta"]["composition"] == {
        "windows.logon_failure": {"malicious": 10, "benign": 24, "benign_provable": 21},
        "windows.service_install": {"malicious": 7, "benign": 11, "benign_provable": 11}}
    # The corpus items ADR 0014 section 1.5 walks through.
    assert {"discovery_through_the_service", "hands_on_keyboard_nearby"} <= set(by_id["cv1-0113"]["malicious_indicators"])
    assert by_id["cv1-0069"]["benign_hypothesis"] == "sanctioned_remote_admin"
    assert by_id["cv1-0057"]["benign_hypothesis"] == "vendor_updater_service"
    assert "binary_in_user_writable_path" in by_id["cv1-0071"]["malicious_indicators"]
    assert {"password_spray", "valid_account_after_failures"} <= set(by_id["cv1-0021"]["malicious_indicators"])
    # In the skills dataset every benign variant built for a proof has it; two variants are benign without one.
    for item in skills.skill_items:
        entry, scenario = skills.gold["items"][item.id], tag(item, "scenario")
        if entry["disposition"] == "benign":
            expected = {"skills:typo": "typo_then_success", "skills:stale-phone": "stale_credentials",
                        "skills:stale-drive": "stale_credentials", "skills:it-admin": "sanctioned_remote_admin",
                        "skills:vendor-update": "vendor_updater_service"}.get(str(scenario))
            assert entry["benign_hypothesis"] == expected, item.id
            assert entry["malicious_indicators"] == (["new_binary"] if scenario == "skills:new-software" else []), item.id


# ---------------------------------------------------------------------------------------------------------------------
# corpus_skills_v1
# ---------------------------------------------------------------------------------------------------------------------

# What each attack variant must show in its gold evidence (an indicator or a never-close condition).
VARIANT_MARKERS = {
    "skills:spray-burst": "password_spray", "skills:spray-lockouts": "lockouts_from_one_source",
    "skills:invented-users": "guessing", "skills:spray-from-admin-workstation": "password_spray",
    "skills:service-account-interactive": "service_account_interactive_failure",
    "skills:psexec-lateral": "discovery_through_the_service",
    "skills:psexec-admin-account-discovery": "discovery_through_the_service",
    "skills:service-user-writable": "binary_in_user_writable_path", "skills:service-masquerade": "new_binary",
    "skills:service-interpreter": "service_runs_an_interpreter",
    "skills:service-outside-maintenance-window": "new_binary",
}


def test_corpus_skills_v1_has_50_attacks_per_family_with_context_abuse(skills: Corpus) -> None:
    items, meta = skills.dataset.items, skills.dataset.meta
    assert meta["synthetic"] is True and meta["composition"]["items"] == len(items)
    counts = Counter((i.family, i.expected.disposition) for i in items)
    for family in KNOWN:
        assert counts[(family, "malicious")] >= 50, family
        assert counts[(family, "benign")] >= 30, family  # a skill is gated on what it closes, too
    assert set(counts) == {(f, d) for f in KNOWN for d in ("malicious", "benign")}
    for item in items:
        assert item.source_type == "wazuh" and item.split == "standard" and item.notes
        assert item.family == SKILL_RULES[item.alert["rule"]["id"]] == tag(item, "skill")
        assert item.expected.escalation is (item.expected.disposition == "malicious")
        marker = VARIANT_MARKERS.get(str(tag(item, "scenario")))
        entry = skills.gold["items"][item.id]
        if marker:
            assert marker in entry["malicious_indicators"] + entry["never_close"], item.id
    second = [i for i in items if tag(i, "scenario") == "skills:psexec-two-sources"]
    assert sum("lateral_from_unsanctioned_source" in skills.gold["items"][i.id]["malicious_indicators"] for i in second) >= 2
    early = [i for i in items if "early-stage" in i.tags]
    assert early and {tag(i, "scenario") for i in early} == {"skills:slow-spray", "skills:many-sources"}
    # Context abuse: attacks that sit inside what the tenant declared, so the declaration alone closes nothing.
    context = skills.dataset.tenant_context
    assert context is not None
    abuse: Dict[str, List[EvalItem]] = {}
    for item in items:
        kind = tag(item, "abuse")
        assert (kind is not None) == ("context-abuse" in item.tags)
        if kind:
            assert item.expected.disposition == "malicious", item.id
            abuse.setdefault(kind, []).append(item)
    assert set(abuse) == {"admin-workstation-spray", "admin-account-discovery", "outside-maintenance-window",
                          "service-account-interactive"}
    assert meta["composition"]["context_abuse"] == {kind: len(found) for kind, found in sorted(abuse.items())}
    admin_ips = {ip for jump in context.jump_hosts for ip in jump.ips if "psexec" in jump.tools}
    for item in abuse["admin-workstation-spray"]:
        source = value(item.alert, "ipAddress") or IT_WORKSTATION_IP
        assert source in admin_ips and (value(item.alert, "callerComputerName") or "IT-WS-01") == "IT-WS-01", item.id
    for item in abuse["admin-account-discovery"]:
        logons = _inbound(skills, item)
        assert {value(d, "ipAddress") for d in logons} <= admin_ips, item.id
        assert {value(d, "targetUserName") for d in logons} <= set(context.admin_accounts), item.id
    for item in abuse["outside-maintenance-window"]:
        host, at = item.alert["agent"]["name"], event_time(item.alert)
        windows = [w for w in context.patch_windows if host in w.hosts]
        assert windows and not any(w.covers(at, [host]) for w in windows), item.id
    for item in abuse["service-account-interactive"]:
        assert value(item.alert, "targetUserName") in context.automation_accounts, item.id
        assert value(item.alert, "logonType") in ("2", "10", "11"), item.id
    # The benign updaters on servers are inside the declared window: only the abuse is outside it.
    for item in items:
        host = item.alert["agent"]["name"]
        if tag(item, "scenario") == "skills:vendor-update" and host.startswith("SRV-"):
            assert any(w.covers(event_time(item.alert), [host]) for w in context.patch_windows), item.id


def test_skills_alerts_and_events_carry_the_4_14_rule_metadata_and_normalise(v1: Corpus, skills: Corpus) -> None:
    normalizer = WazuhNormalizer()
    ctx = NormalizeContext(source_id="src-1", source_type="wazuh", now=datetime(2026, 11, 14, tzinfo=UTC))
    documents = [*(i.alert for i in skills.dataset.items), *skills.events, *v1.events]
    local = skills.events_meta["local_rules"]
    for doc in documents:
        rule = doc["rule"]
        source = RULES.get(rule["id"]) or local[rule["id"]]
        assert (rule["level"], rule["groups"]) == (source["level"], source["groups"]), doc["id"]
        assert rule.get("mitre", {}).get("id", []) == source.get("mitre", []), doc["id"]
        assert "$(" not in rule["description"] and re.fullmatch(r"\d{10}\.\d+", doc["id"])
        values = " ".join(str(v) for v in doc["data"]["win"]["eventdata"].values())
        assert "\\" not in values.replace("\\\\", ""), doc["id"]  # every backslash doubled, as 4.x writes them
        assert normalizer.normalize(doc, ctx).title == rule["description"]


def test_the_skills_dataset_keeps_the_estate_and_the_window_of_its_own(v1: Corpus, skills: Corpus) -> None:
    assert skills.dataset.meta["tenant_context"] == v1.dataset.meta["tenant_context"]
    assert skills.dataset.tenant_settings == v1.dataset.tenant_settings
    first = min(event_time(i.alert) for i in skills.dataset.items)
    assert first > max(event_time(i.alert) for i in v1.dataset.items)
    ids = [i.id for i in skills.dataset.items]
    assert ids == [f"csk1-{n:04d}" for n in range(1, len(ids) + 1)]
    times: Sequence[datetime] = [event_time(i.alert) for i in skills.dataset.items]
    assert list(times) == sorted(times)
