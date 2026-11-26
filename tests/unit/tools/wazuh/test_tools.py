"""The Wazuh evidence tools on the corpus telemetry (INT3.4): the facts, the as-of rule, the outcomes.

The four tools run through the tool registry against the offline event store (``corpus_v1`` and
``corpus_skills_v1`` with their context events). The gold evidence files say which malicious indicators
are true of every item of the two skill families and which benign proof its telemetry supports; here the
same readings are made from the tools' facts alone and must agree with the gold, item by item.
"""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

import pytest

from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, event_time, field_values
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.llm.trace import content_hash, tool_input_hash, use_tape
from lg_sotf.models.evidence_fact import EvidenceFact, fact_is_complete, parse_fact
from lg_sotf.tools.registry import ToolParamsInvalid
from lg_sotf.tools.wazuh import dsl
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from lg_sotf.tools.wazuh.tools import (
    HOST_ACTIVITY,
    LOGON_FANOUT,
    PREVALENCE,
    PROCESS_LINEAGE,
    Evidence,
    register_wazuh_tools,
    wazuh_tools,
)
from tests.fixtures.attack_corpus import gold
from tests.fixtures.attack_corpus.fleet import HOSTS
from tests.unit.tools._support import Ctx, Settings, registry
from tests.unit.tools.wazuh._support import (
    Corpus,
    Investigation,
    corpus,
    fake_secret,
    investigate,
    minutes,
    nothing_found,
    over,
    raw,
)

pytestmark = pytest.mark.unit

CORPORA = ("corpus_v1", "corpus_skills_v1")
PSEXESVC = "C:\\Windows\\PSEXESVC.exe"
DAY = 1_440


def _value(fact: Optional[EvidenceFact]) -> Any:
    return fact.value if fact is not None else None


def _number(fact: Optional[EvidenceFact], name: str) -> int:
    return getattr(fact.value, name) if fact is not None else 0


def _names(fact: Optional[EvidenceFact], name: str) -> List[str]:
    return list(getattr(fact.value, name)) if fact is not None else []


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


# ---- the logon-failure family: spray, guessing, typo, stale credentials ---------------------------------------


async def _logon_reading(c: Corpus, item: Any) -> Tuple[Set[str], Set[str]]:
    """``(malicious indicators, benign proofs supported)`` of a 4625 or 4740 alert, read from the tools' facts."""
    alert, at, user = item.alert, event_time(item.alert), raw(item.alert, "targetUserName").casefold()
    if field_values(alert, dsl.EVENT_ID) == ["4740"]:
        host: Optional[str] = raw(alert, "callerComputerName") or None
        ip = HOSTS[host].ip if host in HOSTS else None
    else:
        ip = raw(alert, "ipAddress") or None
        host = next((h.name for h in HOSTS.values() if h.ip == ip), None)
    look = investigate(c, item, settle_min=10)
    window = {"at": at, "after_min": 10}
    by_ip = {"pivot": "source_ip", "value": ip, **window}
    near = await look.fact("logon_fanout", before_min=30, **by_ip) if ip and _is_address(ip) else None
    day = await look.fact("logon_fanout", before_min=DAY, **by_ip) if ip and _is_address(ip) else None
    caller = await look.fact("logon_fanout", pivot="source_host", value=host, before_min=DAY, **window) if host else None
    by_user = await look.fact("logon_fanout", pivot="target_user", value=user, before_min=DAY, **window)
    # A fact counts every logon of its pivot, successes too. Which of the account's sources *failed* is read
    # by asking about each source in turn: no call can be narrowed to one outcome.
    failing = 0
    for source in _names(by_user, "sources"):
        seen = await look.fact("logon_fanout", pivot="source_ip", value=source, before_min=DAY, **window) if _is_address(source) else None
        failing += user in _names(seen, "failed_users")
    failed_near, failed_day = _names(near, "failed_users"), _names(day, "failed_users")
    indicators = {
        "password_spray": len(failed_near) >= 3 or len(failed_day) >= 5,
        "guessing": failing >= 3 or _number(near, "unknown_user_failures") >= 3,
        "valid_account_after_failures": len(failed_near) >= 2 and _number(near, "successes") >= 1,
        "lockouts_from_one_source": _number(caller, "lockouts") >= 2,
    }
    quick = near.value.first_success_after_failure_s if near is not None else None
    proofs = {
        "typo_then_success": raw(alert, "subStatus") == "0xc000006a" and failed_near == [user]
        and _number(near, "failures") <= 3 and quick is not None and quick <= 600
        and set(_names(near, "success_users")) <= {user} and failed_day == [user]
        and all(fact_is_complete(f) for f in (near, day) if f is not None),
        "stale_credentials": failed_day == [user] and _number(day, "successes") == 0 and failing <= 2,
    }
    return {name for name, true in indicators.items() if true}, {name for name, true in proofs.items() if true}


@pytest.mark.parametrize("name", CORPORA)
async def test_logon_fanout_facts_give_the_gold_indicators_and_proofs(name: str) -> None:
    c = corpus(name)
    items = [c.items[item_id] for item_id, entry in c.gold.items() if entry["skill"] == gold.LOGON_SKILL]
    assert len(items) >= 34
    for item in items:
        entry = c.gold[item.id]
        indicators, proofs = await _logon_reading(c, item)
        assert indicators == set(entry["malicious_indicators"]), item.id
        if entry["benign_hypothesis"] is not None:
            assert entry["benign_hypothesis"] in proofs, item.id
    sprays = [i for i in items if "password_spray" in c.gold[i.id]["malicious_indicators"]]
    assert len(sprays) >= 10, "the spray items are in the comparison"


async def test_the_password_spray_reads_as_the_adr_describes_it() -> None:
    """ADR 0014 section 1.4: four accounts tried from 10.20.1.83, and a success for sbrown."""
    c = corpus("corpus_v1")
    item = c.items["cv1-0021"]
    at = event_time(item.alert)
    fact = await investigate(c, item, 10).fact(
        "logon_fanout", pivot="source_ip", value="10.20.1.83", at=at, before_min=30, after_min=10
    )
    assert fact is not None and fact.kind == "logon_fanout" and fact.subject.model_dump() == {"type": "ip", "value": "10.20.1.83"}
    value = fact.value
    assert (value.failures, value.successes, value.distinct_target_users, value.distinct_sources) == (4, 1, 4, 1)
    assert value.failed_users == ["aturner", "lgarcia", "mjones", "sbrown"] and value.success_users == ["sbrown"]
    assert value.first_success_after_failure_s == 60 and value.logon_types == ["3"]
    assert value.source_hosts == ["sales-ws-03"] and value.sources == ["10.20.1.83"]  # a host name is given in lower case
    assert (value.window_start, value.window_end) == (at - minutes(30), at + minutes(10))
    assert fact.complete is True and fact.source.model_dump() == {"name": LOGON_FANOUT, "version": "1"}
    # The reference reading of the same window agrees, number for number.
    reference = gold.fanout(c.store.as_of(at + minutes(10)), at, before_min=30, ip="10.20.1.83", host="SALES-WS-03")
    assert (reference.failures, reference.successes, list(reference.failed_users), list(reference.success_users)) == (
        value.failures, value.successes, value.failed_users, value.success_users)
    assert int(reference.first_success_after_failure_s or -1) == value.first_success_after_failure_s
    # The lockout names the workstation, not the address: the source-host pivot counts it.
    caller = await investigate(c, item, 10).fact(
        "logon_fanout", pivot="source_host", value="SALES-WS-03", at=at, before_min=DAY, after_min=10
    )
    assert caller is not None and (caller.value.lockouts, reference.lockouts) == (1, 1) and value.lockouts == 0


# ---- the service-install family: PsExec, the IT-admin look-alike, vendor updaters ------------------------------


async def _service_facts(c: Corpus, item: Any) -> Dict[str, Any]:
    alert, at, host = item.alert, event_time(item.alert), str(item.alert["agent"]["name"])
    look = investigate(c, item, settle_min=15)
    if field_values(alert, dsl.EVENT_ID) == ["7045"]:
        image_path = raw(alert, "imagePath")
        subject = {"image": gold.service_exe(image_path)}
    else:  # a process PsExec started: the alert names PSEXESVC by its process GUID
        image_path = gold.PSEXESVC_SERVICE_PATH
        subject = {"process_guid": raw(alert, "parentProcessGuid")}
    return {
        "inbound": await look.fact("logon_fanout", pivot="target_host", value=host, at=at, before_min=15, after_min=1),
        # One fact per process that matches (a list): a 7045 names an image, which several processes may have.
        "lineage": await look.facts("process_lineage", host=host, at=at, after_min=15, **subject),
        "seen": await look.fact("prevalence", kind="service_image_path", value=image_path, days=30),
        "around": await look.fact("host_activity", host=host, at=at, before_min=30, after_min=15),
    }


def _service_reading(item: Any, facts: Mapping[str, Any]) -> Tuple[Set[str], Set[str]]:
    alert, at = item.alert, event_time(item.alert)
    install = field_values(alert, dsl.EVENT_ID) == ["7045"]
    image_path = raw(alert, "imagePath") if install else gold.PSEXESVC_SERVICE_PATH
    exe = gold.service_exe(image_path) if install else raw(alert, "parentImage")
    psexec = gold.basename(exe) == "psexesvc.exe"
    seen = _value(facts["seen"])
    children = [child for lineage in facts["lineage"] for child in lineage.value.children or []]
    sources, users = _names(facts["inbound"], "sources"), set(_names(facts["inbound"], "success_users"))
    first_seen = seen.first_seen_at if seen is not None and seen.first_seen_at is not None else at
    indicators = {
        "binary_in_user_writable_path": gold.path_class(image_path) in ("user_writable", "unc"),
        "new_binary": _number(facts["seen"], "host_count") <= 1 or at - first_seen <= timedelta(days=1),
        "lateral_from_unsanctioned_source": psexec and _number(facts["inbound"], "distinct_sources") >= 2,
        "discovery_through_the_service": any((child.image_name or "").lower() in gold.DISCOVERY_IMAGES for child in children),
        "hands_on_keyboard_nearby": bool(set(_names(facts["around"], "techniques")) & set(gold.HANDS_ON_TECHNIQUES)),
    }
    routine = all(child.command_template in gold.ROUTINE_REMOTE_ADMIN_COMMANDS for child in children)
    proofs = {
        "sanctioned_remote_admin": psexec and len(sources) == 1 and sources[0] in gold.DECLARED.admin_workstation_ips
        and bool(users) and users <= set(gold.DECLARED.admin_accounts) and routine
        and all(fact_is_complete(fact) for fact in (facts["inbound"], facts["around"], *facts["lineage"]) if fact is not None),
        "vendor_updater_service": not psexec and gold.path_class(image_path) == "program_files"
        and _number(facts["seen"], "host_count") >= 10 and at - first_seen >= timedelta(days=7),
    }
    return {name for name, true in indicators.items() if true}, {name for name, true in proofs.items() if true}


@pytest.mark.parametrize("name", CORPORA)
async def test_lineage_prevalence_and_host_activity_facts_give_the_gold_indicators_and_proofs(name: str) -> None:
    c = corpus(name)
    items = [c.items[item_id] for item_id, entry in c.gold.items() if entry["skill"] == gold.SERVICE_SKILL]
    assert len(items) >= 18
    for item in items:
        entry = c.gold[item.id]
        indicators, proofs = _service_reading(item, await _service_facts(c, item))
        assert indicators == set(entry["malicious_indicators"]), item.id
        if entry["benign_hypothesis"] is not None:
            assert entry["benign_hypothesis"] in proofs, item.id
    proven = {c.gold[i.id]["benign_hypothesis"] for i in items}
    found = {n for i in items for n in c.gold[i.id]["malicious_indicators"]}
    assert "sanctioned_remote_admin" in proven and "discovery_through_the_service" in found, "PsExec and its look-alike are compared"


async def test_psexec_and_the_it_admin_lookalike_differ_in_what_the_service_started() -> None:
    """ADR 0014 section 1.5: ``cv1-0113`` (ransomware) and ``cv1-0069`` (desktop support) raise the same alert."""
    c = corpus("corpus_v1")
    attack, admin = c.items["cv1-0113"], c.items["cv1-0069"]
    facts = {item.id: await _service_facts(c, item) for item in (attack, admin)}
    assert len(facts[attack.id]["lineage"]) == 1, "one PSEXESVC process started around the alert"
    lineage = facts[attack.id]["lineage"][0].value
    assert [node.image_name for node in lineage.chain] == ["services.exe", "PSEXESVC.exe"]
    assert lineage.chain[0].started_at is None and lineage.chain[1].started_at == event_time(attack.alert) + timedelta(seconds=2.11)
    # Two levels: the shell PsExec started, and what the shell ran (the discovery commands are the grandchildren).
    assert [(child.image_name, child.command_template) for child in lineage.children] == [
        ("cmd.exe", "cmd.exe /c whoami /all & ipconfig /all"), ("whoami.exe", "whoami /all"), ("ipconfig.exe", "ipconfig /all")]
    assert all(child.process_guid and child.started_at for child in lineage.children)
    one_level = await investigate(c, attack).fact(
        "process_lineage", host="SRV-APP-02", image=PSEXESVC, at=event_time(attack.alert), after_min=15, child_depth=1)
    assert one_level is not None and [child.image_name for child in one_level.value.children] == ["cmd.exe"]
    around = _value(facts[attack.id]["around"])
    assert "T1562.001" in around.techniques and around.max_level == 12 and around.total == len(around.events) == 7
    assert around.events[0].level == 12 and around.events[0].image_name == "powershell.exe"  # highest level first
    assert _names(facts[attack.id]["inbound"], "source_hosts") == ["mkt-ws-11"]
    assert _service_reading(attack, facts[attack.id]) == ({"discovery_through_the_service", "hands_on_keyboard_nearby"}, set())
    # Desktop support: the declared admin workstation, an admin account, one routine command.
    benign = facts[admin.id]
    assert _names(benign["inbound"], "sources") == ["10.20.1.120"] and _names(benign["inbound"], "success_users")[0].startswith("adm.")
    assert [child.command_template for child in benign["lineage"][0].value.children] == ["gpupdate /force"]
    assert _service_reading(admin, benign) == (set(), {"sanctioned_remote_admin"})
    assert all(fact.complete is True for fact in (benign["inbound"], benign["around"], *benign["lineage"]))
    # A process named by its GUID gives the same children as the same process named by its image.
    child_alert = next(i for i in c.items.values() if i.alert["rule"]["id"] == "92068")
    (by_guid,) = (await _service_facts(c, child_alert))["lineage"]
    assert by_guid.value.chain[-1].image_name == "PSEXESVC.exe" and by_guid.value.children and by_guid.complete is True


async def test_prevalence_counts_the_agents_and_reports_the_window_it_covered() -> None:
    c = corpus("corpus_v1")
    item = c.items["cv1-0057"]  # the Edge updater registers its service: on a dozen hosts for over two weeks
    look, at = investigate(c, item), event_time(item.alert)
    path = raw(item.alert, "imagePath")
    fact = await look.fact("prevalence", kind="service_image_path", value=path, days=30)
    assert fact is not None and fact.subject.model_dump() == {"type": "service", "value": path}
    value = fact.value
    assert (value.scope, value.host_count, value.event_count, value.fleet_size) == ("tenant_fleet", 12, 12, None)
    assert value.last_seen_at == at and at - value.first_seen_at >= timedelta(days=7) and value.window_end == look.as_of
    # The store holds 26 days: a 30-day window is not covered, and the fact says where its coverage starts.
    oldest = c.store.as_of(look.as_of).first_time(EventQuery())
    assert value.window_start == oldest and fact.complete is False
    covered = await look.fact("prevalence", kind="service_image_path", value=path, days=20)
    assert covered is not None and covered.complete is True and covered.value.window_start == look.as_of - timedelta(days=20)
    assert covered.value.host_count == 12
    by_name = await look.fact("prevalence", kind="service_name", value=raw(item.alert, "serviceName"), days=20)
    assert by_name is not None and by_name.value.host_count == 12
    image = await look.fact("prevalence", kind="process_image", value=PSEXESVC, days=20)
    assert image is not None and image.subject.type == "process" and image.value.host_count >= 2
    digest = next(d["syscheck"]["sha256_after"] for d in c.store.as_of(look.as_of).select(
        EventQuery()) if d.get("syscheck", {}).get("sha256_after"))
    by_hash = await look.fact("prevalence", kind="sha256", value=digest.upper(), days=20)
    assert by_hash is not None and by_hash.subject.model_dump() == {"type": "file", "value": digest} and by_hash.value.host_count >= 1


async def test_sshd_logons_are_read_by_rule_group() -> None:
    c = corpus("corpus_v1")
    sshd = [d for d in c.store.as_of(datetime(2100, 1, 1, tzinfo=UTC)).select(EventQuery()) if d["decoder"]["name"] == "sshd"]
    guess = next(d for d in sshd if "invalid_login" in d["rule"]["groups"])  # a failed logon for a user that does not exist
    at, ip = event_time(guess), guess["data"]["srcip"]
    window = [d for d in sshd if d["data"].get("srcip") == ip and at - minutes(DAY) <= event_time(d) <= at + minutes(10)]
    failed = [d for d in window if "authentication_failed" in d["rule"]["groups"]]
    fact = await Investigation(c.store, at + minutes(15)).fact(
        "logon_fanout", pivot="source_ip", value=ip, at=at, before_min=DAY, after_min=10, family="sshd")
    assert fact is not None and (fact.value.family, fact.value.failures) == ("sshd", len(failed)) and failed
    assert fact.value.unknown_user_failures == sum("invalid_login" in d["rule"]["groups"] for d in failed) >= 1
    assert fact.value.successes == sum("authentication_success" in d["rule"]["groups"] for d in window)
    assert fact.value.failed_users == sorted({d["data"]["dstuser"] for d in failed if "dstuser" in d["data"]})
    assert (fact.value.lockouts, fact.value.source_hosts, fact.value.logon_types) == (0, [], [])
    assert fact.value.distinct_target_hosts == len({d["agent"]["name"] for d in window}) and fact.value.sources == [ip]
    # The same pivot in the Windows family reads other documents: an sshd logon is not a Windows logon.
    assert await Investigation(c.store, at + minutes(15)).fact(
        "logon_fanout", pivot="source_ip", value=ip, at=at, before_min=DAY, after_min=10) is None
    login = next(d for d in sshd if "authentication_success" in d["rule"]["groups"])
    by_user = await Investigation(c.store, event_time(login) + minutes(15)).fact(
        "logon_fanout", pivot="target_user", value=login["data"]["dstuser"], at=event_time(login), before_min=60, after_min=10,
        family="sshd")
    assert by_user is not None and by_user.value.successes >= 1 and by_user.value.success_users == [login["data"]["dstuser"]]
    assert login["data"]["srcip"] in by_user.value.sources
    # An sshd user name is exact (Linux tells Root from root); a host name is not.
    assert await Investigation(c.store, event_time(login) + minutes(15)).fact(
        "logon_fanout", pivot="target_user", value=login["data"]["dstuser"].upper(), at=event_time(login), before_min=60, family="sshd") is None
    by_host = await Investigation(c.store, at + minutes(15)).fact(
        "logon_fanout", pivot="target_host", value=guess["agent"]["name"].upper(), at=at, before_min=60, family="sshd")
    assert by_host is not None and by_host.value.failures >= 1


# ---- the as-of rule ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", CORPORA)
async def test_no_fact_holds_an_event_after_the_investigation_time(name: str) -> None:
    c = corpus(name)
    for item in list(c.items.values())[::9]:
        at, host = event_time(item.alert), str(item.alert["agent"]["name"])
        look = Investigation(c.store, at)  # investigated the moment the alert was raised
        around = await look.fact("host_activity", host=host, at=at, before_min=60, after_min=60)
        assert around is not None, "the alert itself is in the window"
        assert all(event.at <= at for event in around.value.events) and around.value.total == len(around.value.events)
        later = await Investigation(c.store, at + minutes(60)).fact("host_activity", host=host, at=at, before_min=60, after_min=60)
        assert later is not None and later.value.total >= around.value.total
        # The window reaches an hour past the investigation: what the fact shows is a lower bound, and it says so.
        assert around.complete is False and later.complete is True
        seen = await look.fact("prevalence", kind="process_image", value=PSEXESVC, days=30)
        assert seen is None or (seen.value.last_seen_at <= at and seen.value.window_end == at)


async def test_the_success_after_a_typo_is_invisible_until_it_has_happened() -> None:
    c = corpus("corpus_v1")
    item = c.scenario("noise:logon-typo")[0]
    at, ip = event_time(item.alert), raw(item.alert, "ipAddress")
    params = {"pivot": "source_ip", "value": ip, "at": at, "before_min": 30, "after_min": 10}
    early = await Investigation(c.store, at).fact("logon_fanout", **params)
    settled = await Investigation(c.store, at + minutes(10)).fact("logon_fanout", **params)
    assert early is not None and settled is not None
    assert (early.value.successes, early.value.first_success_after_failure_s, early.complete) == (0, None, False)
    assert settled.value.successes == 1 and settled.value.first_success_after_failure_s is not None and settled.complete is True
    lineage_item = c.items["cv1-0113"]
    start = event_time(lineage_item.alert)
    before = await Investigation(c.store, start + timedelta(seconds=4)).fact(
        "process_lineage", host="SRV-APP-02", image=PSEXESVC, at=start, after_min=15)
    assert before is not None and before.value.children == [] and before.complete is False


# ---- outcomes -----------------------------------------------------------------------------------------------


def _doc(n: int, at: datetime, agent: str = "SRV-01", groups: int = 1, **eventdata: str) -> Dict[str, Any]:
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"
    return {
        "id": f"1790000000.{n}", "timestamp": stamp, "agent": {"name": agent},
        "rule": {"id": "100100", "level": 3 + n % 5, "groups": [f"group_{n}_{g}" for g in range(groups)],
                 "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": eventdata}},
    }


T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


def _store(count: int, groups: int = 1, **eventdata: str) -> EventStore:
    old = _doc(10_000, T0 - timedelta(days=40), agent="OLD-01")  # the index reaches back 40 days
    return EventStore([old, *(_doc(n, T0 + timedelta(seconds=n), groups=groups, **eventdata) for n in range(count))])


async def test_nothing_found_is_empty_and_never_a_fact() -> None:
    look = Investigation(_store(3), T0 + minutes(30))
    for tool, params in (
        (HOST_ACTIVITY, {"host": "NO-SUCH-HOST", "at": T0, "before_min": 5, "after_min": 5}),
        (LOGON_FANOUT, {"pivot": "source_ip", "value": "10.9.9.9", "at": T0, "before_min": 30}),
        (PROCESS_LINEAGE, {"host": "SRV-01", "image": "C:\\nothing.exe", "at": T0, "after_min": 5}),
        (PREVALENCE, {"kind": "service_name", "value": "nothing", "days": 7}),
    ):
        result = await look.tools.call(look.ctx, tool, params, agent="investigation")
        assert (result.outcome, result.rows, tuple(result.value), result.reason, result.value.error) == ("empty", 0, (), None, None)
        assert result.complete is True, "the search ran to its end on a closed, covered window: nothing is there"
    assert [step.outcome for step in look.ctx.trace.steps] == ["empty"] * 4
    # An empty answer on a window that is still open says so: later events may yet match.
    open_window = await Investigation(_store(3), T0).call("host_activity", host="NO-SUCH-HOST", at=T0, before_min=5, after_min=5)
    assert (open_window.outcome, open_window.complete) == ("empty", False)


class Down:
    """A backend that cannot be reached, or that answers something that is not a search response."""

    lag = timedelta(0)

    def __init__(self, reason: Optional[str] = None, answer: Any = None) -> None:
        self.reason, self.answer, self.searches = reason, answer, 0

    def now(self) -> datetime:
        return T0 + minutes(30)

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.searches += 1
        if self.reason is not None:
            raise IndexerUnavailable(self.reason)
        return self.answer


PARTIAL = nothing_found(timed_out=True)
UNASSIGNED = nothing_found(_shards={"total": 5, "successful": 3, "skipped": 0, "failed": 0})  # neither successful nor failed
NO_AGGREGATIONS = {key: value for key, value in nothing_found().items() if key != "aggregations"}
CALLS = (
    (HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 5, "after_min": 5}),
    (LOGON_FANOUT, {"pivot": "target_user", "value": "ann", "at": T0, "before_min": 30}),
    (PROCESS_LINEAGE, {"host": "SRV-01", "process_guid": "{" + "0" * 8 + "-0000-0000-0000-" + "0" * 12 + "}", "at": T0, "after_min": 5}),
    (PREVALENCE, {"kind": "service_name", "value": "svc", "days": 7}),
)


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (Down("unreachable"), "unreachable"),
        (Down("credentials_refused"), "credentials_refused"),
        (Down(answer={"error": {"type": "security_exception"}, "status": 403}), "bad_response"),
        (Down(answer=PARTIAL), "partial_answer"),  # it matched nothing, but it did not finish: not "nothing found"
        (Down(answer=UNASSIGNED), "partial_answer"),  # two of five shards were not searched
        (Down(answer=NO_AGGREGATIONS), "bad_response"),  # not the answer that was asked for
        (Down(answer={**nothing_found(), "aggregations": {"total": {"value": 0}}}), "bad_response"),
    ],
)
async def test_an_unreachable_or_refusing_indexer_is_failed_never_empty(backend: Down, reason: str) -> None:
    ctx = Ctx()
    for tool, params in CALLS:
        result = await over(backend).call(ctx, tool, params, agent="investigation")
        assert (result.outcome, result.value.error, result.complete, tuple(result.value)) == ("failed", reason, False, ())
        assert result.reason == "reported" and result.rows == 0
    assert [(step.outcome, step.error_type) for step in ctx.trace.steps] == [("failed", "reported")] * len(CALLS)
    if backend.reason is not None:
        assert backend.searches == len(CALLS), "one search each: a failed search is not retried"


async def test_missing_credentials_a_switched_off_tool_and_a_broken_tool_are_failed_with_a_bounded_reason() -> None:
    async def no_backend(ctx: Any) -> Any:
        raise IndexerUnavailable("credentials_missing")

    async def broken(ctx: Any) -> Any:
        raise RuntimeError(f"https://indexer.internal:9200 said: {fake_secret(3)}")

    tool, params = CALLS[0]
    missing = await registry(*wazuh_tools(no_backend)).call(Ctx(), tool, params, agent="a")
    assert (missing.outcome, missing.value.error, missing.reason) == ("failed", "credentials_missing", "reported")
    failed = await registry(*wazuh_tools(broken)).call(Ctx(), tool, params, agent="a")
    assert (failed.outcome, failed.value.error, failed.reason) == ("failed", "error", "error:RuntimeError")
    backend = Down("unreachable")
    for entry, reason in (({"enabled": False}, "disabled"), ("off", "disabled")):
        off = await over(backend, Settings({"wazuh_indexer": entry})).call(Ctx(), tool, params, agent="a")
        assert (off.outcome, off.value.error, off.reason, off.complete) == ("failed", reason, reason, False)
    unreadable = await over(backend, Settings(readable=False)).call(Ctx(), tool, params, agent="a")
    assert (unreadable.outcome, unreadable.value.error) == ("failed", "settings_unavailable")
    assert backend.searches == 0, "a switched-off tool sends nothing"
    on = await over(backend, Settings({"wazuh_indexer": {"enabled": True}})).call(Ctx(), tool, params, agent="a")
    assert on.value.error == "unreachable" and backend.searches == 1


async def test_a_capped_result_is_not_complete() -> None:
    at = T0 + minutes(1)
    window = {"host": "SRV-01", "at": at, "before_min": 5, "after_min": 5}
    whole = await Investigation(_store(dsl.MAX_HITS), T0 + minutes(30)).call("host_activity", **window)
    assert (whole.outcome, whole.complete, whole.value[0].complete, len(whole.value[0].value.events)) == ("success", True, True, 50)
    cut = await Investigation(_store(dsl.MAX_HITS + 10), T0 + minutes(30)).call("host_activity", **window)
    fact = cut.value[0]
    # 60 events: the 50 highest are listed, the count is exact, and neither the fact nor the result is complete.
    assert (cut.outcome, cut.rows, cut.complete, fact.complete) == ("success", 1, False, False)
    assert (fact.value.total, len(fact.value.events)) == (60, 50) and not fact_is_complete(fact)
    assert [event.level for event in fact.value.events[:13]] == [7] * 12 + [6], "the highest levels are the ones kept"
    # 30 events, all listed, but 60 rule groups: the list of groups is cut at 50, so the fact is not complete.
    groups = await Investigation(_store(30, groups=2), T0 + minutes(30)).call("host_activity", **window)
    assert (len(groups.value[0].value.events), len(groups.value[0].value.by_group), groups.complete) == (30, 50, False)
    # Children beyond the 50 a search returns: the lineage is not complete either. The process's own event is
    # there, so the cap is the only thing that makes the difference.
    guid = "{11111111-1111-1111-1111-111111111111}"
    old = _doc(9_000, T0 - timedelta(days=3), agent="OLD-01")
    parent = _doc(8_000, T0 - timedelta(seconds=30), image="C:\\\\x\\\\p.exe", processGuid=guid)
    docs = [_doc(n, T0 + timedelta(seconds=n), image="C:\\\\x\\\\child.exe", parentProcessGuid=guid, parentImage="C:\\\\x\\\\p.exe",
                 processGuid="{" + f"{n:08d}" + "-2222-2222-2222-222222222222}") for n in range(dsl.MAX_HITS + 5)]

    async def lineage(*events: Dict[str, Any]) -> Tuple[int, bool]:
        result = await Investigation(EventStore([old, *events]), T0 + minutes(30)).call(
            "process_lineage", host="SRV-01", process_guid=guid, at=T0, after_min=10, child_depth=1)
        assert result.outcome == "success" and result.value[0].value.chain[-1].name == "C:\\x\\p.exe"
        return len(result.value[0].value.children), result.complete

    assert await lineage(parent, *docs[:49]) == (49, True)
    assert await lineage(parent, *docs[:50]) == (50, False), "as many as one search returns: more may exist"
    assert await lineage(parent, *docs) == (50, False)
    # Without its own creation event the process is named by what its children say of it, and the fact is not complete.
    assert await lineage(*docs[:3]) == (3, False)


# ---- the registry: one step per call, hashes, replay ------------------------------------------------------------


class _Tape:
    def __init__(self, replays: bool, recorded: Optional[Dict[str, Any]] = None) -> None:
        self.replays_tools = replays
        self.recorded: Dict[str, Any] = dict(recorded or {})

    def replay_tool(self, tool_name: str, input_hash: str) -> Any:
        return self.recorded[input_hash]

    def record_tool(self, tool_name: str, request: Any, input_hash: str, observation: Any) -> None:
        self.recorded[input_hash] = observation

    def record_llm(self, *args: Any) -> None:
        raise AssertionError("no model call here")


async def test_every_call_is_one_trace_step_with_its_own_outcome_and_hashes() -> None:
    c = corpus("corpus_v1")
    item = c.items["cv1-0113"]
    look, at = investigate(c, item), event_time(item.alert)
    host = {"host": "SRV-APP-02", "at": at}
    calls = [
        ("host_activity", {**host, "before_min": 30, "after_min": 15}),
        ("process_lineage", {**host, "image": PSEXESVC, "after_min": 15}),
        ("logon_fanout", {"pivot": "source_ip", "value": "203.0.113.200", "at": at, "before_min": 30}),
    ]
    tape = _Tape(replays=False)
    with use_tape(tape):
        results = [await look.call(tool, **params) for tool, params in calls]
    steps = look.ctx.trace.steps
    assert [(s.kind, s.tool, s.outcome) for s in steps] == [
        ("tool", HOST_ACTIVITY, "success"), ("tool", PROCESS_LINEAGE, "success"), ("tool", LOGON_FANOUT, "empty")]
    assert [(r.input_hash, r.output_hash) for r in results] == [(s.input_hash, s.output_hash) for s in steps]
    assert len({r.input_hash for r in results}) == len({r.output_hash for r in results}) == 3
    # The hashes are of the request as validated and of the recorded facts: nothing a model wrote.
    request = {"host": "SRV-APP-02", "at": at.isoformat().replace("+00:00", "Z"), "before_min": 30, "after_min": 15,
               "exclude_rule_id": None}
    assert results[0].input_hash == tool_input_hash(HOST_ACTIVITY, request)
    recorded = tape.recorded[results[0].input_hash]
    assert results[0].output_hash == content_hash(recorded) and recorded["facts"][0]["kind"] == "host_activity"
    assert [parse_fact(f) for f in recorded["facts"]] == list(results[0].value), "what is recorded is the facts, in schema 1.1"
    # The ids an investigation cites, and the binding of each fact to these hashes, are the fact ledger's
    # (tests/unit/agents/investigation/test_ledger.py: the Wazuh tools' answers recorded as they come).
    # A replay answers from the recording and gives the same facts, outcome and hashes without asking the backend.
    silent = Down("unreachable")
    with use_tape(_Tape(replays=True, recorded=tape.recorded)):
        replayed = [await over(silent).call(Ctx(), f"wazuh.{tool}", params, agent="investigation") for tool, params in calls]
    assert silent.searches == 0 and [tuple(r.value) for r in replayed] == [tuple(r.value) for r in results]
    assert [(r.outcome, r.complete, r.output_hash) for r in replayed] == [(r.outcome, r.complete, r.output_hash) for r in results]


async def test_the_tools_are_declared_read_only_capped_and_switched_per_tenant() -> None:
    tools = over(Down("unreachable"))
    assert tools.names == [HOST_ACTIVITY, LOGON_FANOUT, PREVALENCE, PROCESS_LINEAGE]
    caps = {HOST_ACTIVITY: minutes(120), LOGON_FANOUT: minutes(1_500), PROCESS_LINEAGE: timedelta(days=1, minutes=30),
            PREVALENCE: timedelta(days=30)}
    for name in tools.names:
        spec = tools.get(name)
        assert (spec.version, spec.risk, spec.egress, spec.egress_boundary) == (1, "read_internal", "tenant_source", "wazuh_indexer")
        facts = 3 if name == PROCESS_LINEAGE else 1  # one per process an image names; one for everything else
        assert (spec.shadow, spec.tenant_setting, spec.row_cap, spec.window_cap) == ("live", "wazuh_indexer", facts, caps[name])
        assert spec.produces == frozenset({name.split(".")[1]}) and 0 < spec.time_cap_s <= 60
    with pytest.raises(ToolParamsInvalid):  # a bound the model states, before anything is asked
        await tools.call(Ctx(), HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 61, "after_min": 0}, agent="a")
    two = Evidence([parse_fact(EXAMPLE), parse_fact(EXAMPLE)])
    assert (len(two), two.complete, two.error) == (2, True, None) and Evidence(error="unreachable").complete is False

    # The registry counts the facts itself: a tool that answered with more than its cap is refused, whatever it says.
    async def two_facts(ctx: Any, params: Any) -> Evidence:
        return two

    async def nowhere(ctx: Any) -> Any:
        raise AssertionError("not asked")

    lying = replace(wazuh_tools(nowhere)[0], run=two_facts, rows=lambda evidence: 1)
    over_cap = await registry(lying).call(Ctx(), HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 1, "after_min": 0}, agent="a")
    assert (over_cap.outcome, over_cap.reason, over_cap.value.error, tuple(over_cap.value)) == ("failed", "row_cap", "row_cap", ())
    # The family registers on an existing registry, once.
    shared = registry()
    register_wazuh_tools(shared, nowhere)
    assert shared.names == tools.names
    with pytest.raises(ValueError, match="registered twice"):
        register_wazuh_tools(shared, nowhere)


async def test_the_ancestry_is_walked_up_to_the_asked_depth() -> None:
    def guid(n: int) -> str:
        return "{" + f"{n:08d}" + "-aaaa-bbbb-cccc-dddddddddddd}"

    names = ["winlogon.exe", "explorer.exe", "cmd.exe", "powershell.exe", "whoami.exe"]
    docs = [_doc(9_000, T0 - timedelta(days=3), agent="OLD-01")]
    for n in range(1, 5):  # explorer (1) started cmd (2), which started powershell (3), which started whoami (4)
        docs.append(_doc(n, T0 + timedelta(seconds=n), image=f"C:\\\\Windows\\\\{names[n]}", processGuid=guid(n), processId=str(100 + n),
                         parentProcessGuid=guid(n - 1), parentImage=f"C:\\\\Windows\\\\{names[n - 1]}", parentProcessId=str(99 + n)))
    look = Investigation(EventStore(docs), T0 + minutes(30))

    async def chain(depth: int) -> Tuple[List[Optional[str]], Optional[bool], List[Tuple[str, str]]]:
        fact = await look.fact("process_lineage", host="SRV-01", process_guid=guid(3), at=T0, after_min=10, depth=depth)
        assert fact is not None and [c.image_name for c in fact.value.children] == ["whoami.exe"]
        assert fact.value.chain[-1].started_at == T0 + timedelta(seconds=3) and fact.value.chain[-1].pid == 103
        return [node.image_name for node in fact.value.chain], fact.complete, [(r.path, r.reason) for r in fact.redactions]

    # The process above the oldest event found is named from that event's parent fields. A walk that used every
    # look-up and still has a parent above it was cut: the fact says so and is not complete.
    cut = [("/value/chain", "truncated")]
    assert await chain(0) == (["cmd.exe", "powershell.exe"], False, cut)
    assert await chain(1) == (["explorer.exe", "cmd.exe", "powershell.exe"], False, cut)
    whole = ["winlogon.exe", "explorer.exe", "cmd.exe", "powershell.exe"]
    assert await chain(2) == (whole, False, cut), "the second look-up found explorer; nothing says winlogon is the top"
    assert await chain(3) == await chain(8) == (whole, True, []), "the look-up above explorer found nothing: the chain ends there"
    by_image = await look.fact("process_lineage", host="SRV-01", image="C:\\Windows\\powershell.exe", at=T0, after_min=10, depth=1)
    assert by_image is not None and [node.process_guid for node in by_image.value.chain] == [guid(1), guid(2), guid(3)]


async def test_several_processes_of_one_image_are_each_described_and_none_is_complete() -> None:
    """An image names every process that started around the alert: a decoy seconds earlier cannot stand in for it."""
    def guid(n: int) -> str:
        return "{" + f"{n:08d}" + "-aaaa-bbbb-cccc-dddddddddddd}"

    ps = "C:\\\\Windows\\\\powershell.exe"
    old = _doc(9_000, T0 - timedelta(days=3), agent="OLD-01")
    decoy = _doc(1, T0 - timedelta(seconds=3), image=ps, processGuid=guid(11), parentProcessGuid=guid(10), parentImage="C:\\\\Windows\\\\explorer.exe")
    real = _doc(2, T0, image=ps, processGuid=guid(21), parentProcessGuid=guid(20), parentImage="C:\\\\Office\\\\WINWORD.EXE")
    child = _doc(3, T0 + timedelta(seconds=5), image="C:\\\\Windows\\\\whoami.exe", processGuid=guid(22), parentProcessGuid=guid(21), parentImage=ps)
    extra = [_doc(10 + n, T0 + timedelta(seconds=n), image=ps, processGuid=guid(30 + n)) for n in range(1, 4)]
    by_image = {"host": "SRV-01", "image": "C:\\Windows\\powershell.exe", "at": T0, "after_min": 10}

    look = Investigation(EventStore([old, decoy, real, child]), T0 + minutes(30))
    both = await look.call("process_lineage", **by_image)
    assert (both.outcome, both.rows, both.complete) == ("success", 2, False)
    assert [[node.image_name for node in fact.value.chain] for fact in both.value] == [
        ["explorer.exe", "powershell.exe"], ["WINWORD.EXE", "powershell.exe"]]
    assert [[c.image_name for c in fact.value.children] for fact in both.value] == [[], ["whoami.exe"]]
    assert [fact.complete for fact in both.value] == [False, False] and [fact.id for fact in both.value] == [
        "wazuh.process_lineage:0", "wazuh.process_lineage:1"]
    # The alert's own process, named by its GUID, is one process: its chain, its children, complete.
    own = await look.call("process_lineage", host="SRV-01", process_guid=guid(21), at=T0, after_min=10)
    assert (own.rows, own.complete) == (1, True) and [n.image_name for n in own.value[0].value.chain] == ["WINWORD.EXE", "powershell.exe"]
    alone = await Investigation(EventStore([old, real, child]), T0 + minutes(30)).call("process_lineage", **by_image)
    assert (alone.rows, alone.complete) == (1, True)
    # More matches than a call describes: the first three, and not a complete answer.
    many = await Investigation(EventStore([old, decoy, real, child, *extra]), T0 + minutes(30)).call("process_lineage", **by_image)
    assert (many.outcome, many.rows, many.complete) == ("success", 3, False)


EXAMPLE = {
    "id": "f:0", "kind": "prevalence", "subject": {"type": "service", "value": "svc"},
    "observed_at": "2026-11-02T09:00:00Z", "source": {"name": PREVALENCE, "version": "1"},
    "value": {"scope": "tenant_fleet", "window_start": "2026-10-03T09:00:00Z", "window_end": "2026-11-02T09:00:00Z",
              "host_count": 1, "event_count": 1},
}


async def test_a_second_tenants_telemetry_is_never_returned() -> None:
    """The backend is the calling run's own (``ctx.tenant_id``): no parameter can ask for another tenant's."""
    ours = _store(3, image="C:\\\\ours.exe")
    theirs = EventStore([_doc(n, T0 + timedelta(seconds=n), agent="THEIR-01", image="C:\\\\theirs.exe") for n in range(4)])
    stores = {"t1": ours, "t2": theirs}
    asked: List[str] = []

    async def backends(ctx: Any) -> EventStoreBackend:
        asked.append(ctx.tenant_id)
        return EventStoreBackend(stores[ctx.tenant_id].as_of(T0 + minutes(30)))

    tools = registry(*wazuh_tools(backends))
    for tenant, image, other_host, other_image in (
        ("t1", "C:\\ours.exe", "THEIR-01", "C:\\theirs.exe"),
        ("t2", "C:\\theirs.exe", "SRV-01", "C:\\ours.exe"),
    ):
        ctx = Ctx(tenant_id=tenant)
        own = await tools.call(ctx, PREVALENCE, {"kind": "process_image", "value": image, "days": 7}, agent="a")
        assert own.outcome == "success" and own.value[0].value.host_count == 1
        for tool, params in (
            (PREVALENCE, {"kind": "process_image", "value": other_image, "days": 7}),
            (HOST_ACTIVITY, {"host": other_host, "at": T0, "before_min": 5, "after_min": 5}),
            (PROCESS_LINEAGE, {"host": other_host, "image": other_image, "at": T0, "after_min": 5}),
        ):
            other = await tools.call(ctx, tool, params, agent="a")
            assert (other.outcome, tuple(other.value)) == ("empty", ()), (tenant, tool)
    assert asked == ["t1"] * 4 + ["t2"] * 4
    with pytest.raises(ToolParamsInvalid):  # there is no parameter to point a call anywhere else
        await tools.call(Ctx(), PREVALENCE, {"kind": "service_name", "value": "x", "days": 7, "tenant_id": "t2"}, agent="a")
    for stray in ({"index": "wazuh-alerts-*"}, {"base_url": "https://198.51.100.9:9200"}, {"source_id": "src-2"}):
        with pytest.raises(ToolParamsInvalid):
            await tools.call(Ctx(), HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 1, "after_min": 1, **stray}, agent="a")
