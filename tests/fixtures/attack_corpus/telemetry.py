"""Context telemetry around the corpus alerts (AI-E1.10): what an analyst queries next to an alert.

``corpus_v1`` holds the alerts only. An investigation skill (ADR 0014) reads
what surrounds an alert: who logged on to the host just before a service was
installed, what the service ran, whether a failed logon was followed by a
success, how often a device retries, how many hosts run a binary. This module
writes those events for the two skill families of ``corpus_v1`` (Windows logon
failures, Windows service installs and PsExec) into a sibling file,
``tests/fixtures/eval/corpus_v1_events.jsonl.gz``, in the Wazuh ``alerts.json``
document shape. ``corpus_v1.jsonl.gz`` itself is untouched: the events are
derived from its alerts and labels, never written back.

Per scenario (one seeded generator per corpus item, so adding an item never
changes another item's events):

* ``noise:logon-typo``: the 4624 success of the same user from the same address
  within four minutes of the 4625;
* ``lookalike:stale-credentials``: the retry cadence over hours (a phone every
  15 to 35 minutes, a mapped drive in bursts every 30 to 60 minutes; a drive
  starts failing only after its owner's last successful logon that day);
* ``lookalike:it-admin`` and ``campaign:lateral-ransomware``: the 4624 type 3
  network logon on the target before every PsExec 7045 and every PsExec child
  (from ``IT-WS-01`` with an ``adm.*`` account for desktop support, from
  ``MKT-WS-11`` and ``ENG-WS-19`` with the stolen operator account for the
  ransomware), the ``PSEXESVC.exe`` process and its Sysmon event 1 children
  (``gpupdate``/``klist``/``shutdown`` for IT; ``whoami`` and ``ipconfig`` under
  the ransomware's ``cmd.exe``), linked by ``processGuid``;
* ``atomic-sweep`` service installs: the ``sc.exe create`` that registered the
  service and the service's own process;
* the estate's history before the window: IT's PsExec sessions over the
  previous four weeks and the fleet installs of every vendor updater service
  (10 or more hosts, at least eight days before the window), which is what
  service-image prevalence reads.

Password spraying needs nothing extra: its failures, lockout and success are
corpus alerts already, and the event store serves them next to these events.

:mod:`.gold` reads the store (alerts and events) and writes the gold evidence
of the skill items; :mod:`.skills` builds the ``corpus_skills_v1`` dataset from
the same building blocks; :mod:`.files` lists what is written.

Plain Sysmon process creations are level 0 in the 4.14 ruleset, so they never
reach ``alerts.json``; the lab raises them with :data:`LOCAL_RULES` (the local
rule ADR 0014 section 3.1 names), which INT3.4's contract test loads.
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.eval.tool_fixtures import EventStore, event_time
from tests.fixtures.attack_corpus import alerts as A
from tests.fixtures.attack_corpus.alerts import Body, Ctx, pick, win
from tests.fixtures.attack_corpus.catalog import rule_block
from tests.fixtures.attack_corpus.corpus import BODY_ORDER, ID_PREFIX, Corpus
from tests.fixtures.attack_corpus.fleet import DCS, HOSTS, MANAGER, WIN_ADMINS, WIN_SERVERS, WORKSTATIONS, Host
from tests.fixtures.attack_corpus.gold import PSEXESVC_SERVICE_PATH, GoldRow, service_exe, skill_of
from tests.fixtures.attack_corpus.scenarios import INSTALLS, START, Truth

NAME = "corpus_v1_events"
VERSION = 1
#: Event ids continue a second ``alerts.json`` (the alert id is ``<epoch>.<byte offset>``), so they never collide.
OFFSET = 268_435_456
PROCESS_RULE = "100100"
LOCAL_RULES: Dict[str, Dict[str, Any]] = {
    # <rule id="100100" level="3"><if_sid>61603</if_sid>
    #   <description>Sysmon - Event 1: Process creation</description><group>sysmon_event1,</group></rule>
    PROCESS_RULE: {"level": 3, "description": "Sysmon - Event 1: Process creation",
                   "groups": ["windows", "sysmon", "sysmon_event1"], "if_sid": "61603"},
}
#: The benign hypothesis (ADR 0014 sections 1.4 and 1.5) each benign scenario of ``corpus_v1`` was written for.
HYPOTHESES: Dict[str, str] = {
    "noise:logon-typo": "typo_then_success",
    "lookalike:stale-credentials": "stale_credentials",
    "lookalike:it-admin": "sanctioned_remote_admin",
    "lookalike:windows-patching": "vendor_updater_service",
}
IT_WS = HOSTS["IT-WS-01"]
PSEXESVC = r"C:\Windows\PSEXESVC.exe"
SERVICES = r"C:\Windows\System32\services.exe"
CMD = r"C:\Windows\System32\cmd.exe"
SC = r"C:\Windows\System32\sc.exe"
#: What desktop support runs through PsExec (the routine commands of ADR 0014 section 1.5).
ROUTINE_PSEXEC = (
    (r"C:\Windows\System32\gpupdate.exe", "gpupdate /force"),
    (r"C:\Windows\System32\gpupdate.exe", "gpupdate /target:computer /force"),
    (r"C:\Windows\System32\klist.exe", "klist purge"),
    (r"C:\Windows\System32\shutdown.exe", "shutdown /r /t 300"),
)
WINDOWS_HOSTS: Tuple[Host, ...] = (*WORKSTATIONS, IT_WS, *WIN_SERVERS, *DCS)


@dataclass
class Event:
    at: datetime
    host: Host
    rule: str
    body: Body
    description: Optional[str] = None


class Tel:
    """Events of one episode, drawn from a generator seeded by the episode's key."""

    def __init__(self, key: str, namespace: str = NAME):
        self.key = key
        self.rng = random.Random(f"{namespace}:{key}")
        self.ctx = Ctx(self.rng)
        self.events: List[Event] = []

    def emit(self, at: datetime, host: Host, rule: str, body: Body, description: Optional[str] = None) -> Event:
        event = Event(at.replace(microsecond=at.microsecond // 1000 * 1000), host, rule, body, description)
        self.events.append(event)
        return event

    def seconds(self, at: datetime, lo: float, hi: float) -> datetime:
        """``at`` moved by ``lo`` to ``hi`` seconds (negative: earlier), millisecond precision."""
        when = at + timedelta(seconds=self.rng.uniform(lo, hi))
        return when.replace(microsecond=when.microsecond // 1000 * 1000)


# ---------------------------------------------------------------------------------------------------------------------
# Building blocks, shared with the skills dataset (tests/fixtures/attack_corpus/skills.py)
# ---------------------------------------------------------------------------------------------------------------------


def logon_success(tel: Tel, dc: Host, at: datetime, *, user: str, src_ip: str, workstation: str,
                  logon_type: int = 3) -> Event:
    return tel.emit(at, dc, "60106", A.logon(tel.ctx, dc, at, user=user, src_ip=src_ip, workstation=workstation,
                                             logon_type=logon_type))


def logon_failure(tel: Tel, dc: Host, at: datetime, *, user: str, src_ip: str, workstation: str,
                  logon_type: int = 3, sub_status: str = "0xc000006a", rule: str = "60122") -> Event:
    """4625; ``rule`` 60204 is the same event when it crosses the manager's failure threshold."""
    status = "0xc000006d"
    return tel.emit(at, dc, rule, A.logon(tel.ctx, dc, at, user=user, src_ip=src_ip, workstation=workstation,
                                             logon_type=logon_type, ok=False, status=status, sub_status=sub_status))


def lockout(tel: Tel, dc: Host, at: datetime, *, user: str, caller: str) -> Event:
    """4740: ``user`` locked out after failures from the computer ``caller``."""
    return tel.emit(at, dc, "60115", A.account_event(tel.ctx, dc, at, 4740, actor=f"{dc.name}$", target=user,
                                                     callerComputerName=caller))


def retries(tel: Tel, dc: Host, at: datetime, *, user: str, src_ip: str, workstation: str, start: datetime,
            end: datetime, every_min: Tuple[float, float], burst: Tuple[int, int] = (1, 1)) -> List[Event]:
    """A device retrying a stale password at a steady cadence; the slot ``at`` falls in is the alert's own."""
    period = tel.rng.uniform(*every_min) * 60
    found: List[Event] = []
    t = start
    while t < end:
        if abs((t - at).total_seconds()) > period / 2:
            moment = t
            for _ in range(tel.rng.randint(*burst)):
                found.append(logon_failure(tel, dc, moment, user=user, src_ip=src_ip, workstation=workstation))
                moment = tel.seconds(moment, 1, 4)
        t = tel.seconds(t, period * 0.9, period * 1.1)
    return found


def process_start(tel: Tel, host: Host, at: datetime, *, image: str, cmd: str, parent: str, parent_cmd: str,
                  user: str = "SYSTEM", guid: Optional[str] = None, parent_guid: Optional[str] = None,
                  rule: str = PROCESS_RULE, description: Optional[str] = None) -> Event:
    """Sysmon event 1; ``guid`` and ``parent_guid`` link it into a process tree."""
    body = A.process(tel.ctx, host, at, image=image, cmd=cmd, parent=parent, parent_cmd=parent_cmd, user=user,
                     integrity="System" if user == "SYSTEM" else "High")
    data = body["data"]["win"]["eventdata"]
    if guid:
        data["processGuid"] = guid
    if parent_guid:
        data["parentProcessGuid"] = parent_guid
    return tel.emit(at, host, rule, body, description)


def psexec_child(tel: Tel, host: Host, at: datetime, *, image: str, cmd: str, parent_guid: str,
                 guid: Optional[str] = None) -> Event:
    """A command PsExec ran (rule 92068: Sysmon event 1 with ``PSEXESVC.exe`` as the parent)."""
    return process_start(tel, host, at, image=image, cmd=cmd, parent=PSEXESVC, parent_cmd=PSEXESVC,
                         guid=guid, parent_guid=parent_guid, rule="92068",
                         description=f"PSEXEC was used to execute: {win(cmd)}")


def service_install(tel: Tel, host: Host, at: datetime, *, name: str, image: str, start: str = "demand start") -> Event:
    return tel.emit(at, host, "61138", A.service_installed(tel.ctx, host, at, name=name, image=image, start=start))


def psexec_service(tel: Tel, host: Host, at: datetime, *, guid: str) -> Tuple[Event, Event]:
    """PsExec's 7045 and the ``PSEXESVC.exe`` process the service control manager starts a moment later."""
    install = service_install(tel, host, at, name="PSEXESVC", image=PSEXESVC_SERVICE_PATH)
    started = process_start(tel, host, tel.seconds(at, 0.3, 1.2), image=PSEXESVC, cmd=PSEXESVC, parent=SERVICES,
                            parent_cmd=SERVICES, guid=guid)
    return install, started


def psexec_session(tel: Tel, target: Host, at: datetime, *, source_ip: str, source_name: str, account: str,
                   commands: Sequence[Tuple[str, str]]) -> List[Event]:
    """A complete PsExec run: network logon, service, ``PSEXESVC.exe`` and the commands it ran, from ``at``."""
    logon = logon_success(tel, target, tel.seconds(at, -40, -3), user=account, src_ip=source_ip,
                          workstation=source_name)
    guid = tel.ctx.guid()
    found = [logon, *psexec_service(tel, target, at, guid=guid)]
    t = tel.seconds(at, 2, 6)
    for image, cmd in commands:
        found.append(psexec_child(tel, target, t, image=image, cmd=cmd, parent_guid=guid))
        t = tel.seconds(t, 3, 40)
    return found


# ---------------------------------------------------------------------------------------------------------------------
# corpus_v1: one episode per skill item
# ---------------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Item:
    id: str
    alert: Mapping[str, Any]
    truth: Truth

    @property
    def at(self) -> datetime:
        return event_time(self.alert)

    @property
    def host(self) -> Host:
        return HOSTS[str(self.alert["agent"]["name"])]

    @property
    def rule(self) -> str:
        return str(self.alert["rule"]["id"])

    @property
    def data(self) -> Dict[str, str]:
        """The Windows ``eventdata`` with the decoder's doubled backslashes undone."""
        raw = ((self.alert.get("data") or {}).get("win") or {}).get("eventdata") or {}
        return {k: str(v).replace("\\\\", "\\") for k, v in raw.items()}


def corpus_items(corpus: Corpus) -> List[Item]:
    """The corpus items in dataset order, with the ids ``dataset_text`` gives them."""
    return [Item(f"{ID_PREFIX}-{i:04d}", a, corpus.labels[a["id"]]) for i, a in enumerate(corpus.alerts, start=1)]


def _typo(tel: Tel, item: Item) -> List[Event]:
    d = item.data
    return [logon_success(tel, item.host, tel.seconds(item.at, 20, 240), user=d["targetUserName"],
                          src_ip=d["ipAddress"], workstation=d["workstationName"])]


def _stale(tel: Tel, item: Item, last_success: Optional[datetime]) -> List[Event]:
    d = item.data
    phone = d["workstationName"] == "-"
    start = item.at - timedelta(hours=tel.rng.uniform(2, 5) if not phone else tel.rng.uniform(3, 6))
    if last_success is not None and last_success.date() == item.at.date():
        start = max(start, last_success + timedelta(minutes=tel.rng.uniform(15, 30)))
    end = item.at + timedelta(hours=tel.rng.uniform(1, 2))
    every, burst = ((15.0, 35.0), (1, 1)) if phone else ((30.0, 60.0), (2, 4))
    return retries(tel, item.host, item.at, user=d["targetUserName"], src_ip=d["ipAddress"],
                   workstation=d["workstationName"], start=start, end=end, every_min=every, burst=burst)


def _it_admin(tel: Tel, item: Item) -> List[Event]:
    account = pick(tel.rng, WIN_ADMINS)
    if item.rule == "61138":  # the 7045 is the alert: the logon before it, PSEXESVC and the routine command after
        logon = logon_success(tel, item.host, tel.seconds(item.at, -40, -3), user=account, src_ip=IT_WS.ip,
                              workstation=IT_WS.name)
        guid = tel.ctx.guid()
        started = process_start(tel, item.host, tel.seconds(item.at, 0.3, 1.2), image=PSEXESVC, cmd=PSEXESVC,
                                parent=SERVICES, parent_cmd=SERVICES, guid=guid)
        image, cmd = pick(tel.rng, ROUTINE_PSEXEC)
        return [logon, started, psexec_child(tel, item.host, tel.seconds(item.at, 2, 15), image=image, cmd=cmd,
                                             parent_guid=guid)]
    # the PsExec child is the alert: the logon, the 7045 and PSEXESVC before it, linked by the alert's parent guid
    install_at = tel.seconds(item.at, -4, -1.5)
    install = service_install(tel, item.host, install_at, name="PSEXESVC", image=PSEXESVC_SERVICE_PATH)
    logon = logon_success(tel, item.host, tel.seconds(install_at, -30, -3), user=account, src_ip=IT_WS.ip,
                          workstation=IT_WS.name)
    started = process_start(tel, item.host, tel.seconds(install_at, 0.3, 1.0), image=PSEXESVC, cmd=PSEXESVC,
                            parent=SERVICES, parent_cmd=SERVICES, guid=item.data["parentProcessGuid"])
    return [logon, install, started]


def _ransomware(tel: Tel, install: Item, child: Item, operator: str) -> List[Event]:
    match = re.search(r"PsExec from (\S+) copies", install.truth.procedure)
    if match is None:  # pragma: no cover - the scenario always names its source
        raise ValueError(f"{install.id}: no PsExec source in {install.truth.procedure!r}")
    source = HOSTS[match.group(1)]
    gap = (child.at - install.at).total_seconds()
    logon = logon_success(tel, install.host, tel.seconds(install.at, -40, -3), user=operator, src_ip=source.ip,
                          workstation=source.name)
    started = process_start(tel, install.host, tel.seconds(install.at, 0.3, max(0.4, gap - 0.5)), image=PSEXESVC,
                            cmd=PSEXESVC, parent=SERVICES, parent_cmd=SERVICES,
                            guid=child.data["parentProcessGuid"])
    shell, shell_cmd, guid = child.data["image"], child.data["commandLine"], child.data["processGuid"]
    t = tel.seconds(child.at, 0.1, 0.6)
    found = [logon, started]
    for image, cmd in ((r"C:\Windows\System32\whoami.exe", "whoami  /all"),
                       (r"C:\Windows\System32\ipconfig.exe", "ipconfig  /all")):
        found.append(process_start(tel, install.host, t, image=image, cmd=cmd, parent=shell, parent_cmd=shell_cmd,
                                   parent_guid=guid))
        t = tel.seconds(t, 0.4, 1.5)
    return found


def sc_create(tel: Tel, host: Host, at: datetime, *, name: str, image: str, user: str) -> List[Event]:
    """Around a 7045 at ``at``: the ``sc.exe create`` that registered the service, and the service's own process."""
    create = f'sc.exe  create {name} binPath= "{image}" start= auto'
    made = process_start(tel, host, tel.seconds(at, -3, -0.5), image=SC, cmd=create, parent=CMD,
                         parent_cmd=f"{CMD} /c {create}", user=user)
    ran = process_start(tel, host, tel.seconds(at, 1, 5), image=service_exe(image), cmd=image, parent=SERVICES,
                        parent_cmd=SERVICES)
    return [made, ran]


def _sweep_service(tel: Tel, item: Item) -> List[Event]:
    d = item.data
    return sc_create(tel, item.host, item.at, name=d["serviceName"], image=d["imagePath"],
                     user=item.host.owner or pick(tel.rng, WIN_ADMINS))


def _ransomware_operator(items: Sequence[Item], install: Item) -> str:
    """The account the operator later clears the Security log with (the campaign's 60117 alert on the host)."""
    for later in items:
        if (later.truth.scenario == install.truth.scenario and later.rule == "60117" and later.host == install.host
                and later.at > install.at):
            return later.data["subjectUserName"]
    raise ValueError(f"{install.id}: no log clearing after the PsExec")  # pragma: no cover - always generated


def item_episodes(items: Sequence[Item]) -> Dict[str, List[Event]]:
    """Context events per skill item id (an episode two alerts share is listed under both)."""
    episodes: Dict[str, List[Event]] = {}
    successes: Dict[str, List[datetime]] = {}  # source address -> the successes written after its typos
    ordered = sorted(items, key=lambda i: (i.truth.scenario != "noise:logon-typo", i.at))  # typos first
    for item in ordered:
        if skill_of(item.rule) is None:
            continue
        tel = Tel(item.id)
        scenario = item.truth.scenario
        if scenario == "noise:logon-typo":
            episodes[item.id] = _typo(tel, item)
            successes.setdefault(item.data["ipAddress"], []).append(max(e.at for e in episodes[item.id]))
        elif scenario == "lookalike:stale-credentials":
            earlier = [at for at in successes.get(item.data["ipAddress"], []) if at < item.at]
            episodes[item.id] = _stale(tel, item, max(earlier, default=None))
        elif scenario == "lookalike:it-admin":
            episodes[item.id] = _it_admin(tel, item)
        elif scenario == "campaign:lateral-ransomware" and item.rule == "61138":
            child = next(i for i in items if i.truth.scenario == scenario and i.rule == "92068"
                         and i.host == item.host and timedelta(0) < i.at - item.at < timedelta(minutes=1))
            shared = _ransomware(tel, item, child, _ransomware_operator(items, item))
            episodes[item.id] = episodes[child.id] = shared
        elif scenario == "atomic-sweep" and item.rule == "61138":
            episodes[item.id] = _sweep_service(tel, item)
        else:
            episodes.setdefault(item.id, [])  # spraying (the corpus alerts tell it), patching (fleet history)
    return episodes


# ---------------------------------------------------------------------------------------------------------------------
# The estate's history before the window
# ---------------------------------------------------------------------------------------------------------------------


def psexec_history(start: datetime, *, sessions: int, days: int, key: str = "history:psexec",
                   namespace: str = NAME) -> List[Event]:
    """IT's routine PsExec sessions from the admin workstation over ``days`` before ``start``."""
    tel = Tel(key, namespace)
    found: List[Event] = []
    for _ in range(sessions):
        day = start - timedelta(days=tel.rng.randrange(1, days + 1))
        at = day + timedelta(hours=tel.rng.uniform(8.5, 17.5))
        commands = [pick(tel.rng, ROUTINE_PSEXEC)]
        found += psexec_session(tel, pick(tel.rng, WORKSTATIONS), at, source_ip=IT_WS.ip, source_name=IT_WS.name,
                                account=pick(tel.rng, WIN_ADMINS), commands=commands)
    return found


def fleet_installs(start: datetime, *, key: str = "history:fleet", namespace: str = NAME,
                   products: Iterable[Tuple[str, str, str]] = INSTALLS) -> List[Event]:
    """Every vendor updater service registered on 10 to 14 Windows hosts, 8 to 17 days before ``start``."""
    tel = Tel(key, namespace)
    found: List[Event] = []
    for _product, service, image in products:
        if not service:
            continue
        for host in tel.rng.sample(WINDOWS_HOSTS, tel.rng.randint(10, 14)):
            day = start - timedelta(days=tel.rng.randint(8, 17))
            hours = (1.0, 5.0) if host.role != "workstation" else (9.0, 17.0)
            at = day + timedelta(hours=tel.rng.uniform(*hours))
            found.append(service_install(tel, host, at, name=service, image=image, start="auto start"))
    return found


def history(start: datetime = START, namespace: str = NAME) -> List[Event]:
    return psexec_history(start, sessions=12, days=28, namespace=namespace) + fleet_installs(start, namespace=namespace)


# ---------------------------------------------------------------------------------------------------------------------
# Documents and the file
# ---------------------------------------------------------------------------------------------------------------------


def _rule(rule_id: str, description: Optional[str]) -> Dict[str, Any]:
    local = LOCAL_RULES.get(rule_id)
    if local is None:
        return rule_block(rule_id, description)
    return {"level": local["level"], "description": description or local["description"], "id": rule_id,
            "mail": False, "groups": list(local["groups"])}


def _stamp(at: datetime) -> Tuple[str, str]:
    at = at.astimezone(UTC)
    base = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}"
    return base + "+0000", base + "Z"


def documents(events: Sequence[Event], *, offset: int = OFFSET) -> Tuple[List[Dict[str, Any]], Dict[int, str]]:
    """Wazuh documents in time order, and each event's document id (keyed by ``id(event)``)."""
    ordered = sorted(enumerate(events), key=lambda pair: (pair[1].at, pair[0]))
    fired: Counter[Tuple[str, str]] = Counter()
    docs: List[Dict[str, Any]] = []
    ids: Dict[int, str] = {}
    for _, event in ordered:
        timestamp, at_timestamp = _stamp(event.at)
        rule = _rule(event.rule, event.description)
        fired[(event.host.agent_id, event.rule)] += 1
        rule = {**{k: rule[k] for k in ("level", "description", "id")},
                "firedtimes": fired[(event.host.agent_id, event.rule)],
                **{k: v for k, v in rule.items() if k not in ("level", "description", "id")}}
        doc_id = f"{int(event.at.timestamp())}.{offset}"
        doc: Dict[str, Any] = {"timestamp": timestamp, "@timestamp": at_timestamp, "rule": rule,
                               "agent": event.host.agent(), "manager": {"name": MANAGER}, "id": doc_id}
        for key in BODY_ORDER:
            if key in event.body:
                doc[key] = event.body[key]
        offset += len(json.dumps(doc)) + 1
        docs.append(doc)
        ids[id(event)] = doc_id
    return docs, ids


def corpus_events(items: Sequence[Item]) -> List[Event]:
    """Every context event of ``corpus_v1``: the skill items' episodes, then the estate's history."""
    unique: Dict[int, Event] = {}
    for events in [*item_episodes(items).values(), history()]:
        for event in events:
            unique.setdefault(id(event), event)
    return list(unique.values())


def build_telemetry(items: Sequence[Item]) -> List[Dict[str, Any]]:
    """The documents of ``corpus_v1_events``, in time order."""
    return documents(corpus_events(items))[0]


def gold_rows(items: Sequence[Item]) -> List[GoldRow]:
    """The skill items of ``corpus_v1`` with the benign hypothesis their scenario was written for."""
    return [GoldRow(i.id, i.alert, i.truth.disposition, HYPOTHESES.get(i.truth.scenario))
            for i in items if skill_of(i.rule) is not None]


def store_of(alerts: Sequence[Mapping[str, Any]], docs: Sequence[Mapping[str, Any]]) -> EventStore:
    """The event store an investigation reads: the dataset's alerts and its context events."""
    return EventStore([*alerts, *docs])


def events_text(docs: Sequence[Mapping[str, Any]], meta: Mapping[str, Any]) -> str:
    lines = [json.dumps({"_meta": dict(meta)}, ensure_ascii=False, separators=(",", ":"))]
    lines += [json.dumps(doc, ensure_ascii=False, separators=(",", ":")) for doc in docs]
    return "\n".join(lines) + "\n"


DESCRIPTION = (
    "Context telemetry around the corpus_v1 alerts (AI-E1.10): the Wazuh documents an investigation reads next to "
    "an alert of the Windows logon-failure and service-install families (logons, process starts, service installs, "
    "the estate's history), in the alerts.json shape. Not dataset items: they carry no label. Generated by "
    "tests/fixtures/attack_corpus (telemetry.py); see docs/evaluation.md."
)


def events_meta(docs: Sequence[Mapping[str, Any]], *, name: str = NAME, dataset: str, dataset_sha256: str,
                description: str = DESCRIPTION, module: str = "tests.fixtures.attack_corpus.telemetry") -> Dict[str, Any]:
    return {
        "synthetic": True,
        "version": VERSION,
        "name": name,
        "description": description,
        "generator": {"module": module, "seed": f"{name}:<episode>"},
        "dataset": {"name": dataset, "sha256": dataset_sha256},
        "local_rules": LOCAL_RULES,
        "composition": {"events": len(docs),
                        "rules": dict(sorted(Counter(str(d["rule"]["id"]) for d in docs).items()))},
    }
