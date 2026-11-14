"""Gold evidence for the two investigation-skill families (AI-E1.10): what the telemetry says about an alert.

ADR 0014 (sections 1.4 and 1.5) defines two skills, ``windows.logon_failure``
and ``windows.service_install``. Each has benign hypotheses (a proof that lets
an alert close), malicious indicators and never-close conditions, all read
from facts the Wazuh evidence tools return. This module is the reference
reading of those facts from an :class:`~lg_sotf.eval.tool_fixtures.EventStore`
(the dataset's alerts plus its context events), with every window closed:

* **malicious indicators** and **never-close conditions** are computed from the
  telemetry and the declared tenant context, exactly as the ADR words them;
* the **benign hypothesis** is the one the scenario was built for; it is kept
  only when the telemetry side of its proof holds and nothing above fires (the
  parts a tenant supplies later, a guidance note or analyst history, are not
  telemetry and are not checked here);
* **evidence** lists the ids of the documents those readings rest on.

The fixture adapter of INT3.4 and the skill files of AI-E3.1a are tested
against this file; where they read a fact differently, the difference is a
finding, not a reason to edit the gold.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, EventView, event_time, field_values
from tests.fixtures.attack_corpus.corpus import TENANT_CONTEXT
from tests.fixtures.attack_corpus.fleet import HOSTS

LOGON_SKILL = "windows.logon_failure"
SERVICE_SKILL = "windows.service_install"
#: The ids ADR 0014 gives the skills' rules, hypotheses, indicators and never-close conditions.
CATALOGUE: Dict[str, Dict[str, Tuple[str, ...]]] = {
    LOGON_SKILL: {
        "rules": ("60122", "60204", "60115"),
        "benign": ("typo_then_success", "stale_credentials"),
        "malicious": ("password_spray", "guessing", "valid_account_after_failures", "lockouts_from_one_source"),
        "never_close": ("privileged_account", "public_source", "service_account_interactive_failure"),
    },
    SERVICE_SKILL: {
        "rules": ("61138", "92068"),
        "benign": ("sanctioned_remote_admin", "vendor_updater_service"),
        "malicious": ("binary_in_user_writable_path", "new_binary", "lateral_from_unsanctioned_source",
                      "discovery_through_the_service", "hands_on_keyboard_nearby"),
        "never_close": ("crown_jewel_or_domain_controller", "service_runs_an_interpreter"),
    },
}
ROUTINE_REMOTE_ADMIN_COMMANDS = ("gpupdate /force", "gpupdate /target:computer /force", "shutdown /r /t <n>",
                                 "klist purge", "ipconfig /flushdns")
DISCOVERY_IMAGES = ("whoami.exe", "nltest.exe", "net.exe", "net1.exe", "quser.exe", "systeminfo.exe", "ipconfig.exe")
HANDS_ON_TECHNIQUES = ("T1562.001", "T1059.001", "T1047", "T1105")
INTERPRETERS = ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wscript.exe", "cscript.exe")
INTERACTIVE_LOGON_TYPES = ("2", "10", "11")
ED = "data.win.eventdata."
SYSMON = "Microsoft-Windows-Sysmon"
PSEXESVC_SERVICE_PATH = "%SystemRoot%\\PSEXESVC.exe"
_PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)")
_EXE = re.compile(r"^(.*?\.exe)\b", re.I)


@dataclass(frozen=True)
class Declared:
    """What the tenant declares about its estate (``_meta.tenant_context``), as the skills use it."""

    admin_accounts: Tuple[str, ...]
    service_accounts: Tuple[str, ...]
    admin_workstation_ips: Tuple[str, ...]

    @classmethod
    def of(cls, context: Mapping[str, Any]) -> Declared:
        ips = [ip for jump in context.get("jump_hosts", []) if "psexec" in jump.get("tools", []) for ip in jump["ips"]]
        return cls(tuple(context.get("admin_accounts", [])), tuple(context.get("automation_accounts", [])), tuple(ips))


DECLARED = Declared.of(TENANT_CONTEXT)


@dataclass(frozen=True)
class Reading:
    """What the telemetry says about one alert of a skill family."""

    skill: str
    indicators: Tuple[str, ...]  # malicious indicators that are true
    never_close: Tuple[str, ...]  # never-close conditions that are true
    supported: Tuple[str, ...]  # benign hypotheses whose telemetry-side proof holds
    evidence: Tuple[str, ...]  # ids of the documents read (the alert itself left out)


def skill_of(rule_id: str) -> Optional[str]:
    return next((skill for skill, entry in CATALOGUE.items() if rule_id in entry["rules"]), None)


def raw(doc: Mapping[str, Any], name: str) -> str:
    """A Windows ``eventdata`` value with the decoder's doubled backslashes undone ('' when absent)."""
    values = field_values(doc, ED + name)
    return values[0].replace("\\\\", "\\") if values else ""


def basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def service_exe(image_path: str) -> str:
    """The executable of a service's ``imagePath``: quotes and arguments dropped, the usual variables expanded."""
    path = image_path.strip().strip('"')
    path = re.sub(r"%systemroot%", r"C:\\Windows", path, flags=re.I)
    path = re.sub(r"%comspec%", r"C:\\Windows\\System32\\cmd.exe", path, flags=re.I)
    match = _EXE.match(path)
    return (match.group(1) if match else path.split(" ", 1)[0]).strip('"')


def path_class(image_path: str) -> str:
    """``system``, ``program_files``, ``user_writable``, ``unc`` or ``other`` (the view's ``image_path_class``)."""
    path = service_exe(image_path).lower()
    if path.startswith("\\\\"):
        return "unc"
    if path.startswith(("c:\\users\\", "c:\\programdata\\")) or "\\temp\\" in path:
        return "user_writable"
    if path.startswith(("c:\\program files\\", "c:\\program files (x86)\\")):
        return "program_files"
    return "system" if path.startswith("c:\\windows\\") else "other"


def command_template(command: str) -> str:
    """A command line with its numbers generalised, lower case (the routine-command list is written this way)."""
    return re.sub(r"(?<![\w.])\d+(?![\w.])", "<n>", " ".join(command.lower().split()))


def _ids(docs: Iterable[Mapping[str, Any]]) -> List[str]:
    return [str(d["id"]) for d in docs]


def _host_of(ip: str) -> Optional[str]:
    return next((h.name for h in HOSTS.values() if h.ip == ip), None)


@dataclass(frozen=True)
class Fanout:
    """Logon failures and successes of one source address in a window (the ``logon_fanout`` fact)."""

    failures: int
    successes: int
    failed_users: Tuple[str, ...]
    success_users: Tuple[str, ...]
    unknown_user_failures: int
    lockouts: int
    first_success_after_failure_s: Optional[float]
    docs: Tuple[str, ...]


def fanout(view: EventView, at: datetime, *, before_min: int, ip: Optional[str], host: Optional[str],
           after_min: int = 10) -> Fanout:
    start, end = at - timedelta(minutes=before_min), at + timedelta(minutes=after_min)
    by_ip = {ED + "ipAddress": ip} if ip else None
    failed = view.select(EventQuery(start=start, end=end, event_ids=("4625",), where=by_ip)) if by_ip else []
    ok = view.select(EventQuery(start=start, end=end, event_ids=("4624",), where=by_ip)) if by_ip else []
    locked = view.select(EventQuery(start=start, end=end, event_ids=("4740",),
                                    where={ED + "callerComputerName": host})) if host else []
    after: Optional[float] = None
    if failed:
        first = event_time(failed[0])
        later = [event_time(d) for d in ok if event_time(d) >= first]
        after = (later[0] - first).total_seconds() if later else None
    return Fanout(
        failures=len(failed), successes=len(ok),
        failed_users=tuple(sorted({raw(d, "targetUserName") for d in failed})),
        success_users=tuple(sorted({raw(d, "targetUserName") for d in ok})),
        unknown_user_failures=sum(raw(d, "subStatus") == "0xc0000064" for d in failed),
        lockouts=len(locked), first_success_after_failure_s=after, docs=tuple(_ids([*failed, *ok, *locked])),
    )


def read_logon(store: EventStore, alert: Mapping[str, Any], declared: Declared = DECLARED) -> Reading:
    """The ``windows.logon_failure`` reading of a 4625 or 4740 alert."""
    at = event_time(alert)
    user = raw(alert, "targetUserName")
    if field_values(alert, "data.win.system.eventID") == ["4740"]:
        host: Optional[str] = raw(alert, "callerComputerName") or None
        ip = HOSTS[host].ip if host in HOSTS else None
    else:
        ip = raw(alert, "ipAddress") or None
        host = _host_of(ip) if ip else None
    view = store.as_of(at + timedelta(minutes=10))
    near = fanout(view, at, before_min=30, ip=ip, host=host)
    day = fanout(view, at, before_min=1440, ip=ip, host=host)
    by_user = view.select(EventQuery(start=at - timedelta(minutes=1440), end=at + timedelta(minutes=10),
                                     event_ids=("4625",), where={ED + "targetUserName": user}))
    sources = {raw(d, "ipAddress") for d in by_user}
    indicators = [name for name, true in (
        ("password_spray", len(near.failed_users) >= 3 or len(day.failed_users) >= 5),
        ("guessing", len(sources) >= 3 or near.unknown_user_failures >= 3),
        ("valid_account_after_failures", len(near.failed_users) >= 2 and near.successes >= 1),
        ("lockouts_from_one_source", day.lockouts >= 2),
    ) if true]
    never = [name for name, true in (
        ("privileged_account", user in declared.admin_accounts),
        ("public_source", bool(ip) and not _PRIVATE.match(str(ip))),
        ("service_account_interactive_failure",
         user in declared.service_accounts and raw(alert, "logonType") in INTERACTIVE_LOGON_TYPES),
    ) if true]
    quick = near.first_success_after_failure_s
    supported = [name for name, true in (
        ("typo_then_success", raw(alert, "subStatus") == "0xc000006a" and near.failed_users == (user,)
         and near.failures <= 3 and quick is not None and quick <= 600 and set(near.success_users) <= {user}
         and day.failed_users == (user,)),
        ("stale_credentials", day.failed_users == (user,) and day.successes == 0 and len(sources) <= 2),
    ) if true]
    evidence = sorted({*day.docs, *_ids(by_user)} - {str(alert["id"])})
    return Reading(LOGON_SKILL, tuple(indicators), tuple(never), tuple(supported), tuple(evidence))


def descendants(view: EventView, host: str, roots: Set[str], start: datetime, end: datetime,
                depth: int = 8) -> List[Dict[str, Any]]:
    """Sysmon event 1 processes on ``host`` started, directly or not, by the processes ``roots`` (their guids)."""
    started = view.select(EventQuery(agent=host, start=start, end=end, event_ids=("1",),
                                     where={"data.win.system.providerName": SYSMON}))
    found: List[Dict[str, Any]] = []
    parents, seen = set(roots), set(roots)
    for _ in range(depth):
        children = [d for d in started if raw(d, "parentProcessGuid") in parents and raw(d, "processGuid") not in seen]
        if not children:
            break
        found += children
        parents = {raw(d, "processGuid") for d in children}
        seen |= parents
    return found


def read_service(store: EventStore, alert: Mapping[str, Any], declared: Declared = DECLARED) -> Reading:
    """The ``windows.service_install`` reading of a 7045 alert or a PsExec child process."""
    at = event_time(alert)
    host = str(alert["agent"]["name"])
    view = store.as_of(at + timedelta(minutes=15))
    lineage_start, lineage_end = at - timedelta(seconds=5), at + timedelta(minutes=15)
    install = field_values(alert, "data.win.system.eventID") == ["7045"]
    if install:
        image_path = raw(alert, "imagePath")
        exe = service_exe(image_path)
        psexec = basename(exe) == "psexesvc.exe"
        started = view.select(EventQuery(agent=host, start=lineage_start, end=lineage_end, event_ids=("1",),
                                         where={"data.win.system.providerName": SYSMON}))
        root_docs = [d for d in started if basename(raw(d, "image")) == basename(exe)
                     and basename(raw(d, "parentImage")) == "services.exe"]
        roots = {raw(d, "processGuid") for d in root_docs}
    else:
        image_path, exe = PSEXESVC_SERVICE_PATH, raw(alert, "parentImage")
        psexec = basename(exe) == "psexesvc.exe"
        root_docs, roots = [], {raw(alert, "parentProcessGuid")}
    inbound = view.select(EventQuery(agent=host, start=at - timedelta(minutes=15), end=at + timedelta(minutes=1),
                                     event_ids=("4624",), where={ED + "logonType": "3"}))
    sources = sorted({raw(d, "ipAddress") for d in inbound})
    users = {raw(d, "targetUserName") for d in inbound}
    children = descendants(view, host, roots, lineage_start, lineage_end)
    same_image = view.select(EventQuery(start=at - timedelta(days=30), end=at + timedelta(minutes=15),
                                        event_ids=("7045",), where={ED + "imagePath": image_path.replace("\\", "\\\\")}))
    image_hosts = {str(d["agent"]["name"]) for d in same_image}
    first_seen = event_time(same_image[0]) if same_image else at
    around = view.select(EventQuery(agent=host, start=at - timedelta(minutes=30), end=at + timedelta(minutes=15)))
    hands_on = [d for d in around if set(field_values(d, "rule.mitre.id")) & set(HANDS_ON_TECHNIQUES)]
    indicators = [name for name, true in (
        ("binary_in_user_writable_path", path_class(image_path) in ("user_writable", "unc")),
        ("new_binary", len(image_hosts) <= 1 or at - first_seen <= timedelta(days=1)),
        ("lateral_from_unsanctioned_source", psexec and len(sources) >= 2),
        ("discovery_through_the_service", any(basename(raw(d, "image")) in DISCOVERY_IMAGES for d in children)),
        ("hands_on_keyboard_nearby", bool(hands_on)),
    ) if true]
    never = [name for name, true in (
        ("crown_jewel_or_domain_controller", HOSTS[host].role == "dc"),
        ("service_runs_an_interpreter", install and basename(exe) in INTERPRETERS),
    ) if true]
    routine = all(command_template(raw(d, "commandLine")) in ROUTINE_REMOTE_ADMIN_COMMANDS for d in children)
    supported = [name for name, true in (
        ("sanctioned_remote_admin", psexec and len(sources) == 1 and sources[0] in declared.admin_workstation_ips
         and bool(users) and users <= set(declared.admin_accounts) and routine),
        ("vendor_updater_service", not psexec and path_class(image_path) == "program_files" and len(image_hosts) >= 10
         and at - first_seen >= timedelta(days=7)),
    ) if true]
    evidence = sorted({*_ids(inbound), *_ids(root_docs), *_ids(children), *_ids(same_image), *_ids(hands_on)}
                      - {str(alert["id"])})
    return Reading(SERVICE_SKILL, tuple(indicators), tuple(never), tuple(supported), tuple(evidence))


def read(store: EventStore, alert: Mapping[str, Any], declared: Declared = DECLARED) -> Optional[Reading]:
    """The reading of ``alert`` for the skill its rule belongs to (None for other alerts)."""
    skill = skill_of(str(alert["rule"]["id"]))
    if skill is None:
        return None
    return read_logon(store, alert, declared) if skill == LOGON_SKILL else read_service(store, alert, declared)


@dataclass(frozen=True)
class GoldRow:
    """A dataset item to grade: its id, alert, label and the benign hypothesis its scenario was built for."""

    id: str
    alert: Mapping[str, Any]
    disposition: str
    hypothesis: Optional[str] = None


def gold_entry(store: EventStore, row: GoldRow, declared: Declared = DECLARED) -> Optional[Dict[str, Any]]:
    reading = read(store, row.alert, declared)
    if reading is None:
        return None
    provable = (row.disposition == "benign" and row.hypothesis in reading.supported
                and not reading.indicators and not reading.never_close)
    return {
        "skill": reading.skill,
        "disposition": row.disposition,
        "benign_hypothesis": row.hypothesis if provable else None,
        "malicious_indicators": list(reading.indicators),
        "never_close": list(reading.never_close),
        "evidence": list(reading.evidence),
    }


def build_gold(store: EventStore, rows: Sequence[GoldRow], declared: Declared = DECLARED) -> Dict[str, Dict[str, Any]]:
    """Gold evidence per skill item id, in the order of ``rows``."""
    found: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        entry = gold_entry(store, row, declared)
        if entry is not None:
            found[row.id] = entry
    return found


def gold_meta(*, name: str, dataset: str, dataset_sha256: str, events: str, events_sha256: str,
              items: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    by_skill: Dict[str, Dict[str, int]] = {}
    for entry in items.values():
        counts = by_skill.setdefault(entry["skill"], {"malicious": 0, "benign": 0, "benign_provable": 0})
        counts[entry["disposition"]] += 1
        counts["benign_provable"] += entry["benign_hypothesis"] is not None
    return {
        "synthetic": True,
        "version": 1,
        "name": name,
        "description": (
            "Gold evidence (AI-E1.10) for the items of the investigation-skill families of ADR 0014: the benign "
            "hypothesis the telemetry supports, the malicious indicators and never-close conditions that are true "
            "with every evidence window closed, and the ids of the documents they rest on. Generated by "
            "tests/fixtures/attack_corpus (gold.py); see docs/evaluation.md."
        ),
        "dataset": {"name": dataset, "sha256": dataset_sha256},
        "events": {"name": events, "sha256": events_sha256},
        "skills": {skill: {k: list(v) for k, v in entry.items()} for skill, entry in CATALOGUE.items()},
        "composition": dict(sorted(by_skill.items())),
    }


def gold_text(meta: Mapping[str, Any], items: Mapping[str, Mapping[str, Any]]) -> str:
    """The gold file: JSON with one item per line, so a diff shows what changed."""
    lines = ["{", f' "_meta": {json.dumps(dict(meta), ensure_ascii=False)},', ' "items": {']
    rows = [f'  {json.dumps(item_id)}: {json.dumps(dict(entry), ensure_ascii=False)}' for item_id, entry in items.items()]
    lines.append(",\n".join(rows))
    lines += [" }", "}"]
    return "\n".join(lines) + "\n"
