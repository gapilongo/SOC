"""PR #344 adversarial review: verdict-key collisions that closed a different activity (adopted, H1 and H2).

Built from a real corpus_v1 Wazuh event (``cv1-0057``) with its event data
replaced, normalised as the eval runner's webhook source does. Two different
analysts decide the benign activity, which is what a cache close needs.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import fakeredis.aioredis
import pytest

from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.domain.verdict_key import verdict_key
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.ingestion.fingerprint import compute_fingerprint
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.models.alert import CanonicalAlert

pytestmark = pytest.mark.unit

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_v1.jsonl.gz"
CTX = NormalizeContext(source_id="eval-wazuh", source_type="webhook", config={"format": "wazuh"},
                       now=datetime(2026, 11, 1, tzinfo=UTC))
Built = Tuple[CanonicalAlert, str, Optional[str]]


def _base() -> Dict[str, Any]:
    return dict(next(e.alert for e in load_dataset(DATASET).items if e.id == "cv1-0057"))


def _alert(rule_id: str, desc: str, event_id: str, eventdata: Dict[str, Any], src_id: str,
           mitre: Optional[Dict[str, Any]] = None) -> Built:
    a = copy.deepcopy(_base())
    a["rule"].update({"id": rule_id, "description": desc})
    if mitre is None:
        a["rule"].pop("mitre", None)
    else:
        a["rule"]["mitre"] = mitre
    a["data"]["win"]["system"]["eventID"] = event_id
    a["data"]["win"]["eventdata"] = eventdata
    a["id"] = src_id
    al = get_normalizer("wazuh").normalize(a, CTX)
    fp = compute_fingerprint(al)
    return al, fp, verdict_key(fp, al.normalized_document(), al.raw)


async def _closes_after_two_analysts(benign: Built, attack: Built) -> bool:
    cache = VerdictCache(fakeredis.aioredis.FakeRedis(), "pfx")
    (_, _, k_benign), (al, fp, k_attack) = benign, attack
    for n in (1, 2):
        await cache.put_analyst_benign("t1", k_benign, decision="false_positive", alert_id=f"b{n}",
                                       escalation_id=f"e{n}", decided_by=f"analyst-{n}", severity="medium")
    return await cache.closing_decision("t1", k_attack, al.severity, fingerprint=fp) is not None


def _task(name: str, cmd: str, src: str, mitre: Optional[Dict[str, Any]] = None) -> Built:
    return _alert("60000", "A scheduled task was created", "4698", {
        "subjectUserName": "SYSTEM", "taskName": name,
        "taskContent": f"<Task><Actions><Exec><Command>{cmd}</Command></Exec></Actions></Task>"}, src, mitre)


EDGE_TASK = ("\\MicrosoftEdgeUpdateTaskMachineUA", "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe")
BEACON_TASK = ("\\WindowsUpdateCheck", "C:\\Users\\Public\\beacon.exe")


async def test_a_malicious_scheduled_task_does_not_inherit_a_benign_tasks_verdict() -> None:
    # Unmapped (the rule carries no ATT&CK id): the task's name and content are part of the key.
    benign, attack = _task(*EDGE_TASK, "s1"), _task(*BEACON_TASK, "s2")
    assert benign[2] is not None and attack[2] is not None
    assert benign[2] != attack[2], "T1053 persistence shares the benign task's verdict key"
    assert not await _closes_after_two_analysts(benign, attack)
    # Mapped to T1053 (named persistence, a never-close class): no key at all, so nothing closes from the cache.
    t1053 = {"id": ["T1053.005"], "tactic": ["Persistence"]}
    benign, attack = _task(*EDGE_TASK, "s3", t1053), _task(*BEACON_TASK, "s4", t1053)
    assert benign[2] is None and attack[2] is None
    assert not await _closes_after_two_analysts(benign, attack)


def _proc(cmd: str, src: str) -> Built:
    return _alert("92052", "Python spawned by service", "1", {
        "image": "C:\\Python311\\python.exe", "commandLine": cmd,
        "parentImage": "C:\\Windows\\System32\\svchost.exe", "user": "CORP\\svc_mon"}, src)


async def test_a_payload_appended_past_512_characters_changes_the_key() -> None:
    long = "C:\\Python311\\python.exe C:\\ops\\collector.py " + " ".join(f"--metric=m{i:02d}" for i in range(50))
    benign = _proc(long, "p1")
    attack = _proc(long + " --exec=\"import os;os.system('powershell -enc SQBFAFgA')\"", "p2")
    assert benign[2] is not None and attack[2] is not None
    assert benign[2] != attack[2], "command lines are cut at 512 characters before hashing"
    assert not await _closes_after_two_analysts(benign, attack)
