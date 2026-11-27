"""Issue 452 (AI-E3.3c): what the deep model reads of a busy host, and what a claim on it is worth.

The tool chooses the 50 listed events in parts (``tests/unit/tools/wazuh/test_host_sample.py``). Here: the
prompt shows them by part, so the noise of one part does not cut the events of another down to nothing, and
a benign claim that cites the sampled fact is a claim on an incomplete fact, as before.
"""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.agents.investigation.claims import investigation_record
from lg_sotf.agents.investigation.executor import InvestigationRun
from lg_sotf.llm.prompting import CONTEXT_TAG
from lg_sotf.settings import Settings
from tests.unit.agents._evidence import AT, THE_ALERT, VERDICT, analyse, block, evidence_of_at, logon, stamp
from tests.unit.agents._support import scripted
from tests.unit.agents.investigation._support import MemoryStore

pytestmark = pytest.mark.unit
Make = Callable[..., Settings]

COMMAND = "certutil.exe -decode c:\\users\\public\\a.b64 c:\\users\\public\\loader.exe"


def busy_host(logons: int = 60) -> List[Dict[str, Any]]:
    """The reviewer's scenario: one quiet Sysmon event 50 minutes before the alert, then 60 failed logons."""
    bad = logon("4624", 50, doc_id="7")
    bad["rule"] = {"id": "92018", "level": 3, "groups": ["sysmon"], "mitre": {"id": ["T1140"]}}
    bad["data"]["win"]["system"] = {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"}
    bad["data"]["win"]["eventdata"] = {"image": "C:\\Windows\\System32\\certutil.exe", "user": "CORP\\x", "commandLine": COMMAND}
    noise = [logon("4625", 1, user=f"svc-backup-job-{n:03d}", doc_id=str(1000 + n)) for n in range(logons)]
    for n, document in enumerate(noise):
        document["timestamp"] = stamp(AT - timedelta(minutes=1 + n % 40, seconds=n))
    old = logon("4624", 60 * 48, user="someone.else", doc_id="2")  # the index reaches back two days
    return [old, bad, *noise, THE_ALERT]


@pytest.mark.parametrize("max_input_chars", [24_000, 12_000])
async def test_the_model_reads_the_sample_by_part_and_the_rare_event_whole(make_settings: Make, max_input_chars: int) -> None:
    model = scripted()
    settings = make_settings(llm={"provider": "fake", "allow_fake": True, "max_input_chars": max_input_chars})
    result = await analyse(settings, model, evidence_of_at(busy_host(), AT + timedelta(hours=1)))
    shown = json.loads(block(model.calls[0], CONTEXT_TAG))["evidence"]["observations"]
    host = next(o for o in shown if o["id"] == "host:0")
    assert host["complete"] is False and host["value"]["total"] == 61 and host["value"]["never_close_technique_truncated"] is True
    events = host["value"]["events"]
    assert set(events) == {"never_close_class", "rare_technique", "rule_level"}
    # Fifty events do not fit the prompt: the two parts the noise fills are cut, the event it cannot reach is not.
    (rare,) = events["rare_technique"]
    assert (rare["image_name"], rare["command_template"], rare["rule_id"], rare["level"]) == ("certutil.exe", COMMAND, "92018", 3)
    assert (result.investigation or {})["evidence_truncated"] is True


async def test_a_benign_claim_on_the_sampled_host_fact_rests_on_an_incomplete_fact(make_settings: Make) -> None:
    """The window had closed and the index covers it: the fact is incomplete only because it lists a sample."""
    claim = {"text": "Nothing else happened on the host.", "supports": "benign", "cites": ["host:0"]}
    model = scripted(CitedVerdict=[{**VERDICT, "claims": [claim]}])
    result = await analyse(make_settings(), model, evidence_of_at(busy_host(), AT + timedelta(hours=1)))
    record: Dict[str, Any] = result.investigation or {}
    (checked,) = record["claims"]
    assert {"fact_id": "host:0", "code": "incomplete_fact"} in checked["findings"]
    assert record["evidence_backed"] is False and record["blocking"]["citations"] == [], "a finding, never a hold: as before"
    # With fifty events in the hour the fact lists them all, and the same claim cites a complete fact.
    few = evidence_of_at(busy_host(logons=49), AT + timedelta(hours=1))
    calm = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": [claim]}]), few)
    codes = [f["code"] for c in (calm.investigation or {})["claims"] for f in c["findings"]]
    assert "incomplete_fact" not in codes


async def test_what_the_prompt_cuts_of_a_part_is_marked_and_the_fact_keeps_the_list(make_settings: Make) -> None:
    """The guarantee is on the list the fact records (review of PR 458, F4). Twenty events of a never-close
    technique with their command lines do not fit the prompt: it cuts the part's events alike and says so,
    the record says ``evidence_truncated``, and the fact the citation check and the API read holds them whole."""
    task = logon("4624", 50, doc_id="7")
    command = "schtasks.exe /create /tn updater /tr c:\\users\\public\\loader.exe /sc onlogon"
    task["rule"] = {"id": "92154", "level": 3, "groups": ["sysmon"], "mitre": {"id": ["T1053.005"]}}
    task["data"]["win"]["eventdata"] = {"image": "C:\\Windows\\System32\\schtasks.exe", "user": "CORP\\x", "commandLine": command}
    keys = [logon("4624", 1 + n, doc_id=str(500 + n)) for n in range(19)]
    for n, document in enumerate(keys):
        document["rule"] = {"id": "92302", "level": 3, "groups": ["sysmon"], "mitre": {"id": ["T1547.001"]}}
        document["data"]["win"]["eventdata"] = {"image": "C:\\Windows\\System32\\reg.exe", "commandLine": f"reg.exe add hkcu\\software\\run /v app{n} /d c:\\program files\\app{n}\\app.exe"}
    old = logon("4624", 60 * 48, user="someone.else", doc_id="2")  # the index reaches back two days
    noise = [logon("4624", 2 + n % 40, user=f"clerk-{n:03d}", doc_id=str(1000 + n)) for n in range(60)]  # logons that succeed
    store, model = MemoryStore(), scripted()
    result = await analyse(make_settings(), model, evidence_of_at([old, task, *keys, *noise, THE_ALERT], AT + timedelta(hours=1)), store=store)
    (fact,) = [entry.fact for rows in store.rows.values() for entry in rows if entry.fact_id == "host:0" and entry.fact]
    listed = [event for event in fact["value"]["events"] if event["listed_for"] == "never_close_class"]
    assert len(listed) == 20 and command in [event.get("command_template") for event in listed]
    shown = block(model.calls[0], CONTEXT_TAG)
    part = next(o for o in json.loads(shown)["evidence"]["observations"] if o["id"] == "host:0")["value"]["events"]["never_close_class"]
    assert len(part) == 20 and all("rule_id" in event for event in part), "every event of the part is still named"
    assert "[truncated]" in json.dumps(part) and (result.investigation or {})["evidence_truncated"] is True


def test_an_observation_the_prompt_leaves_out_whole_is_truncated_evidence() -> None:
    """Review of PR 458, F3: an entry too large for the prompt's view was dropped and the record said nothing."""
    final = SimpleNamespace(verdict="suspicious", claims=[])

    def recorded(omitted: int) -> Any:
        run = InvestigationRun("wazuh.default", "1.0.0", context={"observations": [], "total": 3, "omitted": omitted})
        return (investigation_record(run, final, evidence_truncated=False) or {})["evidence_truncated"]

    assert (recorded(1), recorded(0)) == (True, False)
    assert (investigation_record(InvestigationRun("wazuh.default", "1.0.0"), final) or {})["evidence_truncated"] is False
