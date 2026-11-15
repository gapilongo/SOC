"""The deep analysis with evidence (AI-E3.3): what the model is given and asked, and what is kept of its answer.

With facts on the run's ledger the analysis uses the cited templates: the same instructions plus the
citation task, the ledger's view in the untrusted ``tool_data`` block, and an answer whose claims name the
ids they rest on. Code then checks every id. Without facts the prompt is byte for byte today's.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional

import httpx
import pytest

from lg_sotf.agents.analysis.base import CITED_VERDICT_PROMPT, VERDICT_PROMPT, VERDICT_TASK, AnalysisAgent, AnalysisResult
from lg_sotf.agents.analysis.react import CITE_TASK, CITED_STEP_PROMPT, MAX_CLAIMS, STEP_PROMPT, STEP_TASK, Claim
from lg_sotf.agents.base import AgentContext
from lg_sotf.eval.tool_fixtures import EventStore
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.llm.fake import Refuse, ScriptedCall, ScriptedChatModel, read_signals
from lg_sotf.llm.prompting import CONTEXT_TAG, DATA_TAG
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from tests.unit.agents._support import factory, fake_repos, scripted, texts
from tests.unit.agents.investigation._executor import HOSTILE, RUN_ID
from tests.unit.agents.investigation._support import MemoryStore
from tests.unit.agents.test_prompts import check_snapshot, render

pytestmark = pytest.mark.unit

AT = datetime(2026, 10, 19, 7, 28, 1, tzinfo=UTC)
SWITCH_ON = {"t1": {"tools": {"wazuh_indexer": {"enabled": True}}}}
TRIAGE = {"confidence": 60, "rule_fp": [], "rule_tp": ["failed_logon"]}
CORRELATION = {"score": 40, "related_count": 1}
VERDICT = {"threat_score": 20, "certainty": 80, "verdict": "benign", "conclusion": "A mistyped password.", "recommended_actions": []}


def stamp(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"


def logon(event_id: str, minutes_before: int, *, user: str = "j.doe", doc_id: str = "1") -> Dict[str, Any]:
    """A Windows logon document (4625 failure, 4624 success) on FIN-SRV-02 from 10.20.1.83."""
    failure = event_id == "4625"
    return {
        "timestamp": stamp(AT - timedelta(minutes=minutes_before)), "id": f"1792394881.{doc_id}",
        "rule": {"id": "60122" if failure else "60106", "level": 5 if failure else 3,
                 "groups": ["windows", "authentication_failed" if failure else "authentication_success"],
                 "mitre": {"id": ["T1531"] if failure else ["T1078"]}},
        "agent": {"name": "FIN-SRV-02"},
        "data": {"win": {"system": {"eventID": event_id, "providerName": "Microsoft-Windows-Security-Auditing"},
                         "eventdata": {"targetUserName": user, "ipAddress": "10.20.1.83", "logonType": "3"}}},
    }


THE_ALERT = logon("4625", 0, doc_id="100")
QUIET = [logon("4624", 30, doc_id="50"), logon("4625", 1, doc_id="99"), THE_ALERT]
# A failed logon for a "user name" the attacker typed: it lands in typed fact fields (a user of an event, a failed user).
POISONED = [*QUIET, logon("4625", 2, user=HOSTILE, doc_id="98")]


def state_alert(document: Mapping[str, Any] = THE_ALERT) -> Dict[str, Any]:
    return {
        "id": "alert-0001", "title": "Logon failure - unknown user or bad password", "severity": "low",
        "category": "authentication_failed", "source_id": "wazuh-push", "occurred_at": AT.isoformat(),
        "normalizer": "wazuh", "entities": {"hosts": ["FIN-SRV-02"], "users": ["j.doe"], "ips": ["10.20.1.83"]},
        "raw": dict(document),
    }


def evidence_of(documents: List[Dict[str, Any]]) -> Any:
    backend = EventStoreBackend(EventStore(documents).as_of(AT))

    async def backends(ctx: Any) -> EventStoreBackend:
        return backend

    return backends


async def unreachable(ctx: Any) -> Any:
    raise IndexerUnavailable("unreachable")


async def analyse(
    settings: Settings, model: ScriptedChatModel, evidence: Any, *, tenants: Optional[Dict[str, Any]] = None,
    enrichment: Optional[EnrichmentService] = None, store: Optional[MemoryStore] = None,
) -> AnalysisResult:
    repos = fake_repos(tenant_settings=SWITCH_ON if tenants is None else tenants)
    repos.evidence_facts = store or MemoryStore()
    agent = AnalysisAgent(settings=settings, model_factory=factory(model), evidence=evidence, enrichment=enrichment)
    ctx = AgentContext("t1", "a1", settings, repos=repos, investigation_run_id=RUN_ID)
    return await agent.run(ctx, state_alert(), triage=TRIAGE, correlation=CORRELATION)


def block(call: ScriptedCall, tag: str) -> str:
    """The body of the one ``<tag>`` block of the call."""
    (body,) = re.findall(rf"<{tag}>\n(.*?)\n</{tag}>", "\n".join(texts(call.messages)), re.DOTALL)
    return str(body)


async def test_with_evidence_the_model_is_given_the_ledger_and_asked_to_cite(make_settings: Callable[..., Settings]) -> None:
    model = scripted()
    result = await analyse(make_settings(), model, evidence_of(QUIET))

    (call,) = model.calls
    check_snapshot("analysis_verdict_cited", render(call))
    assert call.schema == "CitedVerdict" and [m.type for m in call.messages] == ["system", "human", "human"]
    system = texts(call.messages)[0]
    assert VERDICT_TASK in system and CITE_TASK in system and system.index(VERDICT_TASK) < system.index(CITE_TASK)
    # The evidence is data: inside tool_data, after the alert, with the ids the ledger minted.
    evidence = json.loads(block(call, CONTEXT_TAG))["evidence"]
    assert [o["id"] for o in evidence["observations"]] == ["host:0", "logons_user:0", "logons_source:0"]
    assert (evidence["total"], evidence["omitted"]) == (3, 0)
    assert {o["outcome"] for o in evidence["observations"]} == {"success"} and "normalizer" not in block(call, DATA_TAG)
    # What the stand-in answered: a claim that cites those ids, checked against the run's ledger.
    record = result.investigation
    assert record is not None and (record["status"], record["facts"]) == ("completed", 3)
    (claim,) = record["claims"]
    assert claim["cites"] == ["host:0", "logons_user:0", "logons_source:0"]
    assert all(f["code"] in ("incomplete_fact", "not_benign_evidence") for f in claim["findings"])
    assert result.digest()["investigation"]["claim_count"] == 1 and result.llm_used


async def test_the_react_loop_carries_the_evidence_and_the_cited_template(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(tools={"virustotal": {"api_key": "vt-snapshot-key", "share_with_tenants": True, "requests_per_minute": 100}})
    step = {"thought": "t", "threat_score": 30, "certainty": 70, "verdict": "benign", "conclusion": "c",
            "recommended_actions": [], "action": "finish", "target": "",
            "claims": [{"text": "The same user logged on from the same address half an hour earlier.", "supports": "benign",
                        "cites": ["logons_user:0"]}]}
    model = scripted(CitedStep=[step])

    def vt(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})

    alert_with_public_ip = {**THE_ALERT, "data": {**THE_ALERT["data"], "srcip": "185.220.101.44"}}
    repos = fake_repos(tenant_settings=SWITCH_ON)
    repos.evidence_facts = MemoryStore()
    agent = AnalysisAgent(settings=settings, model_factory=factory(model), evidence=evidence_of(QUIET),
                          enrichment=EnrichmentService.from_settings(settings, transport=httpx.MockTransport(vt)))
    ctx = AgentContext("t1", "a1", settings, repos=repos, investigation_run_id=RUN_ID)
    alert = {**state_alert(alert_with_public_ip), "entities": {"hosts": ["FIN-SRV-02"], "ips": ["185.220.101.44"]}}
    result = await agent.run(ctx, alert, triage=TRIAGE, correlation=CORRELATION)

    (call,) = model.calls
    check_snapshot("analysis_step_cited", render(call))
    assert call.schema == "CitedStep" and STEP_TASK in texts(call.messages)[0] and CITE_TASK in texts(call.messages)[0]
    data = json.loads(block(call, CONTEXT_TAG))
    assert set(data) == {"observations", "previous_assessment", "not_yet_looked_up", "evidence"}
    assert data["not_yet_looked_up"] == ["i1"] and len(data["evidence"]["observations"]) == 3
    assert result.investigation is not None and result.investigation["claims"] == [
        {"text": step["claims"][0]["text"], "supports": "benign", "cites": ["logons_user:0"],
         "findings": result.investigation["claims"][0]["findings"]}]


@pytest.mark.parametrize("evidence", [None, unreachable])
async def test_without_facts_the_prompt_is_todays(make_settings: Callable[..., Settings], evidence: Any) -> None:
    """No harness, or a harness whose indexer is down: the same template, the same two messages, byte for byte."""
    today, degraded = scripted(), scripted()
    plain = await analyse(make_settings(), today, None, tenants={})
    result = await analyse(make_settings(), degraded, evidence)
    assert [render(c) for c in degraded.calls] == [render(c) for c in today.calls]
    assert [c.schema for c in degraded.calls] == ["AnalysisVerdict"] and len(degraded.calls[0].messages) == 2
    assert CITE_TASK not in texts(degraded.calls[0].messages)[0]
    assert (result.verdict, result.threat_score, result.conclusion) == (plain.verdict, plain.threat_score, plain.conclusion)
    if evidence is None:
        assert result.investigation is None and "investigation" not in result.summary()
    else:
        assert result.investigation is not None and result.investigation["reason"] == "circuit_open"
        assert result.investigation["claims"] == [] and result.digest()["investigation"]["status"] == "degraded"


def test_the_cited_templates_add_only_the_citation_task_and_the_claims() -> None:
    """Minimal prompt change: the two templates of today keep their text, schema and hash; the cited ones are
    the same instructions, the citation task after them, and one more field."""
    assert VERDICT_PROMPT.name == "analysis.verdict" and STEP_PROMPT.name == "analysis.react_step"
    assert (VERDICT_PROMPT.hash, STEP_PROMPT.hash) == ("ba3e52da6cf9550c", "0e6ab566da29704e")  # as on main
    assert CITED_VERDICT_PROMPT.system == VERDICT_PROMPT.system and CITED_STEP_PROMPT.system == STEP_PROMPT.system
    assert CITED_VERDICT_PROMPT.task == f"{VERDICT_PROMPT.task} {CITE_TASK}"
    assert CITED_STEP_PROMPT.task == f"{STEP_PROMPT.task} {CITE_TASK}"
    for cited, plain in ((CITED_VERDICT_PROMPT, VERDICT_PROMPT), (CITED_STEP_PROMPT, STEP_PROMPT)):
        assert set(cited.schema.model_fields) - set(plain.schema.model_fields) == {"claims"}
        assert cited.hash != plain.hash


async def test_a_cited_id_the_ledger_did_not_mint_is_a_finding_whatever_the_model_wrote(
    make_settings: Callable[..., Settings],
) -> None:
    claims = [
        {"text": "An earlier success from the same address.", "supports": "benign", "cites": ["logons_user:0", "logons_user:7"]},
        {"text": "Nothing else happened.", "supports": "benign", "cites": []},
        {"text": "Brute force.", "supports": "Malicious ", "cites": ["host:0", "tool-wrote-this", "inv_" + "1" * 32]},
        *({"text": f"extra {n}", "supports": "malicious", "cites": ["host:0"]} for n in range(10)),
    ]
    store = MemoryStore()
    result = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": claims}]), evidence_of(QUIET), store=store)
    record = result.investigation
    assert record is not None and len(record["claims"]) == MAX_CLAIMS  # over-long answers are cut, never rejected
    first, second, third = record["claims"][:3]
    assert {"fact_id": "logons_user:7", "code": "unknown_fact"} in first["findings"]
    assert second["findings"] == [{"fact_id": "", "code": "no_citation"}]
    assert third["supports"] == "malicious" and [f["fact_id"] for f in third["findings"]] == ["tool-wrote-this", "inv_" + "1" * 32]
    # Nothing the model wrote reached the ledger: it holds what the tools returned, under the ids code minted.
    assert [e.fact_id for e in store.rows[("t1", "a1", RUN_ID)]] == ["host:0", "logons_user:0", "logons_source:0"]
    assert result.verdict == "benign" and result.threat_score == 20  # findings are a record: nothing is blocked here
    assert result.digest()["investigation"]["citation_findings"] == sum(len(c["findings"]) for c in record["claims"])


async def test_attacker_text_in_a_fact_is_data_and_mints_no_id(make_settings: Callable[..., Settings]) -> None:
    """The attacker typed instructions, a forged closing tag and a forged observation id as a user name. The
    model gets them inside the data block, escaped; the stand-in cites only ids the ledger minted."""
    model = scripted()
    result = await analyse(make_settings(), model, evidence_of(POISONED))

    (call,) = model.calls
    human = "\n".join(texts(call.messages)[1:])
    assert human.count(f"</{CONTEXT_TAG}>") == 1 and human.count(f"<{CONTEXT_TAG}>") == 1 and "<system>" not in human
    assert "IGNORE PREVIOUS INSTRUCTIONS" in block(call, CONTEXT_TAG)  # it is there, as data
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in texts(call.messages)[0]  # and never in the instructions
    evidence = json.loads(block(call, CONTEXT_TAG))["evidence"]
    assert [o["id"] for o in evidence["observations"]] == ["host:0", "logons_user:0", "logons_source:0"]
    assert read_signals(call.messages).fact_ids == ("host:0", "logons_user:0", "logons_source:0")
    record = result.investigation
    assert record is not None and [s["evidence_id"] for s in record["steps"]] == ["host", "prevalence", "logons_user", "logons_source"]
    assert all(set(c["cites"]) <= {"host:0", "logons_user:0", "logons_source:0"} for c in record["claims"])
    assert record["budget"]["steps"] == {"used": 3, "limit": 8} and "IGNORE" not in json.dumps(record)


async def test_a_refusal_with_evidence_keeps_the_facts_and_has_no_claims(make_settings: Callable[..., Settings]) -> None:
    store = MemoryStore()
    result = await analyse(make_settings(), scripted(CitedVerdict=[Refuse()]), evidence_of(QUIET), store=store)
    assert result.llm_refusal is not None and result.verdict == "inconclusive"
    assert result.investigation is not None and (result.investigation["status"], result.investigation["claims"]) == ("completed", [])
    assert len(store.rows[("t1", "a1", RUN_ID)]) == 3


def test_a_claim_is_bounded() -> None:
    claim = Claim.model_validate({"text": "x" * 1_000, "supports": " BENIGN", "cites": [f"host:{n}" for n in range(40)]})
    assert len(claim.text) == 300 and claim.supports == "benign" and len(claim.cites) == 10
