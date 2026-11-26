"""The deep analysis with evidence (AI-E3.3): what the model is given and asked, and what is kept of its answer.

With facts on the run's ledger the analysis uses the cited templates: the same instructions plus the
citation task, the ledger's view in the untrusted ``tool_data`` block, and an answer whose claims name the
ids they rest on. Code then checks every id. Without facts the prompt is byte for byte today's.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.agents.analysis.base import (
    CITED_VERDICT_PROMPT,
    VERDICT_PROMPT,
    VERDICT_TASK,
    AnalysisAgent,
)
from lg_sotf.agents.analysis.react import (
    CITE_TASK,
    CITED_STEP_PROMPT,
    MAX_CLAIMS,
    STEP_PROMPT,
    STEP_TASK,
    AnalysisRunContext,
    Candidate,
    Claim,
    ReActReasoner,
)
from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.investigation.executor import STEERING_MARKER
from lg_sotf.domain import closure
from lg_sotf.domain.benign_evidence import INJECTION_SIGNAL
from lg_sotf.domain.ledger import LedgerEntry
from lg_sotf.llm.fake import Refuse, read_signals
from lg_sotf.llm.prompting import CONTEXT_TAG, DATA_TAG, PROVENANCE_NOTE
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from tests.unit.agents._evidence import (
    AT,
    CORRELATION,
    POISONED,
    QUIET,
    SWITCH_ON,
    THE_ALERT,
    TRIAGE,
    VERDICT,
    analyse,
    block,
    evidence_of,
    evidence_of_at,
    logon,
    state_alert,
    unreachable,
)
from tests.unit.agents._snapshots import check_snapshot, render
from tests.unit.agents._support import factory, fake_repos, scripted, texts
from tests.unit.agents.investigation._executor import RUN_ID
from tests.unit.agents.investigation._support import MemoryStore

pytestmark = pytest.mark.unit

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
    assert (VERDICT_PROMPT.hash, STEP_PROMPT.hash) == ("55be9077a443c0d6", "2e00700d33f8cdab")  # as on main
    # The provenance sentence of the plain templates (AI-E3.16) is in the cited ones too: they are built on them.
    assert PROVENANCE_NOTE in CITED_VERDICT_PROMPT.task and PROVENANCE_NOTE in CITED_STEP_PROMPT.task
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
    scan finds them in the facts: the model is shown a marker in their place and the run carries the alert
    text's own signal; the stand-in cites only ids the ledger minted."""
    model = scripted()
    result = await analyse(make_settings(), model, evidence_of(POISONED))

    (call,) = model.calls
    human = "\n".join(texts(call.messages)[1:])
    assert human.count(f"</{CONTEXT_TAG}>") == 1 and human.count(f"<{CONTEXT_TAG}>") == 1 and "<system>" not in human
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in "\n".join(texts(call.messages))  # no model reads it
    assert STEERING_MARKER in block(call, CONTEXT_TAG)
    evidence = json.loads(block(call, CONTEXT_TAG))["evidence"]
    assert [o["id"] for o in evidence["observations"]] == ["host:0", "logons_user:0", "logons_source:0"]
    assert read_signals(call.messages).fact_ids == ("host:0", "logons_user:0", "logons_source:0")
    record = result.investigation
    assert record is not None and [s["evidence_id"] for s in record["steps"]] == ["host", "prevalence", "logons_user", "logons_source"]
    assert all(set(c["cites"]) <= {"host:0", "logons_user:0", "logons_source:0"} for c in record["claims"])
    assert record["budget"]["steps"] == {"used": 3, "limit": 8} and "IGNORE" not in json.dumps(record)
    assert record["steering"] and record["blocking"]["steering"] == record["steering"]
    assert INJECTION_SIGNAL in result.threat_indicators and result.digest()["investigation"]["blocking"]["steering"]
    quiet = await analyse(make_settings(), scripted(), evidence_of(QUIET))
    assert INJECTION_SIGNAL not in quiet.threat_indicators and (quiet.investigation or {})["steering"] == []


async def test_a_refusal_with_evidence_keeps_the_facts_and_has_no_claims(make_settings: Callable[..., Settings]) -> None:
    store = MemoryStore()
    result = await analyse(make_settings(), scripted(CitedVerdict=[Refuse()]), evidence_of(QUIET), store=store)
    assert result.llm_refusal is not None and result.verdict == "inconclusive"
    assert result.investigation is not None and (result.investigation["status"], result.investigation["claims"]) == ("completed", [])
    assert len(store.rows[("t1", "a1", RUN_ID)]) == 3


def test_a_claim_is_bounded() -> None:
    claim = Claim.model_validate({"text": "x" * 1_000, "supports": " BENIGN", "cites": [f"host:{n}" for n in range(40)]})
    assert len(claim.text) == 300 and claim.supports == "benign" and len(claim.cites) == 10


@pytest.mark.parametrize(
    ("claims", "kept"),
    [
        (None, []), ("the host is quiet", []), ({"text": "one claim, not a list", "supports": "benign"}, []), ([], []),
        ([{"text": "neither", "supports": "neutral", "cites": ["host:0"]}, "junk", 7, {"supports": "benign"}, {"text": " "},
          {"text": "kept", "supports": " Benign", "cites": "host:0"},
          {"text": "kept too", "supports": "MALICIOUS", "cites": [1, None, "host:0", "", {"id": "host:0"}]},
          {"text": "no cites at all", "supports": "malicious"}],
         [("kept", "benign", ["host:0"]), ("kept too", "malicious", ["host:0"]), ("no cites at all", "malicious", [])]),
    ],
)
async def test_claims_a_model_gets_wrong_never_cost_the_alert_its_verdict(
    make_settings: Callable[..., Settings], claims: Any, kept: List[Any]
) -> None:
    """A provider that does not enforce the schema, a model that writes "neutral": the claim is dropped, the
    verdict stands. Without this a bad ``claims`` field would throw away the deep verdict the alert has today."""
    result = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": claims}]), evidence_of(QUIET))
    assert result.llm_used and (result.verdict, result.threat_score) == ("benign", 20)
    assert result.investigation is not None
    assert [(c["text"], c["supports"], c["cites"]) for c in result.investigation["claims"]] == kept


@pytest.mark.parametrize("llm", [{"enabled": False}, None])
async def test_without_a_model_the_facts_are_kept_and_the_record_does_not_claim_one_saw_them(
    make_settings: Callable[..., Settings], llm: Any
) -> None:
    """The LLM is off, or the tenant's token budget is spent: the lookups still run for the analyst, the
    record says ``no_model``, and no prompt is built."""
    settings = make_settings(llm={"provider": "fake", "allow_fake": True, **(llm or {})})
    model, store = scripted(), MemoryStore()
    repos = fake_repos(tenant_settings=SWITCH_ON)
    repos.evidence_facts = store
    agent = AnalysisAgent(settings=settings, model_factory=factory(model), evidence=evidence_of(QUIET))
    ctx = AgentContext("t1", "a1", settings, repos=repos, investigation_run_id=RUN_ID, llm_budget_exceeded=llm is None)
    result = await agent.run(ctx, state_alert(), triage=TRIAGE, correlation=CORRELATION)
    assert model.calls == [] and result.llm_used is False and len(store.rows[("t1", "a1", RUN_ID)]) == 3
    record = result.investigation
    assert record is not None and (record["status"], record["reason"], record["claims"]) == ("degraded", "no_model", [])
    assert record["facts"] == 3 and record["evidence_truncated"] is False


async def test_evidence_cut_to_fit_the_prompt_is_recorded(make_settings: Callable[..., Settings]) -> None:
    """The prompt builder marks what it cuts and says so to the model; the record says so too, so a later
    check knows the model saw some facts in part."""
    whole = await analyse(make_settings(), scripted(), evidence_of(QUIET))
    assert whole.investigation is not None and whole.investigation["evidence_truncated"] is False
    assert whole.investigation["claims_checked"] is True
    model = scripted()
    tight = await analyse(make_settings(llm={"provider": "fake", "allow_fake": True, "max_input_chars": 1_500}), model, evidence_of(QUIET))
    assert tight.investigation is not None and tight.investigation["evidence_truncated"] is True
    assert "truncated" in texts(model.calls[0].messages)[-1]


async def test_the_lookups_time_counts_against_the_analysis_time_budget(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The evidence lookups and the model share one node budget: seconds the lookups used are gone for the loop."""
    settings = make_settings()
    step = {"thought": "t", "threat_score": 50, "certainty": 40, "verdict": "inconclusive", "conclusion": "c",
            "recommended_actions": [], "action": "lookup", "target": "i1"}

    async def looked_up(run: AnalysisRunContext, candidate: Candidate, *, agent: str) -> None:
        run.lookups += 1

    monkeypatch.setattr(ReActReasoner, "_observe", staticmethod(looked_up))
    calls = []
    for spent_s in (0.0, 60.0):  # the lookups used nothing; the lookups used more than the loop's whole budget
        agent = AnalysisAgent(settings=settings, model_factory=factory(scripted(InvestigationStep=[step, {**step, "threat_score": 90}])))
        reasoner = ReActReasoner(agent.tools, time_budget_s=50.0, clock=lambda: 100.0)
        candidates = {"i1": Candidate("i1", "ip", "203.0.113.7", []), "i2": Candidate("i2", "ip", "203.0.113.8", [])}
        run = AnalysisRunContext(AgentContext("t1", "a1", settings), {}, candidates, spent_s=spent_s)
        await reasoner.reason(agent, run)
        calls.append((run.llm_calls, run.stop_reason))
    assert calls[1] == (1, "time_budget") and calls[0][0] > 1 and calls[0][1] != "time_budget"


# ------------------------------------------------------------ what of the investigation holds a model-led close


#: The alert and one success of the same account half an hour before (T1078, level 3): nothing against a close.
CALM = [logon("4624", 30, doc_id="50"), THE_ALERT]


def held(result: Any) -> Dict[str, Any]:
    """The close blockers of a tier-on, benign-by-both-tiers state built on the analysis the agent returned."""
    state = {
        # An alert of no never-close class, so that what is listed is what the evidence holds.
        "severity": "low", "alert": {"title": "Successful logon", "mitre": {"tactics": [], "techniques": ["T1078"]}},
        "triage": {"rule_fp": [], "rule_tp": [], "llm_used": True, "threat_assessment": "benign"},
        "correlation": {}, "analysis": result.digest(), closure.RELATED_OPEN: {"threats": [], "in_progress": []},
    }
    return {"blockers": closure.model_close_blockers(state, tier=closure.MODEL_CLOSE_TIER), "holds": closure.evidence_holds(result.digest())}


@pytest.mark.parametrize(
    ("documents", "claims", "citations", "blockers"),
    [
        # A complete answer would be citable; these are incomplete (the window is still open): recorded only.
        (CALM, [{"text": "One earlier success.", "supports": "benign", "cites": ["logons_user:0"]}], [], []),
        (CALM, [{"text": "Nothing else.", "supports": "benign", "cites": []}], [], []),
        # An entry whose stored fact no longer matches its hash is cited (see the test body).
        (CALM, [{"text": "Tampered.", "supports": "benign", "cites": ["host:0"]}], ["altered_fact"], ["evidence_citation"]),
        # An id the ledger did not mint, among good ones.
        (CALM, [{"text": "Seen before.", "supports": "benign", "cites": ["logons_user:0", "logons_user:7"]}],
         ["unknown_fact"], ["evidence_citation"]),
        # The alert is alone on its host: the host lookup is empty, and "nothing found" is not benign evidence.
        # That is a finding and no forgery: the models close it on their word, as they do without a harness.
        ([THE_ALERT], [{"text": "The host is quiet.", "supports": "benign", "cites": ["host:0"]}], [], []),
        # The same empty lookup cited for a malicious claim is no finding.
        ([THE_ALERT], [{"text": "Odd.", "supports": "malicious", "cites": ["host:0"]}], [], []),
    ],
)
async def test_a_hard_citation_finding_on_a_benign_verdict_holds_the_close(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch, documents: List[Dict[str, Any]],
    claims: List[Dict[str, Any]], citations: List[str], blockers: List[str],
) -> None:
    """Review of PR 443 (rule b): a benign verdict that cites an id the ledger never minted, or an altered
    entry, is held (forgery or corruption). Every other finding is recorded: the harness never closes fewer
    alerts than no harness would, except on evidence of an attack or on forgery."""
    if citations == ["altered_fact"]:
        monkeypatch.setattr(LedgerEntry, "intact", property(lambda entry: entry.evidence_id != "host"))
    result = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": claims}]), evidence_of(documents))
    record = result.investigation or {}
    assert record["evidence_backed"] is False  # incomplete, empty, uncited or forged: never evidence-backed
    assert record["blocking"]["citations"] == citations == result.digest()["investigation"]["blocking"]["citations"]
    assert held(result)["blockers"] == blockers
    assert result.verdict == "benign" and result.threat_score == 20  # the verdict is the model's, unchanged


async def test_a_close_is_called_evidence_backed_only_when_every_benign_claim_rests_on_a_complete_fact(
    make_settings: Callable[..., Settings],
) -> None:
    """Round 3 of the review: a benign claim on a lookup that found nothing does not hold the close, and the
    record never calls such a close evidence-backed. The label is true only when every benign claim cites at
    least one complete fact a tool observed and has no finding; nothing reads it yet."""
    # An hour later the windows are closed, and the index reaches back past their start: complete facts.
    old = logon("4624", 60 * 48, user="someone.else", doc_id="2")
    settled = evidence_of_at([old, *CALM], AT + timedelta(hours=1))

    async def backed(claims: List[Dict[str, Any]], verdict: str = "benign", evidence: Any = settled) -> Any:
        answer = {**VERDICT, "verdict": verdict, "claims": claims}
        result = await analyse(make_settings(), scripted(CitedVerdict=[answer]), evidence)
        record = result.investigation or {}
        return record["evidence_backed"], sorted({f["code"] for c in record["claims"] for f in c["findings"]})

    good = {"text": "The account logged on from the same address before.", "supports": "benign", "cites": ["logons_user:0"]}
    assert await backed([good]) == (True, [])
    assert await backed([good, {"text": "A second look.", "supports": "malicious", "cites": ["host:0"]}]) == (True, [])
    # One benign claim that rests on less is enough to lose the label; none holds the close.
    assert await backed([good, {"text": "Nothing else.", "supports": "benign", "cites": []}]) == (False, ["no_citation"])
    assert await backed([good, {"text": "Made up.", "supports": "benign", "cites": ["host:7"]}]) == (False, ["unknown_fact"])
    assert await backed([]) == (False, []) and await backed([{"text": "Odd.", "supports": "malicious", "cites": ["host:0"]}]) == (False, [])
    assert await backed([good], verdict="suspicious") == (False, [])  # the label is about a benign verdict
    assert await backed([good], evidence=evidence_of(CALM)) == (False, ["incomplete_fact"])  # the window was still open
    alone = evidence_of_at([old, THE_ALERT], AT + timedelta(hours=1))
    quiet = {"text": "The host is quiet.", "supports": "benign", "cites": ["host:0"]}
    assert await backed([quiet], evidence=alone) == (False, ["not_benign_evidence"])
    result = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": [quiet]}]), alone)
    assert held(result) == {"blockers": [], "holds": {}}  # closed on the model's word, as without a harness
    assert "evidence_backed" not in result.digest()["investigation"]  # a label of the stored record only


async def test_a_benign_verdict_that_rests_on_no_claim_is_a_finding(make_settings: Callable[..., Settings]) -> None:
    """Review finding 6: evidence shown, verdict benign, zero claims, and the record said completed with no finding."""
    silent = await analyse(make_settings(), scripted(CitedVerdict=[{**VERDICT, "claims": []}]), evidence_of(CALM))
    record, digest = silent.investigation or {}, silent.digest()["investigation"]
    assert record["verdict_findings"] == [{"code": "no_claims"}] and record["claims"] == []
    assert (digest["claim_count"], digest["citation_findings"]) == (0, 1)
    assert held(silent)["blockers"] == []  # recorded; the full checker (AI-E3.4) decides what it is worth
    wary = {**VERDICT, "verdict": "suspicious", "threat_score": 60, "claims": []}
    other = await analyse(make_settings(), scripted(CitedVerdict=[wary]), evidence_of(QUIET))
    assert (other.investigation or {})["verdict_findings"] == [] and other.digest()["investigation"]["citation_findings"] == 0
    # Without a model nothing was judged, so nothing is missing.
    none = await analyse(make_settings(llm={"enabled": False}), scripted(), evidence_of(QUIET))
    assert (none.investigation or {})["verdict_findings"] == []


async def test_a_true_indicator_holds_the_close_and_names_its_facts(make_settings: Callable[..., Settings]) -> None:
    """Review of PR 443 (rule a). The alert is rule 60122, T1531, level 5: with nothing else on the host no
    indicator is true (the alert is not its own evidence); another alert of a never-close class, or a
    level-12 one, on the same host in the hour is."""
    cites = [{"text": "Routine.", "supports": "benign", "cites": ["logons_user:0"]}]
    model = lambda: scripted(CitedVerdict=[{**VERDICT, "claims": cites}])  # noqa: E731
    calm = await analyse(make_settings(), model(), evidence_of(CALM))
    # Not shown, and not ruled out either: the host's window was still open when it was read (no settle delay).
    assert (calm.investigation or {})["indicators"] == {"never_close_class_on_host": "unknown", "high_level_alert_on_host": "unknown"}
    assert (calm.investigation or {})["blocking"]["indicators"] == {} and held(calm)["blockers"] == []
    loud = logon("4624", 20, doc_id="60")
    loud["rule"] = {"id": "92652", "level": 13, "groups": ["windows"], "mitre": {"id": ["T1078"]}}
    high = await analyse(make_settings(), model(), evidence_of([*CALM, loud]))
    assert (high.investigation or {})["blocking"]["indicators"] == {"high_level_alert_on_host": ["host:0"]}
    assert held(high) == {"blockers": ["evidence_indicator"], "holds": {"evidence_indicator": ["high_level_alert_on_host (host:0)"]}}
    other = await analyse(make_settings(), model(), evidence_of(QUIET))  # another failed logon (T1531) a minute before
    assert (other.investigation or {})["blocking"]["indicators"] == {"never_close_class_on_host": ["host:0"]}
    assert held(other)["blockers"] == ["evidence_indicator"]
    # A lookup that could not answer leaves the indicator unknown, and unknown does not hold the close.
    down = await analyse(make_settings(), scripted(), unreachable)
    assert set((down.investigation or {})["indicators"].values()) == {"unknown"}
    assert (down.investigation or {})["blocking"] == {"steering": [], "indicators": {}, "citations": []}
    assert held(down)["holds"] == {}
