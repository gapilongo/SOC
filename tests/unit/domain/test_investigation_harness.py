"""The evidence lookups in the investigation view (AI-E3.3): what ran, what it used, why not, and the cited claims."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.agents.investigation.executor import InvestigationRun, StepRecord
from lg_sotf.domain.investigation import AlertFacts, EventFacts, InvestigationFacts, assemble, words
from lg_sotf.domain.investigation.harness import cited_claims, evidence_run
from lg_sotf.domain.investigation.steps import evidence_step
from lg_sotf.domain.ledger import LedgerEntry, ToolStep, build_entries
from tests.unit.agents.investigation._executor import HOSTILE, RUN_ID, host_fact

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 14, 10, 4, tzinfo=UTC)
SHA = "0" * 64
WAZUH_VIEW = {"normalizer": "wazuh", "entities": {"hosts": ["FIN-SRV-02"]}}


def run_record(reason: Optional[str] = None, **changes: Any) -> Dict[str, Any]:
    """An investigation as the analysis node stores it."""
    run = InvestigationRun(
        "wazuh.default", "1.0.0", RUN_ID, stop_reason="finished" if reason in (None, "no_facts") else reason,
        steps=[
            StepRecord("host", "wazuh.host_activity", "success", None, ("host:0",), True),
            StepRecord("prevalence", "wazuh.prevalence", "skipped", "no_binding"),
            StepRecord("logons_user", "wazuh.logon_fanout", "empty", None, ("logons_user:0",), False, True),
            StepRecord("logons_source", "wazuh.logon_fanout", "failed", "reported", ("logons_source:0",)),
        ],
        budget={"steps": {"used": 3, "limit": 8}, "wall_s": {"used": 0.412, "limit": 60.0},
                "tokens": {"used": 0, "limit": 20_000}, "usd": {"used": 0.0, "limit": 0.25}},
        indicators={"never_close_class_on_host": "false", "high_level_alert_on_host": "unknown"}, facts=1, reason=reason,
    )
    return {**run.record(), "claims": [], **changes}


def claim(text: str, cites: List[str], supports: str = "benign", findings: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    return {"text": text, "supports": supports, "cites": cites, "findings": findings or []}


def ledger() -> List[LedgerEntry]:
    entries: List[LedgerEntry] = []
    for evidence_id, outcome, facts in (("host", "success", (host_fact(),)), ("logons_user", "empty", ()), ("logons_source", "failed", ())):
        step = ToolStep(evidence_id, "wazuh.host_activity" if facts else "wazuh.logon_fanout", 1, SHA,
                        SHA if outcome != "failed" else None, outcome, outcome == "success",  # type: ignore[arg-type]
                        None if outcome != "failed" else "unreachable", facts)
        entries += build_entries(step, [e.fact_id for e in entries], NOW)
    return entries


def view(summary: Dict[str, Any], *, alert_view: Optional[Dict[str, Any]] = None, events: Any = (), with_ledger: bool = True) -> Any:
    alert = AlertFacts(id="alert-1", tenant_id="tenant-a", status="waiting_human", severity="low", summary=summary,
                       view=WAZUH_VIEW if alert_view is None else alert_view, ingested_at=NOW)
    entries = ledger() if with_ledger else []
    return assemble(InvestigationFacts(alert=alert, now=NOW, events=events, ledger=entries, ledger_total=len(entries)))


def analysed(investigation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    analysis: Dict[str, Any] = {"verdict": "benign", "threat_score": 20, "llm_used": True, "conclusion": "c"}
    if investigation is not None:
        analysis["investigation"] = investigation
    return {"analysis": analysis}


def test_the_view_shows_what_the_lookups_did_and_used() -> None:
    run = view(analysed(run_record())).evidence_run
    assert (run.status, run.reason, run.stop_reason) == ("ran", None, "finished")
    assert (run.playbook_id, run.playbook_version, run.run_id) == ("wazuh.default", "1.0.0", RUN_ID)
    assert [(lookup.evidence_id, lookup.outcome, lookup.reason, lookup.observation_ids) for lookup in run.lookups] == [
        ("host", "success", None, ["host:0"]), ("prevalence", "skipped", "no_binding", []),
        ("logons_user", "empty", None, ["logons_user:0"]), ("logons_source", "failed", "reported", ["logons_source:0"]),
    ]
    assert [(lookup.complete, lookup.reused) for lookup in run.lookups] == [(True, False), (False, False), (False, True), (False, False)]
    assert [(b.kind, b.used, b.limit) for b in run.budgets] == [
        ("steps", 3, 8), ("wall_s", 0.412, 60.0), ("tokens", 0, 20_000), ("usd", 0.0, 0.25)]
    assert [(i.id, i.state) for i in run.indicators] == [
        ("never_close_class_on_host", "false"), ("high_level_alert_on_host", "unknown")]


@pytest.mark.parametrize("reason", ["budget_steps", "budget_wall", "budget_tokens", "budget_usd", "circuit_open", "no_facts", "no_run_id", "error"])
def test_a_degraded_run_says_why_in_a_fixed_sentence(reason: str) -> None:
    run = view(analysed(run_record(reason))).evidence_run
    assert run.status == "degraded" and run.reason is not None
    assert (run.reason.code, run.reason.sentence) == (reason, words.EVIDENCE_REASONS[reason])


@pytest.mark.parametrize(
    ("summary", "alert_view", "code"),
    [
        (analysed(), WAZUH_VIEW, "switched_off"),
        (analysed(), {"normalizer": "sentinel"}, "no_evidence_tools"),
        (analysed(), {}, "no_evidence_tools"),
        ({}, WAZUH_VIEW, "not_analysed"),
        ({"suppressed_by": {"type": "suppression_rule"}}, WAZUH_VIEW, "not_analysed"),
    ],
)
def test_without_a_record_the_view_says_why_no_lookup_ran(summary: Dict[str, Any], alert_view: Dict[str, Any], code: str) -> None:
    run = view(summary, alert_view=alert_view, with_ledger=False).evidence_run
    assert run.status == "not_run" and run.reason is not None and run.reason.code == code
    assert run.reason.sentence == words.EVIDENCE_REASONS[code]
    assert (run.lookups, run.budgets, run.indicators, run.playbook_id) == ([], [], [], None)


def test_each_claim_sits_beside_the_observations_it_cites_with_its_check() -> None:
    record = run_record(claims=[
        claim("The host shows routine activity only.", ["host:0"]),
        claim("No other logon from the address.", ["logons_user:0", "host:9"],
              findings=[{"fact_id": "logons_user:0", "code": "not_benign_evidence"}, {"fact_id": "host:9", "code": "unknown_fact"}]),
        claim("Brute force from one address.", [], supports="malicious"),
        claim("Nothing to see.", [], findings=[{"fact_id": "", "code": "no_citation"}]),
    ])
    shown = view({**analysed(record), "triage": {"llm_tp": ["fast-tier claim"]}})
    first, second, third, fourth, fast = shown.claims
    assert (first.id, first.written_by, first.direction, first.observation_ids, first.check, first.findings) == (
        "C-01", "model", "benign", ["host:0"], "supported", [])
    assert {o.id for o in shown.observations} >= set(first.observation_ids)  # the cited id is a listed observation
    # An id the ledger did not mint is a finding, never an observation the claim "rests on".
    assert second.observation_ids == ["logons_user:0"] and second.check == "unsupported"
    assert [(f.code, f.cited) for f in second.findings] == [("not_benign_evidence", "logons_user:0"), ("unknown_fact", "host:9")]
    assert second.check_reason == words.CITATION_FINDINGS["not_benign_evidence"]
    assert (third.direction, third.observation_ids, third.check, third.check_reason) == (
        "malicious", [], "unsupported", words.CITATION_FINDINGS["no_citation"])
    assert (fourth.check, fourth.check_reason) == ("unsupported", words.CITATION_FINDINGS["no_citation"])
    assert (fast.text, fast.observation_ids, fast.findings) == ("fast-tier claim", [], [])


def test_stored_text_is_data_bounded_and_never_a_sentence() -> None:
    record = run_record(
        "a_code_of_a_newer_release " + HOSTILE,
        claims=[claim(HOSTILE * 9, [HOSTILE, "host:0"], findings=[{"fact_id": HOSTILE * 3, "code": "unknown_fact"},
                                                                  {"fact_id": "x", "code": "a_newer_code"}])],
        indicators={HOSTILE: "certainly"}, budget={"steps": {"used": "many", "limit": 8}, "barrels": {"used": 1, "limit": 2}},
    )
    record["steps"][0].update(outcome="exploded", reason=HOSTILE, fact_ids=[HOSTILE * 2, 7])
    shown = view(analysed(record))
    run = shown.evidence_run
    assert run.status == "degraded" and run.reason is not None and run.reason.sentence == words.UNKNOWN_EVIDENCE_REASON
    assert len(run.reason.code) <= 64 and HOSTILE not in run.reason.sentence
    assert run.lookups[0].outcome == "failed" and len(run.lookups[0].reason or "") <= 64
    assert [len(i) <= 128 for i in run.lookups[0].observation_ids] == [True] and run.budgets == []
    assert [(len(i.id) <= 64, i.state) for i in run.indicators] == [(True, "unknown")]
    cited = shown.claims[0]
    assert len(cited.text) <= 300 and [f.code for f in cited.findings] == ["unknown_fact"] and len(cited.findings[0].cited) <= 128
    for sentence in (cited.check_reason, *(f.sentence for f in cited.findings)):
        assert sentence in words.CITATION_FINDINGS.values()
    # A record that is not one (an older row, a hand-edited summary) is no record at all.
    for broken in ("x", ["x"], {"status": 7}, {"claims": "all"}):
        assert evidence_run({"analysis": {"investigation": broken}}, WAZUH_VIEW).status in ("not_run", "degraded")
        assert cited_claims({"analysis": {"investigation": broken}}) == []


def test_a_skipped_lookup_is_named_as_not_checked_and_a_failed_one_as_unavailable() -> None:
    shown = view(analysed(run_record()))
    not_checked = {(item.what, item.why) for item in shown.not_established.not_checked}
    assert (words.EVIDENCE_TOOL_TITLES["wazuh.prevalence"], words.SKIPPED_LOOKUP_REASONS["no_binding"]) in not_checked
    assert words.NO_TELEMETRY[0] not in {what for what, _ in not_checked}  # the source's own data was read
    assert shown.not_established.empty == ["logons_user:0"]
    assert [item.observation_id for item in shown.not_established.unavailable] == ["logons_source:0"]


def analysis_event(investigation: Any) -> EventFacts:
    data: Dict[str, Any] = {"verdict": "benign", "llm_used": True, "tool_steps": 0}
    if investigation is not None:
        data["investigation"] = investigation
    return EventFacts(ts=NOW, event_type="node.completed", node="analysis", data=data)


def test_the_lookups_or_the_reason_they_did_not_finish_are_a_step_before_the_analysis() -> None:
    ran = {"status": "completed", "skill": "wazuh.default", "stop_reason": "finished", "lookups": 3, "facts": 1, "empty": 1,
           "failed": 1, "skipped": 1, "citation_findings": 2}
    steps = view(analysed(run_record()), events=[analysis_event(ran)]).steps
    lookups, analysis = steps[-2], steps[-1]
    assert (lookups.actor, lookups.text) == ("code", words.EVIDENCE_STEP.text)
    assert lookups.produced == "3 lookups · 1 facts · 1 found nothing · 1 failed · 1 skipped · 2 citation findings"
    assert analysis.text == words.NODE_STEP_VARIANTS["analysis:model"].text
    down = evidence_step(analysis_event({"status": "degraded", "reason": "circuit_open", "lookups": 2, "failed": 2, "skipped": 2}))
    assert down is not None and (down.text, down.produced) == (words.EVIDENCE_REASONS["circuit_open"], "2 lookups · 2 failed · 2 skipped")
    newer = evidence_step(analysis_event({"status": "degraded", "reason": HOSTILE}))
    assert newer is not None and newer.text == words.UNKNOWN_EVIDENCE_REASON and newer.produced is None
    # Today's path has no such step: an analysis without an investigation, or any other node's event.
    assert evidence_step(analysis_event(None)) is None and evidence_step(analysis_event("completed")) is None
    other = EventFacts(ts=NOW, event_type="node.completed", node="triage", data={"investigation": ran})
    assert evidence_step(other) is None
    assert len(view(analysed(), events=[analysis_event(None)]).steps) == len(steps) - 1


def test_a_hidden_alert_shows_no_lookups() -> None:
    alert = AlertFacts(id="alert-1", tenant_id="tenant-a", status="closed", severity="low", summary=analysed(run_record()),
                       view=WAZUH_VIEW, ingested_at=NOW)
    hidden = assemble(InvestigationFacts(alert=alert, now=NOW, hidden=True, events=[analysis_event({"status": "completed"})]))
    assert (hidden.evidence_run.status, hidden.evidence_run.reason, hidden.evidence_run.lookups) == ("not_run", None, [])
    assert hidden.claims == [] and all(step.text != words.EVIDENCE_STEP.text for step in hidden.steps)
