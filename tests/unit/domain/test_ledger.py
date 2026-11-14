"""The fact ledger's rules (AI-E3.2): ids, entries, what may be cited and what a prompt may show. Pure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from lg_sotf.domain.ledger import (
    MAX_RUN_ENTRIES,
    LedgerError,
    ToolStep,
    build_entries,
    check_citations,
    mint_fact_id,
    planner_view,
)
from lg_sotf.models.evidence_fact import EvidenceFact, parse_fact

pytestmark = pytest.mark.unit

AT = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
IN, OUT = "a" * 64, "b" * 64


def fact(**changes: Any) -> EvidenceFact:
    base: Dict[str, Any] = {
        "id": "x", "kind": "reputation", "subject": {"type": "ip", "value": "198.51.100.7"},
        "observed_at": "2026-11-14T09:59:00Z", "source": {"name": "virustotal"},
        "value": {"verdict": "malicious", "score": 91.0},
    }
    return parse_fact({**base, **changes})


def step(outcome: str = "success", *facts: EvidenceFact, **changes: Any) -> ToolStep:
    values: Dict[str, Any] = {
        "evidence_id": "rep", "tool": "reputation.virustotal", "tool_version": 1, "input_hash": IN,
        "output_hash": OUT, "outcome": outcome, "complete": outcome != "failed", "facts": facts,
    }
    return ToolStep(**{**values, **changes})


def test_ids_are_numbered_per_evidence_id_after_the_ids_taken() -> None:
    assert mint_fact_id("host", []) == "host:0"
    assert mint_fact_id("host", ["host:0", "host:4", "hosts:9", "host.b:7", "host:x"]) == "host:5"
    assert mint_fact_id("host.b", ["host:0", "host.b:7"]) == "host.b:8"
    for bad in ("", "Host", "0host", "host:1", "host 1", "h" * 65, "host\n"):
        with pytest.raises(LedgerError):
            mint_fact_id(bad, [])


def test_a_step_gives_one_entry_per_fact_or_one_entry_without_a_fact() -> None:
    two = build_entries(step("success", fact(), fact(confidence=0.5)), ["rep:0"], AT)
    assert [e.fact_id for e in two] == ["rep:1", "rep:2"]
    assert [e.fact["id"] for e in two if e.fact] == ["rep:1", "rep:2"]
    assert all(e.fact and e.fact["provenance"] == {"input_hash": IN, "output_hash": OUT} for e in two)
    assert two[0].content_hash != two[1].content_hash and all(e.intact for e in two)
    typed = two[1].evidence_fact()
    assert typed is not None and (typed.id, typed.kind, typed.confidence) == ("rep:2", "reputation", 0.5)

    for outcome in ("empty", "failed"):
        (none,) = build_entries(step(outcome, reason="time_cap" if outcome == "failed" else None), [], AT)
        assert (none.fact_id, none.fact, none.kind, none.citable_as_benign_evidence) == ("rep:0", None, None, False)
        assert none.evidence_fact() is None
        with pytest.raises(LedgerError, match="carries no fact"):
            build_entries(step(outcome, fact()), [], AT)
    with pytest.raises(LedgerError, match="never complete"):
        build_entries(step("failed", complete=True), [], AT)
    # A hash that is not a SHA-256 is no binding to a trace step.
    with pytest.raises(ValidationError):
        build_entries(step("empty", input_hash="not-a-hash"), [], AT)


def test_a_runs_ledger_is_bounded() -> None:
    full = [f"rep:{n}" for n in range(MAX_RUN_ENTRIES - 1)]
    assert len(build_entries(step("empty"), full, AT)) == 1
    with pytest.raises(LedgerError, match=f"at most {MAX_RUN_ENTRIES}"):
        build_entries(step("success", fact(), fact()), full, AT)


def test_citations_are_checked_against_the_runs_own_ledger() -> None:
    ledger = [*build_entries(step("success", fact()), [], AT), *build_entries(step("empty", evidence_id="hist"), [], AT)]
    assert check_citations(["rep:0"], ledger, benign_claim=True) == []
    assert check_citations(["rep:0", "hist:0", "rep:1", "rep:0", "x" * 500], ledger, benign_claim=True) == [
        ("hist:0", "not_benign_evidence"), ("rep:1", "unknown_fact"), ("x" * 128, "unknown_fact")
    ]
    assert check_citations(["rep:0"], [], benign_claim=False) == [("rep:0", "unknown_fact")]


def test_a_prompt_sees_ids_outcomes_and_typed_fields_only() -> None:
    ledger = [
        *build_entries(step("success", fact()), [], AT),
        *build_entries(step("failed", evidence_id="hist", reason="disabled"), [], AT),
    ]
    assert planner_view(ledger) == [
        {
            "id": "rep:0", "tool": "reputation.virustotal", "outcome": "success", "complete": True,
            "kind": "reputation", "subject": {"type": "ip", "value": "198.51.100.7"},
            "observed_at": "2026-11-14T09:59:00Z", "value": {"verdict": "malicious", "score": 91.0, "categories": []},
        },
        {"id": "hist:0", "tool": "reputation.virustotal", "outcome": "failed", "complete": False, "reason": "disabled"},
    ]
