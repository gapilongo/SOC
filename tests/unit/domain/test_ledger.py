"""The fact ledger's rules (AI-E3.2): ids, entries, what may be cited and what a prompt may show. Pure."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from lg_sotf.db.pool import json_dumps
from lg_sotf.domain.ledger import (
    MAX_PLANNER_CHARS,
    MAX_RUN_ENTRIES,
    RUN_ID_PATTERN,
    LedgerEntry,
    LedgerError,
    ToolStep,
    build_entries,
    canonical,
    check_citations,
    mint_fact_id,
    new_run_id,
    plan_record,
    planner_view,
)
from lg_sotf.models.evidence_fact import EvidenceFact, parse_fact

pytestmark = pytest.mark.unit

AT = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
IN, OUT = "a" * 64, "b" * 64


def fact(**changes: Any) -> EvidenceFact:
    base: Dict[str, Any] = {
        "id": "x", "kind": "reputation", "subject": {"type": "ip", "value": "198.51.100.7"},
        "observed_at": "2026-11-14T09:59:00Z", "source": {"name": "virustotal"}, "complete": True,
        "value": {"verdict": "malicious", "score": 91.0},
    }
    return parse_fact({**base, **changes})


def step(outcome: str = "success", *facts: EvidenceFact, **changes: Any) -> ToolStep:
    values: Dict[str, Any] = {
        "evidence_id": "rep", "tool": "reputation.virustotal", "tool_version": 1, "input_hash": IN,
        "output_hash": OUT, "outcome": outcome, "complete": outcome != "failed", "facts": facts,
    }
    return ToolStep(**{**values, **changes})


def test_a_run_id_names_one_investigation_run() -> None:
    first, second = new_run_id(), new_run_id()
    assert first != second and all(re.fullmatch(RUN_ID_PATTERN, run) for run in (first, second))


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
    with pytest.raises(LedgerError, match=f"at most {MAX_RUN_ENTRIES}"):
        build_entries(step("empty"), [f"rep:{n}" for n in range(MAX_RUN_ENTRIES)], AT)


def test_an_id_that_only_looks_like_one_is_not_an_entry() -> None:
    (entry,) = build_entries(step("empty"), [], AT)
    for lookalike in ("rep:0\n", "rep:00", "rep:0 ", " rep:0", "Rep:0", "rep:０", "rеp:0", "rep:0#x", "rep:-1", "rep"):
        with pytest.raises(ValidationError):
            LedgerEntry(**{**entry.model_dump(), "fact_id": lookalike})
        assert check_citations([lookalike], [entry], benign_claim=False) == [(lookalike, "unknown_fact")]


def test_recording_is_idempotent_and_never_overflows() -> None:
    ledger: List[LedgerEntry] = []
    first = plan_record(step("success", fact(), fact(confidence=0.5)), ledger, AT)
    assert first.new == first.entries and [e.fact_id for e in first.new] == ["rep:0", "rep:1"]
    ledger += first.new
    # The same call again (a retried node), whenever it comes: the entries it has, nothing to add.
    again = plan_record(step("success", fact(), fact(confidence=0.5)), ledger, AT + timedelta(hours=1))
    assert again.new == () and again.entries == first.entries
    # Another evidence id, another input, another output or another tool (the members of a family call share
    # one step's hashes) is another observation.
    others = (
        step("success", fact(), evidence_id="other"), step("success", fact(), input_hash="c" * 64),
        step("empty", output_hash="d" * 64), step("success", fact(), tool="reputation.abuseipdb"),
    )
    for other in others:
        planned = plan_record(other, ledger, AT)
        assert len(planned.new) == 1 and planned.new == planned.entries
        ledger += planned.new
    assert [e.fact_id for e in ledger] == ["rep:0", "rep:1", "other:0", "rep:2", "rep:3", "rep:4"]

    # The last place of a run's ledger is kept for the entry that says it is full.
    full = [e for n in range(MAX_RUN_ENTRIES - 1) for e in build_entries(step("empty", evidence_id=f"e{n}"), [], AT)]
    over = plan_record(step("success", fact(), evidence_id="late"), full, AT)
    (marker,) = over.new
    assert (marker.fact_id, marker.outcome, marker.reason, marker.complete, marker.fact) == ("late:0", "failed", "ledger_capacity", False, None)
    assert (marker.input_hash, marker.output_hash) == (IN, OUT)  # still bound to the call it stands for
    after = plan_record(step("empty", evidence_id="later"), [*full, marker], AT)
    assert after.new == () and after.entries == (marker,)


def test_what_is_hashed_is_what_the_table_stores() -> None:
    """A NUL, a lone surrogate, a negative zero or a whole float would come back from JSONB changed: the fact
    is put in its stored form before it is hashed, so the row read back still matches its hash."""
    hostile = "FIN\x00SRV café \U0001f600 " + "A" * 900  # a NUL, and the longest text a subject may hold
    assert len(hostile) > 900
    odd = fact(
        subject={"type": "host", "value": hostile}, confidence=1.0,
        value={"verdict": "benign", "score": -0.0, "categories": ["a\x00b"]},
    )
    (entry,) = build_entries(step("success", odd), [], AT)
    assert entry.fact is not None and entry.intact
    stored = entry.fact
    text = json.dumps(stored, ensure_ascii=False)
    assert "\x00" not in text and "\\u0000" not in json.dumps(stored) and text.encode("utf-8")  # storable as it is
    assert stored["subject"]["value"] == "FIN�SRV café \U0001f600 " + "A" * 900
    assert stored["value"]["categories"] == ["a�b"]
    assert (stored["value"]["score"], stored["confidence"]) == (0, 1) and repr(stored["value"]["score"]) == "0"
    # A lone surrogate never gets this far: the fact schema refuses it. The stored form handles it all the
    # same, as the database's codec does (a ``?``).
    with pytest.raises(ValidationError):
        fact(subject={"type": "host", "value": "bad \ud800 half"})
    hostile += " \ud800 \udfff"

    # The database's JSON codec and JSONB leave the stored form as it is: the round trip changes nothing.
    values: List[Any] = [
        stored, hostile, "\x00", -0.0, 0.0, 85.0, 1e22, 1e-7, 0.30000000000000004, 5e-324, 2**53 + 1, True, None,
        {"k\x00": [float("nan"), float("inf"), {"deep": ("t", -0.0)}]},
    ]
    for value in values:
        once = canonical(value)
        assert canonical(once) == once and repr(canonical(once)) == repr(once)
        assert repr(json.loads(json_dumps(once))) == repr(once), value
    # What the codec would have done to the raw value is what canonical does to its strings.
    assert json.loads(json_dumps({"v": hostile}))["v"] == canonical(hostile)

    # The entry as the table returns it (JSON round trip, time in another zone) is the same entry.
    row = {**json.loads(json_dumps(entry.model_dump(mode="json"))), "as_of": AT.astimezone(timezone(timedelta(hours=2)))}
    back = LedgerEntry.model_validate(row)
    assert back.intact and back.content_hash == entry.content_hash and back.fact == entry.fact
    assert check_citations(["rep:0"], [back], benign_claim=True) == []


def test_citations_are_checked_against_the_runs_own_ledger() -> None:
    ledger = [
        *build_entries(step("success", fact()), [], AT),
        *build_entries(step("empty", evidence_id="hist"), [], AT),
        *build_entries(step("success", fact(complete=None), evidence_id="old"), [], AT),
        *build_entries(step("success", fact(source={"name": "reader.mail"}), evidence_id="read"), [], AT),
    ]
    assert check_citations(["rep:0"], ledger, benign_claim=True) == []
    assert check_citations(["rep:0", "hist:0", "rep:1", "rep:0", "x" * 500, "old:0", "read:0"], ledger, benign_claim=True) == [
        ("hist:0", "not_benign_evidence"), ("rep:1", "unknown_fact"), ("x" * 128, "unknown_fact"),
        ("old:0", "incomplete_fact"), ("read:0", "not_benign_evidence"),
    ]
    # Only a benign claim has to rest on complete, observed facts, and has to cite something.
    assert check_citations(["rep:0", "hist:0", "old:0", "read:0"], ledger, benign_claim=False) == []
    assert check_citations([], ledger, benign_claim=True) == [("", "no_citation")]
    assert check_citations([], ledger, benign_claim=False) == []
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
            "observed_at": "2026-11-14T09:59:00Z", "value": {"verdict": "malicious", "score": 91, "categories": []},
        },
        {"id": "hist:0", "tool": "reputation.virustotal", "outcome": "failed", "complete": False, "reason": "disabled"},
    ]


def test_what_a_prompt_sees_is_bounded() -> None:
    big = fact(subject={"type": "host", "value": "H" * 1024})
    ledger: List[LedgerEntry] = []
    for n in range(100):
        ledger += build_entries(step("success", big, evidence_id=f"e{n}"), [], AT)
    ledger += build_entries(step("failed", evidence_id="last", reason="time_cap"), [], AT)
    shown = planner_view(ledger)
    assert len(json.dumps(shown, separators=(",", ":"))) <= MAX_PLANNER_CHARS + 2 * len(shown)
    # In order, as many as fit; a small entry after a large one that did not fit is still shown.
    assert [o["id"] for o in shown[:2]] == ["e0:0", "e1:0"] and 40 < len(shown) < 60 and shown[-1]["id"] == "last:0"
    assert planner_view(ledger, max_chars=10) == []
