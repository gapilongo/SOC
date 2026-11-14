"""Matching the lookups an alert's summary records to the trace store's tool steps (PRD-2.8a).

The trace store keeps hashes, never inputs, so the investigation view finds
a lookup's step by hash: the input hash when the stored target is the value
that was sent, else the output hash, in the order the lookups ran.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

import pytest

from lg_sotf.db.repos import TraceStep
from lg_sotf.domain.investigation.evidence import lookups_of
from lg_sotf.llm.trace import content_hash, tool_input_hash
from lg_sotf.services.investigation import decided_tier, match_traces
from tests.fixtures import investigation as prototype

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 14, 9, 44, 28, tzinfo=UTC)
NOT_FOUND = {"provider": "virustotal", "status": "not_found", "verdict": "unknown"}


def step(index: int, tool: Optional[str], *, input_hash: str = "", output: Any = None, **changes: Any) -> TraceStep:
    values: Dict[str, Any] = {
        "id": uuid4(), "tenant_id": "tenant-a", "alert_id": "a-1", "run_id": "tenant-a:a-1", "step_index": index,
        "created_at": T0, "agent": "analysis", "kind": "tool" if tool else "llm", "tool": tool,
        "input_hash": input_hash or f"{index:064x}", "outcome": "success", "started_at": T0 + timedelta(seconds=index),
        "output_hash": content_hash(output) if output is not None else None,
    }
    return TraceStep(**{**values, **changes})


def reputation_step(index: int, kind: str, value: str, results: List[Dict[str, Any]]) -> TraceStep:
    request = {"kind": kind, "value": value, "providers": sorted(r["provider"] for r in results)}
    return step(index, "reputation", input_hash=tool_input_hash("reputation", request), output=results)


def summary(*tools: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"analysis": {"tools": list(tools), "history": history or []}}


def test_a_lookup_is_matched_by_the_input_hash_of_its_call() -> None:
    past, tools = prototype.lookups()
    lookups = lookups_of({"analysis": {"tools": tools, "history": past}})
    steps = [
        step(0, None),  # a model call: never a lookup's step
        step(1, "history", input_hash=tool_input_hash("history", {"kind": "user", "value": prototype.USER}),
             output={k: v for k, v in past[0].items() if k not in ("kind", "value", "checked_at")}),
        *[reputation_step(i + 2, t["kind"], t["target"], t["results"]) for i, t in enumerate(tools)],
    ]
    matched, failed = match_traces(lookups, steps)
    assert failed == []
    assert [lookup.trace.input_hash if lookup.trace else None for lookup in matched] == [
        steps[1].input_hash, None, *[s.input_hash for s in steps[2:]]
    ]
    assert matched[2].trace is not None and matched[2].trace.started_at == steps[2].started_at
    assert [(m.tool, m.kind, m.target) for m in matched] == [(x.tool, x.kind, x.target) for x in lookups]


def test_a_redacted_target_is_matched_by_the_output_hash_in_the_order_the_lookups_ran() -> None:
    """The summary stores targets redacted and cut, so their input hash can differ from the one recorded."""
    answer = [{"provider": "virustotal", "status": "ok", "verdict": "malicious", "data": {"votes": 9}}]
    lookups = lookups_of(
        summary(
            prototype.reputation("url", "https://x.example/?token=[REDACTED]", NOT_FOUND),
            prototype.reputation("url", "https://y.example/?token=[REDACTED]", NOT_FOUND),
            prototype.reputation("domain", "z.example", *answer),
        )
    )
    steps = [
        step(0, "reputation", input_hash="a" * 64, output=[NOT_FOUND]),
        step(1, "reputation", input_hash="b" * 64, output=[NOT_FOUND]),
        step(2, "reputation", input_hash="c" * 64, output=answer),
        step(3, "history", input_hash="d" * 64, output=[NOT_FOUND]),  # another tool: never a reputation lookup's
    ]
    matched, _ = match_traces(lookups, steps)
    assert [m.trace.input_hash if m.trace else None for m in matched] == ["a" * 64, "b" * 64, "c" * 64]


def test_the_newest_analysis_wins_and_its_failed_calls_are_reported() -> None:
    results = [NOT_FOUND]
    lookups = lookups_of(summary(prototype.reputation("ip", prototype.ADDRESS, *results)))
    older = reputation_step(0, "ip", prototype.ADDRESS, results)
    raised_before = step(1, "history", outcome="error", error_type="TimeoutError")
    newer = reputation_step(2, "ip", prototype.ADDRESS, results)
    raised_after = step(3, "reputation", outcome="error", error_type="ConnectError")
    matched, failed = match_traces(lookups, [older, raised_before, newer, raised_after])
    assert matched[0].trace is not None and matched[0].trace.started_at == newer.started_at
    assert [(f.tool, f.error_type, f.output_hash) for f in failed] == [("reputation", "ConnectError", None)]

    # No lookup returned: only the calls that raised after the last one that did.
    none_matched, tail = match_traces([], [older, raised_before, newer, raised_after])
    assert none_matched == [] and [f.error_type for f in tail] == ["ConnectError"]
    assert match_traces(lookups, []) == (lookups, [])


def test_the_tier_is_the_one_the_decision_recorded() -> None:
    class Event:
        def __init__(self, node: str, data: Dict[str, Any]) -> None:
            self.event_type, self.node, self.data = "node.completed", node, data

    auto = {"ai_closure": {"tier": "auto_full_audit"}}
    recorded: Any = [Event("decide", {"autonomy_tier": "auto_full_audit"}), Event("decide", {"autonomy_tier": "off"})]
    assert decided_tier(recorded, auto) == "off"  # the last decision's, not today's setting
    assert decided_tier([], auto) == "auto_full_audit"
    unreadable: Any = [Event("decide", {"autonomy_tier": "everything"}), Event("close", {})]
    assert decided_tier(unreadable, None) == "off"
