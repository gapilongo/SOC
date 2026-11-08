"""Characterization goldens for the evidence pack: the HTML rendering and ``bundle_sha256`` of a fixed pack.

``build_evidence_pack`` runs against in-memory repositories holding a fixed
case: automated and human steps, ties in the oversight sort keys (so the
pre-sort append order is pinned), a rollback and a retry from the audit
log, every kind of override. The digest covers the whole canonical JSON
(``human_oversight`` included), so a refactor of the pack builder or of the
oversight classification that changes a byte fails here. The HTML golden
pins ``render_evidence_html`` byte for byte.

The goldens are today's behaviour: a diff is a reviewed change. After an
intended change, regenerate with ``REGENERATE``.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator, Dict, List
from uuid import UUID

import pytest

from lg_sotf.compliance import evidence
from lg_sotf.compliance.canonical import canonical_bytes, sha256_hex
from lg_sotf.compliance.evidence import build_evidence_pack, render_evidence_html
from lg_sotf.db.repos import TraceStep
from lg_sotf.db.repos.audit import ChainVerification
from tests.unit.compliance._support import ANALYST, T0, action, alert, escalation, event, feedback

GOLDEN_HTML = Path(__file__).with_name("evidence_pack.golden.html")
# sha256 of the canonical JSON of the fixed pack below (integrity block excluded, as seal() computes it).
GOLDEN_BUNDLE_SHA256 = "d8dd4d89631e9d686a427ca2ea472698fdb33ebfbd2a9ec552cab1fc7934d7ad"
UPDATE_ENV = "LG_SOTF_UPDATE_GOLDENS"
REGENERATE = f"{UPDATE_ENV}=1 python -m pytest tests/unit/compliance/test_evidence_golden.py"


def _uuid(n: int) -> UUID:
    return UUID(f"00000000-0000-4000-8000-{n:012d}")


def _hash(n: int) -> str:
    return f"{n:02d}" * 32


def _trace_step(n: int, kind: str, **fields: Any) -> TraceStep:
    data: Dict[str, Any] = {
        "id": _uuid(200 + n), "tenant_id": "t1", "alert_id": "a1", "run_id": "t1:a1", "step_index": n,
        "agent": "analysis", "kind": kind, "input_hash": _hash(40 + n), "outcome": "success",
        "started_at": T0 + timedelta(minutes=4, seconds=n), "created_at": T0 + timedelta(minutes=5),
    }
    data.update(fields)
    return TraceStep.model_validate(data)


def _trace() -> List[TraceStep]:
    """One LLM step per outcome kind that renders differently, and a tool step that failed."""
    return [
        _trace_step(0, "llm", agent="triage", prompt_name="triage.assess", prompt_hash="0123456789abcdef",
                    provider="anthropic", model="claude-x", output_hash=_hash(50),
                    result_digest={"value": {"reasoning": "LSASS access <b>pattern</b>"}}, input_tokens=900,
                    output_tokens=120, cache_read_tokens=10, latency_ms=812),
        _trace_step(1, "tool", tool="history", output_hash=_hash(51),
                    result_digest={"value": {"provider": "history", "status": "not_found"}}, latency_ms=4),
        _trace_step(2, "tool", tool="reputation", outcome="error", error_type="ProviderHTTPError", latency_ms=3000),
        _trace_step(3, "llm", prompt_name="analysis.react_step", prompt_hash="fedcba9876543210", provider="anthropic",
                    model="claude-y", outcome="invalid_output", error_type="LLMOutputError", input_tokens=1500,
                    output_tokens=4096, latency_ms=20_000),
    ]


def _fixed_case() -> Dict[str, Any]:
    ticket = action(
        "create_ticket", "SOC", "succeeded", id=_uuid(101), idempotency_key="idem-101", approved_by="policy:auto",
        approved_at=T0 + timedelta(minutes=40), executed_at=T0 + timedelta(minutes=41), connector="webhook",
        attempts=1, result={"ticket": "SOC-1"},
    )
    block_a = action(
        "block_ip", "203.0.113.7", "approved", id=_uuid(102), idempotency_key="idem-102", approved_by=str(ANALYST),
        approved_at=T0 + timedelta(minutes=30), params={"duration": "24h"},
    )
    # Same step name and the same timestamp as block_a: only the append order decides which comes first.
    block_b = action(
        "block_ip", "198.51.100.9", "approved", id=_uuid(103), idempotency_key="idem-103", approved_by=str(ANALYST),
        approved_at=T0 + timedelta(minutes=30),
    )
    rejected = action(
        "isolate_host", "ws-042", "rejected", id=_uuid(104), idempotency_key="idem-104", approved_by=str(ANALYST),
        updated_at=T0 + timedelta(minutes=50),
    )
    blocked = action(
        "disable_user", "admin", "blocked", id=_uuid(105), idempotency_key="idem-105",
        blocked_reason="protected asset",
    )
    rollback = action(
        "create_ticket", "SOC", "succeeded", id=_uuid(106), idempotency_key="idem-106", rollback_of=_uuid(101),
        requested_by=str(ANALYST), approved_by=str(ANALYST), approved_at=T0 + timedelta(minutes=50),
        executed_at=T0 + timedelta(minutes=51), connector="webhook", created_at=T0 + timedelta(minutes=50),
        updated_at=T0 + timedelta(minutes=51), verification="verified", verified_at=T0 + timedelta(minutes=52),
    )
    summary = {
        "triage": {"confidence": 82, "llm_used": True, "reasoning": "LSASS access <b>pattern</b>"},
        "correlation": {"related": 2, "llm_used": False},
        "analysis": {
            "verdict": "malicious", "threat_score": 77, "confidence": 70, "llm_used": True,
            "conclusion": "Credential dumping", "tools": [{"tool": "vt", "result": "known bad"}],
            "threat_indicators": ["T1003.001"], "history": [],
        },
        "llm_models": {
            "triage": {
                "provider": "anthropic", "model": "claude-x", "tier": "fast", "prompt_name": "triage.assess",
                "prompt_hash": "0123456789abcdef",
            },
        },
        "llm_usage": {"by_agent": {"triage": {"calls": 1, "input_tokens": 900}}},
        "decision": {"route": "escalate", "reason": "high severity"},
        "response": {"threat_type": "credential_theft"},
        "close_reason": "analyst:false_positive",
    }
    audit = [
        _audit(1, T0 + timedelta(minutes=1), "alert.ingested", "alert", "a1", actor_type="system", actor_id="ingest"),
        _audit(2, T0 + timedelta(minutes=30), "escalation.decided", "escalation", "e1"),
        # Same timestamp as the rejected action's override: only the append order decides.
        _audit(3, T0 + timedelta(minutes=50), "response_action.rollback_requested", "response_action",
               str(_uuid(101)), details={"reason": "ticket opened in error"}),
        _audit(4, T0 + timedelta(minutes=55), "response_action.retry_requested", "response_action",
               str(_uuid(105)), details={"reason": "exception granted"}),
        _audit(5, T0 + timedelta(minutes=56), "response_action.noted", "response_action", str(_uuid(102))),
    ]
    return {
        "alert": alert(summary=summary, raw={"vendor": "splunk", "note": "<iframe src=//x>"}),
        "events": [
            event("gate", minutes=1),
            event("triage", minutes=2),
            event("correlation", minutes=3),
            event("analysis", minutes=4),
            event("escalate", minutes=5),
            event("note", event_type="note", actor_type="user", minutes=20),
            event("enrichment", event_type="node.failed", minutes=6),
        ],
        "escalations": [escalation(decision="false_positive", related_alert_ids=["a2", "a0"])],
        "actions": [ticket, block_a, block_b, rejected, blocked, rollback],
        "feedback": [feedback(correlation_helpful=False)],
        "sightings": [
            SimpleNamespace(indicator_type="ip", value_display="203.0.113.7", value_hash=_hash(7), seen_at=T0),
        ],
        "audit": audit,
        "trace": _trace(),
    }


def _audit(n: int, ts: Any, action_name: str, resource_type: str, resource_id: str, *, actor_type: str = "user",
           actor_id: str = str(ANALYST), details: Any = None) -> Dict[str, Any]:
    return {
        "tenant_id": "t1", "id": n, "ts": ts, "actor_type": actor_type, "actor_id": actor_id, "action": action_name,
        "resource_type": resource_type, "resource_id": resource_id, "details": details or {},
        "prev_hash": _hash(n - 1), "hash": _hash(n), "hash_valid": True,
    }


def _page(items: List[Any]) -> SimpleNamespace:
    return SimpleNamespace(items=items, next_cursor=None)


class _Conn:
    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.rows = rows

    async def fetch(self, *_args: Any) -> List[Dict[str, Any]]:
        return self.rows


def _repos(case: Dict[str, Any]) -> Any:
    conn = _Conn(case["audit"])

    @asynccontextmanager
    async def tenant_tx(_tenant_id: str, **_kwargs: Any) -> AsyncIterator[_Conn]:
        yield conn

    async def returning(value: Any, *_args: Any, **_kwargs: Any) -> Any:
        return value

    def fake(value: Any) -> Any:
        return lambda *args, **kwargs: returning(value, *args, **kwargs)

    return SimpleNamespace(
        db=SimpleNamespace(tenant_tx=tenant_tx),
        alerts=SimpleNamespace(get=fake(case["alert"])),
        alert_events=SimpleNamespace(list_for_alert=fake(_page(case["events"]))),
        escalations=SimpleNamespace(list=fake(_page(case["escalations"]))),
        actions=SimpleNamespace(list=fake(_page(case["actions"]))),
        feedback=SimpleNamespace(list_for_alert=fake(case["feedback"])),
        indicators=SimpleNamespace(sightings_for_alert=fake(case["sightings"])),
        investigation_steps=SimpleNamespace(list_for_alert=fake(case["trace"])),
        blind_audit=SimpleNamespace(pending_alert_ids=fake(set())),
        audit=SimpleNamespace(verify_chain=fake(ChainVerification(ok=True, first_bad_id=None))),
    )


@pytest.fixture
def fixed_pack(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    # The version and the install's signing key are not part of what the goldens pin.
    monkeypatch.setattr(evidence, "__version__", "0.0.0-golden")
    monkeypatch.setattr(evidence, "optional_signing_key", lambda _settings: None)
    case = _fixed_case()
    return asyncio.run(
        build_evidence_pack(
            _repos(case), None, "t1", "a1",
            generated_by={"actor_type": "user", "actor_id": str(ANALYST)}, now=T0 + timedelta(hours=3),
        )
    )


def test_fixed_pack_bundle_sha256_matches_golden(fixed_pack: Dict[str, Any]) -> None:
    digest = fixed_pack["integrity"]["bundle_sha256"]
    body = {k: v for k, v in fixed_pack.items() if k != "integrity"}
    assert digest == sha256_hex(canonical_bytes(body))
    assert digest == GOLDEN_BUNDLE_SHA256, (
        f"the evidence pack of the fixed case changed (bundle_sha256 {digest}). If this is intended, update "
        "GOLDEN_BUNDLE_SHA256 and review the HTML golden diff."
    )


def test_fixed_pack_oversight_covers_the_tie_breaks(fixed_pack: Dict[str, Any]) -> None:
    """The fixed case exercises what the digest is meant to pin; guard the fixture itself."""
    oversight = fixed_pack["human_oversight"]
    steps = [(s["step"], s["detail"]) for s in oversight["steps"]]
    assert steps.index(("action_approved:block_ip", "203.0.113.7")) + 1 == steps.index(
        ("action_approved:block_ip", "198.51.100.9")
    )
    kinds = [o["kind"] for o in oversight["overrides"]]
    assert kinds.index("action_rolled_back") + 1 == kinds.index("action_rejected")
    assert sorted(set(kinds)) == ["action_rejected", "action_rolled_back", "agent_output_disputed",
                                  "verdict_overridden"]
    assert {"rollback_requested:create_ticket", "retry_requested:disable_user", "action_blocked:disable_user",
            "action_executed:create_ticket", "escalation_claimed", "analyst_decision", "note"} <= {s for s, _ in steps}


def test_fixed_pack_shows_every_trace_step(fixed_pack: Dict[str, Any]) -> None:
    trace = fixed_pack["investigation"]
    assert [(s["step_index"], s["kind"], s["outcome"]) for s in trace["steps"]] == [
        (0, "llm", "success"), (1, "tool", "success"), (2, "tool", "error"), (3, "llm", "invalid_output"),
    ]
    assert trace["totals"] == {"llm_steps": 2, "tool_steps": 2, "input_tokens": 2400, "output_tokens": 4216,
                               "latency_ms": 23816}
    assert trace["runs"] == ["t1:a1"] and fixed_pack["limits"]["investigation_truncated"] is False
    page = render_evidence_html(fixed_pack)
    for step in trace["steps"]:
        assert (step["output_hash"] or "-") in page
    assert "triage.assess (version 0123456789abcdef)" in page and "anthropic / claude-x" in page
    assert "error: ProviderHTTPError" in page and "LSASS access" not in page.split('id="trace"')[1].split("</section>")[0]


def test_evidence_html_matches_golden(fixed_pack: Dict[str, Any]) -> None:
    page = render_evidence_html(fixed_pack)
    # The file carries one final newline the page does not have (pre-commit's end-of-file-fixer).
    if os.environ.get(UPDATE_ENV) == "1":
        GOLDEN_HTML.write_text(page + "\n", encoding="utf-8")
        return
    assert GOLDEN_HTML.exists(), f"{GOLDEN_HTML.name} is missing; create it with: {REGENERATE}"
    assert page + "\n" == GOLDEN_HTML.read_text(encoding="utf-8"), (
        f"render_evidence_html output changed. If this is intended, regenerate and review the diff: {REGENERATE}"
    )
