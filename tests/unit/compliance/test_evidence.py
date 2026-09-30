"""Human-oversight classification and the evidence-pack HTML rendering (no database)."""

from __future__ import annotations

from typing import Any, Dict

from lg_sotf.compliance.canonical import jsonable, seal
from lg_sotf.compliance.evidence import human_oversight, render_evidence_html
from tests.unit.compliance._support import ANALYST, T0, TITLE, action, alert, escalation, event, feedback


def _oversight(**kwargs: Any) -> Dict[str, Any]:
    summary = kwargs.pop("summary", alert().summary)
    return jsonable(
        human_oversight(
            summary,
            kwargs.pop("events", [event("triage"), event("analysis", minutes=2)]),
            kwargs.pop("escalations", []),
            kwargs.pop("actions", []),
            kwargs.pop("feedback", []),
        )
    )


def test_fully_automated_close_has_no_human_steps() -> None:
    summary = {"analysis": {"verdict": "benign"}, "close_reason": "policy:close"}
    out = _oversight(summary=summary, events=[event("gate"), event("triage", minutes=2), event("close", minutes=3)])
    assert [s["mode"] for s in out["steps"]] == ["automated"] * 3
    assert out["summary"]["closed_without_human"] is True and out["overrides"] == []


def test_analyst_decisions_approvals_and_overrides_are_attributed() -> None:
    policy_approved = action("create_ticket", "SOC", "succeeded", approved_by="policy:auto", executed_at=T0,
                             connector="webhook")
    human_approved = action("block_ip", "203.0.113.7", "approved", approved_by=str(ANALYST))
    rejected = action("isolate_host", "ws-042", "rejected", approved_by=str(ANALYST))
    blocked = action("disable_user", "admin", "blocked", blocked_reason="protected asset")
    out = _oversight(
        summary={"analysis": {"verdict": "malicious"}, "close_reason": "analyst:false_positive"},
        events=[event("triage"), event("note", event_type="note", actor_type="user", minutes=20)],
        escalations=[escalation(decision="false_positive")],
        actions=[policy_approved, human_approved, rejected, blocked],
        feedback=[feedback()],
    )
    modes = {s["step"]: (s["mode"], s["actor"]) for s in out["steps"]}
    assert modes["analyst_decision"] == ("human", str(ANALYST))
    assert modes["escalation_claimed"] == ("human", str(ANALYST))
    assert modes["note"][0] == "human"
    assert modes["action_approved:create_ticket"] == ("automated", "policy:auto")
    assert modes["action_approved:block_ip"] == ("human", str(ANALYST))
    assert modes["action_rejected:isolate_host"] == ("human", str(ANALYST))
    assert modes["action_blocked:disable_user"] == ("automated", "guardrails")
    assert modes["action_executed:create_ticket"] == ("automated", "webhook")
    kinds = [o["kind"] for o in out["overrides"]]
    assert sorted(kinds) == ["action_rejected", "agent_output_disputed", "verdict_overridden"]
    assert out["summary"]["human_decisions"] == 1 and out["summary"]["human_action_approvals"] == 1
    assert out["summary"]["closed_without_human"] is False
    assert [s["at"] for s in out["steps"]] == sorted(s["at"] for s in out["steps"])


def test_agreeing_analyst_decision_is_not_an_override() -> None:
    out = _oversight(escalations=[escalation(decision="true_positive")])
    assert out["overrides"] == []


def _pack() -> Dict[str, Any]:
    a = alert()
    return seal(
        jsonable(
            {
                "format": "lg-sotf.evidence-pack",
                "version": 1,
                "tenant_id": "t1",
                "generated_at": T0,
                "generated_by": {"actor_type": "user", "actor_id": str(ANALYST)},
                "alert": {**a.model_dump(), "raw_redacted": {"note": "<iframe src=//x>"}, "raw_redactions": 0},
                "timeline": [e.model_dump() for e in (event("triage"),)],
                "agents": {
                    "triage": {"ran": True, "model": {"recorded": True, "provider": "anthropic", "model": "claude-x",
                                                     "tier": "fast"}, "reasoning": "<script>x()</script>"},
                    "decision": {"route": "escalate"},
                },
                "human_oversight": _oversight(escalations=[escalation(decision="false_positive")]),
                "escalations": [escalation().model_dump()],
                "feedback": [],
                "actions": [action("block_ip", "1.2.3.4", "rejected").model_dump()],
                "audit": {
                    "entries": [{"id": 1, "action": "escalation.decided", "hash": "ab" * 32, "hash_valid": True}],
                    "chain_verification": {"ok": True, "since": T0, "first_bad_id": None},
                    "included_entry_hashes_valid": True,
                },
                "limits": {"timeline_truncated": False},
            }
        ),
        b"k" * 32,
    )


def test_evidence_html_is_self_contained_escaped_and_complete() -> None:
    pack = _pack()
    page = render_evidence_html(pack)
    assert page.startswith("<!DOCTYPE html>") and page.rstrip().endswith("</html>")
    for heading in ("Human oversight", "Agent reasoning and verdicts", "Escalations", "Analyst feedback",
                    "Response ledger", "Timeline", "Audit trail", "Integrity"):
        assert f"<h2>{heading}</h2>" in page
    assert "<script" not in page and "<iframe" not in page and "<b>Mimikatz" not in page
    assert "&lt;script&gt;x()&lt;/script&gt;" in page and "&lt;iframe" in page and TITLE not in page
    assert "anthropic / claude-x (fast tier)" in page and "VALID" in page
    assert pack["integrity"]["bundle_sha256"] in page
    assert "http://" not in page and "https://" not in page and "src=" not in page.replace("src=//x", "")
    assert 'border="1"' in page and "@media print" in page
