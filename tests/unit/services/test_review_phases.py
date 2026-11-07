"""The pure phases of ``ReviewService.decide``: request parsing, approval authority and resume messages."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.db.repos import Escalation
from lg_sotf.services.review import (
    MAX_APPROVED_ACTIONS,
    MAX_APPROVED_ENTRY_CHARS,
    MAX_NOTES_CHARS,
    ReviewDenied,
    ReviewError,
    _Actor,
    _authorise_approvals,
    _DecisionRequest,
    _parse_decision,
    _resume_requests,
)

pytestmark = pytest.mark.unit

APPROVE_ALL = {"low": "approval", "medium": "approval", "high": "approval", "critical": "approval"}
USER = uuid.UUID("00000000-0000-4000-8000-000000000001")


def escalation(alert_id: str = "a1", related: Optional[List[str]] = None) -> Escalation:
    now = datetime.now(UTC)
    return Escalation(
        id="e1", tenant_id="t1", alert_id=alert_id, thread_id=f"t1:{alert_id}", level="L1", status="decided",
        reason="grey zone", priority=5, summary={}, related_alert_ids=related or [], assigned_to=None,
        sla_deadline=now, decision="true_positive", decision_notes=None, approved_actions=[], decided_by=USER,
        decided_at=now, claimed_at=None, version=2, created_at=now, updated_at=now,
    )


# ------------------------------------------------------------------ _parse_decision


def test_parse_decision_trims_notes_and_approvals() -> None:
    parsed = _parse_decision("true_positive", "  seen on host  ", [" block_ip ", "", "  ", "isolate_host:h1"], None)
    assert parsed == _DecisionRequest("true_positive", "seen on host", ["block_ip", "isolate_host:h1"], {})


def test_parse_decision_blank_notes_become_none_and_long_notes_are_cut() -> None:
    assert _parse_decision("false_positive", "   ", [], None).notes is None
    assert _parse_decision("false_positive", None, [], None).notes is None
    assert _parse_decision("false_positive", "x" * (MAX_NOTES_CHARS + 10), [], None).notes == "x" * MAX_NOTES_CHARS


def test_parse_decision_keeps_known_feedback_and_drops_none() -> None:
    feedback = {"confidence": 80, "triage_correct": True, "correlation_helpful": None}
    assert _parse_decision("benign_positive", None, [], feedback).feedback == {"confidence": 80, "triage_correct": True}


@pytest.mark.parametrize(
    ("decision", "approved", "feedback", "message"),
    [
        ("maybe", [], None, "decision must be one of"),
        ("true_positive", ["block_ip"] * (MAX_APPROVED_ACTIONS + 1), None, f"at most {MAX_APPROVED_ACTIONS} approved"),
        ("false_positive", ["block_ip"], None, "only accepted with a true_positive decision"),
        ("true_positive", [], {"mood": True}, "unknown feedback field 'mood'"),
        ("true_positive", [], {"confidence": 101}, "confidence must be an integer 0-100"),
        ("true_positive", [], {"confidence": True}, "confidence must be an integer 0-100"),
        ("true_positive", [], {"triage_correct": "yes"}, "feedback triage_correct must be true or false"),
    ],
)
def test_parse_decision_refuses(decision: str, approved: List[str], feedback: Optional[Dict[str, Any]], message: str) -> None:
    with pytest.raises(ReviewError, match=message):
        _parse_decision(decision, None, approved, feedback)


def test_parse_decision_checks_the_decision_before_anything_else() -> None:
    with pytest.raises(ReviewError, match="decision must be one of"):
        _parse_decision("maybe", None, ["block_ip"], {"mood": True})


# ------------------------------------------------------------------ _authorise_approvals


def test_authorise_approvals_accepts_entries_within_authority() -> None:
    _authorise_approvals(["block_ip", "block_ip:10.0.0.1", "create_ticket"], "analyst", APPROVE_ALL)
    _authorise_approvals(["isolate_host:h1", "disable_user"], "admin", APPROVE_ALL)
    _authorise_approvals([], "analyst", {})


@pytest.mark.parametrize(
    ("entries", "role", "autonomy", "error", "message"),
    [
        (["launch_missiles"], "analyst", APPROVE_ALL, ReviewError, "unknown action type 'launch_missiles'"),
        (["block_ip: "], "analyst", APPROVE_ALL, ReviewError, "approved action 'block_ip' names an empty target"),
        (
            ["block_ip:" + "1" * MAX_APPROVED_ENTRY_CHARS], "analyst", APPROVE_ALL, ReviewError,
            f"at most {MAX_APPROVED_ENTRY_CHARS} characters",
        ),
        (["isolate_host"], "analyst", APPROVE_ALL, ReviewDenied, "role 'analyst' may not approve high risk action"),
        (
            ["block_ip"], "admin", {**APPROVE_ALL, "medium": "disabled"}, ReviewDenied,
            "role 'admin' may not approve medium risk action 'block_ip'",
        ),
    ],
)
def test_authorise_approvals_refuses(
    entries: List[str], role: str, autonomy: Dict[str, str], error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        _authorise_approvals(entries, role, autonomy)


def test_authorise_approvals_stops_at_the_first_bad_entry_in_order() -> None:
    with pytest.raises(ReviewDenied):
        _authorise_approvals(["isolate_host", "launch_missiles"], "analyst", APPROVE_ALL)
    with pytest.raises(ReviewError, match="unknown action type"):
        _authorise_approvals(["launch_missiles", "isolate_host"], "analyst", APPROVE_ALL)


# ------------------------------------------------------------------ _resume_requests


def test_resume_requests_give_pre_approvals_to_the_reviewed_alert_only() -> None:
    request = _DecisionRequest("true_positive", None, ["block_ip"], {})
    approved = ["block_ip:10.0.0.1"]
    requests = _resume_requests("e1", escalation("a1", ["a2", "a1", "a3"]), request, approved, _Actor(USER, "admin"))
    assert [r.alert_id for r in requests] == ["a1", "a2", "a3"]
    assert requests[0].payload == {
        "type": "analyst_decision",
        "escalation_id": "e1",
        "decision": "true_positive",
        "approved_actions": ["block_ip:10.0.0.1"],
        "decided_by": str(USER),
        "notes": "",
        "approver_role": "admin",
    }
    assert [r.payload["approved_actions"] for r in requests[1:]] == [[], []]
    assert {r.payload["notes"] for r in requests} == {""}


def test_resume_requests_carry_the_notes() -> None:
    request = _DecisionRequest("false_positive", "scanner", [], {})
    (only,) = _resume_requests("e1", escalation(), request, [], _Actor(USER, "analyst"))
    assert only.payload["notes"] == "scanner" and only.payload["decision"] == "false_positive"
