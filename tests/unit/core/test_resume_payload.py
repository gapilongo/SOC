"""Resume payload validation (contract section 8 shapes)."""

from __future__ import annotations

import pytest

from lg_sotf.core.exceptions import InvalidResumePayload
from lg_sotf.core.workflow import validate_resume_payload


def test_valid_analyst_decision() -> None:
    data = validate_resume_payload(
        {"type": "analyst_decision", "escalation_id": "e1", "decision": "true_positive",
         "approved_actions": ["block_ip"], "decided_by": "u1", "notes": "ok"}
    )
    assert data["decision"] == "true_positive" and data["approved_actions"] == ["block_ip"]


def test_valid_approval() -> None:
    data = validate_resume_payload(
        {"type": "approval", "approved_action_ids": ["a"], "rejected_action_ids": ["b"], "decided_by": "u1"}
    )
    assert data["type"] == "approval" and data["reject_remaining"] is False
    final = validate_resume_payload(
        {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": "u1",
         "reject_remaining": True}
    )
    assert final["reject_remaining"] is True


def test_analyst_decision_approver_role() -> None:
    base = {"type": "analyst_decision", "escalation_id": "e1", "decision": "true_positive", "decided_by": "u1"}
    assert validate_resume_payload(base)["approver_role"] is None
    assert validate_resume_payload({**base, "approver_role": "admin"})["approver_role"] == "admin"
    with pytest.raises(InvalidResumePayload):
        validate_resume_payload({**base, "approver_role": "root"})


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"type": "other"},
        {"type": "analyst_decision", "escalation_id": "e", "decision": "maybe", "decided_by": "u"},
        {"type": "analyst_decision", "escalation_id": "e", "decision": "true_positive", "decided_by": "u", "x": 1},
        {"type": "analyst_decision", "escalation_id": "", "decision": "true_positive", "decided_by": "u"},
        {"type": "approval", "approved_action_ids": ["a"], "rejected_action_ids": ["a"], "decided_by": "u"},
        {"type": "approval", "approved_action_ids": "a", "decided_by": "u"},
    ],
)
def test_invalid_payloads(payload: dict) -> None:
    with pytest.raises(InvalidResumePayload):
        validate_resume_payload(payload)
