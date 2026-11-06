"""Helpers shared by the service unit tests (and the connector TLS tests)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Dict

from lg_sotf.db.repos.actions import ResponseAction, action_idempotency_key


def make_action(**kw: Any) -> ResponseAction:
    now = datetime.now(UTC)
    base: Dict[str, Any] = dict(
        id=uuid.uuid4(), tenant_id="t1", alert_id="a1", action_type="block_ip", target="185.220.101.44",
        params={"playbook": "malware", "alert": {"severity": "high", "title": "C2 beacon"}}, risk_level="medium",
        idempotency_key=action_idempotency_key("t1", "a1", "block_ip", "185.220.101.44"), status="executing",
        blocked_reason=None, requested_by="agent:workflow", approved_by="u1", approved_at=now, executed_at=now,
        connector="webhook", result=None, rollback_of=None, created_at=now, updated_at=now,
    )
    base.update(kw)
    return ResponseAction(**base)
