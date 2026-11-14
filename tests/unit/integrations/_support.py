"""Shared builders for the integrations unit tests (no credential-shaped literals: values are built at runtime)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

import httpx

from lg_sotf.db.repos.integrations import Integration
from lg_sotf.db.repos.outbox import OutboxEntry
from lg_sotf.integrations.events import action_summary, alert_summary, build_event, escalation_summary

PUBLIC_IP = "93.184.216.34"
TENANT = "tenant-a"


def fake_secret(label: str = "secret", size: int = 24) -> str:
    return f"test-{label}-" + "x" * size


def slack_url() -> str:
    return "https://hooks.slack.com/services/" + "/".join(["T" + "0" * 8, "B" + "0" * 8, "z" * 24])


async def public_resolver(host: str, port: int) -> List[str]:
    return [PUBLIC_IP]


def alert_row(**overrides: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "id": "alert-1",
        "title": "Beacon to <!channel> from ws-042",
        "severity": "high",
        "status": "waiting_human",
        "disposition": None,
        "confidence": 72.4,
        "threat_score": 81.0,
        "category": "malware",
        "source_id": "splunk-prod",
        "summary": {"verdict": "malicious"},
        "normalized": {
            "entities": {
                "hosts": [f"ws-{i:03d}" for i in range(9)],
                "ips": ["185.220.101.44"],
                "command_lines": ["curl -H 'Authorization: Bearer " + "a" * 30 + "' http://x"],
            }
        },
        "raw": {"password": "must-never-appear"},
    }
    row.update(overrides)
    return row


def escalation(**overrides: Any) -> Dict[str, Any]:
    esc: Dict[str, Any] = {
        "id": "esc-1",
        "level": "L2",
        "priority": 8,
        "status": "open",
        "reason": "grey zone",
        "decision": None,
        "sla_deadline": datetime(2026, 9, 30, 13, 0, tzinfo=UTC),
        "related_alert_ids": [],
    }
    esc.update(overrides)
    return esc


def event(event_type: str = "escalation.created", *, with_escalation: bool = True, action: Any = None,
          alert: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    return build_event(
        event_type,
        TENANT,
        alert=alert_summary(alert or alert_row()),
        escalation=escalation_summary(escalation()) if with_escalation else None,
        action=action_summary(action) if action is not None else None,
    )


def integration(kind: str, *, config: Optional[Dict[str, Any]] = None, ciphertext: Optional[str] = None,
                enabled: bool = True, events: Sequence[str] = ("escalation.created",)) -> Integration:
    now = datetime.now(UTC)
    return Integration.model_validate(
        {
            "id": uuid.uuid4(), "tenant_id": TENANT, "kind": kind, "name": f"{kind} test", "enabled": enabled,
            "config": config or {}, "secret_ciphertext": ciphertext, "events": list(events), "min_severity": "low",
            "created_by": None, "created_at": now, "updated_at": now,
        }
    )


def outbox_entry(integration_id: Optional[uuid.UUID], payload: Dict[str, Any], *, operation: str = "notify", attempts: int = 1,
                 created_at: Optional[datetime] = None, escalation_id: Optional[str] = None) -> OutboxEntry:
    now = datetime.now(UTC)
    return OutboxEntry.model_validate(
        {
            "id": uuid.uuid4(), "tenant_id": TENANT, "integration_id": integration_id, "event_id": uuid.UUID(payload["id"]),
            "event_type": payload["event"], "operation": operation, "dedupe_key": f"k-{uuid.uuid4()}",
            "alert_id": "alert-1", "escalation_id": escalation_id, "payload": payload, "status": "pending",
            "attempts": attempts, "next_attempt_at": now, "last_error": None, "result": None, "sent_at": None,
            "created_at": created_at or now, "updated_at": now,
        }
    )


class Recorder:
    """An httpx.MockTransport handler that records requests and answers from a script."""

    def __init__(self, *responses: Any) -> None:
        self.requests: List[httpx.Request] = []
        self._responses = list(responses) or [httpx.Response(200, text="ok")]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            return answer(request)
        return answer

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


Handler = Callable[[httpx.Request], httpx.Response]
