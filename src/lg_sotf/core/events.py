"""Event publishing for the UI fan-out (contract section 7)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Mapping, Optional, Protocol, runtime_checkable

from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

EVENT_TYPES = frozenset(
    {"alert.updated", "alert.created", "escalation.created", "escalation.updated", "action.updated"}
)


@runtime_checkable
class EventPublisher(Protocol):
    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None: ...


def make_event(event_type: str, tenant_id: str, alert_id: str, data: Mapping[str, Any]) -> Dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    return {
        "type": event_type,
        "tenant_id": tenant_id,
        "alert_id": alert_id,
        "data": dict(data),
        "ts": datetime.now(UTC).isoformat(),
    }


async def publish_event(
    events: Optional[EventPublisher], event_type: str, tenant_id: str, alert_id: str, data: Mapping[str, Any]
) -> None:
    """Publish after the change is committed. Delivery is best effort: pub/sub only feeds live UIs,
    which re-read state from the API, so a lost event must not fail or repeat the workflow step."""
    if events is None:
        return
    event = make_event(event_type, tenant_id, alert_id, data)
    try:
        await events.publish(tenant_id, event)
    except Exception as exc:  # noqa: BLE001 - see docstring
        log.warning("events.publish_failed", event_type=event_type, error_type=type(exc).__name__)
