from __future__ import annotations

import json
from typing import Any, List, Tuple

import pytest

from lg_sotf.db.errors import InvalidTenantId
from lg_sotf.queue.events import EventBus, make_event


class _RecordingRedis:
    def __init__(self) -> None:
        self.published: List[Tuple[str, str]] = []

    async def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 1


def test_make_event_has_contract_shape() -> None:
    event = make_event("alert.updated", "tenant-a", "alert-1", {"status": "closed"})
    assert set(event) == {"type", "tenant_id", "alert_id", "data", "ts"}
    assert event["data"] == {"status": "closed"}
    with pytest.raises(ValueError):
        make_event("alert.deleted", "tenant-a", "alert-1")


async def test_publish_uses_tenant_channel(make_settings: Any) -> None:
    redis = _RecordingRedis()
    bus = EventBus(redis, make_settings(redis={"key_prefix": "px"}))  # type: ignore[arg-type]
    await bus.publish("tenant-a", {"type": "alert.updated", "alert_id": "a", "data": {}})
    channel, body = redis.published[0]
    assert channel == "px:events:tenant-a"
    decoded = json.loads(body)
    assert decoded["tenant_id"] == "tenant-a"
    assert "ts" in decoded


async def test_publish_refuses_cross_tenant_event_and_bad_tenant(make_settings: Any) -> None:
    bus = EventBus(_RecordingRedis(), make_settings())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="does not match"):
        await bus.publish("tenant-a", make_event("alert.updated", "tenant-b", "a"))
    with pytest.raises(InvalidTenantId):
        await bus.publish("Tenant*", {"type": "alert.updated"})
