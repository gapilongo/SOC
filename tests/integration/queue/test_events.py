from __future__ import annotations

import asyncio
import contextlib
from typing import Any, Callable

import pytest

from lg_sotf.queue.events import EventBus, SubscriberLimitReached, make_event
from lg_sotf.queue.redis import create_redis
from lg_sotf.settings import Settings


async def _pattern_subscribers(redis_client: Any) -> int:
    db = redis_client.connection_pool.connection_kwargs.get("db", 0)
    return sum(
        1
        for client in await redis_client.client_list()
        if int(client.get("db", -1)) == int(db) and int(client.get("psub", 0)) > 0
    )


async def _kill_own_pubsub_connections(redis_client: Any) -> None:
    """Kill only subscribers on this test's database; the server is shared with other suites."""
    db = redis_client.connection_pool.connection_kwargs.get("db", 0)
    killed = 0
    for client in await redis_client.client_list():
        if int(client.get("db", -1)) == int(db) and int(client.get("psub", 0)) > 0:
            await redis_client.client_kill_filter(_id=client["id"])
            killed += 1
    assert killed >= 1


async def test_subscriber_receives_only_its_tenant(redis_client: Any, queue_settings: Callable[..., Settings]) -> None:
    bus = EventBus(redis_client, queue_settings())
    async with bus.subscribe("tenant-a") as events:
        await bus.publish("tenant-b", make_event("alert.updated", "tenant-b", "b1"))
        await bus.publish("tenant-a", make_event("alert.updated", "tenant-a", "a1", {"status": "closed"}))
        event = await asyncio.wait_for(anext(events), timeout=3)
    assert event["alert_id"] == "a1"
    assert event["data"] == {"status": "closed"}
    assert event["tenant_id"] == "tenant-a"


async def test_last_unsubscribe_releases_the_pubsub_connection(
    redis_client: Any, queue_settings: Callable[..., Settings]
) -> None:
    bus = EventBus(redis_client, queue_settings())
    async with bus.subscribe("tenant-a"), bus.subscribe("tenant-b"):
        assert bus.subscriber_count == 2
        assert await _pattern_subscribers(redis_client) == 1
    assert bus.subscriber_count == 0
    for _ in range(20):
        if await _pattern_subscribers(redis_client) == 0:
            break
        await asyncio.sleep(0.05)
    assert await _pattern_subscribers(redis_client) == 0


async def test_many_subscribers_share_one_connection_and_leave_the_pool_usable(
    queue_settings: Callable[..., Settings],
) -> None:
    s = queue_settings()
    s = s.model_copy(update={"redis": s.redis.model_copy(update={"max_connections": 3})})
    redis = create_redis(s)
    bus = EventBus(redis, s)
    try:
        async with contextlib.AsyncExitStack() as stack:
            streams = [await stack.enter_async_context(bus.subscribe("tenant-a")) for _ in range(10)]
            other = await stack.enter_async_context(bus.subscribe("tenant-b"))
            await redis.set(f"{s.redis.key_prefix}:probe", b"1")
            assert await redis.get(f"{s.redis.key_prefix}:probe") == b"1"
            await bus.publish("tenant-a", make_event("alert.updated", "tenant-a", "a1"))
            received = [await asyncio.wait_for(anext(events), timeout=3) for events in streams]
            assert {e["alert_id"] for e in received} == {"a1"}
            received[0]["data"]["mutated"] = True
            assert "mutated" not in received[1]["data"]
            await bus.publish("tenant-b", make_event("alert.updated", "tenant-b", "b1"))
            assert (await asyncio.wait_for(anext(other), timeout=3))["alert_id"] == "b1"
    finally:
        await bus.aclose()
        await redis.delete(f"{s.redis.key_prefix}:probe")
        await redis.aclose()


async def test_subscriber_limit(redis_client: Any, queue_settings: Callable[..., Settings]) -> None:
    bus = EventBus(redis_client, queue_settings(), max_subscribers=2)
    async with bus.subscribe("tenant-a"), bus.subscribe("tenant-a"):
        with pytest.raises(SubscriberLimitReached):
            async with bus.subscribe("tenant-a"):
                pass
    async with bus.subscribe("tenant-a"):
        assert bus.subscriber_count == 1


async def test_slow_subscriber_is_ended_without_affecting_others(
    redis_client: Any, queue_settings: Callable[..., Settings]
) -> None:
    bus = EventBus(redis_client, queue_settings(), subscriber_buffer=2)
    async with bus.subscribe("tenant-a") as slow, bus.subscribe("tenant-a") as fast:
        got: list[str] = []
        for i in range(5):
            await bus.publish("tenant-a", make_event("alert.updated", "tenant-a", f"a{i}"))
            got.append((await asyncio.wait_for(anext(fast), timeout=3))["alert_id"])
        assert got == [f"a{i}" for i in range(5)]
        assert [e async for e in slow] == []
        assert slow.lagged  # type: ignore[attr-defined]
        assert bus.subscriber_count == 1


async def test_resubscribes_after_connection_is_killed(
    redis_client: Any, queue_settings: Callable[..., Settings]
) -> None:
    bus = EventBus(redis_client, queue_settings())
    async with bus.subscribe("tenant-a") as events:
        await _kill_own_pubsub_connections(redis_client)
        received: list[dict] = []

        async def consume() -> None:
            received.append(await anext(events))

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.2)
        for _ in range(50):
            if await _pattern_subscribers(redis_client) == 1:
                break
            await asyncio.sleep(0.1)
        await bus.publish("tenant-a", make_event("escalation.created", "tenant-a", "a9"))
        await asyncio.wait_for(task, timeout=5)
    assert received[0]["type"] == "escalation.created"
