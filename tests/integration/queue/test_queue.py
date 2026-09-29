from __future__ import annotations

import asyncio
from typing import Any, Callable

from lg_sotf.queue.consumer import CONSUMER_GROUP, StreamConsumer, queue_stats
from lg_sotf.queue.dlq import DeadLetterQueue
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.settings import Settings

Build = Callable[..., Settings]


async def _setup(redis_client: Any, settings: Settings, name: str = "c1") -> tuple[WorkQueue, StreamConsumer]:
    consumer = StreamConsumer(redis_client, settings, name)
    await consumer.ensure_groups()
    await consumer.ensure_groups()
    return WorkQueue(redis_client, settings), consumer


async def test_roundtrip_process_and_resume(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings()
    queue, consumer = await _setup(redis_client, s)
    await queue.enqueue_process("tenant-a", "a1", "medium")
    payload = {"type": "approval", "approved_action_ids": ["x"], "rejected_action_ids": [], "decided_by": "u1"}
    await queue.enqueue_resume("tenant-a", "a2", payload)

    msgs = await consumer.read(10)
    assert [(m.alert_id, m.kind) for m in msgs] == [("a2", "resume"), ("a1", "process")]
    assert msgs[0].payload == payload
    assert msgs[0].stream == queue.streams.high
    assert msgs[1].stream == queue.streams.normal
    assert all(m.deliveries == 1 for m in msgs)


async def test_high_priority_is_read_before_normal(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    for i in range(3):
        await queue.enqueue_process("tenant-a", f"n{i}", "low")
    await queue.enqueue_process("tenant-a", "h0", "critical")
    await queue.enqueue_process("tenant-a", "h1", "high")

    first = await consumer.read(2)
    assert [m.alert_id for m in first] == ["h0", "h1"]
    second = await consumer.read(2)
    assert [m.alert_id for m in second] == ["n0", "n1"]


async def test_blocking_read_returns_new_high_entry(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings(block_ms=2_000))

    async def later() -> None:
        await asyncio.sleep(0.2)
        await queue.enqueue_process("tenant-a", "late", "critical")

    task = asyncio.create_task(later())
    msgs = await consumer.read(5)
    await task
    assert [m.alert_id for m in msgs] == ["late"]


async def test_ack_removes_entry_from_stream_and_pel(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    await queue.enqueue_process("tenant-a", "a1", "high")
    (msg,) = await consumer.read(1)
    assert await redis_client.xlen(queue.streams.high) == 1
    assert await consumer.ack(msg) is True
    assert await redis_client.xlen(queue.streams.high) == 0
    assert (await redis_client.xpending(queue.streams.high, CONSUMER_GROUP))["pending"] == 0
    assert await consumer.ack(msg) is False


async def test_unacked_entry_is_reclaimed_after_visibility_timeout(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings(visibility_timeout_s=1)
    queue, first = await _setup(redis_client, s, "w1")
    second = StreamConsumer(redis_client, s, "w2")
    await queue.enqueue_process("tenant-a", "a1", "high")
    (msg,) = await first.read(1)
    assert msg.deliveries == 1

    assert await second.read(1) == []
    await asyncio.sleep(1.1)
    (again,) = await second.read(1)
    assert again.entry_id == msg.entry_id
    assert again.deliveries == 2


async def test_touch_prevents_reclaim(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings(visibility_timeout_s=1)
    queue, first = await _setup(redis_client, s, "w1")
    second = StreamConsumer(redis_client, s, "w2")
    await queue.enqueue_process("tenant-a", "a1", "high")
    (msg,) = await first.read(1)
    for _ in range(3):
        await asyncio.sleep(0.5)
        assert await first.touch(msg) is True
    assert await second.read(1) == []
    await first.ack(msg)
    assert await first.touch(msg) is False


async def test_reclaim_skips_entries_deleted_while_pending(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings(visibility_timeout_s=1)
    queue, consumer = await _setup(redis_client, s, "w1")
    await queue.enqueue_process("tenant-a", "gone", "high")
    await queue.enqueue_process("tenant-a", "kept", "high")
    msgs = await consumer.read(2)
    await redis_client.xdel(queue.streams.high, msgs[0].entry_id)
    await asyncio.sleep(1.1)
    reclaimed = await StreamConsumer(redis_client, s, "w2").read(5)
    assert [m.alert_id for m in reclaimed] == ["kept"]


async def test_dead_letter_moves_entry_with_reason(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings()
    queue, consumer = await _setup(redis_client, s)
    await queue.enqueue_process("tenant-a", "a1", "low")
    (msg,) = await consumer.read(1)
    dlq_id = await consumer.dead_letter(msg, "exceeded 3 deliveries")
    assert await redis_client.xlen(queue.streams.normal) == 0

    letters = await DeadLetterQueue(redis_client, s).list()
    assert [(d.entry_id, d.alert_id, d.kind, d.reason) for d in letters] == [
        (dlq_id, "a1", "process", "exceeded 3 deliveries")
    ]
    assert letters[0].source_stream == queue.streams.normal
    assert letters[0].failed_at

    dlq = DeadLetterQueue(redis_client, s)
    new_id = await dlq.requeue(letters[0])
    assert await dlq.depth() == 0
    (back,) = await consumer.read(1)
    assert back.entry_id == new_id
    assert back.deliveries == 1
    assert back.stream == queue.streams.normal


async def test_malformed_entry_goes_to_dlq_and_is_not_returned(redis_client: Any, queue_settings: Build) -> None:
    s = queue_settings()
    queue, consumer = await _setup(redis_client, s)
    await redis_client.xadd(queue.streams.high, {"tenant_id": "tenant-a", "kind": "process"})
    await queue.enqueue_process("tenant-a", "ok", "high")
    msgs = await consumer.read(5)
    assert [m.alert_id for m in msgs] == ["ok"]
    (letter,) = await DeadLetterQueue(redis_client, s).list()
    assert letter.reason.startswith("malformed")


async def test_requeue_moves_entry_to_tail(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    await queue.enqueue_process("tenant-a", "first", "high")
    await queue.enqueue_process("tenant-a", "second", "high")
    (msg,) = await consumer.read(1)
    await consumer.requeue(msg)
    assert [m.alert_id for m in await consumer.read(5)] == ["second", "first"]


async def test_stats_report_depth_pending_and_lag(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    for i in range(3):
        await queue.enqueue_process("tenant-a", f"a{i}", "medium")
    await consumer.read(1)
    stats = {s.label: s for s in await queue_stats(redis_client, queue.streams)}
    assert stats["normal"].depth == 3
    assert stats["normal"].pending == 1
    assert stats["normal"].lag == 2
    assert stats["high"].depth == 0
    assert stats["dlq"].depth == 0


async def test_group_is_recreated_after_flush(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    await redis_client.flushdb()
    assert await consumer.read(1) == []
    await queue.enqueue_process("tenant-a", "a1", "high")
    assert [m.alert_id for m in await consumer.read(1)] == ["a1"]


async def test_remove_if_idle_keeps_consumer_with_pending_work(redis_client: Any, queue_settings: Build) -> None:
    queue, consumer = await _setup(redis_client, queue_settings())
    await queue.enqueue_process("tenant-a", "a1", "high")
    (msg,) = await consumer.read(1)
    assert await consumer.pending_count() == 1
    assert await consumer.remove_if_idle() is False
    await consumer.ack(msg)
    assert await consumer.remove_if_idle() is True
