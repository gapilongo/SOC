"""Work queue consumer: consumer-group reads, reclaim of stalled entries, ack and dead-lettering."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.streams import (
    CONSUMER_GROUP,
    FIELD_RETRIES,
    WORK_FIELDS,
    MalformedMessage,
    Message,
    QueueStreams,
    decode_fields,
    parse_message,
    utc_now_iso,
)
from lg_sotf.security.shadow import REFUSE, egress
from lg_sotf.settings import Settings

log = get_logger(__name__)

# The DLQ is not work, so bounding it cannot lose anything that would otherwise run.
DLQ_MAXLEN = 100_000
MAX_REASON_CHARS = 500
# XREADGROUP BLOCK must end before the socket read timeout fires.
_BLOCK_MARGIN_MS = 1_000
_START = "0-0"
# Two live consumers racing for a dead consumer's entry: XCLAIM with this min-idle lets only the first win.
_DEAD_CLAIM_MIN_IDLE_MS = 1_000
# A dead consumer with nothing pending is deleted from the group once idle this long.
_FORGET_MIN_IDLE_MS = 60_000
_MAX_DEAD_SCAN_INTERVAL_S = 5.0
_OWN_PENDING_BATCH = 100


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


@dataclass(frozen=True)
class StreamStats:
    stream: str
    label: str
    depth: int
    pending: int
    lag: Optional[int]
    """Entries not yet delivered to the group; ``None`` when Redis cannot tell."""


async def ensure_groups(redis: Redis, streams: QueueStreams) -> None:
    """Create the ``workers`` group on each work stream (idempotent)."""
    for stream in streams.work:
        try:
            await redis.xgroup_create(stream, CONSUMER_GROUP, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise


async def queue_stats(redis: Redis, streams: QueueStreams) -> List[StreamStats]:
    """Depth, pending and lag of the work streams plus the DLQ depth."""
    result: List[StreamStats] = []
    for stream in streams.work:
        depth = int(await redis.xlen(stream))
        pending = 0
        lag: Optional[int] = None
        try:
            summary = await redis.xpending(stream, CONSUMER_GROUP)
            pending = int(summary.get("pending") or 0)
            for group in await redis.xinfo_groups(stream):
                if _text(group.get("name")) == CONSUMER_GROUP:
                    raw_lag = group.get("lag")
                    lag = int(raw_lag) if raw_lag is not None else None
        except ResponseError as exc:
            if "NOGROUP" not in str(exc) and "no such key" not in str(exc):
                raise
        result.append(StreamStats(stream, streams.label(stream), depth, pending, lag))
    dlq_depth = int(await redis.xlen(streams.dlq))
    result.append(StreamStats(streams.dlq, streams.label(streams.dlq), dlq_depth, 0, None))
    return result


class StreamConsumer:
    """One worker's view of the ``workers`` consumer group.

    :meth:`read` returns reclaimed entries first, then new high-priority
    entries, then new normal entries. Entries stay pending until :meth:`ack`
    or :meth:`dead_letter`; an entry left pending is reclaimed by some
    consumer, with its delivery count incremented:

    * at once when its consumer is dead: once this consumer has called
      :meth:`announce_alive`, it claims the entries of consumers whose
      liveness key has expired (their process died without cleanup);
    * otherwise after it has been idle for ``worker.visibility_timeout_s``.

    Reclaiming an entry never runs it twice concurrently: the worker's claim
    on ``workflow_runs`` (a live lease) decides who executes the run.
    """

    def __init__(self, redis: Redis, settings: Settings, consumer_name: str) -> None:
        if not consumer_name:
            raise ValueError("consumer_name must be non-empty")
        self._redis = redis
        self._streams = QueueStreams(settings.redis.key_prefix)
        self._name = consumer_name
        self._min_idle_ms = int(settings.worker.visibility_timeout_s * 1000)
        max_block_ms = int(settings.redis.socket_timeout_s * 1000) - _BLOCK_MARGIN_MS
        self._block_ms = max(1, min(settings.worker.block_ms, max_block_ms)) if max_block_ms > 0 else 1
        if self._block_ms < settings.worker.block_ms:
            log.warning("queue.block_ms_clamped", block_ms=self._block_ms, configured=settings.worker.block_ms)
        self._claim_cursor: Dict[str, str] = {stream: _START for stream in self._streams.work}
        self._alive_ttl_ms: Optional[int] = None
        self._dead_scan_interval_s = _MAX_DEAD_SCAN_INTERVAL_S
        self._next_dead_scan = 0.0

    @property
    def name(self) -> str:
        return self._name

    @property
    def streams(self) -> QueueStreams:
        return self._streams

    async def ensure_groups(self) -> None:
        await ensure_groups(self._redis, self._streams)

    async def read(self, max_count: int) -> List[Message]:
        if max_count < 1:
            return []
        try:
            return await self._read(max_count)
        except ResponseError as exc:
            if "NOGROUP" not in str(exc):
                raise
            # The stream or group vanished (e.g. FLUSHDB); recreate and retry once.
            log.warning("queue.group_missing_recreating")
            await self.ensure_groups()
            return await self._read(max_count)

    async def _read(self, max_count: int) -> List[Message]:
        messages = await self._reclaim(max_count)
        remaining = max_count - len(messages)
        if remaining > 0:
            messages.extend(await self._read_new({self._streams.high: ">"}, remaining, block_ms=None))
            remaining = max_count - len(messages)
        if remaining > 0:
            if messages:
                messages.extend(await self._read_new({self._streams.normal: ">"}, remaining, block_ms=None))
            else:
                # Block on both streams so a high-priority entry arriving mid-wait is not delayed.
                messages.extend(
                    await self._read_new(
                        {self._streams.high: ">", self._streams.normal: ">"}, remaining, block_ms=self._block_ms
                    )
                )
        return messages

    async def announce_alive(self, ttl_s: float) -> None:
        """Mark this consumer live for ``ttl_s``; the owner refreshes it well within ``ttl_s`` while it runs.

        From the first call on, :meth:`read` also claims the pending entries
        of consumers whose liveness key has expired.
        """
        ttl_ms = max(int(ttl_s * 1000), 1)
        await self._redis.set(self._streams.consumer_alive(self._name), b"1", px=ttl_ms)
        if self._alive_ttl_ms is None:
            self._dead_scan_interval_s = min(ttl_s / 3.0, _MAX_DEAD_SCAN_INTERVAL_S)
        self._alive_ttl_ms = ttl_ms

    async def withdraw(self) -> None:
        """Drop the liveness key (clean shutdown): entries this consumer still holds are claimable at once."""
        await self._redis.delete(self._streams.consumer_alive(self._name))

    @egress("queue", REFUSE)
    async def requeue_own_pending(self) -> int:
        """Send entries still pending under this consumer name back to the tail of their stream.

        A restarted process that reuses its predecessor's consumer name
        inherits its pending entries; ``XREADGROUP >`` never returns them and
        no other consumer sees the name as dead. Call once, before the first
        :meth:`read`. Returns the number of entries requeued.
        """
        requeued = 0
        for stream in self._streams.work:
            try:
                while True:
                    rows = await self._redis.xpending_range(
                        stream, CONSUMER_GROUP, min="-", max="+", count=_OWN_PENDING_BATCH, consumername=self._name
                    )
                    ids: List[Any] = [_text(r["message_id"]) for r in rows]
                    if not ids:
                        break
                    entries: Any = await self._redis.xclaim(
                        stream, CONSUMER_GROUP, self._name, min_idle_time=0, message_ids=ids
                    )
                    pipe = self._redis.pipeline(transaction=True)
                    for entry_id, fields in entries:
                        if entry_id is None or not fields:
                            continue
                        decoded = decode_fields(fields)
                        pipe.xadd(stream, {k: v for k, v in decoded.items() if k in WORK_FIELDS})
                        requeued += 1
                    pipe.xack(stream, CONSUMER_GROUP, *ids)
                    pipe.xdel(stream, *ids)
                    await pipe.execute()
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
        if requeued:
            log.warning("queue.own_pending_requeued", consumer=self._name, count=requeued)
        return requeued

    async def _reclaim(self, max_count: int) -> List[Message]:
        found = await self._claim_from_dead(max_count)
        for stream in self._streams.work:
            remaining = max_count - len(found)
            if remaining <= 0:
                break
            response = await self._redis.xautoclaim(
                stream,
                CONSUMER_GROUP,
                self._name,
                min_idle_time=self._min_idle_ms,
                start_id=self._claim_cursor[stream],
                count=remaining,
            )
            next_cursor = _text(response[0])
            self._claim_cursor[stream] = next_cursor
            entries = [(entry_id, fields) for entry_id, fields in response[1] if entry_id is not None and fields]
            if not entries:
                continue
            deliveries = await self._delivery_counts(stream, [_text(e) for e, _ in entries])
            for entry_id, fields in entries:
                eid = _text(entry_id)
                msg = await self._parse_or_dead_letter(stream, eid, fields, deliveries.get(eid, 1))
                if msg is not None:
                    found.append(msg)
            if found:
                log.info("queue.reclaimed", stream=self._streams.label(stream), count=len(entries))
        return found

    async def _claim_from_dead(self, max_count: int) -> List[Message]:
        """Claim entries pending for consumers whose liveness key has expired (at most every few seconds)."""
        now = time.monotonic()
        if self._alive_ttl_ms is None or now < self._next_dead_scan:
            return []
        self._next_dead_scan = now + self._dead_scan_interval_s
        min_idle_ms = min(_DEAD_CLAIM_MIN_IDLE_MS, self._alive_ttl_ms // 2)
        found: List[Message] = []
        for stream in self._streams.work:
            summary = await self._redis.xpending(stream, CONSUMER_GROUP)
            for consumer in summary.get("consumers") or []:
                remaining = max_count - len(found)
                if remaining <= 0:
                    # More may be waiting: look again on the next read.
                    self._next_dead_scan = now
                    return found
                name = _text(consumer["name"])
                if name == self._name or int(consumer["pending"]) == 0:
                    continue
                if await self._redis.exists(self._streams.consumer_alive(name)):
                    continue
                rows = await self._redis.xpending_range(
                    stream, CONSUMER_GROUP, min="-", max="+", count=remaining, consumername=name
                )
                ids: List[Any] = [_text(r["message_id"]) for r in rows]
                if not ids:
                    continue
                claimed: Any = await self._redis.xclaim(
                    stream, CONSUMER_GROUP, self._name, min_idle_time=min_idle_ms, message_ids=ids
                )
                entries = [(_text(e), f) for e, f in claimed if e is not None and f]
                if not entries:
                    continue
                deliveries = await self._delivery_counts(stream, [e for e, _ in entries])
                for entry_id, fields in entries:
                    msg = await self._parse_or_dead_letter(stream, entry_id, fields, deliveries.get(entry_id, 1))
                    if msg is not None:
                        found.append(msg)
                log.warning(
                    "queue.claimed_from_dead_consumer",
                    stream=self._streams.label(stream),
                    dead_consumer=name,
                    count=len(entries),
                )
        await self._forget_dead_consumers()
        return found

    async def _forget_dead_consumers(self) -> int:
        """Delete group consumers that are dead (no liveness key), hold nothing and have been idle
        for a while: every killed worker process leaves one behind otherwise, and the group's
        consumer list (and Redis memory) would grow without bound."""
        assert self._alive_ttl_ms is not None
        min_idle_ms = max(4 * self._alive_ttl_ms, _FORGET_MIN_IDLE_MS)
        removed = 0
        for stream in self._streams.work:
            try:
                consumers = await self._redis.xinfo_consumers(stream, CONSUMER_GROUP)
            except ResponseError:
                continue
            for consumer in consumers:
                name = _text(consumer.get("name"))
                if name == self._name or int(consumer.get("pending", 0)) or int(consumer.get("idle", 0)) < min_idle_ms:
                    continue
                if await self._redis.exists(self._streams.consumer_alive(name)):
                    continue
                await self._redis.xgroup_delconsumer(stream, CONSUMER_GROUP, name)
                removed += 1
                log.info("queue.dead_consumer_removed", stream=self._streams.label(stream), consumer=name)
        return removed

    async def _delivery_counts(self, stream: str, entry_ids: Sequence[str]) -> Dict[str, int]:
        pipe = self._redis.pipeline(transaction=False)
        for entry_id in entry_ids:
            pipe.xpending_range(stream, CONSUMER_GROUP, min=entry_id, max=entry_id, count=1)
        results = await pipe.execute()
        counts: Dict[str, int] = {}
        for entry_id, rows in zip(entry_ids, results, strict=True):
            if rows:
                counts[entry_id] = int(rows[0]["times_delivered"])
        return counts

    async def _read_new(self, streams: Dict[str, str], count: int, *, block_ms: Optional[int]) -> List[Message]:
        response: Any = await self._redis.xreadgroup(
            CONSUMER_GROUP,
            self._name,
            streams,  # type: ignore[arg-type]
            count=count,
            block=block_ms,
        )
        if not response:
            return []
        by_stream: Dict[str, Any] = {}
        if isinstance(response, dict):
            for key, value in response.items():
                entries = value[0] if value and isinstance(value[0], list) else value
                by_stream[_text(key)] = entries
        else:
            for key, entries in response:
                by_stream[_text(key)] = entries
        messages: List[Message] = []
        for stream in self._streams.work:
            for entry_id, fields in by_stream.get(stream, []):
                if entry_id is None or not fields:
                    continue
                msg = await self._parse_or_dead_letter(stream, _text(entry_id), fields, 1)
                if msg is not None:
                    messages.append(msg)
        return messages

    async def _parse_or_dead_letter(
        self, stream: str, entry_id: str, fields: Mapping[Any, Any], deliveries: int
    ) -> Optional[Message]:
        try:
            return parse_message(stream, entry_id, fields, deliveries)
        except MalformedMessage as exc:
            log.warning(
                "queue.malformed_message", stream=self._streams.label(stream), entry_id=entry_id, reason=str(exc)
            )
            await self._move_to_dlq(stream, entry_id, decode_fields(fields), f"malformed: {exc}", deliveries)
            return None

    async def ack(self, msg: Message) -> bool:
        """Acknowledge and delete the entry; False if it was no longer pending for the group."""
        pipe = self._redis.pipeline(transaction=True)
        pipe.xack(msg.stream, CONSUMER_GROUP, msg.entry_id)
        pipe.xdel(msg.stream, msg.entry_id)
        acked, _deleted = await pipe.execute()
        return bool(acked)

    async def touch(self, msg: Message) -> bool:
        """Reset the entry's idle time so it is not reclaimed while still being processed.

        ``XCLAIM ... JUSTID`` does not increment the delivery counter.
        Returns False when the entry is no longer pending (acked elsewhere).
        """
        claimed = await self._redis.xclaim(
            msg.stream, CONSUMER_GROUP, self._name, min_idle_time=0, message_ids=[msg.entry_id], justid=True
        )
        return bool(claimed)

    async def dead_letter(self, msg: Message, reason: str) -> str:
        """Copy the entry to the DLQ with ``reason`` and ``failed_at``, then ack it. Returns the DLQ entry id."""
        return await self._move_to_dlq(msg.stream, msg.entry_id, msg.raw_fields, reason, msg.deliveries)

    @egress("queue", REFUSE)
    async def requeue(self, msg: Message, *, count_attempt: bool = False) -> str:
        """Put a copy of the entry at the tail of its stream and ack the original.

        Fair-share deferral keeps the retry count; a retry (``count_attempt``)
        carries this entry's deliveries into the copy (``retries``), so
        ``worker.max_deliveries`` still bounds it.
        """
        fields = {k: v for k, v in msg.raw_fields.items() if k in WORK_FIELDS}
        if count_attempt:
            fields[FIELD_RETRIES] = str(msg.attempts)
        pipe = self._redis.pipeline(transaction=True)
        pipe.xadd(msg.stream, fields)  # type: ignore[arg-type]
        pipe.xack(msg.stream, CONSUMER_GROUP, msg.entry_id)
        pipe.xdel(msg.stream, msg.entry_id)
        new_id, _acked, _deleted = await pipe.execute()
        return _text(new_id)

    @egress("queue", REFUSE)
    async def _move_to_dlq(
        self, stream: str, entry_id: str, fields: Mapping[str, str], reason: str, deliveries: int
    ) -> str:
        record = dict(fields)
        record.update(
            {
                "reason": reason[:MAX_REASON_CHARS],
                "failed_at": utc_now_iso(),
                "source_stream": stream,
                "source_entry_id": entry_id,
                "deliveries": str(deliveries),
            }
        )
        pipe = self._redis.pipeline(transaction=True)
        pipe.xadd(self._streams.dlq, record, maxlen=DLQ_MAXLEN, approximate=True)  # type: ignore[arg-type]
        pipe.xack(stream, CONSUMER_GROUP, entry_id)
        pipe.xdel(stream, entry_id)
        dlq_id, _acked, _deleted = await pipe.execute()
        return _text(dlq_id)

    async def pending_count(self) -> int:
        """Entries currently pending for this consumer across the work streams."""
        total = 0
        for stream in self._streams.work:
            try:
                summary = await self._redis.xpending(stream, CONSUMER_GROUP)
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
                continue
            for consumer in summary.get("consumers") or []:
                if _text(consumer["name"]) == self._name:
                    total += int(consumer["pending"])
        return total

    async def remove_if_idle(self) -> bool:
        """Delete this consumer from the group when it holds no pending entries (clean shutdown).

        Deleting a consumer drops its pending entries, so a consumer that
        still owns any is kept; once its liveness key is gone (:meth:`withdraw`
        or expiry) live consumers claim them.
        """
        if await self.pending_count() > 0:
            return False
        for stream in self._streams.work:
            try:
                await self._redis.xgroup_delconsumer(stream, CONSUMER_GROUP, self._name)
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
        return True

    async def stats(self) -> List[StreamStats]:
        return await queue_stats(self._redis, self._streams)
