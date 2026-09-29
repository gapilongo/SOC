"""Work queue consumer: consumer-group reads, reclaim of stalled entries, ack and dead-lettering."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.streams import (
    CONSUMER_GROUP,
    WORK_FIELDS,
    MalformedMessage,
    Message,
    QueueStreams,
    decode_fields,
    parse_message,
    utc_now_iso,
)
from lg_sotf.settings import Settings, get_settings

log = get_logger(__name__)

# The DLQ is not work, so bounding it cannot lose anything that would otherwise run.
DLQ_MAXLEN = 100_000
MAX_REASON_CHARS = 500
# XREADGROUP BLOCK must end before the socket read timeout fires.
_BLOCK_MARGIN_MS = 1_000
_START = "0-0"


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

    :meth:`read` returns reclaimed entries (idle longer than
    ``worker.visibility_timeout_s``) first, then new high-priority entries,
    then new normal entries. Entries stay pending until :meth:`ack` or
    :meth:`dead_letter`; an entry left pending is reclaimed by some consumer
    after the visibility timeout, with its delivery count incremented.
    """

    def __init__(self, redis: Redis, settings: Optional[Settings], consumer_name: str) -> None:
        if not consumer_name:
            raise ValueError("consumer_name must be non-empty")
        s = settings or get_settings()
        self._redis = redis
        self._streams = QueueStreams(s.redis.key_prefix)
        self._name = consumer_name
        self._min_idle_ms = int(s.worker.visibility_timeout_s * 1000)
        max_block_ms = int(s.redis.socket_timeout_s * 1000) - _BLOCK_MARGIN_MS
        self._block_ms = max(1, min(s.worker.block_ms, max_block_ms)) if max_block_ms > 0 else 1
        if self._block_ms < s.worker.block_ms:
            log.warning("queue.block_ms_clamped", block_ms=self._block_ms, configured=s.worker.block_ms)
        self._claim_cursor: Dict[str, str] = {stream: _START for stream in self._streams.work}

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

    async def _reclaim(self, max_count: int) -> List[Message]:
        found: List[Message] = []
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

    async def requeue(self, msg: Message) -> str:
        """Put a copy of the entry at the tail of its stream and ack the original (fair-share deferral)."""
        fields = {k: v for k, v in msg.raw_fields.items() if k in WORK_FIELDS}
        pipe = self._redis.pipeline(transaction=True)
        pipe.xadd(msg.stream, fields)  # type: ignore[arg-type]
        pipe.xack(msg.stream, CONSUMER_GROUP, msg.entry_id)
        pipe.xdel(msg.stream, msg.entry_id)
        new_id, _acked, _deleted = await pipe.execute()
        return _text(new_id)

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
        still owns any is kept; they are reclaimed after the visibility timeout.
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
