"""Dead-letter queue inspection and requeue (operations)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from redis.asyncio import Redis

from lg_sotf.queue.streams import WORK_FIELDS, QueueStreams, decode_fields
from lg_sotf.settings import Settings, get_settings


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


@dataclass(frozen=True)
class DeadLetter:
    entry_id: str
    tenant_id: str
    alert_id: str
    kind: str
    reason: str
    failed_at: str
    deliveries: str
    source_stream: str
    fields: Dict[str, str]


def _to_dead_letter(entry_id: Any, fields: Any) -> DeadLetter:
    data = decode_fields(fields)
    return DeadLetter(
        entry_id=_text(entry_id),
        tenant_id=data.get("tenant_id", ""),
        alert_id=data.get("alert_id", ""),
        kind=data.get("kind", ""),
        reason=data.get("reason", ""),
        failed_at=data.get("failed_at", ""),
        deliveries=data.get("deliveries", ""),
        source_stream=data.get("source_stream", ""),
        fields=data,
    )


class DeadLetterQueue:
    def __init__(self, redis: Redis, settings: Optional[Settings] = None) -> None:
        self._redis = redis
        self._streams = QueueStreams((settings or get_settings()).redis.key_prefix)

    async def list(self, *, limit: int = 50, start: str = "-") -> List[DeadLetter]:
        """Oldest first, starting at entry id ``start`` (inclusive)."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        rows = await self._redis.xrange(self._streams.dlq, min=start, max="+", count=limit) or []
        return [_to_dead_letter(entry_id, fields) for entry_id, fields in rows]

    async def get(self, entry_id: str) -> Optional[DeadLetter]:
        rows = await self._redis.xrange(self._streams.dlq, min=entry_id, max=entry_id, count=1) or []
        return _to_dead_letter(*rows[0]) if rows else None

    def target_stream(self, letter: DeadLetter) -> str:
        """The work stream a dead letter goes back to (its source, or ``high`` if unknown)."""
        if letter.source_stream in self._streams.work:
            return letter.source_stream
        return self._streams.high

    async def requeue(self, letter: DeadLetter) -> str:
        """Move a dead letter back to its work stream with a fresh delivery count; returns the new entry id."""
        fields = {k: v for k, v in letter.fields.items() if k in WORK_FIELDS}
        missing = [k for k in ("tenant_id", "alert_id", "kind") if not fields.get(k)]
        if missing:
            raise ValueError(f"dead letter {letter.entry_id} cannot be requeued: missing {', '.join(missing)}")
        pipe = self._redis.pipeline(transaction=True)
        pipe.xadd(self.target_stream(letter), fields)  # type: ignore[arg-type]
        pipe.xdel(self._streams.dlq, letter.entry_id)
        new_id, _deleted = await pipe.execute()
        return _text(new_id)

    async def delete(self, entry_id: str) -> bool:
        return bool(await self._redis.xdel(self._streams.dlq, entry_id))

    async def depth(self) -> int:
        return int(await self._redis.xlen(self._streams.dlq))
