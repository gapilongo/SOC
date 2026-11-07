"""Work queue producer (Redis Streams)."""

from __future__ import annotations

from typing import Any, List, Mapping, Sequence, Tuple

from redis.asyncio import Redis

from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.streams import SEVERITIES, QueueStreams, encode_work
from lg_sotf.settings import Settings

log = get_logger(__name__)


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


class WorkQueue:
    """Enqueue workflow work for the workers.

    Work streams are never trimmed: ``MAXLEN`` would silently delete entries
    that are still pending. Acked entries are removed with ``XDEL`` by the
    consumer instead.
    """

    def __init__(self, redis: Redis, settings: Settings) -> None:
        self._redis = redis
        self._streams = QueueStreams(settings.redis.key_prefix)

    @property
    def streams(self) -> QueueStreams:
        return self._streams

    async def enqueue_process(self, tenant_id: str, alert_id: str, severity: str) -> str:
        """Queue a (fresh or continued) run of the workflow; returns the stream entry id."""
        if severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {severity!r}")
        stream = self._streams.for_severity(severity)
        entry_id = await self._add(stream, encode_work(tenant_id, alert_id, "process", {}))
        log.debug("queue.enqueued", kind="process", stream=self._streams.label(stream), entry_id=entry_id)
        return entry_id

    async def enqueue_process_many(self, tenant_id: str, alerts: Sequence[Tuple[str, str]]) -> List[str]:
        """``enqueue_process`` for several ``(alert_id, severity)`` pairs in one pipelined round trip."""
        if not alerts:
            return []
        for _, severity in alerts:
            if severity not in SEVERITIES:
                raise ValueError(f"invalid severity: {severity!r}")
        async with self._redis.pipeline(transaction=False) as pipe:
            for alert_id, severity in alerts:
                pipe.xadd(self._streams.for_severity(severity), dict(encode_work(tenant_id, alert_id, "process", {})))  # type: ignore[arg-type]
            ids = await pipe.execute()
        log.debug("queue.enqueued", kind="process", count=len(ids))
        return [_text(i) for i in ids]

    async def enqueue_resume(self, tenant_id: str, alert_id: str, payload: Mapping[str, Any]) -> str:
        """Queue a resume of an interrupted run on the high-priority stream (an analyst is waiting)."""
        kind = payload.get("type")
        if kind not in ("analyst_decision", "approval"):
            raise ValueError("resume payload type must be 'analyst_decision' or 'approval'")
        stream = self._streams.high
        entry_id = await self._add(stream, encode_work(tenant_id, alert_id, "resume", payload))
        log.debug("queue.enqueued", kind="resume", stream=self._streams.label(stream), entry_id=entry_id)
        return entry_id

    async def _add(self, stream: str, fields: Mapping[str, str]) -> str:
        entry_id = await self._redis.xadd(stream, dict(fields))  # type: ignore[arg-type]
        return _text(entry_id)
