"""Tenant event fan-out over Redis pub/sub (contract section 7).

Delivery is at-most-once: subscribers that are disconnected miss events and
re-read state from the API. Events carry identifiers and small status data
only, never alert bodies.

Publishing goes to ``{prefix}:events:{tenant_id}``. Subscribing is
multiplexed: each :class:`EventBus` holds at most one pub/sub connection
(``PSUBSCRIBE {prefix}:events:*``) while it has subscribers, and fans events
out to per-subscriber bounded queues. The API therefore uses one Redis
connection for all its WebSockets instead of one each, and a slow consumer
cannot stall the others: when its buffer fills, its iteration ends (its
``lagged`` flag is set) and the client is expected to reconnect and re-read
state. A bus accepts at most ``max_subscribers`` concurrent subscriptions.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, AsyncIterator, Dict, Mapping, Optional, Set, Union

from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from lg_sotf.db.tenancy import validate_tenant_id
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings, get_settings

log = get_logger(__name__)

EVENT_TYPES = (
    "alert.updated",
    "alert.created",
    "escalation.created",
    "escalation.updated",
    "action.updated",
)
MAX_EVENT_BYTES = 64 * 1024
DEFAULT_MAX_SUBSCRIBERS = 1_000
DEFAULT_SUBSCRIBER_BUFFER = 256
_POLL_TIMEOUT_S = 1.0
_CONFIRM_TIMEOUT_S = 5.0
_RECONNECT_INITIAL_S = 0.2
_RECONNECT_MAX_S = 5.0
_REDIS_ERRORS = (RedisConnectionError, RedisTimeoutError, OSError, TimeoutError)
_GLOB_SPECIAL = "\\*?[]"


class SubscriberLimitReached(RuntimeError):
    """The bus already serves ``max_subscribers`` subscriptions (or a per-owner/tenant quota)."""


class SubscriberQuotaReached(SubscriberLimitReached):
    """This owner or tenant already holds its share of subscriptions; others are unaffected."""


def make_event(
    event_type: str, tenant_id: str, alert_id: Optional[str], data: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Event in the contract shape: ``{type, tenant_id, alert_id, data, ts}``."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type!r}")
    return {
        "type": event_type,
        "tenant_id": tenant_id,
        "alert_id": alert_id,
        "data": dict(data or {}),
        "ts": datetime.now(UTC).isoformat(),
    }


def _glob_escape(text: str) -> str:
    return "".join("\\" + ch if ch in _GLOB_SPECIAL else ch for ch in text)


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


class EventBus:
    """Publishes to and subscribes to ``{prefix}:events:{tenant_id}``."""

    def __init__(
        self,
        redis: Redis,
        settings: Optional[Settings] = None,
        *,
        max_subscribers: Optional[int] = None,
        subscriber_buffer: Optional[int] = None,
        max_per_tenant: Optional[int] = None,
        max_per_owner: Optional[int] = None,
    ) -> None:
        settings = settings or get_settings()
        api = settings.api
        max_subscribers = api.ws_max_subscribers if max_subscribers is None else max_subscribers
        subscriber_buffer = api.ws_subscriber_buffer if subscriber_buffer is None else subscriber_buffer
        max_per_tenant = api.ws_max_per_tenant if max_per_tenant is None else max_per_tenant
        max_per_owner = api.ws_max_per_principal if max_per_owner is None else max_per_owner
        if min(max_subscribers, subscriber_buffer, max_per_tenant, max_per_owner) < 1:
            raise ValueError("subscriber limits and buffer must be >= 1")
        self._redis = redis
        self._prefix = settings.redis.key_prefix
        self._hub = _Hub(
            redis,
            f"{_glob_escape(self._prefix)}:events:*",
            max_subscribers,
            subscriber_buffer,
            max_per_channel=max_per_tenant,
            max_per_owner=max_per_owner,
        )

    def channel(self, tenant_id: str) -> str:
        return f"{self._prefix}:events:{validate_tenant_id(tenant_id)}"

    @property
    def subscriber_count(self) -> int:
        return self._hub.count

    async def publish(self, tenant_id: str, event: Mapping[str, Any]) -> None:
        channel = self.channel(tenant_id)
        body = dict(event)
        if body.get("tenant_id") not in (None, tenant_id):
            raise ValueError("event tenant_id does not match the channel tenant")
        body["tenant_id"] = tenant_id
        body.setdefault("ts", datetime.now(UTC).isoformat())
        payload = json.dumps(body, separators=(",", ":"), default=str)
        if len(payload.encode()) > MAX_EVENT_BYTES:
            raise ValueError(f"event exceeds {MAX_EVENT_BYTES} bytes")
        await self._redis.publish(channel, payload)

    @asynccontextmanager
    async def subscribe(
        self, tenant_id: str, *, owner: Optional[str] = None
    ) -> AsyncIterator[AsyncIterator[Dict[str, Any]]]:
        """Iterate this tenant's events until the context exits.

        The subscription is live before the context is entered, so events
        published after entry are delivered. A lost connection is
        re-established with backoff (events published meanwhile are missed).
        Iteration ends early if this subscriber falls ``subscriber_buffer``
        events behind. Raises :class:`SubscriberLimitReached` when the bus is full,
        and :class:`SubscriberQuotaReached` when the tenant or ``owner`` (e.g. a
        principal id) already holds its share, so one tenant cannot use up the
        bus for the others.
        """
        subscription = await self._hub.add(self.channel(tenant_id), owner=owner)
        try:
            yield subscription
        finally:
            await self._hub.remove(subscription)

    async def aclose(self) -> None:
        """End every subscription and release the pub/sub connection."""
        await self._hub.close()


class _End:
    pass


_END = _End()


class Subscription:
    """One subscriber's bounded event buffer; an async iterator of event dicts."""

    def __init__(self, channel: str, buffer: int, owner: Optional[str] = None) -> None:
        self.channel = channel
        self.owner = owner
        self.lagged = False
        self._queue: asyncio.Queue[Union[Dict[str, Any], _End]] = asyncio.Queue(maxsize=buffer + 1)
        self._buffer = buffer
        self._ended = False

    @property
    def ended(self) -> bool:
        return self._ended

    def offer(self, event: Dict[str, Any]) -> bool:
        """Queue an event; False (and the subscription ends) when the buffer is full."""
        if self._ended:
            return False
        if self._queue.qsize() >= self._buffer:
            self.lagged = True
            self.end()
            return False
        self._queue.put_nowait(event)
        return True

    def end(self) -> None:
        if self._ended:
            return
        self._ended = True
        while not self._queue.empty():
            self._queue.get_nowait()
        self._queue.put_nowait(_END)

    def __aiter__(self) -> Subscription:
        return self

    async def __anext__(self) -> Dict[str, Any]:
        item = await self._queue.get()
        if isinstance(item, _End):
            self._queue.put_nowait(item)
            raise StopAsyncIteration
        return item


class _Hub:
    """Shares one pattern subscription between all subscribers of a bus."""

    def __init__(
        self,
        redis: Redis,
        pattern: str,
        max_subscribers: int,
        buffer: int,
        *,
        max_per_channel: Optional[int] = None,
        max_per_owner: Optional[int] = None,
    ) -> None:
        self._redis = redis
        self._pattern = pattern
        self._max = max_subscribers
        self._max_per_channel = max_per_channel or max_subscribers
        self._max_per_owner = max_per_owner or max_subscribers
        self._buffer = buffer
        self._subs: Dict[str, Set[Subscription]] = {}
        self._owners: Dict[str, int] = {}
        self._count = 0
        self._lock = asyncio.Lock()
        self._pubsub: Optional[PubSub] = None
        self._reader: Optional[asyncio.Task[None]] = None

    @property
    def count(self) -> int:
        return self._count

    async def add(self, channel: str, owner: Optional[str] = None) -> Subscription:
        async with self._lock:
            if owner is not None and self._owners.get(owner, 0) >= self._max_per_owner:
                raise SubscriberQuotaReached(f"this principal already has {self._max_per_owner} subscriptions")
            if len(self._subs.get(channel, ())) >= self._max_per_channel:
                raise SubscriberQuotaReached(f"this tenant already has {self._max_per_channel} subscriptions")
            if self._count >= self._max:
                raise SubscriberLimitReached(f"event bus already has {self._max} subscribers")
            if self._reader is None or self._reader.done():
                await self._start()
            sub = Subscription(channel, self._buffer, owner)
            self._subs.setdefault(channel, set()).add(sub)
            self._count += 1
            if owner is not None:
                self._owners[owner] = self._owners.get(owner, 0) + 1
            return sub

    async def remove(self, sub: Subscription) -> None:
        async with self._lock:
            self._detach(sub)
            sub.end()
            if self._count == 0:
                await self._stop()

    async def close(self) -> None:
        async with self._lock:
            for subs in list(self._subs.values()):
                for sub in list(subs):
                    self._detach(sub)
                    sub.end()
            await self._stop()

    def _detach(self, sub: Subscription) -> None:
        subs = self._subs.get(sub.channel)
        if subs is None or sub not in subs:
            return
        subs.discard(sub)
        self._count -= 1
        if sub.owner is not None:
            left = self._owners.get(sub.owner, 1) - 1
            if left > 0:
                self._owners[sub.owner] = left
            else:
                self._owners.pop(sub.owner, None)
        if not subs:
            del self._subs[sub.channel]

    async def _open(self) -> PubSub:
        pubsub = self._redis.pubsub()
        try:
            await pubsub.psubscribe(self._pattern)
            # Wait for the confirmation so events published after subscribe() returns are delivered.
            async with asyncio.timeout(_CONFIRM_TIMEOUT_S):
                while True:
                    message = await pubsub.get_message(timeout=_POLL_TIMEOUT_S)
                    if message is not None and message.get("type") == "psubscribe":
                        break
        except BaseException:
            await pubsub.aclose()
            raise
        return pubsub

    async def _start(self) -> None:
        await self._stop()
        self._pubsub = await self._open()
        self._reader = asyncio.create_task(self._read_loop(), name="event-bus-reader")

    async def _stop(self) -> None:
        reader, self._reader = self._reader, None
        if reader is not None:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        pubsub, self._pubsub = self._pubsub, None
        if pubsub is not None:
            await pubsub.aclose()

    async def _read_loop(self) -> None:
        try:
            await self._read_forever()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Unexpected: end every subscription so no consumer waits forever; the next subscribe restarts.
            log.error("events.reader_failed", error=type(exc).__name__)
            for subs in list(self._subs.values()):
                for sub in list(subs):
                    self._detach(sub)
                    sub.end()
            raise

    async def _read_forever(self) -> None:
        delay = _RECONNECT_INITIAL_S
        while True:
            if self._pubsub is None:
                try:
                    self._pubsub = await self._open()
                except _REDIS_ERRORS as exc:
                    log.warning("events.reconnect_failed", error=type(exc).__name__, retry_in_s=delay)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, _RECONNECT_MAX_S)
                    continue
                log.info("events.resubscribed")
                delay = _RECONNECT_INITIAL_S
            try:
                message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=_POLL_TIMEOUT_S)
            except _REDIS_ERRORS as exc:
                log.warning("events.connection_lost", error=type(exc).__name__)
                broken, self._pubsub = self._pubsub, None
                try:
                    await broken.aclose()
                except _REDIS_ERRORS:
                    pass
                continue
            if message is None or message.get("type") != "pmessage":
                continue
            self._dispatch(_text(message.get("channel")), message.get("data"))

    def _dispatch(self, channel: str, data: Any) -> None:
        subs = self._subs.get(channel)
        if not subs:
            return
        try:
            event = json.loads(data)
        except (TypeError, ValueError):
            log.warning("events.invalid_payload")
            return
        if not isinstance(event, dict):
            return
        # Each subscriber gets its own copy; decoding the small JSON payload again is several
        # times cheaper than copy.deepcopy of the decoded event.
        first = True
        for sub in list(subs):
            copy_ = event if first else json.loads(data)
            first = False
            if not sub.offer(copy_):
                self._detach(sub)
                if sub.lagged:
                    log.warning("events.subscriber_lagged", buffer=self._buffer)
