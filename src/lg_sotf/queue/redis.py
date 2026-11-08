"""Redis client factory, and the client class that refuses writes in a shadow run."""

from __future__ import annotations

from typing import Any, Optional

from redis.asyncio import Redis
from redis.asyncio.client import Pipeline
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from lg_sotf.security.shadow import REFUSE, egress, refuse_in_shadow
from lg_sotf.settings import Settings

HEALTH_CHECK_INTERVAL_S = 30
CONNECT_RETRIES = 3
# The commands a shadow run may send: reads only. Anything else, and every pipeline, is refused.
SHADOW_READ_COMMANDS = frozenset({
    "GET", "MGET", "EXISTS", "TTL", "PTTL", "TYPE", "STRLEN", "DUMP", "KEYS", "SCAN", "DBSIZE", "PING",
    "HGET", "HMGET", "HGETALL", "HEXISTS", "HLEN", "HKEYS", "HVALS", "LRANGE", "LLEN", "LINDEX",
    "SMEMBERS", "SISMEMBER", "SCARD", "ZRANGE", "ZRANGEBYSCORE", "ZSCORE", "ZCARD", "ZCOUNT", "ZRANK",
    "XRANGE", "XREVRANGE", "XLEN", "XPENDING", "XINFO",
})


class ShadowSafeRedis(Redis):
    """A Redis client that, in a shadow run, sends only :data:`SHADOW_READ_COMMANDS` (live: unchanged)."""

    async def execute_command(self, *args: Any, **options: Any) -> Any:
        command = str(args[0]).split()[0].upper() if args else ""
        if command not in SHADOW_READ_COMMANDS:
            refuse_in_shadow("redis", f"Redis {command}")
        return await super().execute_command(*args, **options)

    def pipeline(self, transaction: bool = True, shard_hint: Optional[str] = None) -> Pipeline:
        refuse_in_shadow("redis", "Redis pipeline")
        return super().pipeline(transaction, shard_hint)


@egress("redis", REFUSE)
def create_redis(settings: Settings) -> Redis:
    """Client for ``redis.url`` (``redis://`` or TLS ``rediss://``) returning raw bytes.

    Connections are opened lazily, so this never blocks or fails on an
    unreachable server; the first command does.
    """
    cfg = settings.redis
    return ShadowSafeRedis.from_url(
        cfg.url.get_secret_value(),
        max_connections=cfg.max_connections,
        socket_timeout=cfg.socket_timeout_s,
        socket_connect_timeout=cfg.socket_timeout_s,
        socket_keepalive=True,
        health_check_interval=HEALTH_CHECK_INTERVAL_S,
        retry=Retry(ExponentialBackoff(cap=2.0, base=0.1), CONNECT_RETRIES),
        retry_on_error=[RedisConnectionError, RedisTimeoutError],
        decode_responses=False,
        client_name=settings.observability.service_name,
    )
