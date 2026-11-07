"""Redis client factory."""

from __future__ import annotations

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from lg_sotf.settings import Settings

HEALTH_CHECK_INTERVAL_S = 30
CONNECT_RETRIES = 3


def create_redis(settings: Settings) -> Redis:
    """Client for ``redis.url`` (``redis://`` or TLS ``rediss://``) returning raw bytes.

    Connections are opened lazily, so this never blocks or fails on an
    unreachable server; the first command does.
    """
    cfg = settings.redis
    return Redis.from_url(
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
