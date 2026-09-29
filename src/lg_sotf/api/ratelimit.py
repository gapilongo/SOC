"""Redis fixed-window rate limits.

A request increments ``{prefix}:...:rl:<bucket>:<identity>:<window>`` and is
refused once the count passes the limit; the key expires with its window.
When Redis is unreachable requests are allowed (and a warning logged):
availability wins over throttling, and login brute force is still bounded by
account lockout.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable, Optional

from redis.asyncio import Redis
from redis.exceptions import RedisError

from lg_sotf.api.errors import ApiError
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

WINDOW_S = 60


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int


class RateLimiter:
    def __init__(self, redis: Redis, prefix: str, *, clock: Callable[[], float] = time.time) -> None:
        self._redis = redis
        self._prefix = prefix
        self._clock = clock

    def key(self, bucket: str, identity: str, window: int, tenant_id: Optional[str] = None) -> str:
        scope = f"{self._prefix}:t:{tenant_id}" if tenant_id else self._prefix
        return f"{scope}:rl:{bucket}:{identity}:{window}"

    async def hit(
        self,
        bucket: str,
        identity: str,
        limit: int,
        *,
        tenant_id: Optional[str] = None,
        window_s: int = WINDOW_S,
        cost: int = 1,
    ) -> RateDecision:
        now = self._clock()
        window = int(now // window_s)
        retry_after = max(1, math.ceil((window + 1) * window_s - now))
        if limit <= 0:
            return RateDecision(True, limit, 0, retry_after)
        key = self.key(bucket, identity, window, tenant_id)
        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.incrby(key, cost)
                pipe.expire(key, window_s + 1, nx=True)
                count, _ = await pipe.execute()
        except (RedisError, OSError, TimeoutError) as exc:
            log.warning("ratelimit.unavailable", bucket=bucket, error_type=type(exc).__name__)
            return RateDecision(True, limit, limit, retry_after)
        count = int(count)
        return RateDecision(count <= limit, limit, max(0, limit - count), retry_after)

    async def peek(self, bucket: str, identity: str, *, window_s: int = WINDOW_S) -> int:
        """Current count in this window without incrementing (0 when Redis is unavailable)."""
        window = int(self._clock() // window_s)
        try:
            value = await self._redis.get(self.key(bucket, identity, window))
        except (RedisError, OSError, TimeoutError):
            return 0
        return int(value) if value is not None else 0

    async def enforce(
        self,
        bucket: str,
        identity: str,
        limit: int,
        *,
        tenant_id: Optional[str] = None,
        cost: int = 1,
    ) -> RateDecision:
        decision = await self.hit(bucket, identity, limit, tenant_id=tenant_id, cost=cost)
        if not decision.allowed:
            raise rate_limited(decision)
        return decision


def rate_limited(decision: RateDecision) -> ApiError:
    return ApiError(
        429,
        "rate_limited",
        "too many requests; retry later",
        headers={
            "Retry-After": str(decision.retry_after_s),
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": "0",
        },
    )
