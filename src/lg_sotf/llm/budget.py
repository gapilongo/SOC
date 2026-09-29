"""Per-tenant daily LLM token budget backed by Redis.

Usage is counted per UTC day under ``{prefix}:t:{tenant}:llm:tokens:{YYYYMMDD}``.
A call reserves an estimate up front (rejected if it would cross the limit)
and settles the difference once real usage is known.

Redis is only a cache of the day's usage: when the day's key is missing or
empty (Redis restarted without persistence, failed over, evicted the key),
it is seeded from ``llm_usage_daily`` (the ``usage_seed`` callable) before
the first reservation, so a Redis data loss does not hand a tenant a fresh
budget. Usage not yet flushed to PostgreSQL (at most the usage recorder's
flush interval per process) is the remaining window.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Awaitable, Callable, Final, Literal, Optional, Union

from redis.asyncio import Redis

from lg_sotf.llm.errors import LLMBudgetExceeded
from lg_sotf.settings import Settings, get_settings

_KEY_TTL_S = 2 * 24 * 3600


class _UseDefault(enum.Enum):
    DEFAULT = "use-default"


USE_DEFAULT: Final = _UseDefault.DEFAULT
"""Limit argument meaning "use ``llm.daily_token_budget_per_tenant``"; ``None`` means unlimited."""

BudgetLimit = Union[int, None, Literal[_UseDefault.DEFAULT]]


@dataclass(frozen=True)
class Reservation:
    tenant_id: str
    day: date
    tokens: int


def _today() -> date:
    return datetime.now(UTC).date()


UsageSeed = Callable[[str, date], Awaitable[int]]


class TokenBudget:
    def __init__(
        self,
        redis: Redis,
        settings: Optional[Settings] = None,
        *,
        key_prefix: Optional[str] = None,
        usage_seed: Optional[UsageSeed] = None,
    ):
        s = settings or get_settings()
        self._redis = redis
        self._default_limit = s.llm.daily_token_budget_per_tenant
        self._prefix = key_prefix or s.redis.key_prefix
        self._usage_seed = usage_seed

    def key(self, tenant_id: str, day: Optional[date] = None) -> str:
        d = day or _today()
        return f"{self._prefix}:t:{tenant_id}:llm:tokens:{d:%Y%m%d}"

    async def used(self, tenant_id: str, *, day: Optional[date] = None) -> int:
        value = await self._redis.get(self.key(tenant_id, day))
        return int(value) if value is not None else 0

    async def _incr(self, key: str, amount: int) -> int:
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incrby(key, amount)
            pipe.expire(key, _KEY_TTL_S)
            new_value, _ = await pipe.execute()
        return int(new_value)

    async def check_and_reserve(
        self,
        tenant_id: str,
        estimated_tokens: int,
        *,
        limit: BudgetLimit = USE_DEFAULT,
    ) -> Reservation:
        """Reserve ``estimated_tokens`` for today or raise :class:`LLMBudgetExceeded`.

        ``limit`` overrides the configured default (e.g. a tenant setting);
        ``None`` means unlimited, in which case usage is still counted.
        """
        if estimated_tokens < 0:
            raise ValueError("estimated_tokens must be >= 0")
        effective = self._default_limit if limit is USE_DEFAULT else limit
        day = _today()
        key = self.key(tenant_id, day)
        new_total = await self._incr(key, estimated_tokens)
        if new_total == estimated_tokens and self._usage_seed is not None:
            # The counter was empty: nothing counted today, or Redis lost it. Only this caller
            # sees its own estimate as the total, so the day is seeded once.
            recorded = await self._usage_seed(tenant_id, day)
            if recorded > 0:
                new_total = await self._incr(key, recorded)
        if effective is not None and new_total > effective:
            await self._incr(key, -estimated_tokens)
            raise LLMBudgetExceeded(
                tenant_id, limit=effective, used=new_total - estimated_tokens, requested=estimated_tokens
            )
        return Reservation(tenant_id=tenant_id, day=day, tokens=estimated_tokens)

    async def add(self, tenant_id: str, tokens: int, *, day: Optional[date] = None) -> int:
        """Add (or, with a negative value, remove) tokens from a day's usage."""
        return await self._incr(self.key(tenant_id, day), tokens)

    async def settle(self, reservation: Reservation, actual_tokens: int) -> None:
        delta = actual_tokens - reservation.tokens
        if delta:
            await self.add(reservation.tenant_id, delta, day=reservation.day)

    async def release(self, reservation: Reservation) -> None:
        await self.settle(reservation, 0)
