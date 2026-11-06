"""Per-tenant daily token budget (fakeredis; the real-Redis case is in tests/integration/llm)."""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable

import fakeredis
import pytest

from lg_sotf.llm.budget import USE_DEFAULT, TokenBudget
from lg_sotf.llm.errors import LLMBudgetExceeded
from lg_sotf.settings import Settings


@pytest.fixture
async def fake_redis() -> AsyncIterator[Any]:
    client = fakeredis.FakeAsyncRedis()
    yield client
    await client.aclose()


async def test_unlimited_still_counts(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": None}))
    reservation = await budget.check_and_reserve("t1", 10**9)
    assert reservation.tokens == 10**9
    assert await budget.used("t1") == 10**9


async def test_limit_enforced_and_rejection_leaves_usage(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 1000}))
    await budget.check_and_reserve("t1", 600)
    with pytest.raises(LLMBudgetExceeded) as exc:
        await budget.check_and_reserve("t1", 500)
    assert (exc.value.limit, exc.value.used, exc.value.requested) == (1000, 600, 500)
    assert exc.value.tenant_id == "t1"
    assert await budget.used("t1") == 600
    await budget.check_and_reserve("t1", 400)
    assert await budget.used("t1") == 1000


async def test_tenants_are_isolated(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 100}))
    await budget.check_and_reserve("t1", 100)
    await budget.check_and_reserve("t2", 100)
    assert await budget.used("t1") == 100 and await budget.used("t2") == 100


async def test_settle_and_release(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 10_000}))
    r = await budget.check_and_reserve("t1", 3000)
    await budget.settle(r, 1200)
    assert await budget.used("t1") == 1200
    r2 = await budget.check_and_reserve("t1", 500)
    await budget.release(r2)
    assert await budget.used("t1") == 1200
    assert await budget.add("t1", 50) == 1250


async def test_limit_override(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 10}))
    await budget.check_and_reserve("t1", 50, limit=100)
    await budget.check_and_reserve("t1", 10**6, limit=None)
    with pytest.raises(LLMBudgetExceeded):
        await budget.check_and_reserve("t1", 1)


async def test_use_default_versus_unlimited(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 100}))
    with pytest.raises(LLMBudgetExceeded):
        await budget.check_and_reserve("t1", 101, limit=USE_DEFAULT)
    await budget.check_and_reserve("t1", 101, limit=None)
    assert await budget.used("t1") == 101


async def test_key_layout_and_ttl(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(fake_redis, make_settings(redis={"key_prefix": "acme"}))
    await budget.check_and_reserve("tenant-9", 1)
    key = budget.key("tenant-9")
    assert key.startswith("acme:t:tenant-9:llm:tokens:")
    ttl = await fake_redis.ttl(key)
    assert 0 < ttl <= 2 * 24 * 3600


async def test_negative_estimate_rejected(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValueError):
        await TokenBudget(fake_redis, make_settings()).check_and_reserve("t1", -1)


async def test_lost_counter_is_seeded_from_recorded_usage(fake_redis: Any, make_settings: Callable[..., Settings]) -> None:
    """M4: a Redis restart must not hand the tenant a fresh daily budget."""
    recorded = {"t1": 9_500}
    seeded: list = []

    async def seed(tenant_id: str, day: Any) -> int:
        seeded.append(tenant_id)
        return recorded.get(tenant_id, 0)

    budget = TokenBudget(fake_redis, make_settings(llm={"daily_token_budget_per_tenant": 10_000}), usage_seed=seed)
    await fake_redis.flushdb()  # Redis lost the day's counter
    with pytest.raises(LLMBudgetExceeded):
        await budget.check_and_reserve("t1", 1_000)
    assert await budget.used("t1") == 9_500
    await budget.check_and_reserve("t1", 400)  # still within the remaining 500
    assert seeded == ["t1"]  # seeded once, not on every call
    await budget.check_and_reserve("t2", 5_000)  # nothing recorded: nothing to seed
    assert await budget.used("t2") == 5_000
