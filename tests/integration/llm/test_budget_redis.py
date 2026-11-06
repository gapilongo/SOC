"""The per-tenant daily token budget against the real test Redis."""

from __future__ import annotations

from typing import Any, Callable

import pytest

from lg_sotf.llm.budget import TokenBudget
from lg_sotf.llm.errors import LLMBudgetExceeded
from lg_sotf.settings import Settings

pytestmark = pytest.mark.integration


async def test_real_redis(redis_client: Any, unique_prefix: str, make_settings: Callable[..., Settings]) -> None:
    budget = TokenBudget(redis_client, make_settings(llm={"daily_token_budget_per_tenant": 1000}), key_prefix=unique_prefix)
    try:
        r = await budget.check_and_reserve("t1", 900)
        with pytest.raises(LLMBudgetExceeded):
            await budget.check_and_reserve("t1", 200)
        await budget.settle(r, 100)
        await budget.check_and_reserve("t1", 800)
        assert await budget.used("t1") == 900
        assert await redis_client.ttl(budget.key("t1")) > 0
    finally:
        await redis_client.delete(budget.key("t1"))
