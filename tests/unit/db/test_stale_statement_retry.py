"""ARCH-E1.6: a transaction a migration made stale runs again once (no server needed)."""

from __future__ import annotations

from typing import Any, List, Optional

import asyncpg
import pytest

from lg_sotf.db.pool import retry_stale_statement
from lg_sotf.db.repos._base import retries_stale_statement
from lg_sotf.observability.metrics import REGISTRY

pytestmark = pytest.mark.unit


def _retries() -> float:
    return REGISTRY.get_sample_value("lgsotf_db_stale_statement_retries_total") or 0.0


class Attempts:
    """Raises the scripted errors in turn, then returns how many calls it took."""

    def __init__(self, *errors: BaseException) -> None:
        self.errors: List[BaseException] = list(errors)
        self.calls = 0

    async def __call__(self) -> int:
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return self.calls


@pytest.mark.parametrize(
    "stale", [asyncpg.InvalidCachedStatementError("stale"), asyncpg.OutdatedSchemaCacheError("stale")]
)
async def test_a_stale_statement_runs_the_attempt_once_more(stale: Exception) -> None:
    before = _retries()
    attempts = Attempts(stale)
    assert await retry_stale_statement(attempts) == 2
    assert _retries() == before + 1


async def test_a_second_stale_statement_is_raised() -> None:
    attempts = Attempts(asyncpg.InvalidCachedStatementError("stale"), asyncpg.InvalidCachedStatementError("again"))
    with pytest.raises(asyncpg.InvalidCachedStatementError, match="again"):
        await retry_stale_statement(attempts)
    assert attempts.calls == 2


async def test_other_errors_are_not_retried() -> None:
    attempts = Attempts(asyncpg.UniqueViolationError("dup"))
    with pytest.raises(asyncpg.UniqueViolationError):
        await retry_stale_statement(attempts)
    assert attempts.calls == 1


class Repo:
    def __init__(self) -> None:
        self.attempts = Attempts(asyncpg.InvalidCachedStatementError("stale"))

    @retries_stale_statement
    async def get(self, tenant_id: str, *, conn: Optional[Any] = None) -> int:
        return await self.attempts()


async def test_a_repository_method_owning_its_transaction_is_retried() -> None:
    repo = Repo()
    assert await repo.get("tenant-a") == 2


async def test_a_repository_method_on_the_callers_transaction_is_not_retried() -> None:
    """The stale statement aborted the caller's transaction; only the caller can run it again."""
    repo = Repo()
    with pytest.raises(asyncpg.InvalidCachedStatementError):
        await repo.get("tenant-a", conn=object())
    assert repo.attempts.calls == 1
