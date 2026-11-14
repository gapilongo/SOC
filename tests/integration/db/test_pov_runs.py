"""``pov_runs`` (migration 0019): what the runtime role may write, tenant isolation and the backtest queue."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict
from uuid import uuid4

import pytest

from lg_sotf.db.errors import InvalidValue, NotFound, SystemScopeDenied
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.pov import MAX_BACKTEST_ATTEMPTS, PovWindows, plan_windows
from tests.integration.db._support import TENANT_A, TENANT_B, attempt_as

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
WINDOWS = plan_windows(NOW, backtest_days=30, shadow_days=14)
INSERT_COMPLETED = (
    "INSERT INTO pov_runs (tenant_id, name, backtest_start, backtest_end, shadow_start, shadow_end, backtest_status) "
    "VALUES ($1, 'forged', now() - interval '1 day', now(), now(), now() + interval '1 day', 'completed')"
)
INSERT_PLAIN = (
    "INSERT INTO pov_runs (tenant_id, name, backtest_start, backtest_end, shadow_start, shadow_end) "
    "VALUES ($1, 'other tenant', now() - interval '1 day', now(), now(), now() + interval '1 day')"
)


async def test_runtime_role_creates_and_cancels_a_run_and_writes_nothing_else(app: Repositories) -> None:
    run = await app.pov_runs.create(TENANT_A, "Acme PoV", WINDOWS, created_by="admin-1")
    assert (run.backtest_status, run.backtest_attempts, run.backtest_result, run.cancelled_at) == ("pending", 0, None, None)
    assert (run.backtest_start, run.backtest_end) == (NOW - timedelta(days=30), NOW)
    assert (run.shadow_start, run.shadow_end) == (NOW, NOW + timedelta(days=14))

    results: Dict[str, str] = {}
    for stmt in (
        "UPDATE pov_runs SET backtest_status = 'completed' WHERE id = $1",
        "UPDATE pov_runs SET backtest_result = '{}' WHERE id = $1",
        "UPDATE pov_runs SET backtest_attempts = 0 WHERE id = $1",
        "UPDATE pov_runs SET shadow_end = now() WHERE id = $1",
        "UPDATE pov_runs SET name = 'renamed' WHERE id = $1",
        "DELETE FROM pov_runs WHERE id = $1",
    ):
        results[stmt] = await attempt_as(app, stmt, run.id)
    results["insert with a backtest status"] = await attempt_as(app, INSERT_COMPLETED, TENANT_A)
    results["insert into another tenant"] = await attempt_as(app, INSERT_PLAIN, TENANT_B)
    assert set(results.values()) == {"InsufficientPrivilegeError"}, results
    # The backtest queue is the scheduler's: the runtime role cannot take or finish a backtest.
    with pytest.raises(SystemScopeDenied):
        await app.pov_runs.claim_backtest()

    assert await app.pov_runs.in_progress(TENANT_A, NOW) == run
    assert await app.pov_runs.in_progress(TENANT_A, WINDOWS.shadow_end) is None  # its shadow period is over
    cancelled = await app.pov_runs.cancel(TENANT_A, run.id, cancelled_by="admin-1", now=NOW + timedelta(hours=1))
    assert cancelled is not None and (cancelled.cancelled_at, cancelled.cancelled_by) == (NOW + timedelta(hours=1), "admin-1")
    assert await app.pov_runs.cancel(TENANT_A, run.id, cancelled_by="admin-2", now=NOW + timedelta(hours=2)) is None
    assert await app.pov_runs.in_progress(TENANT_A, NOW) is None


async def test_runs_are_isolated_by_tenant_and_listed_newest_first(app: Repositories, db: Database) -> None:
    runs = [await app.pov_runs.create(TENANT_A, f"run {n}", WINDOWS, created_by=None) for n in range(3)]
    async with db.system_tx() as conn:
        for n, run in enumerate(runs):
            await conn.execute("UPDATE pov_runs SET created_at = $2 WHERE id = $1", run.id, NOW + timedelta(minutes=n))
    other = await app.pov_runs.create(TENANT_B, "tenant B's", WINDOWS, created_by=None)

    first = await app.pov_runs.list(TENANT_A, limit=2)
    assert [r.name for r in first.items] == ["run 2", "run 1"] and first.next_cursor
    rest = await app.pov_runs.list(TENANT_A, limit=2, cursor=first.next_cursor)
    assert [r.name for r in rest.items] == ["run 0"] and rest.next_cursor is None
    assert await app.pov_runs.count_created_since(TENANT_A, NOW + timedelta(minutes=1)) == 2

    assert [r.id for r in (await app.pov_runs.list(TENANT_B)).items] == [other.id]
    with pytest.raises(NotFound):
        await app.pov_runs.get(TENANT_B, runs[0].id)
    with pytest.raises(NotFound):
        await app.pov_runs.get(TENANT_A, uuid4())
    assert await app.pov_runs.cancel(TENANT_B, runs[0].id, cancelled_by="b", now=NOW) is None
    assert (await app.pov_runs.get(TENANT_A, runs[0].id)).cancelled_at is None
    with pytest.raises(InvalidValue):  # the shadow period never starts before the history window ends
        overlapping = PovWindows(NOW - timedelta(days=2), NOW, NOW - timedelta(days=1), NOW + timedelta(days=1))
        await app.pov_runs.create(TENANT_A, "overlap", overlapping, created_by=None)


async def test_the_backtest_queue_takes_the_oldest_waiting_run_of_an_active_tenant(
    repos: Repositories, db: Database
) -> None:
    old = await repos.pov_runs.create(TENANT_A, "old", WINDOWS, created_by=None)
    new = await repos.pov_runs.create(TENANT_B, "new", WINDOWS, created_by=None)
    cancelled = await repos.pov_runs.create(TENANT_B, "cancelled", WINDOWS, created_by=None)
    async with db.system_tx() as conn:
        await conn.execute("UPDATE pov_runs SET created_at = now() - interval '1 hour' WHERE id = $1", old.id)
        await conn.execute("UPDATE pov_runs SET created_at = now() - interval '2 hours' WHERE id = $1", cancelled.id)
        await conn.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1", TENANT_A)
    assert await repos.pov_runs.cancel(TENANT_B, cancelled.id, cancelled_by=None, now=NOW) is not None

    # Tenant A is suspended and the oldest run of tenant B is cancelled: the queue gives tenant B's other run.
    claimed = await repos.pov_runs.claim_backtest()
    assert claimed is not None and (claimed.id, claimed.backtest_status, claimed.backtest_attempts) == (new.id, "running", 1)
    assert claimed.backtest_started_at is not None

    with pytest.raises(ValueError, match="only a completed one"):
        await repos.pov_runs.finish_backtest(claimed, "failed", result={"metrics": {}})
    with pytest.raises(ValueError, match="only a completed one"):
        await repos.pov_runs.finish_backtest(claimed, "completed")
    assert await repos.pov_runs.finish_backtest(claimed, "completed", result={"metrics": {"items": 3}})
    done = await repos.pov_runs.get(TENANT_B, new.id)
    assert (done.backtest_status, done.backtest_result, done.backtest_error) == ("completed", {"metrics": {"items": 3}}, None)
    assert done.backtest_finished_at is not None
    assert not await repos.pov_runs.finish_backtest(claimed, "failed", error="late")  # settled: not written twice
    assert await repos.pov_runs.claim_backtest() is None

    async with db.system_tx() as conn:
        await conn.execute("UPDATE tenants SET status = 'active' WHERE id = $1", TENANT_A)
    assert (await repos.pov_runs.claim_backtest()).id == old.id  # type: ignore[union-attr]


async def test_an_interrupted_backtest_is_taken_again_then_recorded_as_failed(repos: Repositories) -> None:
    run = await repos.pov_runs.create(TENANT_A, "interrupted", WINDOWS, created_by=None)
    claims = [await repos.pov_runs.claim_backtest() for _ in range(MAX_BACKTEST_ATTEMPTS)]
    assert [(c.id, c.backtest_status, c.backtest_attempts) for c in claims if c] == [
        (run.id, "running", n) for n in range(1, MAX_BACKTEST_ATTEMPTS + 1)
    ]
    # An earlier attempt that comes back late no longer owns the run.
    assert claims[0] is not None and not await repos.pov_runs.finish_backtest(claims[0], "no_data")

    last = await repos.pov_runs.claim_backtest()
    assert last is not None and (last.backtest_status, last.backtest_attempts) == ("failed", MAX_BACKTEST_ATTEMPTS)
    assert last.backtest_error == f"the backtest was interrupted {MAX_BACKTEST_ATTEMPTS} times and was not run again"
    assert last.backtest_finished_at is not None
    assert await repos.pov_runs.claim_backtest() is None
