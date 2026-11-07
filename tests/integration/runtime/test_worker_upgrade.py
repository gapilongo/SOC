"""ARCH-E1.6: a rolling upgrade migrates the schema while the previous release's worker is mid-run."""

from __future__ import annotations

from typing import Any, Callable, Optional

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.observability.metrics import REGISTRY
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, db_settings
from tests.integration.runtime._support import (
    FakeEngine,
    Outcome,
    dispatch_alert,
    eventually,
    make_worker,
    running,
    stream_empty,
)

PROBE_COLUMN = "arch_e1_6_probe"


def _stale_retries() -> float:
    return REGISTRY.get_sample_value("lgsotf_db_stale_statement_retries_total") or 0.0


async def test_a_migration_mid_run_does_not_fail_the_message(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings], migrated_database_url: str
) -> None:
    """The worker's cached statements on ``workflow_runs`` go stale while the engine runs.

    Before ARCH-E1.6 the transaction that finishes the run failed with
    ``InvalidCachedStatementError`` and the message waited for the visibility
    timeout; now that transaction runs again and the message is acked.
    """
    s = runtime_settings()
    migrate = False

    async def behaviour(kind: str, tenant_id: str, alert_id: str, payload: Optional[dict]) -> Outcome:
        if migrate:  # what `lg-sotf migrate` of the next release does to the table meanwhile
            async with repos.db.connection() as ddl:
                await ddl.execute(f"ALTER TABLE workflow_runs ADD COLUMN {PROBE_COLUMN} text")
        return Outcome("completed")

    engine = FakeEngine(behaviour)
    # One connection, so the second run finishes on the statements the first run cached.
    worker_db = Database(db_settings(migrated_database_url, pool_min=1, pool_max=1))
    await worker_db.open()
    worker = make_worker(s, worker_db, redis_client, engine)
    try:
        async with running(worker):
            first = await dispatch_alert(repos, s, redis_client, TENANT_A)
            await eventually(lambda: stream_empty(redis_client, s))
            migrate = True
            before = _stale_retries()
            second = await dispatch_alert(repos, s, redis_client, TENANT_A)
            await eventually(lambda: stream_empty(redis_client, s))
            assert _stale_retries() == before + 1
        assert [call[2] for call in engine.calls] == [first, second]
        assert (worker.stats.completed, worker.stats.failed) == (2, 0)
        for alert_id in (first, second):
            assert (await repos.runs.get(TENANT_A, alert_id)).status == "completed"
    finally:
        await worker_db.close()
        async with repos.db.connection() as ddl:
            await ddl.execute(f"ALTER TABLE workflow_runs DROP COLUMN IF EXISTS {PROBE_COLUMN}")
