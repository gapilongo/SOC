"""Retention of workflow state: checkpoints never outlive their alert (M5), failed alerts expire (L1),
and a finished run keeps only its final checkpoint (PERF-8)."""

from __future__ import annotations

from typing import Any

import pytest

from lg_sotf.db.retention import purge_expired
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.e2e.conftest import eventually, running
from tests.integration.e2e.test_pipeline import BENIGN_EVENT

pytestmark = pytest.mark.integration


async def _counts(db: Any, thread: str) -> tuple:
    async with db.system_tx() as conn:
        return tuple(
            [await conn.fetchval(f"SELECT count(*) FROM {t} WHERE thread_id = $1", thread)  # noqa: S608
             for t in ("checkpoints", "checkpoint_blobs", "checkpoint_writes")]
        )


async def _completed(stack: Any, alert_id: str) -> bool:
    return await stack.run_status(TENANT_A, alert_id) == "completed"


async def test_finished_runs_keep_only_their_final_checkpoint_and_it_goes_with_the_alert(
    stack_factory: Any, repos: Any, db: Any
) -> None:
    stack = stack_factory()
    await repos.tenants.update_settings(TENANT_A, {"retention": {"alerts_days": 7}})
    result = await stack.ingest(TENANT_A, "api", [BENIGN_EVENT])
    alert_id = result.inserted[0].alert_id
    async with running(stack.worker(await stack.engine())):
        await stack.dispatch(TENANT_A, result)
        await eventually(lambda: _completed(stack, alert_id))
    thread = f"{TENANT_A}:{alert_id}"
    checkpoints, blobs, _ = await _counts(db, thread)
    assert checkpoints == 1 and blobs >= 1  # intermediate checkpoints were pruned
    # The final state is still readable (the engine answers "completed" from it).
    engine = await stack.engine()
    assert (await engine.run(TENANT_A, alert_id)).status == "completed"

    async with db.system_tx() as conn:  # older than the tenant's 7 days, younger than checkpoints_days (30)
        await conn.execute("UPDATE alerts SET closed_at = now() - interval '10 days' WHERE id = $1", alert_id)
        await conn.execute(
            "UPDATE workflow_runs SET completed_at = now() - interval '10 days' WHERE alert_id = $1", alert_id
        )
    report = await purge_expired(db, stack.settings.retention)
    assert report.alerts == 1
    assert await _counts(db, thread) == (0, 0, 0)


async def test_failed_alerts_expire_and_runless_checkpoints_are_swept(repos: Any, db: Any) -> None:
    from datetime import UTC, datetime, timedelta

    from lg_sotf.settings import RetentionSettings
    failed = await make_alert(repos, TENANT_A)
    async with db.system_tx() as conn:
        await conn.execute(
            "UPDATE alerts SET status = 'failed', updated_at = now() - interval '500 days' WHERE id = $1", failed
        )
    report = await purge_expired(db, RetentionSettings(alerts_days=90))
    assert report.alerts == 1
    async with db.system_tx() as conn:
        assert await conn.fetchval("SELECT count(*) FROM alerts WHERE id = $1", failed) == 0
        present = await conn.fetchval("SELECT to_regclass('public.checkpoints') IS NOT NULL")
        if not present:
            return
        old = (datetime.now(UTC) - timedelta(days=45)).isoformat()
        await conn.execute(
            "INSERT INTO checkpoints (thread_id, checkpoint_id, checkpoint) VALUES ($1, 'c1', jsonb_build_object('ts', $2::text))",
            f"{TENANT_A}:gone-alert",
            old,
        )
    report = await purge_expired(db, RetentionSettings(checkpoints_days=30))
    assert report.checkpoint_threads >= 1
    assert await _counts(db, f"{TENANT_A}:gone-alert") == (0, 0, 0)
