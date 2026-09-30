"""Workers and sweeps honour tenant suspension; finished triage is metered once per alert."""

from __future__ import annotations

from typing import Any, Callable, Optional

from lg_sotf.db.repos import Repositories
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.orphans import claim_orphaned_runs, find_stranded_new_alerts
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.runtime.conftest import FakeEngine, Outcome, eventually, returns
from tests.integration.runtime.test_worker import Ingested, _dispatch, _status, _stream_empty, _worker, running


async def test_worker_leaves_a_suspended_tenants_work_queued(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()
    engine = FakeEngine(returns("completed"))
    worker = _worker(s, repos.db, redis_client, engine)
    await repos.tenants.set_status(TENANT_B, "suspended")
    alert_a = await _dispatch(repos, s, redis_client, TENANT_A)
    alert_b = await _dispatch(repos, s, redis_client, TENANT_B)

    async with running(worker):
        await eventually(lambda: _stream_empty(redis_client, s))
        await eventually(lambda: _is(repos, TENANT_A, alert_a, "completed"))

    assert [c[1] for c in engine.calls] == [TENANT_A]
    assert await _status(repos, TENANT_B, alert_b) == "queued"
    assert worker.stats.skipped == 1
    assert (await repos.alerts.get(TENANT_B, alert_b)).status == "queued"


async def test_sweeps_skip_suspended_tenants_until_reactivated(repos: Repositories) -> None:
    queued_b = await make_alert(repos, TENANT_B)
    await repos.runs.queue_alerts(TENANT_B, [queued_b])
    stranded_b = await make_alert(repos, TENANT_B)
    async with repos.db.system_tx() as conn:
        await conn.execute("UPDATE workflow_runs SET updated_at = now() - interval '1 hour'")
        await conn.execute("UPDATE alerts SET ingested_at = now() - interval '1 hour' WHERE id = $1", stranded_b)
    await repos.tenants.set_status(TENANT_B, "suspended")

    assert await claim_orphaned_runs(repos.db, queued_older_than_s=60, failed_older_than_s=60, limit=10) == []
    assert await find_stranded_new_alerts(repos.db, older_than_s=60, limit=10) == []

    await repos.tenants.set_status(TENANT_B, "active")
    orphans = await claim_orphaned_runs(repos.db, queued_older_than_s=60, failed_older_than_s=60, limit=10)
    assert [(o.tenant_id, o.alert_id) for o in orphans] == [(TENANT_B, queued_b)]
    assert [a.alert_id for a in await find_stranded_new_alerts(repos.db, older_than_s=60, limit=10)] == [stranded_b]


async def test_finished_triage_is_metered_once_and_samples_never(
    repos: Repositories, redis_client: Any, runtime_settings: Callable[..., Settings]
) -> None:
    s = runtime_settings()

    async def behaviour(kind: str, tenant: str, alert: str, payload: Optional[dict]) -> Outcome:
        return Outcome("waiting_human" if kind == "process" else "completed")

    engine = FakeEngine(behaviour)
    worker = _worker(s, repos.db, redis_client, engine)
    alert_id = await _dispatch(repos, s, redis_client, TENANT_A)
    sample_id = await make_alert(repos, TENANT_A, source_id="demo:samples")
    await dispatch_new_alerts(repos, WorkQueue(redis_client, s), TENANT_A, [Ingested(sample_id, "high")])
    payload = {
        "type": "analyst_decision",
        "escalation_id": "e1",
        "decision": "false_positive",
        "approved_actions": [],
        "decided_by": "u1",
        "notes": "",
    }
    async with running(worker):
        await eventually(lambda: _is(repos, TENANT_A, alert_id, "waiting_human"))
        await eventually(lambda: _is(repos, TENANT_A, sample_id, "waiting_human"))
        await WorkQueue(redis_client, s).enqueue_resume(TENANT_A, alert_id, payload)
        await eventually(lambda: _is(repos, TENANT_A, alert_id, "completed"))

    usage = await repos.usage.get_day(TENANT_A)
    assert usage is not None and usage.alerts_processed == 1


async def _is(repos: Repositories, tenant: str, alert_id: str, status: str) -> bool:
    return await _status(repos, tenant, alert_id) == status
