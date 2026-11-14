"""#350: an alert retro-reopen requeues (no open case to fold into) gets its run message right away, so a worker
claims it without waiting for the orphan sweep (2 x visibility timeout), which stays the backstop."""

from __future__ import annotations

from typing import Dict, List

import pytest
import redis.asyncio as aioredis

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain import closure
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.runtime.worker import Worker
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.engine._support import RecordingEvents, analyst, decide, suspicious_alert

pytestmark = pytest.mark.integration


async def model_closed_with_run(repos: Repositories, entities: Dict[str, List[str]]) -> str:
    """A model-closed alert as production leaves it: its workflow run is ``completed``."""
    alert_id = await make_alert(repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    await repos.runs.start(TENANT_A, alert_id, "w0", lease_s=30, kind="process")
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(TENANT_A, alert_id, status)
    await repos.alerts.update(TENANT_A, alert_id, disposition="benign",
                              summary={"close_reason": closure.MODEL_CLOSE_REASON})
    await repos.runs.complete(TENANT_A, alert_id, worker_id="w0")
    return alert_id


async def test_a_requeued_alert_is_claimed_by_a_worker_without_the_orphan_sweep(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, db: Database, redis_client: aioredis.Redis,
) -> None:
    # The response plan after an analyst's true positive (AI-E3.15: a plan on the models' word only links): the
    # case is decided, so the related model-closed alert has no case to fold into.
    settings = engine_settings
    closed = await model_closed_with_run(repos, {"hosts": ["ws-042"]})
    threat = await suspicious_alert(repos)
    first = await engine.run(TENANT_A, threat)
    await decide(engine, repos, threat, first.interrupt["escalation_id"], "true_positive", await analyst(repos))
    reopened = await repos.alerts.get(TENANT_A, closed)
    assert (reopened.status, reopened.summary["reopened"]["mode"]) == ("queued", "requeued")

    # A worker reads its run message from the stream (no sweep ran) and processes it.
    consumer = StreamConsumer(redis_client, settings, "w-350")
    await consumer.ensure_groups()
    messages = [m for m in await consumer.read(50) if m.alert_id == closed]
    assert [m.kind for m in messages] == ["process"]
    worker = Worker(settings, db, redis_client, engine, consumer, RecordingEvents())
    await worker.process(messages[0])
    run = await repos.runs.get(TENANT_A, closed)
    assert run.status != "queued" and (await repos.alerts.get(TENANT_A, closed)).status != "queued"
