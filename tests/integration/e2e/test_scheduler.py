"""The scheduler (leader) polls pull sources and dispatches; the worker processes what it enqueued."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, List

import httpx
import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps, encrypt_source_secret
from lg_sotf.runtime.health import build_health_app
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.security.crypto import SecretBox
from tests.fixtures.vendors import vendor_events
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.e2e.conftest import Stack, eventually, running
from tests.integration.e2e.test_pipeline import BENIGN_EVENT, SUSPICIOUS_EVENT
from tests.integration.ingestion.test_poll import QRadarMock
from tests.unit.ingestion._support import public_resolver

pytestmark = pytest.mark.integration


async def _alert_ids(repos: Repositories, tenant_id: str) -> List[str]:
    return [a.id for a in (await repos.alerts.list(tenant_id, limit=50)).items]


async def test_scheduler_polls_sources_and_the_worker_processes_them(
    stack_factory: Callable[..., Stack], repos: Repositories, tmp_path: Path
) -> None:
    stack = stack_factory()
    box = SecretBox.from_settings(stack.settings)

    offenses = vendor_events("qradar_offenses")
    for offense in offenses:
        offense["start_time"] = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp() * 1000)
    qradar = QRadarMock(offenses)
    await repos.sources.create(
        TENANT_A,
        "qradar",
        "QRadar",
        source_id="qradar-1",
        config={"base_url": "https://qradar.example.com"},
        secret_ciphertext=encrypt_source_secret(box, TENANT_A, "qradar-1", {"token": qradar.token}),
    )
    jsonl = tmp_path / "alerts.jsonl"
    jsonl.write_text("".join(json.dumps(e) + "\n" for e in (BENIGN_EVENT, SUSPICIOUS_EVENT)), encoding="utf-8")
    await repos.sources.create(TENANT_B, "file", "Dev file", source_id="dev-file", config={"path": str(jsonl)})

    def ingestion_factory() -> IngestionService:
        return IngestionService(
            stack.db,
            stack.settings,
            secret_box=box,
            connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(qradar)),
        )

    scheduler = Scheduler(stack.settings, stack.db, stack.redis, ingestion_factory, stack.queue, stack.events)
    worker = stack.worker(await stack.engine())
    scheduler_task = asyncio.create_task(scheduler.run())
    try:
        async with running(worker):
            await eventually(lambda: _count_is(repos, TENANT_A, len(offenses)))
            await eventually(lambda: _count_is(repos, TENANT_B, 2))
            ids_a, ids_b = await _alert_ids(repos, TENANT_A), await _alert_ids(repos, TENANT_B)
            await eventually(lambda: stack.all_settled(TENANT_A, ids_a))
            await eventually(lambda: stack.all_settled(TENANT_B, ids_b))
            await eventually(stack.stream_empty)
            assert scheduler.is_leader
    finally:
        scheduler.request_stop()
        await asyncio.wait_for(scheduler_task, timeout=20)

    assert not scheduler.is_leader
    qradar_source = await repos.sources.get(TENANT_A, "qradar-1")
    assert qradar_source.cursor is not None and qradar_source.cursor["last_id"] == max(o["id"] for o in offenses)
    assert qradar_source.last_error is None and qradar_source.last_polled_at is not None
    file_source = await repos.sources.get(TENANT_B, "dev-file")
    assert file_source.cursor == {"v": 1, "offset": jsonl.stat().st_size}

    for tenant_id, ids in ((TENANT_A, ids_a), (TENANT_B, ids_b)):
        for alert_id in ids:
            assert (await repos.runs.get(tenant_id, alert_id)).status in ("completed", "waiting_human")
            assert [e["tenant_id"] for e in stack.events.of(alert_id, "alert.created")] == [tenant_id]
    benign = [a for a in (await repos.alerts.list(TENANT_B, limit=10)).items if a.source_alert_id == "bk-001"]
    assert benign and (benign[0].status, benign[0].disposition) == ("closed", "benign")
    # Every source polled once, then the cursors stopped re-ingesting: no duplicates were dispatched.
    assert len(ids_a) == len(offenses) and len(ids_b) == 2
    assert worker.stats.started == len(offenses) + 2

    # The scheduler's health server exports the ingestion metrics its polls recorded.
    app = build_health_app({})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://health") as client:
        body = (await client.get("/metrics")).text
    assert 'lgsotf_source_polls_total{outcome="ok",source_type="qradar"}' in body
    assert "lgsotf_runs_total" in body


async def _count_is(repos: Repositories, tenant_id: str, expected: int) -> bool:
    return len(await _alert_ids(repos, tenant_id)) == expected
