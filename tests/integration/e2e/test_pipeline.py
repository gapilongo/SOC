"""Ingest -> dispatch -> worker -> workflow engine, all real, against Postgres, Redis and the fake LLM."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List, Tuple
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.queue.events import EventBus
from tests.fixtures.vendors import vendor_events
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.e2e.conftest import Stack, count_calls, eventually, running

pytestmark = pytest.mark.integration

BENIGN_EVENT: Dict[str, Any] = {
    "source_alert_id": "bk-001",
    "title": "Scheduled backup maintenance test job",
    "severity": "low",
    "occurred_at": "2024-03-05T10:00:00Z",
    "entities": {"hosts": ["backup-01"]},
}
SUSPICIOUS_EVENT: Dict[str, Any] = {
    "source_alert_id": "c2-001",
    "title": "Possible C2 beacon from workstation",
    "severity": "medium",
    "occurred_at": "2024-03-05T10:05:00Z",
    "entities": {
        "ips": ["185.220.101.44", "10.0.0.5"],
        "hosts": ["ws-042"],
        "users": ["jdoe"],
        "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        "processes": ["powershell.exe"],
    },
}


async def ingest_fixtures(stack: Stack, tenant_id: str = TENANT_A) -> Tuple[str, List[str]]:
    """A benign canonical event through ``api`` and the Splunk notables through a webhook source."""
    await stack.repos.sources.create(
        tenant_id, "webhook", "Splunk hook", source_id="splunk-hook", config={"format": "splunk"}
    )
    benign = await stack.ingest(tenant_id, "api", [BENIGN_EVENT])
    vendor = await stack.ingest(tenant_id, "splunk-hook", vendor_events("splunk_notable"))
    assert len(benign.inserted) == 1 and not benign.rejected
    assert len(vendor.inserted) == 2 and not vendor.rejected
    assert await stack.dispatch(tenant_id, benign) == 1
    assert await stack.dispatch(tenant_id, vendor) == 2
    return benign.inserted[0].alert_id, [a.alert_id for a in vendor.inserted]


async def analyst_decides(
    stack: Stack, tenant_id: str, alert_id: str, decision: str, user_id: str, **extra: Any
) -> str:
    """What ``POST /escalations/{id}/decision`` does: record the decision, then enqueue the resume."""
    esc = await stack.repos.escalations.get_active_for_alert(tenant_id, alert_id)
    assert esc is not None
    await stack.repos.escalations.decide(
        tenant_id, esc.id, decision=decision, decided_by=UUID(user_id), expected_version=esc.version
    )
    payload: Dict[str, Any] = {
        "type": "analyst_decision",
        "escalation_id": esc.id,
        "decision": decision,
        "approved_actions": [],
        "decided_by": user_id,
        "notes": "confirmed on the host",
        "approver_role": "analyst",
    }
    payload.update(extra)
    await stack.queue.enqueue_resume(tenant_id, alert_id, payload)
    return esc.id


async def test_ingested_alerts_are_triaged_by_the_worker(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    benign_id, suspicious_ids = await ingest_fixtures(stack)
    for alert_id in [benign_id, *suspicious_ids]:
        assert (await repos.alerts.get(TENANT_A, alert_id)).status == "queued"
        assert (await repos.runs.get(TENANT_A, alert_id)).status == "queued"
        assert [e["data"]["status"] for e in stack.events.of(alert_id, "alert.created")] == ["queued"]
    worker = stack.worker(await stack.engine())

    async with running(worker):
        await eventually(lambda: stack.all_settled(TENANT_A, [benign_id, *suspicious_ids]))
        await eventually(stack.stream_empty)

    benign = await repos.alerts.get(TENANT_A, benign_id)
    assert (benign.status, benign.disposition) == ("closed", "benign")
    assert benign.summary["close_reason"] == "triage:false_positive"
    run = await repos.runs.get(TENANT_A, benign_id)
    assert run.status == "completed" and run.completed_at is not None and run.attempt == 1
    assert run.thread_id == thread_id_for(TENANT_A, benign_id)
    assert await repos.escalations.get_active_for_alert(TENANT_A, benign_id) is None

    for alert_id in suspicious_ids:
        alert = await repos.alerts.get(TENANT_A, alert_id)
        assert alert.status == "waiting_human" and alert.severity in ("high", "critical")
        assert (await repos.runs.get(TENANT_A, alert_id)).status == "waiting_human"
        esc = await repos.escalations.get_active_for_alert(TENANT_A, alert_id)
        assert esc is not None and esc.status == "open"
        assert stack.events.of(alert_id, "escalation.created")
        nodes = [e.node for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items]
        assert nodes[:2] == ["gate", "triage"] and "escalate" in nodes

    statuses = [e["data"].get("status") for e in stack.events.of(benign_id, "alert.updated")]
    assert statuses[0] == "processing" and statuses[-1] == "closed"
    assert worker.stats.completed == 1 and worker.stats.waiting == 2 and worker.stats.failed == 0
    # The worker flushes the fake LLM's metered usage on shutdown.
    usage = await repos.llm_usage.day_totals(TENANT_A, datetime.now(UTC).date())
    assert usage.calls > 0 and usage.input_tokens > 0


async def test_analyst_decision_and_approval_are_resumed_by_the_worker(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    result = await stack.ingest(TENANT_A, "api", [SUSPICIOUS_EVENT])
    alert_id = result.inserted[0].alert_id
    await stack.dispatch(TENANT_A, result)
    user_id = str((await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id)
    worker = stack.worker(await stack.engine())

    async with running(worker):
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
        escalation_id = await analyst_decides(stack, TENANT_A, alert_id, "true_positive", user_id)
        await eventually(lambda: _run_is(stack, alert_id, "waiting_approval"))

        assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_approval"
        ledger = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
        awaiting = [str(a.id) for a in ledger if a.status == "awaiting_approval"]
        assert awaiting, "the plan must leave actions for approval"
        blocked = {(a.action_type, a.target): a for a in ledger if a.status == "blocked"}
        assert blocked[("block_ip", "10.0.0.5")].blocked_reason == "non_public_ip"

        await stack.queue.enqueue_resume(
            TENANT_A,
            alert_id,
            {
                "type": "approval",
                "approved_action_ids": awaiting,
                "rejected_action_ids": [],
                "decided_by": user_id,
                "reject_remaining": True,
            },
        )
        await eventually(lambda: _run_is(stack, alert_id, "completed"))
        await eventually(stack.stream_empty)

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "malicious")
    assert alert.summary["analyst_decision"] == "true_positive"
    final = {str(a.id): a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    for action_id in awaiting:
        assert final[action_id].status == "dry_run" and final[action_id].approved_by == user_id
    assert (await repos.escalations.get(TENANT_A, escalation_id)).status == "decided"
    run = await repos.runs.get(TENANT_A, alert_id)
    assert run.status == "completed" and run.completed_at is not None
    assert worker.stats.completed == 1 and worker.stats.waiting == 2
    assert stack.events.of(alert_id, "action.updated")
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_duplicate_ingest_creates_no_duplicate_alerts_or_runs(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory()
    events = [BENIGN_EVENT, SUSPICIOUS_EVENT]
    first = await stack.ingest(TENANT_A, "api", events)
    assert len(first.inserted) == 2
    assert await stack.dispatch(TENANT_A, first) == 2
    engine = await stack.engine()
    runs = count_calls(monkeypatch, engine, "run")
    worker = stack.worker(engine)

    async with running(worker):
        await eventually(lambda: stack.all_settled(TENANT_A, [a.alert_id for a in first.inserted]))
        again = await stack.ingest(TENANT_A, "api", events)
        assert again.inserted == [] and again.duplicates == 2
        assert [i.alert_id for i in again.items] == [a.alert_id for a in first.inserted]
        assert await stack.dispatch(TENANT_A, again) == 0
        # Re-dispatching the original batch finds the runs past 'queued' and enqueues nothing.
        assert await stack.dispatch(TENANT_A, first) == 0
        await eventually(stack.stream_empty)

    page = await repos.alerts.list(TENANT_A, limit=50)
    assert len(page.items) == 2
    async with repos.db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval("SELECT count(*) FROM workflow_runs WHERE tenant_id = $1", TENANT_A) == 2
    assert len(runs) == 2


async def test_two_tenants_are_processed_concurrently_and_stay_isolated(
    stack_factory: Callable[..., Stack], repos: Repositories, redis_client: Any
) -> None:
    stack = stack_factory(concurrency=6, per_tenant_concurrency=3)
    listener = EventBus(redis_client, stack.settings)
    received: Dict[str, List[Dict[str, Any]]] = {TENANT_A: [], TENANT_B: []}

    async def listen(tenant_id: str, ready: asyncio.Event) -> None:
        async with listener.subscribe(tenant_id) as subscription:
            ready.set()
            async for event in subscription:
                received[tenant_id].append(event)

    ready = {TENANT_A: asyncio.Event(), TENANT_B: asyncio.Event()}
    listeners = [asyncio.create_task(listen(t, ready[t])) for t in (TENANT_A, TENANT_B)]
    await asyncio.gather(*(r.wait() for r in ready.values()))

    # The same vendor events for both tenants: identical source keys, separate rows.
    events = [BENIGN_EVENT, SUSPICIOUS_EVENT, {**BENIGN_EVENT, "source_alert_id": "bk-002"}]
    ingested = {t: await stack.ingest(t, "api", events) for t in (TENANT_A, TENANT_B)}
    ids = {t: [a.alert_id for a in r.inserted] for t, r in ingested.items()}
    assert not set(ids[TENANT_A]) & set(ids[TENANT_B])
    await asyncio.gather(*(stack.dispatch(t, r) for t, r in ingested.items()))
    worker = stack.worker(await stack.engine())

    try:
        async with running(worker):
            await eventually(lambda: stack.all_settled(TENANT_A, ids[TENANT_A]))
            await eventually(lambda: stack.all_settled(TENANT_B, ids[TENANT_B]))
            await eventually(lambda: _closed_events_seen(received, ids))
    finally:
        await listener.aclose()
        await asyncio.gather(*listeners, return_exceptions=True)

    for tenant, other in ((TENANT_A, TENANT_B), (TENANT_B, TENANT_A)):
        listed = {a.id for a in (await repos.alerts.list(tenant, limit=50)).items}
        assert listed == set(ids[tenant])
        for alert_id in ids[other]:
            with pytest.raises(NotFound):
                await repos.alerts.get(tenant, alert_id)
        for alert_id in ids[tenant]:
            assert (await repos.runs.get(tenant, alert_id)).thread_id == thread_id_for(tenant, alert_id)
        assert received[tenant] and all(e["tenant_id"] == tenant for e in received[tenant])
        assert {e["alert_id"] for e in received[tenant]} <= set(ids[tenant])
        statuses = sorted([(await repos.alerts.get(tenant, a)).status for a in ids[tenant]])
        assert statuses == ["closed", "closed", "waiting_human"]

    async with repos.db.system_tx() as conn:
        threads = {r["thread_id"] for r in await conn.fetch("SELECT DISTINCT thread_id FROM checkpoints")}
    expected = {thread_id_for(t, a) for t in ids for a in ids[t]}
    assert threads == expected
    for tenant in (TENANT_A, TENANT_B):
        escalations = (await repos.escalations.list(tenant, limit=50)).items
        assert len(escalations) == 1 and escalations[0].alert_id in ids[tenant]
        assert escalations[0].thread_id == thread_id_for(tenant, escalations[0].alert_id)


async def _closed_events_seen(received: Dict[str, List[Dict[str, Any]]], ids: Dict[str, List[str]]) -> bool:
    for events in received.values():
        closed = {e["alert_id"] for e in events if e["type"] == "alert.updated" and e["data"].get("status") == "closed"}
        if len(closed) < 2:
            return False
    return True


async def _run_is(stack: Stack, alert_id: str, status: str, tenant_id: str = TENANT_A) -> bool:
    return await stack.run_status(tenant_id, alert_id) == status
