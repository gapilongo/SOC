"""Ingest -> queued alerts and queue messages; analyst decisions and approvals -> resume messages."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, List

import pytest

from lg_sotf.queue.streams import QueueStreams, parse_message
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def _messages(api: ApiHarness, stream: str) -> List[Any]:
    entries = await api.ctx.redis.xrange(stream)
    return [parse_message(stream, entry_id, fields, 1) for entry_id, fields in entries]


def _streams(api: ApiHarness) -> QueueStreams:
    return api.ctx.queue.streams


async def test_ingest_alerts_inserts_queues_and_reports_per_item(api: ApiHarness) -> None:
    key, token = await api.api_key(TENANT_A, ["ingest"])
    batch = [
        {"source_alert_id": "e-1", "title": "Brute force", "severity": "high"},
        {"source_alert_id": "e-2", "title": "Port scan", "severity": "low"},
        {"source_alert_id": "e-1", "title": "Brute force again", "severity": "high"},
        {"title": "missing severity"},
    ]
    response = await api.client.post("/api/v1/ingest/alerts", json={"alerts": batch}, headers={"X-API-Key": token})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["source_id"] == f"api:{key.id}"
    assert (body["received"], body["inserted"], body["duplicates"], body["rejected"], body["enqueued"]) == (
        4,
        2,
        1,
        1,
        2,
    )
    assert [i["status"] for i in body["items"]] == ["inserted", "inserted", "duplicate", "rejected"]
    assert body["items"][2]["alert_id"] == body["items"][0]["alert_id"]
    assert "severity" in body["items"][3]["reason"]

    high_id, normal_id = body["items"][0]["alert_id"], body["items"][1]["alert_id"]
    assert (await api.repos.alerts.get(TENANT_A, high_id)).status == "queued"
    assert (await api.repos.runs.get(TENANT_A, high_id)).status == "queued"
    high = await _messages(api, _streams(api).high)
    normal = await _messages(api, _streams(api).normal)
    assert [(m.tenant_id, m.alert_id, m.kind) for m in high] == [(TENANT_A, high_id, "process")]
    assert [(m.tenant_id, m.alert_id, m.kind) for m in normal] == [(TENANT_A, normal_id, "process")]

    again = await api.client.post("/api/v1/ingest/alerts", json=batch[:1], headers={"X-API-Key": token})
    assert again.status_code == 202
    assert again.json()["items"][0]["status"] == "duplicate"
    assert again.json()["enqueued"] == 0
    assert len(await _messages(api, _streams(api).high)) == 1


async def test_retry_after_a_failed_dispatch_queues_the_stranded_alerts(api: ApiHarness) -> None:
    key, token = await api.api_key(TENANT_A, ["ingest"])
    event = {"source_alert_id": "s-1", "title": "Stored but never queued", "severity": "medium"}
    # The first attempt stored the alert and then failed before dispatching it.
    first = await api.ctx.ingestion.ingest(TENANT_A, f"api:{key.id}", [event])
    [stored] = first.inserted
    assert (await api.repos.alerts.get(TENANT_A, stored.alert_id)).status == "new"

    retry = await api.client.post("/api/v1/ingest/alerts", json=[event], headers={"X-API-Key": token})
    assert retry.status_code == 202
    assert retry.json()["items"][0] == {"index": 0, "status": "duplicate", "alert_id": stored.alert_id, "reason": None}
    assert retry.json()["enqueued"] == 1
    assert (await api.repos.alerts.get(TENANT_A, stored.alert_id)).status == "queued"
    assert [m.alert_id for m in await _messages(api, _streams(api).normal)] == [stored.alert_id]

    again = await api.client.post("/api/v1/ingest/alerts", json=[event], headers={"X-API-Key": token})
    assert again.json()["enqueued"] == 0


async def test_ingest_validates_the_batch(make_api) -> None:
    api = await make_api(api={"max_ingest_batch": 2})
    headers = await api.key_headers(TENANT_A, ["ingest"])
    too_many = [{"title": f"t{i}", "severity": "low"} for i in range(3)]
    response = await api.client.post("/api/v1/ingest/alerts", json=too_many, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "batch_too_large"
    for bad in ({"events": []}, [], "text"):
        assert (await api.client.post("/api/v1/ingest/alerts", json=bad, headers=headers)).status_code == 400
    not_json = await api.client.post(
        "/api/v1/ingest/alerts", content=b"{nope", headers={**headers, "Content-Type": "application/json"}
    )
    assert not_json.status_code == 400
    assert not_json.json()["error"]["code"] == "invalid_json"


async def test_webhook_resolves_the_source_in_the_keys_tenant(api: ApiHarness) -> None:
    config = {
        "format": "generic",
        "field_map": {"title": "alert.name", "severity": "alert.sev", "source_alert_id": "alert.id"},
    }
    await api.repos.sources.create(TENANT_A, "webhook", "Hook A", source_id="hook", config=config)
    await api.repos.sources.create(TENANT_B, "webhook", "Hook B", source_id="hook-b", config=config)
    await api.repos.sources.create(TENANT_A, "splunk", "Splunk", source_id="splunk-a", config={"base_url": "https://s"})
    headers = await api.key_headers(TENANT_A, ["ingest"])
    payload = {"alert": {"name": "Malware", "sev": "critical", "id": "w-1"}}

    ok = await api.client.post("/api/v1/ingest/webhook/hook", json=payload, headers=headers)
    assert ok.status_code == 202, ok.text
    alert_id = ok.json()["items"][0]["alert_id"]
    alert = await api.repos.alerts.get(TENANT_A, alert_id)
    assert (alert.source_id, alert.severity, alert.status) == ("hook", "critical", "queued")
    assert [m.alert_id for m in await _messages(api, _streams(api).high)] == [alert_id]

    other_tenant = await api.client.post("/api/v1/ingest/webhook/hook-b", json=payload, headers=headers)
    assert other_tenant.status_code == 404
    pull = await api.client.post("/api/v1/ingest/webhook/splunk-a", json=payload, headers=headers)
    assert pull.status_code == 404
    reserved = await api.client.post("/api/v1/ingest/webhook/api", json=payload, headers=headers)
    assert reserved.status_code == 404
    await api.repos.sources.update(TENANT_A, "hook", enabled=False)
    disabled = await api.client.post("/api/v1/ingest/webhook/hook", json=payload, headers=headers)
    assert disabled.status_code == 409


async def _escalation(api: ApiHarness, tenant_id: str = TENANT_A):
    alert_id = await make_alert(api.repos, tenant_id, title="Needs review")
    escalation, _ = await api.repos.escalations.create_or_attach(
        tenant_id, alert_id, reason="uncertain", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    return alert_id, escalation


async def test_claim_and_decision_enqueue_resume_and_stale_version_conflicts(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    headers = api.auth(analyst)
    alert_id, escalation = await _escalation(api)

    claimed = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/claim", json={"version": escalation.version}, headers=headers
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["status"] == "claimed"
    assert claimed.json()["assigned_to"] == str(analyst.id)
    version = claimed.json()["version"]

    stale = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "true_positive", "version": escalation.version},
        headers=headers,
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "conflict"
    assert await _messages(api, _streams(api).high) == []

    decided = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "true_positive", "version": version, "notes": "confirmed", "feedback": {"confidence": 90}},
        headers=headers,
    )
    assert decided.status_code == 200, decided.text
    body = decided.json()
    assert body["escalation"]["status"] == "decided"
    assert body["resumed_alert_ids"] == [alert_id]
    assert (body["resumes_enqueued"], body["resumes_failed"]) == (1, 0)
    [message] = await _messages(api, _streams(api).high)
    assert (message.tenant_id, message.alert_id, message.kind) == (TENANT_A, alert_id, "resume")
    assert message.payload["type"] == "analyst_decision"
    assert message.payload["decision"] == "true_positive"
    assert message.payload["decided_by"] == str(analyst.id)
    assert message.payload["approver_role"] == "analyst"

    again = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "true_positive", "version": body["escalation"]["version"]},
        headers=headers,
    )
    assert again.status_code == 409


async def test_expired_escalation_can_still_be_decided(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_A, "analyst")
    alert_id, escalation = await _escalation(api)
    expired = await api.repos.escalations.expire(TENANT_A, escalation.id)
    response = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "false_positive", "version": expired.version},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["resumed_alert_ids"] == [alert_id]
    entries = (await api.repos.audit.list(TENANT_A, action="escalation.decided")).items
    assert entries[0].details["after_sla_expiry"] is True


async def test_claim_on_an_expired_escalation_succeeds_and_state_errors_are_not_version_races(api: ApiHarness) -> None:
    """Expired: claimable. Decided: 409 ``invalid_transition``. A stale version on an active one: 409 ``conflict``."""
    analyst = await api.user(TENANT_A, "analyst")
    headers = api.auth(analyst)
    _, escalation = await _escalation(api)
    expired = await api.repos.escalations.expire(TENANT_A, escalation.id)
    url = f"/api/v1/escalations/{escalation.id}"

    claimed = await api.client.post(f"{url}/claim", json={"version": expired.version}, headers=headers)
    assert claimed.status_code == 200, claimed.text
    assert (claimed.json()["status"], claimed.json()["assigned_to"]) == ("expired", str(analyst.id))
    decided = await api.client.post(
        f"{url}/decision", json={"decision": "false_positive", "version": claimed.json()["version"]}, headers=headers
    )
    assert decided.status_code == 200, decided.text
    version = decided.json()["escalation"]["version"]
    for stale in (version, version - 1):
        refused = await api.client.post(f"{url}/claim", json={"version": stale}, headers=headers)
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "invalid_transition"

    _, active = await _escalation(api)
    raced = await api.client.post(
        f"/api/v1/escalations/{active.id}/claim", json={"version": active.version + 1}, headers=headers
    )
    assert raced.status_code == 409
    assert raced.json()["error"]["code"] == "conflict"


async def test_viewer_cannot_decide_and_claim_by_other_analyst_is_refused(api: ApiHarness) -> None:
    _, escalation = await _escalation(api)
    viewer = await api.login_headers(TENANT_A, "viewer")
    denied = await api.client.post(f"/api/v1/escalations/{escalation.id}/claim", json={"version": 1}, headers=viewer)
    assert denied.status_code == 403
    first = await api.login_headers(TENANT_A, "analyst")
    second = await api.login_headers(TENANT_A, "analyst")
    claimed = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/claim", json={"version": escalation.version}, headers=first
    )
    taken = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/claim", json={"version": claimed.json()["version"]}, headers=second
    )
    assert taken.status_code == 403


async def _pending_action(api: ApiHarness, alert_id: str, action_type: str, target: str, risk: str):
    # The alert's run is live: an approval for an ended (or missing) run goes to the scheduler, not the run.
    await api.repos.runs.upsert_queued(TENANT_A, alert_id)
    action, _ = await api.repos.actions.propose(
        TENANT_A, alert_id, action_type, target, risk, status="awaiting_approval"
    )
    return action


async def test_per_action_approval_and_explicit_reject_remaining(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    headers = api.auth(analyst)
    alert_id = await make_alert(api.repos, TENANT_A)
    block = await _pending_action(api, alert_id, "block_ip", "203.0.113.7", "medium")
    ticket = await _pending_action(api, alert_id, "create_ticket", alert_id, "low")
    forensics = await _pending_action(api, alert_id, "collect_forensics", "host-1", "low")

    response = await api.client.post(f"/api/v1/actions/{block.id}/approve", json={}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["action"]["status"] == "approved"
    assert response.json()["action"]["approved_by"] == str(analyst.id)
    assert (await api.repos.actions.get(TENANT_A, ticket.id)).status == "awaiting_approval"
    [first] = await _messages(api, _streams(api).high)
    assert first.payload == {
        "type": "approval",
        "approved_action_ids": [str(block.id)],
        "rejected_action_ids": [],
        "decided_by": str(analyst.id),
        "reject_remaining": False,
    }

    response = await api.client.post(
        f"/api/v1/actions/{ticket.id}/approve", json={"reject_remaining": True}, headers=headers
    )
    assert response.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, forensics.id)).status == "rejected"
    second = (await _messages(api, _streams(api).high))[-1]
    assert second.payload["approved_action_ids"] == [str(ticket.id)]
    assert second.payload["rejected_action_ids"] == [str(forensics.id)]


async def test_high_risk_needs_admin_and_reject_works(api: ApiHarness) -> None:
    alert_id = await make_alert(api.repos, TENANT_A)
    isolate = await _pending_action(api, alert_id, "isolate_host", "host-9", "high")
    analyst = await api.login_headers(TENANT_A, "analyst")
    admin = await api.login_headers(TENANT_A, "admin")
    denied = await api.client.post(f"/api/v1/actions/{isolate.id}/approve", headers=analyst)
    assert denied.status_code == 403
    assert (await api.repos.actions.get(TENANT_A, isolate.id)).status == "awaiting_approval"
    rejected = await api.client.post(f"/api/v1/actions/{isolate.id}/reject", headers=analyst)
    assert rejected.status_code == 200
    assert rejected.json()["action"]["status"] == "rejected"
    again = await api.client.post(f"/api/v1/actions/{isolate.id}/approve", headers=admin)
    assert again.status_code == 409

    other = await _pending_action(api, alert_id, "revoke_sessions", "bob", "high")
    approved = await api.client.post(f"/api/v1/actions/{other.id}/approve", headers=admin)
    assert approved.status_code == 200
    assert approved.json()["action"]["status"] == "approved"


async def test_reprocess_requeues_a_finished_alert(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    alert_id = await make_alert(api.repos, TENANT_A, severity="medium")
    await api.repos.runs.upsert_queued(TENANT_A, alert_id)
    await api.repos.alerts.update_status(TENANT_A, alert_id, "queued")
    await api.repos.alerts.update_status(TENANT_A, alert_id, "processing")
    await api.repos.alerts.update_status(TENANT_A, alert_id, "closed")
    run = await api.repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
    await api.repos.runs.complete(TENANT_A, alert_id, worker_id="w1")
    assert run is not None
    response = await api.client.post(f"/api/v1/alerts/{alert_id}/reprocess", headers=admin)
    assert response.status_code == 202, response.text
    assert (await api.repos.alerts.get(TENANT_A, alert_id)).status == "queued"
    [message] = await _messages(api, _streams(api).normal)
    assert (message.alert_id, message.kind) == (alert_id, "process")
    busy = await api.client.post(f"/api/v1/alerts/{alert_id}/reprocess", headers=admin)
    assert busy.status_code == 202  # still queued: a duplicate message is harmless (the worker drops it)


async def test_notes_are_stored_as_alert_events(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    alert_id = await make_alert(api.repos, TENANT_A)
    response = await api.client.post(
        f"/api/v1/alerts/{alert_id}/notes", json={"text": "  checked with the owner  "}, headers=api.auth(analyst)
    )
    assert response.status_code == 201, response.text
    events = await api.client.get(f"/api/v1/alerts/{alert_id}/events", headers=api.auth(analyst))
    [note] = [e for e in events.json()["items"] if e["event_type"] == "note"]
    assert note["data"]["text"] == "checked with the owner"
    assert (note["actor_type"], note["actor_id"]) == ("user", str(analyst.id))
    missing = await api.client.post("/api/v1/alerts/nope/notes", json={"text": "x"}, headers=api.auth(analyst))
    assert missing.status_code == 404


async def test_ingest_over_the_inflight_cap_is_refused_at_once(make_api) -> None:
    """PERF-3: overload is refused with 503 + Retry-After instead of queueing on the database pool."""
    import asyncio

    api = await make_api(api={"max_inflight_ingest": 1})
    headers = await api.key_headers(TENANT_A, ["ingest"])
    gate = asyncio.Event()
    real_ingest = api.ctx.ingestion.ingest

    async def slow_ingest(*args: Any, **kwargs: Any) -> Any:
        await gate.wait()
        return await real_ingest(*args, **kwargs)

    api.ctx.ingestion.ingest = slow_ingest  # type: ignore[method-assign]
    event = [{"source_alert_id": "adm-1", "title": "t", "severity": "low"}]
    first = asyncio.create_task(api.client.post("/api/v1/ingest/alerts", json=event, headers=headers))
    for _ in range(500):  # until the first request holds its admission slot
        if api.ctx.ingest_admission.inflight:
            break
        await asyncio.sleep(0.01)
    refused = await api.client.post("/api/v1/ingest/alerts", json=event, headers=headers)
    assert refused.status_code == 503 and refused.headers["retry-after"] == "1"
    assert refused.json()["error"]["code"] == "overloaded"
    gate.set()
    assert (await first).status_code == 202
    assert api.ctx.ingest_admission.inflight == 0
    after = await api.client.post("/api/v1/ingest/alerts", json=event, headers=headers)
    assert after.status_code == 202
