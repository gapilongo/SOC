"""Characterization: the audit entry each audited API change writes, field by field.

These pin ``(action, resource, actor, details)`` of changes whose transaction
moved from a router into a service (roadmap D5), so a move cannot silently
change what the hash-chained audit log records.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import pytest

from tests.integration.api.conftest import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"


async def _only(api: ApiHarness, action: str, tenant_id: str = TENANT_A) -> Tuple[Any, ...]:
    """``(resource_type, resource_id, actor_type, actor_id, details)`` of the one ``action`` entry."""
    [entry] = (await api.repos.audit.list(tenant_id, action=action)).items
    return entry.resource_type, entry.resource_id, entry.actor_type, entry.actor_id, entry.details


async def _actions(api: ApiHarness, tenant_id: str = TENANT_A) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in (await api.repos.audit.list(tenant_id, limit=200)).items:
        counts[entry.action] = counts.get(entry.action, 0) + 1
    return counts


async def _finished_alert(api: ApiHarness, *, status: Optional[str] = "closed") -> str:
    alert_id = await make_alert(api.repos, TENANT_A, severity="medium")
    await api.repos.runs.upsert_queued(TENANT_A, alert_id)
    await api.repos.alerts.update_status(TENANT_A, alert_id, "queued")
    await api.repos.alerts.update_status(TENANT_A, alert_id, "processing")
    if status is not None:
        await api.repos.alerts.update_status(TENANT_A, alert_id, status)
    return alert_id


# ------------------------------------------------------------------------------ alerts


async def test_alert_note_entry(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    alert_id = await make_alert(api.repos, TENANT_A)
    response = await api.client.post(f"{API}/alerts/{alert_id}/notes", json={"text": "seen"}, headers=api.auth(analyst))
    assert response.status_code == 201, response.text
    event_id = response.json()["id"]
    assert await _only(api, "alert.note_added") == ("alert", alert_id, "user", str(analyst.id), {"event_id": event_id})


async def test_alert_note_by_api_key_entry(api: ApiHarness) -> None:
    key, token = await api.api_key(TENANT_A, ["read", "write"])
    alert_id = await make_alert(api.repos, TENANT_A)
    response = await api.client.post(f"{API}/alerts/{alert_id}/notes", json={"text": "bot"}, headers={"X-API-Key": token})
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["actor_type"], body["actor_id"], body["data"]["author"]) == ("system", str(key.id), str(key.id))
    assert await _only(api, "alert.note_added") == ("alert", alert_id, "api_key", str(key.id), {"event_id": body["id"]})


async def test_alert_reprocess_entry(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    alert_id = await _finished_alert(api)
    await api.repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
    await api.repos.runs.complete(TENANT_A, alert_id, worker_id="w1")
    response = await api.client.post(f"{API}/alerts/{alert_id}/reprocess", headers=api.auth(admin))
    assert response.status_code == 202, response.text
    assert await _only(api, "alert.reprocess_requested") == (
        "alert",
        alert_id,
        "user",
        str(admin.id),
        {"previous_status": "closed"},
    )


async def test_alert_reprocess_of_an_active_run_is_refused_and_changes_nothing(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    alert_id = await _finished_alert(api, status=None)
    await api.repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
    response = await api.client.post(f"{API}/alerts/{alert_id}/reprocess", headers=api.auth(admin))
    assert response.status_code == 409
    error = response.json()["error"]
    assert (error["code"], error["message"]) == ("run_active", "the alert's run is running; it cannot be reprocessed now")
    assert (await api.repos.alerts.get(TENANT_A, alert_id)).status == "processing"
    assert (await api.repos.runs.get(TENANT_A, alert_id)).status == "running"
    assert "alert.reprocess_requested" not in await _actions(api)
