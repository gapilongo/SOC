"""Characterization: the audit entry each audited API change writes, field by field.

These pin ``(action, resource, actor, details)`` of changes whose transaction
moved from a router into a service (roadmap D5), so a move cannot silently
change what the hash-chained audit log records.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import pytest

from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness
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


# -------------------------------------------------------------------------- compliance


async def test_incident_report_draft_entry(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    alert_id = await make_alert(api.repos, TENANT_A)
    response = await api.client.post(
        f"{API}/alerts/{alert_id}/incident-report",
        json={"stage": "early_warning", "include_ai_narrative": False},
        headers=api.auth(analyst),
    )
    assert response.status_code == 201, response.text
    event_id = response.json()["event_id"]
    [draft] = [e for e in (await api.repos.alert_events.list_for_alert(TENANT_A, alert_id)).items if e.id == event_id]
    assert (draft.event_type, draft.actor_type, draft.actor_id) == ("incident_report_draft", "user", str(analyst.id))
    assert draft.data["author"] == analyst.email and draft.data["ai_narrative"] is None
    sha = draft.data["draft_sha256"]
    details = {"stage": "early_warning", "event_id": event_id, "draft_sha256": sha, "ai_narrative": False}
    assert await _only(api, "alert.incident_report_drafted") == ("alert", alert_id, "user", str(analyst.id), details)


# ---------------------------------------------------------------------------- identity


async def _signed_in(api: ApiHarness, email: str) -> Any:
    user = await api.user(TENANT_A, "analyst", email=email)
    login = await api.client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return user


async def test_user_update_entry(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    user = await _signed_in(api, "updated@a.example.com")
    response = await api.client.patch(
        f"{API}/users/{user.id}",
        json={"password": "another long passphrase", "role": "viewer", "is_active": False},
        headers=api.auth(admin),
    )
    assert response.status_code == 200, response.text
    details = {"fields": ["is_active", "role", "password"], "role": "viewer", "revoked_sessions": 1}
    assert await _only(api, "user.updated") == ("user", str(user.id), "user", str(admin.id), details)


async def test_user_reactivation_over_quota_is_refused_and_changes_nothing(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    dormant = await api.user(TENANT_A, "analyst", active=False)
    await api.repos.tenants.update_admin(TENANT_A, max_users=1)
    response = await api.client.patch(f"{API}/users/{dormant.id}", json={"is_active": True}, headers=api.auth(admin))
    assert response.status_code == 409 and response.json()["error"]["code"] == "quota_exceeded"
    assert (await api.repos.users.get(TENANT_A, dormant.id)).is_active is False
    assert "user.updated" not in await _actions(api)


async def test_user_refusals_keep_their_codes_and_messages(api: ApiHarness) -> None:
    only_admin = await api.user(TENANT_A, "admin")
    operator = await api.user(TENANT_B, "admin", platform_admin=True)
    platform = await api.user(TENANT_A, "viewer", platform_admin=True)
    as_operator = {**api.auth(operator), "X-Tenant-ID": TENANT_A}
    last_admin = ["last_admin", "the tenant must keep at least one active admin"]
    guarded = ["forbidden", "only a platform admin can modify a platform-admin account"]
    for method, path, body, headers, expected in (
        ("PATCH", f"users/{only_admin.id}", {"role": "viewer"}, as_operator, last_admin),
        ("DELETE", f"users/{only_admin.id}", None, as_operator, last_admin),
        ("PATCH", f"users/{platform.id}", {"role": "admin"}, api.auth(only_admin), guarded),
        ("DELETE", f"users/{platform.id}", None, api.auth(only_admin), guarded),
        ("POST", f"users/{platform.id}/mfa/reset", None, api.auth(only_admin), guarded),
    ):
        response = await api.client.request(method, f"{API}/{path}", json=body, headers=headers)
        error = response.json()["error"]
        assert [error["code"], error["message"]] == expected, (method, path)
    assert not {"user.updated", "user.deleted", "auth.mfa_reset"} & set(await _actions(api))


async def test_user_delete_entry(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    user = await _signed_in(api, "gone@b.example.org")
    response = await api.client.delete(f"{API}/users/{user.id}", headers=api.auth(admin))
    assert response.status_code == 204, response.text
    details = {"email_domain": "b.example.org"}
    assert await _only(api, "user.deleted") == ("user", str(user.id), "user", str(admin.id), details)


async def test_user_mfa_reset_entry(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    user = await _signed_in(api, "reset@a.example.com")
    response = await api.client.post(f"{API}/users/{user.id}/mfa/reset", headers=api.auth(admin))
    assert response.status_code == 204, response.text
    details = {
        "was_enabled": False,
        "revoked_sessions": 1,
        "by_platform_admin": False,
        "actor_home_tenant_id": TENANT_A,
    }
    assert await _only(api, "auth.mfa_reset") == ("user", str(user.id), "user", str(admin.id), details)

