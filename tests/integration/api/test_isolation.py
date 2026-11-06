"""A tenant A principal never sees or changes tenant B objects."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def _seed_tenant_b(api: ApiHarness) -> dict:
    alert_id = await make_alert(api.repos, TENANT_B, title="Tenant B secret incident")
    await api.repos.alert_events.append(TENANT_B, alert_id, "note", data={"text": "b"})
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_B, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    action, _ = await api.repos.actions.propose(
        TENANT_B, alert_id, "block_ip", "203.0.113.9", "medium", status="awaiting_approval"
    )
    source = await api.repos.sources.create(
        TENANT_B, "webhook", "B hook", source_id="b-hook", config={"format": "generic"}
    )
    rule = await api.repos.suppressions.create(TENANT_B, "B rule", {"fingerprint": "x"})
    user = await api.user(TENANT_B, "analyst")
    key, _ = await api.api_key(TENANT_B, ["read"])
    await api.repos.tenants.update_settings(TENANT_B, {"autonomy": {"low": "auto"}})
    return {
        "alert": alert_id,
        "escalation": escalation,
        "action": action,
        "source": source.id,
        "rule": rule.id,
        "user": user.id,
        "key": key.id,
    }


async def test_reads_and_writes_across_tenants_are_not_found(api: ApiHarness) -> None:
    b = await _seed_tenant_b(api)
    await make_alert(api.repos, TENANT_A, title="A alert")
    admin = await api.user(TENANT_A, "admin")
    headers = api.auth(admin)

    by_id = [
        ("GET", f"/api/v1/alerts/{b['alert']}", None),
        ("GET", f"/api/v1/alerts/{b['alert']}/events", None),
        ("POST", f"/api/v1/alerts/{b['alert']}/notes", {"text": "x"}),
        ("POST", f"/api/v1/alerts/{b['alert']}/reprocess", None),
        ("GET", f"/api/v1/escalations/{b['escalation'].id}", None),
        ("POST", f"/api/v1/escalations/{b['escalation'].id}/claim", {"version": b["escalation"].version}),
        (
            "POST",
            f"/api/v1/escalations/{b['escalation'].id}/decision",
            {"decision": "false_positive", "version": b["escalation"].version},
        ),
        ("GET", f"/api/v1/actions/{b['action'].id}", None),
        ("POST", f"/api/v1/actions/{b['action'].id}/approve", None),
        ("POST", f"/api/v1/actions/{b['action'].id}/reject", None),
        ("GET", f"/api/v1/sources/{b['source']}", None),
        ("PATCH", f"/api/v1/sources/{b['source']}", {"name": "stolen"}),
        ("DELETE", f"/api/v1/sources/{b['source']}", None),
        ("POST", f"/api/v1/sources/{b['source']}/test", None),
        ("GET", f"/api/v1/suppressions/{b['rule']}", None),
        ("PATCH", f"/api/v1/suppressions/{b['rule']}", {"enabled": False}),
        ("DELETE", f"/api/v1/suppressions/{b['rule']}", None),
        ("GET", f"/api/v1/users/{b['user']}", None),
        ("PATCH", f"/api/v1/users/{b['user']}", {"role": "viewer"}),
        ("DELETE", f"/api/v1/users/{b['user']}", None),
        ("DELETE", f"/api/v1/api-keys/{b['key']}", None),
    ]
    for method, path, body in by_id:
        response = await api.client.request(method, path, headers=headers, json=body)
        assert response.status_code == 404, f"{method} {path}: {response.status_code} {response.text}"

    listings = {
        "/api/v1/alerts": "items",
        "/api/v1/escalations": "items",
        "/api/v1/actions": "items",
        "/api/v1/sources": None,
        "/api/v1/suppressions": None,
        "/api/v1/users": None,
        "/api/v1/api-keys": None,
    }
    for path, field in listings.items():
        response = await api.client.get(path, headers=headers)
        assert response.status_code == 200, path
        items = response.json()[field] if field else response.json()
        assert all(item["tenant_id"] == TENANT_A for item in items), path
        assert "Tenant B" not in response.text

    settings = await api.client.get("/api/v1/tenant/settings", headers=headers)
    assert settings.json()["tenant_id"] == TENANT_A
    assert "autonomy" not in settings.json()["settings"]
    summary = await api.client.get("/api/v1/dashboard/summary", headers=headers)
    assert summary.json()["alerts_total"] == 1

    # Nothing in tenant B changed.
    assert (await api.repos.actions.get(TENANT_B, b["action"].id)).status == "awaiting_approval"
    assert (await api.repos.escalations.get(TENANT_B, b["escalation"].id)).status == "open"
    assert (await api.repos.sources.get(TENANT_B, b["source"])).name == "B hook"
    assert (await api.repos.suppressions.get(TENANT_B, b["rule"])).enabled is True


async def test_api_key_only_sees_its_own_tenant(api: ApiHarness) -> None:
    b = await _seed_tenant_b(api)
    headers = await api.key_headers(TENANT_A, ["read"])
    assert (await api.client.get(f"/api/v1/alerts/{b['alert']}", headers=headers)).status_code == 404
    listed = await api.client.get("/api/v1/alerts", headers=headers)
    assert listed.json()["items"] == []


async def test_ingest_with_tenant_a_key_lands_in_tenant_a(api: ApiHarness) -> None:
    headers = await api.key_headers(TENANT_A, ["ingest"])
    response = await api.client.post(
        "/api/v1/ingest/alerts", json=[{"title": "x", "severity": "low", "tenant_id": TENANT_B}], headers=headers
    )
    alert_id = response.json()["items"][0]["alert_id"]
    assert (await api.repos.alerts.get(TENANT_A, alert_id)).tenant_id == TENANT_A
    b_page = await api.repos.alerts.list(TENANT_B)
    assert b_page.items == []
