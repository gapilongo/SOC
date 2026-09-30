"""First-run onboarding: checklist transitions, sample alerts and per-tenant retention settings."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf.onboarding import SAMPLE_COUNT, SAMPLE_SOURCE_ID
from tests.integration.api.conftest import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

WEBHOOK_SOURCE = {"type": "webhook", "name": "hook", "config": {"format": "generic", "field_map": {"title": "t"}}}


def _steps(body: Dict[str, Any]) -> Dict[str, bool]:
    return {s["id"]: s["done"] for s in body["steps"]}


async def _status(api: ApiHarness, headers: Dict[str, str]) -> Dict[str, Any]:
    response = await api.client.get("/api/v1/onboarding/status", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


async def test_checklist_moves_with_the_tenants_own_data(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_B, "admin")

    fresh = await _status(api, admin)
    assert _steps(fresh) == {
        "source_connected": False,
        "notifications_configured": False,
        "teammate_invited": False,
        "autonomy_reviewed": False,
        "first_alert_triaged": False,
    }
    notifications = next(s for s in fresh["steps"] if s["id"] == "notifications_configured")
    async with api.ctx.db.connection() as conn:
        has_integrations = await conn.fetchval("SELECT to_regclass('public.integrations') IS NOT NULL")
    assert notifications["available"] is has_integrations
    assert (fresh["completed"], fresh["complete"], fresh["dismissed"], fresh["samples_sent"]) == (0, False, False, False)

    samples = await api.client.post("/api/v1/onboarding/sample-alerts", headers=admin)
    assert samples.status_code == 200, samples.text
    assert (samples.json()["inserted"], samples.json()["enqueued"]) == (SAMPLE_COUNT, SAMPLE_COUNT)
    after_samples = await _status(api, admin)
    assert after_samples["samples_sent"] is True
    assert _steps(after_samples)["source_connected"] is False, "sample alerts are not a connected source"

    assert (await api.client.post("/api/v1/sources", json=WEBHOOK_SOURCE, headers=admin)).status_code == 201
    invited = await api.client.post("/api/v1/users", json={"email": "mate@b.example.com", "role": "analyst"}, headers=admin)
    assert invited.status_code == 201
    saved = await api.client.patch("/api/v1/tenant/settings", json={"autonomy": {"low": "approval"}}, headers=admin)
    assert saved.status_code == 200
    sample_alert = samples.json()["alert_ids"][0]
    await api.repos.alerts.update(TENANT_B, sample_alert, disposition="benign")

    done = await _status(api, admin)
    steps = _steps(done)
    assert steps["source_connected"] and steps["teammate_invited"]
    assert steps["autonomy_reviewed"] and steps["first_alert_triaged"]
    assert done["completed"] == done["total"] - (1 if has_integrations else 0)
    assert done["complete"] is (not has_integrations)

    other = await _status(api, await api.login_headers(TENANT_A, "admin"))
    assert not any(_steps(other).values()), "one tenant's progress never shows in another"


async def test_alerts_from_a_real_source_count_as_connected_and_reviewed_can_be_marked(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_B, "admin")
    key = await api.key_headers(TENANT_B, ["ingest"])
    pushed = await api.client.post("/api/v1/ingest/alerts", json=[{"title": "t", "severity": "low"}], headers=key)
    assert pushed.status_code == 202
    assert _steps(await _status(api, admin))["source_connected"] is True

    marked = await api.client.post("/api/v1/onboarding/autonomy-reviewed", headers=admin)
    assert marked.status_code == 200 and _steps(marked.json())["autonomy_reviewed"] is True
    first_mark = (await api.repos.tenants.get(TENANT_B)).onboarding["autonomy_reviewed_at"]
    await api.client.post("/api/v1/onboarding/autonomy-reviewed", headers=admin)
    assert (await api.repos.tenants.get(TENANT_B)).onboarding["autonomy_reviewed_at"] == first_mark

    dismissed = await api.client.post("/api/v1/onboarding/dismiss", headers=admin)
    assert dismissed.status_code == 200 and dismissed.json()["dismissed"] is True
    assert dismissed.json()["dismissed_at"]
    actions = {e.action for e in (await api.repos.audit.list(TENANT_B, resource_type="tenant")).items}
    assert {"onboarding.autonomy_reviewed", "onboarding.dismissed"} <= actions


async def test_notifications_step_uses_the_integrations_table_when_present(api: ApiHarness) -> None:
    async with api.ctx.db.connection() as conn:
        if await conn.fetchval("SELECT to_regclass('public.integrations') IS NOT NULL"):
            pytest.skip("the integrations feature owns this table here")
        await conn.execute("CREATE TABLE integrations (tenant_id TEXT NOT NULL)")
    try:
        admin = await api.login_headers(TENANT_B, "admin")
        step = next(s for s in (await _status(api, admin))["steps"] if s["id"] == "notifications_configured")
        assert step == {"id": "notifications_configured", "done": False, "available": True}
        async with api.ctx.db.connection() as conn:
            await conn.execute("INSERT INTO integrations (tenant_id) VALUES ($1)", TENANT_B)
        assert _steps(await _status(api, admin))["notifications_configured"] is True
        assert _steps(await _status(api, await api.login_headers(TENANT_A, "admin")))["notifications_configured"] is False
    finally:
        async with api.ctx.db.connection() as conn:
            await conn.execute("DROP TABLE IF EXISTS integrations")


async def test_sample_alerts_are_idempotent_flagged_and_not_metered(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_B, "admin")
    first = await api.client.post("/api/v1/onboarding/sample-alerts", headers=admin)
    second = await api.client.post("/api/v1/onboarding/sample-alerts", headers=admin)

    assert first.status_code == second.status_code == 200
    assert (first.json()["inserted"], first.json()["duplicates"]) == (SAMPLE_COUNT, 0)
    assert (second.json()["inserted"], second.json()["duplicates"], second.json()["enqueued"]) == (0, SAMPLE_COUNT, 0)
    assert sorted(second.json()["alert_ids"]) == sorted(first.json()["alert_ids"])
    alerts = (await api.repos.alerts.list(TENANT_B, source_id=SAMPLE_SOURCE_ID)).items
    assert len(alerts) == SAMPLE_COUNT
    for item in alerts:
        alert = await api.repos.alerts.get(TENANT_B, item.id)
        assert "sample" in alert.normalized["flags"]
        assert alert.status == "queued"
    assert await api.repos.usage.get_day(TENANT_B) is None
    audited = (await api.repos.audit.list(TENANT_B, action="onboarding.sample_alerts_sent")).items
    assert [e.details["inserted"] for e in audited] == [0, SAMPLE_COUNT]

    await api.repos.tenants.update_admin(TENANT_B, max_alerts_per_day=0)
    api.ctx.tenants.invalidate(TENANT_B)
    assert (await api.client.post("/api/v1/onboarding/sample-alerts", headers=admin)).status_code == 200

    # The reserved id cannot be registered or pushed to.
    taken = await api.client.post("/api/v1/sources", json={**WEBHOOK_SOURCE, "id": SAMPLE_SOURCE_ID}, headers=admin)
    assert taken.status_code == 422
    key = await api.key_headers(TENANT_B, ["ingest"])
    pushed = await api.client.post(f"/api/v1/ingest/webhook/{SAMPLE_SOURCE_ID}", json={"title": "x"}, headers=key)
    assert pushed.status_code == 404


async def test_onboarding_is_for_tenant_admins(api: ApiHarness) -> None:
    for headers in (
        await api.login_headers(TENANT_B, "analyst"),
        await api.login_headers(TENANT_B, "viewer"),
        await api.key_headers(TENANT_B, ["read", "write", "ingest"]),
    ):
        for method, path in (
            ("GET", "/api/v1/onboarding/status"),
            ("POST", "/api/v1/onboarding/sample-alerts"),
            ("POST", "/api/v1/onboarding/dismiss"),
            ("POST", "/api/v1/onboarding/autonomy-reviewed"),
        ):
            response = await api.client.request(method, path, headers=headers)
            assert response.status_code == 403, (method, path, response.text)
    assert (await api.repos.alerts.list(TENANT_B)).items == []


# ---------------------------------------------------------------- retention


async def test_retention_settings_are_validated_within_install_bounds(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_B, "admin")
    settings = await api.client.get("/api/v1/tenant/settings", headers=admin)
    assert settings.json()["retention_limits"] == {"min_days": 7, "max_days": 730, "alerts_days": 90, "indicators_days": 30}

    first = await api.client.patch("/api/v1/tenant/settings", json={"retention": {"alerts_days": 30}}, headers=admin)
    assert first.status_code == 200, first.text
    assert first.json()["settings"]["retention"] == {"alerts_days": 30}
    merged = await api.client.patch("/api/v1/tenant/settings", json={"retention": {"indicators_days": 14}}, headers=admin)
    assert merged.json()["settings"]["retention"] == {"alerts_days": 30, "indicators_days": 14}

    for bad in (
        {"alerts_days": 6},
        {"alerts_days": 731},
        {"alerts_days": "30"},
        {"alerts_days": True},
        {"alerts_days": 30.5},
        {"events_days": 10},
        {"audit_days": 3650},
        [],
        "90",
    ):
        response = await api.client.patch("/api/v1/tenant/settings", json={"retention": bad}, headers=admin)
        assert response.status_code == 422, (bad, response.text)
        assert response.json()["error"]["code"] == "invalid_settings"
    assert (await api.repos.tenants.get(TENANT_B)).settings["retention"] == {"alerts_days": 30, "indicators_days": 14}

    dropped = await api.client.patch("/api/v1/tenant/settings", json={"retention": {"alerts_days": None}}, headers=admin)
    assert dropped.json()["settings"]["retention"] == {"indicators_days": 14}
    cleared = await api.client.patch("/api/v1/tenant/settings", json={"retention": None}, headers=admin)
    assert "retention" not in cleared.json()["settings"]
    audited = (await api.repos.audit.list(TENANT_B, action="tenant.settings_updated")).items
    assert audited[0].details["keys"] == ["retention"]


async def test_retention_bounds_are_install_settings(make_api: Any) -> None:
    api: ApiHarness = await make_api(retention={"tenant_min_days": 1, "tenant_max_days": 10})
    admin = await api.login_headers(TENANT_B, "admin")
    ok = await api.client.patch("/api/v1/tenant/settings", json={"retention": {"alerts_days": 1}}, headers=admin)
    assert ok.status_code == 200
    over = await api.client.patch("/api/v1/tenant/settings", json={"retention": {"indicators_days": 11}}, headers=admin)
    assert over.status_code == 422
    assert "from 1 to 10" in over.json()["error"]["details"][0]
