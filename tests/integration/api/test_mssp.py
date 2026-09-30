"""MSSP console: tenant listing, lifecycle, quotas, usage, templates and the cross-tenant escalation queue."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer
from lg_sotf.db.repos import LLMUsageDelta
from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

WEBHOOK_SOURCE = {"type": "webhook", "name": "hook", "config": {"format": "generic", "field_map": {"title": "t"}}}


def _events(n: int, prefix: str = "e") -> List[Dict[str, Any]]:
    return [{"source_alert_id": f"{prefix}-{i}", "title": f"alert {i}", "severity": "high"} for i in range(n)]


async def _platform(api: ApiHarness) -> Dict[str, str]:
    return await api.login_headers(TENANT_A, "admin", email="platform@a.example.com", platform_admin=True)


def _by_id(rows: List[Dict[str, Any]], tenant_id: str) -> Dict[str, Any]:
    return next(r for r in rows if r["id"] == tenant_id)


async def _stream_entries(api: ApiHarness) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    streams = api.ctx.queue.streams
    for stream in streams.work:
        for _, fields in await api.ctx.redis.xrange(stream):
            entries.append({k.decode(): v.decode() for k, v in fields.items()})
    return entries


# ------------------------------------------------------------------ listing


async def test_tenant_listing_reports_activity_quotas_and_is_audited(api: ApiHarness) -> None:
    headers = await _platform(api)
    await api.user(TENANT_B, "admin")
    key_b = await api.key_headers(TENANT_B, ["ingest"])
    ingested = await api.client.post("/api/v1/ingest/alerts", json=_events(3), headers=key_b)
    assert ingested.status_code == 202 and ingested.json()["inserted"] == 3
    old = await make_alert(api.repos, TENANT_B, ingested_at=datetime.now(UTC) - timedelta(days=2))
    recent = (await api.repos.alerts.list(TENANT_B, limit=1)).items[0].id
    now = datetime.now(UTC)
    await api.repos.escalations.create_or_attach(TENANT_B, old, reason="r", sla_deadline=now - timedelta(minutes=5))
    await api.repos.escalations.create_or_attach(TENANT_B, recent, reason="r", sla_deadline=now + timedelta(hours=1))
    await api.repos.audit.append(TENANT_B, "system", "scheduler", "escalation.sla_escalated", "escalation", "e1")
    await api.repos.llm_usage.upsert_daily(
        [
            LLMUsageDelta(
                tenant_id=TENANT_B, day=now.date(), model="m", agent="a", calls=2, input_tokens=100,
                output_tokens=50, cost_usd=Decimal("0.25"),
            )
        ]
    )
    await api.repos.sources.create(TENANT_B, "webhook", "hook", config={"format": "generic"})
    await api.repos.tenants.update_admin(TENANT_B, max_alerts_per_day=100, max_users=5)

    response = await api.client.get("/api/v1/platform/tenants", headers=headers)

    assert response.status_code == 200, response.text
    rows = response.json()
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows) and {TENANT_A, TENANT_B} <= {r["id"] for r in rows}
    b = _by_id(rows, TENANT_B)
    assert b["status"] == "active" and b["name"] == "Tenant B"
    stats = b["stats"]
    assert (stats["alerts_24h"], stats["alerts_today"]) == (3, 3)
    assert stats["last_ingest_at"] is not None
    assert (stats["open_escalations"], stats["overdue_escalations"], stats["sla_breaches_24h"]) == (2, 1, 1)
    assert Decimal(str(stats["llm_cost_mtd_usd"])) == Decimal("0.25") and stats["llm_tokens_mtd"] == 150
    assert (stats["users"], stats["sources"]) == (1, 1)
    assert b["quotas"] == {"max_alerts_per_day": 100, "max_sources": None, "max_users": 5}
    assert b["quota_usage"]["max_alerts_per_day"] == {"used": 3, "limit": 100}
    assert b["quota_usage"]["max_sources"] == {"used": 1, "limit": None}
    a = _by_id(rows, TENANT_A)
    assert a["stats"]["alerts_24h"] == 0 and a["stats"]["users"] == 1

    suspended_only = await api.client.get("/api/v1/platform/tenants", params={"status": "suspended"}, headers=headers)
    assert suspended_only.status_code == 200 and suspended_only.json() == []
    audited = (await api.repos.audit.list(TENANT_A, action="platform.tenants_listed")).items
    assert len(audited) == 2 and audited[-1].details["count"] >= 2
    assert (await api.repos.audit.list(TENANT_B, action="platform.tenants_listed")).items == []


# --------------------------------------------------------------- suspension


async def test_suspension_blocks_ingest_keys_and_logins_and_reactivation_requeues(api: ApiHarness) -> None:
    headers = await _platform(api)
    await api.user(TENANT_B, "admin", email="root@b.example.com")
    key_b = await api.key_headers(TENANT_B, ["ingest", "read"])
    queued_alert = await make_alert(api.repos, TENANT_B, severity="critical")
    await api.repos.runs.queue_alerts(TENANT_B, [queued_alert])

    suspended = await api.client.patch(f"/api/v1/platform/tenants/{TENANT_B}", json={"status": "suspended"}, headers=headers)
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["status"] == "suspended"

    ingest = await api.client.post("/api/v1/ingest/alerts", json=_events(1), headers=key_b)
    assert ingest.status_code == 403 and ingest.json()["error"]["code"] == "tenant_suspended"
    read = await api.client.get("/api/v1/alerts", headers=key_b)
    assert read.status_code == 403 and read.json()["error"]["code"] == "tenant_suspended"
    login = await api.client.post(
        "/api/v1/auth/login", json={"email": "root@b.example.com", "password": PASSWORD, "tenant": TENANT_B}
    )
    assert login.status_code == 403 and login.json()["error"]["code"] == "tenant_suspended"
    assert [e.action for e in (await api.repos.audit.list(TENANT_B, action="tenant.suspended")).items] == [
        "tenant.suspended"
    ]
    home = (await api.repos.audit.list(TENANT_A, action="platform.tenant_updated")).items
    assert home[0].details["tenant_action"] == "tenant.suspended"
    assert home[0].details["changes"] == {"status": {"from": "active", "to": "suspended"}}

    own = await api.client.patch(f"/api/v1/platform/tenants/{TENANT_A}", json={"status": "suspended"}, headers=headers)
    assert own.status_code == 409

    await api.ctx.redis.flushdb()
    reactivated = await api.client.patch(
        f"/api/v1/platform/tenants/{TENANT_B}", json={"status": "active", "name": " Beta Corp "}, headers=headers
    )
    assert reactivated.status_code == 200, reactivated.text
    assert (reactivated.json()["status"], reactivated.json()["name"]) == ("active", "Beta Corp")
    entries = await _stream_entries(api)
    assert any(e.get("alert_id") == queued_alert and e.get("tenant_id") == TENANT_B for e in entries), entries
    assert (await api.client.post("/api/v1/ingest/alerts", json=_events(1), headers=key_b)).status_code == 202
    assert (await api.repos.audit.list(TENANT_B, action="tenant.reactivated")).items


async def test_update_validation(api: ApiHarness) -> None:
    headers = await _platform(api)
    for body in (
        {"status": "deleted"},
        {"status": None},
        {"name": ""},
        {"name": "   "},
        {"quotas": {"max_users": -1}},
        {"quotas": {"max_sources": "many"}},
        {"quotas": {"max_widgets": 3}},
        {"settings": {}},
    ):
        response = await api.client.patch(f"/api/v1/platform/tenants/{TENANT_B}", json=body, headers=headers)
        assert response.status_code == 422, (body, response.text)
    missing = await api.client.patch("/api/v1/platform/tenants/no-such-tenant", json={"name": "x"}, headers=headers)
    assert missing.status_code == 404


# ------------------------------------------------------------------- quotas


async def test_quotas_limit_ingest_sources_and_users(api: ApiHarness) -> None:
    headers = await _platform(api)
    admin_b = await api.login_headers(TENANT_B, "admin")
    key_b = await api.key_headers(TENANT_B, ["ingest"])
    set_quotas = await api.client.patch(
        f"/api/v1/platform/tenants/{TENANT_B}",
        json={"quotas": {"max_alerts_per_day": 2, "max_sources": 1, "max_users": 2}},
        headers=headers,
    )
    assert set_quotas.status_code == 200, set_quotas.text
    assert set_quotas.json()["quotas"] == {"max_alerts_per_day": 2, "max_sources": 1, "max_users": 2}

    first = await api.client.post("/api/v1/ingest/alerts", json=_events(2), headers=key_b)
    assert first.status_code == 202 and first.json()["inserted"] == 2
    for batch in (_events(3, "x"), _events(1, "y")):
        refused = await api.client.post("/api/v1/ingest/alerts", json=batch, headers=key_b)
        assert refused.status_code == 429, refused.text
        assert refused.json()["error"]["code"] == "quota_exceeded"
        assert 0 < int(refused.headers["Retry-After"]) <= 86_400
    audited = (await api.repos.audit.list(TENANT_B, action="tenant.quota_exceeded")).items
    assert len(audited) == 1 and audited[0].details == {"quota": "max_alerts_per_day", "limit": 2, "used": 2}
    usage = await api.repos.usage.get_day(TENANT_B)
    assert usage is not None and (usage.alerts_ingested, usage.alerts_rejected_quota) == (2, 4)
    assert len((await api.repos.alerts.list(TENANT_B)).items) == 2

    assert (await api.client.post("/api/v1/sources", json=WEBHOOK_SOURCE, headers=admin_b)).status_code == 201
    over = await api.client.post("/api/v1/sources", json={**WEBHOOK_SOURCE, "name": "hook-2"}, headers=admin_b)
    assert over.status_code == 409 and over.json()["error"]["code"] == "quota_exceeded"

    second = await api.client.post("/api/v1/users", json={"email": "u2@b.example.com", "role": "analyst"}, headers=admin_b)
    assert second.status_code == 201, second.text
    third = await api.client.post("/api/v1/users", json={"email": "u3@b.example.com", "role": "viewer"}, headers=admin_b)
    assert third.status_code == 409 and third.json()["error"]["code"] == "quota_exceeded"
    dormant = await api.client.post(
        "/api/v1/users", json={"email": "u4@b.example.com", "role": "viewer", "is_active": False}, headers=admin_b
    )
    assert dormant.status_code == 201
    wake = await api.client.patch(f"/api/v1/users/{dormant.json()['id']}", json={"is_active": True}, headers=admin_b)
    assert wake.status_code == 409 and wake.json()["error"]["code"] == "quota_exceeded"

    lifted = await api.client.patch(
        f"/api/v1/platform/tenants/{TENANT_B}", json={"quotas": {"max_sources": None}}, headers=headers
    )
    assert lifted.json()["quotas"] == {"max_alerts_per_day": 2, "max_sources": None, "max_users": 2}
    assert (await api.client.post("/api/v1/sources", json={**WEBHOOK_SOURCE, "name": "hook-2"}, headers=admin_b)).status_code == 201


async def test_tenant_admins_cannot_set_quotas(api: ApiHarness) -> None:
    admin_b = await api.login_headers(TENANT_B, "admin")
    denied = await api.client.patch(
        f"/api/v1/platform/tenants/{TENANT_B}", json={"quotas": {"max_users": 1000}}, headers=admin_b
    )
    assert denied.status_code == 403
    for body in ({"quotas": {"max_users": 1000}}, {"max_users": 1000}, {"onboarding": {}}):
        refused = await api.client.patch("/api/v1/tenant/settings", json=body, headers=admin_b)
        assert refused.status_code == 422, (body, refused.text)
    tenant = await api.repos.tenants.get(TENANT_B)
    assert tenant.max_users is None and "quotas" not in tenant.settings


# -------------------------------------------------------------------- usage


async def test_usage_report_json_and_csv(api: ApiHarness) -> None:
    headers = await _platform(api)
    await api.user(TENANT_B, "analyst", email="analyst@b.example.com")
    key_b = await api.key_headers(TENANT_B, ["ingest"])
    key_a = await api.key_headers(TENANT_A, ["ingest"])
    assert (await api.client.post("/api/v1/ingest/alerts", json=_events(3), headers=key_b)).status_code == 202
    assert (await api.client.post("/api/v1/ingest/alerts", json=_events(1), headers=key_a)).status_code == 202
    b_alert = (await api.repos.alerts.list(TENANT_B, limit=1)).items[0].id
    assert await api.repos.usage.add_processed(TENANT_B, b_alert)
    now = datetime.now(UTC)
    await api.repos.llm_usage.upsert_daily(
        [
            LLMUsageDelta(
                tenant_id=TENANT_B, day=now.date(), model="m", agent="triage", calls=4, input_tokens=1_000,
                output_tokens=200, cost_usd=Decimal("1.5"),
            )
        ]
    )
    login = await api.client.post(
        "/api/v1/auth/login", json={"email": "analyst@b.example.com", "password": PASSWORD, "tenant": TENANT_B}
    )
    assert login.status_code == 200
    admin_b = await api.login_headers(TENANT_B, "admin")
    samples = await api.client.post("/api/v1/onboarding/sample-alerts", headers=admin_b)
    assert samples.status_code == 200 and samples.json()["inserted"] == 5
    await api.repos.tenants.provision("formula", "=HYPERLINK(\"http://x.example\")")
    month = now.strftime("%Y-%m")

    report = await api.client.get("/api/v1/platform/usage", params={"month": month}, headers=headers)

    assert report.status_code == 200, report.text
    body = report.json()
    assert body["month"] == month and body["start"] == f"{month}-01"
    b = next(r for r in body["tenants"] if r["tenant_id"] == TENANT_B)
    assert (b["alerts_ingested"], b["alerts_processed"], b["alerts_rejected_quota"]) == (3, 1, 0)
    assert (b["llm_calls"], b["llm_input_tokens"], b["llm_output_tokens"]) == (4, 1_000, 200)
    assert Decimal(str(b["llm_cost_usd"])) == Decimal("1.5")
    # The analyst signed in and the admin sent the samples; the sample alerts are not metered.
    assert (b["active_users"], b["users"], b["sources"]) == (2, 2, 0)
    a = next(r for r in body["tenants"] if r["tenant_id"] == TENANT_A)
    assert a["alerts_ingested"] == 1
    assert body["totals"]["alerts_ingested"] == 4

    previous = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    empty = (await api.client.get("/api/v1/platform/usage", params={"month": previous}, headers=headers)).json()
    assert all(r["alerts_ingested"] == 0 and r["active_users"] == 0 for r in empty["tenants"])

    exported = await api.client.get("/api/v1/platform/usage", params={"month": month, "format": "csv"}, headers=headers)
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    assert f"lg-sotf-usage-{month}.csv" in exported.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert next(r for r in rows if r["tenant_id"] == TENANT_B)["alerts_ingested"] == "3"
    assert next(r for r in rows if r["tenant_id"] == "formula")["tenant_name"].startswith("'=")

    for bad in ("2026-13", "2026-1", "last", "2026-00"):
        assert (await api.client.get("/api/v1/platform/usage", params={"month": bad}, headers=headers)).status_code == 422
    assert (await api.repos.audit.list(TENANT_A, action="platform.usage_exported")).items


# ---------------------------------------------------------------- templates


async def test_profiles_seed_settings(api: ApiHarness) -> None:
    headers = await _platform(api)
    created = await api.client.post(
        "/api/v1/platform/tenants", json={"id": "acme", "name": "Acme", "profile": "balanced"}, headers=headers
    )
    assert created.status_code == 201, created.text
    assert created.json()["settings_keys"] == ["autonomy", "response", "review"]
    settings = (await api.repos.tenants.get("acme")).settings
    assert settings["autonomy"] == {"low": "auto", "medium": "approval", "high": "approval", "critical": "disabled"}
    assert settings["response"]["dry_run"] is True
    assert (await api.repos.audit.list("acme", action="tenant.created")).items[0].details["profile"] == "balanced"

    conservative = await api.client.post(
        "/api/v1/platform/tenants", json={"id": "safe-co", "name": "Safe", "profile": "conservative"}, headers=headers
    )
    assert conservative.status_code == 201
    assert (await api.repos.tenants.get("safe-co")).settings["autonomy"]["high"] == "disabled"

    for body in (
        {"id": "nope", "name": "N", "profile": "yolo"},
        {"id": "nope", "name": "N", "profile": "balanced", "copy_settings_from": TENANT_B},
        {"id": "nope", "name": "N", "copy_settings_from": "no-such-tenant"},
        {"id": "nope", "name": "N", "copy_settings_from": "Bad Id"},
    ):
        response = await api.client.post("/api/v1/platform/tenants", json=body, headers=headers)
        assert response.status_code == 422, (body, response.text)
    assert not [t for t in await api.repos.tenants.list_all_tenants() if t.id == "nope"]


async def test_copy_settings_copies_policy_but_never_secrets_or_destinations(api: ApiHarness) -> None:
    headers = await _platform(api)
    admin_b = await api.login_headers(TENANT_B, "admin")
    configured = await api.client.patch(
        "/api/v1/tenant/settings",
        json={
            "autonomy": {"low": "auto"},
            "review": {"sla_minutes": {"L1": 20}},
            "llm_daily_token_budget": 5_000_000,
            "retention": {"alerts_days": 120},
            "protected_assets": {"hosts": ["dc01.customer-b.example"]},
            "response": {
                "connector": "webhook",
                "webhook_url": "https://soar.customer-b.example/hook",
                "webhook_secret": "test-" + "s" * 24,
                "dry_run": False,
                "max_actions_per_hour": 7,
            },
            "tools": {"virustotal": {"enabled": True, "api_key": "test-" + "k" * 24}, "internal_domains": ["b.example"]},
        },
        headers=admin_b,
    )
    assert configured.status_code == 200, configured.text

    created = await api.client.post(
        "/api/v1/platform/tenants",
        json={"id": "clone", "name": "Clone", "copy_settings_from": TENANT_B},
        headers=headers,
    )

    assert created.status_code == 201, created.text
    copied = (await api.repos.tenants.get("clone")).settings
    assert copied["autonomy"] == {"low": "auto"}
    assert copied["review"] == {"sla_minutes": {"L1": 20}}
    assert copied["llm_daily_token_budget"] == 5_000_000 and copied["retention"] == {"alerts_days": 120}
    assert copied["response"] == {"dry_run": False, "max_actions_per_hour": 7}
    assert copied["tools"] == {"virustotal": {"enabled": True}}
    assert "protected_assets" not in copied
    text = json.dumps(copied)
    for leaked in ("ciphertext", "customer-b", "test-s", "test-k", "b.example"):
        assert leaked not in text
    copied_audit = (await api.repos.audit.list(TENANT_B, action="platform.settings_copied")).items
    assert copied_audit and copied_audit[0].details["to_tenant"] == "clone"


# -------------------------------------------------------------- escalations


async def test_cross_tenant_escalation_queue_is_sorted_by_sla_and_paginated(api: ApiHarness) -> None:
    headers = await _platform(api)
    now = datetime.now(UTC)
    created = {}
    for tenant_id, label, deadline in (
        (TENANT_B, "late", now - timedelta(minutes=10)),
        (TENANT_A, "soon", now + timedelta(minutes=5)),
        (TENANT_B, "later", now + timedelta(hours=2)),
        (TENANT_A, "none", None),
    ):
        alert_id = await make_alert(api.repos, tenant_id, title=f"{label} alert")
        esc, _ = await api.repos.escalations.create_or_attach(tenant_id, alert_id, reason=label, sla_deadline=deadline)
        created[label] = esc
    done_alert = await make_alert(api.repos, TENANT_B)
    done, _ = await api.repos.escalations.create_or_attach(TENANT_B, done_alert, reason="done")
    await api.repos.escalations.cancel(TENANT_B, done.id, expected_version=done.version)

    first = await api.client.get("/api/v1/platform/escalations", params={"limit": 2}, headers=headers)
    assert first.status_code == 200, first.text
    page = first.json()
    assert [e["reason"] for e in page["items"]] == ["late", "soon"]
    late = page["items"][0]
    assert (late["tenant_id"], late["tenant_name"], late["alert_title"], late["overdue"]) == (
        TENANT_B, "Tenant B", "late alert", True
    )
    assert page["items"][1]["overdue"] is False and page["next_cursor"]
    second = await api.client.get(
        "/api/v1/platform/escalations", params={"limit": 2, "cursor": page["next_cursor"]}, headers=headers
    )
    assert [e["reason"] for e in second.json()["items"]] == ["later", "none"]
    assert second.json()["next_cursor"] is None

    only_b = await api.client.get("/api/v1/platform/escalations", params={"tenant_id": TENANT_B}, headers=headers)
    assert [e["reason"] for e in only_b.json()["items"]] == ["late", "later"]
    bad = await api.client.get("/api/v1/platform/escalations", params={"cursor": "garbage"}, headers=headers)
    assert bad.status_code == 400
    assert (await api.repos.audit.list(TENANT_A, action="platform.escalations_listed")).items


# ------------------------------------------------------------ authorization


async def test_platform_endpoints_need_a_platform_admin(api: ApiHarness) -> None:
    requests = (
        ("GET", "/api/v1/platform/tenants", None),
        ("PATCH", f"/api/v1/platform/tenants/{TENANT_B}", {"status": "suspended"}),
        ("GET", "/api/v1/platform/escalations", None),
        ("GET", "/api/v1/platform/usage", None),
        ("POST", "/api/v1/platform/tenants", {"id": "nope", "name": "N", "profile": "balanced"}),
    )
    for headers in (
        await api.login_headers(TENANT_A, "admin"),
        await api.login_headers(TENANT_B, "admin"),
        await api.login_headers(TENANT_A, "analyst", platform_admin=True),
        await api.key_headers(TENANT_A, ["read", "write", "ingest"]),
    ):
        for method, path, body in requests:
            response = await api.client.request(method, path, json=body, headers=headers)
            assert response.status_code == 403, (method, path, response.text)
    for method, path, body in requests:
        assert (await api.client.request(method, path, json=body)).status_code == 401
    assert (await api.repos.tenants.get(TENANT_B)).status == "active"


async def test_console_works_as_the_runtime_role(make_api: Callable, migrated_database_url: str) -> None:
    """The runtime role cannot bypass RLS: the console must go through the lgsotf_platform_* functions."""
    await setup_checkpointer(migrated_database_url)
    await asyncio.to_thread(grant_runtime_privileges, "pg_database_owner", migrated_database_url)
    separator = "&" if "?" in migrated_database_url else "?"
    api: ApiHarness = await make_api(database={"url": f"{migrated_database_url}{separator}role=pg_database_owner"})
    headers = await _platform(api)
    await make_alert(api.repos, TENANT_B)
    key_b = await api.key_headers(TENANT_B, ["ingest"])
    assert (await api.client.post("/api/v1/ingest/alerts", json=_events(1), headers=key_b)).status_code == 202

    listed = await api.client.get("/api/v1/platform/tenants", headers=headers)
    assert listed.status_code == 200, listed.text
    assert _by_id(listed.json(), TENANT_B)["stats"]["alerts_today"] == 1
    patched = await api.client.patch(
        f"/api/v1/platform/tenants/{TENANT_B}", json={"quotas": {"max_users": 3}, "status": "suspended"}, headers=headers
    )
    assert patched.status_code == 200, patched.text
    assert (await api.client.get("/api/v1/platform/escalations", headers=headers)).status_code == 200
    assert (await api.client.get("/api/v1/platform/usage", headers=headers)).status_code == 200
    created = await api.client.post(
        "/api/v1/platform/tenants", json={"id": "rt-clone", "name": "C", "copy_settings_from": TENANT_A}, headers=headers
    )
    assert created.status_code == 201, created.text
