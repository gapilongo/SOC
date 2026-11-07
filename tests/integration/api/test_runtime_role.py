"""The API works under the least-privilege runtime role (no table ownership, no RLS bypass).

As in ``tests/integration/db/test_runtime_role.py``, sessions started with
``role=pg_database_owner`` act as a role that owns no tables and is not a
member of the schema owner: exactly the production runtime role.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Callable

import pytest

from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer
from lg_sotf.settings import DatabaseSettings
from tests.integration.api._support import PASSWORD, TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

RUNTIME_ROLE = "pg_database_owner"


async def test_api_end_to_end_as_runtime_role(make_api: Callable, migrated_database_url: str) -> None:
    await setup_checkpointer(migrated_database_url, DatabaseSettings())
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url, DatabaseSettings())
    separator = "&" if "?" in migrated_database_url else "?"
    api: ApiHarness = await make_api(database={"url": f"{migrated_database_url}{separator}role={RUNTIME_ROLE}"})
    async with api.ctx.db.connection() as conn:
        assert await conn.fetchval("SELECT current_user") == RUNTIME_ROLE

    admin = await api.user(TENANT_A, "admin", email="root@a.example.com")
    login = await api.client.post("/api/v1/auth/login", json={"email": "root@a.example.com", "password": PASSWORD})
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await api.client.post("/api/v1/auth/refresh")).status_code == 200

    key = await api.client.post("/api/v1/api-keys", json={"name": "k", "scopes": ["ingest"]}, headers=headers)
    assert key.status_code == 201
    ingest = await api.client.post(
        "/api/v1/ingest/alerts", json=[{"title": "t", "severity": "high"}], headers={"X-API-Key": key.json()["key"]}
    )
    assert ingest.status_code == 202 and ingest.json()["enqueued"] == 1

    alert_id = await make_alert(api.repos, TENANT_A)
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, alert_id, reason="r", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    decided = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "false_positive", "version": escalation.version},
        headers=headers,
    )
    assert decided.status_code == 200, decided.text

    for method, path, body in (
        ("GET", "/api/v1/alerts", None),
        ("GET", "/api/v1/dashboard/summary", None),
        ("PATCH", "/api/v1/tenant/settings", {"autonomy": {"low": "auto"}}),
        ("POST", "/api/v1/suppressions", {"name": "r", "match": {"fingerprint": "x"}}),
        ("POST", "/api/v1/users", {"email": "v@a.example.com", "role": "viewer"}),
        (
            "POST",
            "/api/v1/sources",
            {"type": "webhook", "name": "h", "config": {"format": "generic", "field_map": {"title": "t"}}},
        ),
        ("POST", f"/api/v1/alerts/{alert_id}/notes", {"text": "n"}),
        ("GET", "/api/v1/usage/llm", None),
        ("GET", "/api/v1/reports/value", None),
        ("GET", "/api/v1/reports/accuracy", None),
        ("GET", "/api/v1/reports/detections", None),
        ("GET", "/api/v1/reports/monthly", None),
    ):
        response = await api.client.request(method, path, json=body, headers=headers)
        assert response.status_code < 300, f"{method} {path}: {response.text}"
    assert admin.id is not None


async def test_platform_admin_provisions_a_tenant_as_runtime_role(make_api: Callable, migrated_database_url: str) -> None:
    """The runtime role has no INSERT on tenants: provisioning goes through lgsotf_create_tenant only."""
    await setup_checkpointer(migrated_database_url, DatabaseSettings())
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url, DatabaseSettings())
    separator = "&" if "?" in migrated_database_url else "?"
    api: ApiHarness = await make_api(database={"url": f"{migrated_database_url}{separator}role={RUNTIME_ROLE}"})
    async with api.ctx.db.connection() as conn:
        assert await conn.fetchval("SELECT has_table_privilege('tenants', 'INSERT')") is False
        assert await conn.fetchval("SELECT has_function_privilege('lgsotf_create_tenant(text, text)', 'EXECUTE')")

    headers = await api.login_headers(TENANT_A, "admin", platform_admin=True)
    created = await api.client.post(
        "/api/v1/platform/tenants",
        json={"id": "runtime-new", "name": "Runtime New", "admin_email": "boss@runtime.example", "admin_password": PASSWORD},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["admin"]["tenant_id"] == "runtime-new"
    again = await api.client.post("/api/v1/platform/tenants", json={"id": "runtime-new", "name": "x"}, headers=headers)
    assert again.status_code == 409
