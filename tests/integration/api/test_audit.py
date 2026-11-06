"""``GET /audit`` and ``GET /audit/verify``: admin-only, tenant-scoped, filtered and paginated."""

from __future__ import annotations

import pytest

from lg_sotf.audit.logger import AuditLogger
from tests.integration.api.conftest import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration


async def _record(api: ApiHarness, tenant_id: str, action: str, resource_id: str) -> None:
    await AuditLogger(api.repos).record_event(
        tenant_id, action, "source", resource_id, actor_type="user", actor_id="u-1", details={"n": resource_id}
    )


async def test_admin_lists_own_tenant_newest_first_with_filters_and_cursor(api: ApiHarness) -> None:
    for n in range(5):
        await _record(api, TENANT_A, "source.updated", f"s-{n}")
    await _record(api, TENANT_A, "source.deleted", "s-x")
    await _record(api, TENANT_B, "source.updated", "b-secret-resource")
    headers = await api.login_headers(TENANT_A, "admin")

    first = await api.client.get("/api/v1/audit", params={"action": "source.updated", "limit": 3}, headers=headers)
    assert first.status_code == 200, first.text
    page = first.json()
    assert [e["resource_id"] for e in page["items"]] == ["s-4", "s-3", "s-2"]
    assert all(e["tenant_id"] == TENANT_A and e["hash"] for e in page["items"])
    assert page["items"][0]["prev_hash"] == page["items"][1]["hash"]
    rest = await api.client.get(
        "/api/v1/audit", params={"action": "source.updated", "limit": 3, "cursor": page["next_cursor"]}, headers=headers
    )
    assert [e["resource_id"] for e in rest.json()["items"]] == ["s-1", "s-0"]
    assert rest.json()["next_cursor"] is None

    everything = (await api.client.get("/api/v1/audit", params={"limit": 200}, headers=headers)).json()["items"]
    assert "b-secret-resource" not in {e["resource_id"] for e in everything}
    by_resource = await api.client.get("/api/v1/audit", params={"resource_id": "s-x"}, headers=headers)
    assert [e["action"] for e in by_resource.json()["items"]] == ["source.deleted"]


async def test_verify_reports_an_intact_chain(api: ApiHarness) -> None:
    for n in range(3):
        await _record(api, TENANT_A, "source.updated", f"s-{n}")
    response = await api.client.get("/api/v1/audit/verify", headers=await api.login_headers(TENANT_A, "admin"))
    assert response.status_code == 200
    assert response.json() == {"ok": True, "first_bad_id": None, "since": None}


async def test_only_admin_users_may_read_the_audit_log(api: ApiHarness) -> None:
    for role in ("viewer", "analyst"):
        headers = await api.login_headers(TENANT_A, role)
        assert (await api.client.get("/api/v1/audit", headers=headers)).status_code == 403
        assert (await api.client.get("/api/v1/audit/verify", headers=headers)).status_code == 403
    for scopes in (["read"], ["read", "write", "ingest"]):
        key = await api.key_headers(TENANT_A, scopes)
        assert (await api.client.get("/api/v1/audit", headers=key)).status_code == 403
    assert (await api.client.get("/api/v1/audit")).status_code == 401


async def test_bad_window_and_cursor_are_client_errors(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_A, "admin")
    window = await api.client.get(
        "/api/v1/audit", params={"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z"}, headers=headers
    )
    assert window.status_code == 400 and window.json()["error"]["code"] == "invalid_window"
    cursor = await api.client.get("/api/v1/audit", params={"cursor": "not-a-cursor"}, headers=headers)
    assert cursor.status_code == 400
