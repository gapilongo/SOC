"""``POST /api/v1/tenant/llm/test``: probe both model tiers, admin only, metered, audited, rate limited."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lg_sotf.llm.usage import get_usage_recorder
from lg_sotf.services.llm_check import AGENT
from tests.integration.api.conftest import TENANT_A, TENANT_B, ApiHarness, fresh_rate_window

pytestmark = pytest.mark.integration

URL = "/api/v1/tenant/llm/test"


async def test_admin_tests_the_fake_model(api: ApiHarness) -> None:
    get_usage_recorder().reset()
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.post(URL, headers=analyst)).status_code == 403
    assert (await api.client.post(URL)).status_code == 401

    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.post(URL, headers=admin)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "fake" and body["enabled"] is True and body["ok"] is True
    assert [t["tier"] for t in body["tiers"]] == ["fast", "deep"]
    for tier in body["tiers"]:
        assert tier["ok"] is True and tier["error"] is None and tier["error_code"] is None
        assert tier["model"] == f"fake-{tier['tier']}" and tier["latency_ms"] >= 0
        assert tier["structured_output"] == "json_schema"

    # Metered to the calling tenant only, and written to the usage table at once.
    today = datetime.now(UTC).date()
    rows = await api.repos.llm_usage.list_range(TENANT_A, today, today)
    probe = [r for r in rows if r.agent == AGENT]
    assert {r.model for r in probe} == {"fake-fast", "fake-deep"} and all(r.calls == 1 for r in probe)
    assert not [r for r in await api.repos.llm_usage.list_range(TENANT_B, today, today) if r.agent == AGENT]

    audit = (await api.repos.audit.list(TENANT_A, action="tenant.llm_tested")).items
    assert len(audit) == 1
    assert audit[0].details["ok"] is True and audit[0].details["provider"] == "fake"
    assert set(audit[0].details["tiers"]) == {"fast", "deep"}


async def test_misconfigured_model_is_reported_not_500(make_api) -> None:  # type: ignore[no-untyped-def]
    api: ApiHarness = await make_api(
        llm={"provider": "openai_compatible", "base_url": "http://llm.example.com/v1", "allow_fake": False}
    )
    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.post(URL, headers=admin)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is False and body["provider"] == "openai_compatible"
    assert {t["error_code"] for t in body["tiers"]} == {"unavailable"}
    assert all("llm.example.com" not in t["error"] for t in body["tiers"])


async def test_the_probe_is_rate_limited_per_tenant(api: ApiHarness) -> None:
    await fresh_rate_window()
    admin = await api.login_headers(TENANT_A, "admin")
    statuses = [(await api.client.post(URL, headers=admin)).status_code for _ in range(7)]
    assert statuses[:6] == [200] * 6 and statuses[6] == 429
    other = await api.login_headers(TENANT_B, "admin")
    assert (await api.client.post(URL, headers=other)).status_code == 200
