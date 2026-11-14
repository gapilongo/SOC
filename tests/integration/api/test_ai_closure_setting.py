"""The model-led closure tier (FIX-1): ``ai_closure.tier`` in the tenant settings.

Only a tenant admin changes it, never under an MSSP grant; every change is
audited with the tier set; values other than ``off`` and ``auto_full_audit``
are refused; a new tenant never copies it from a template.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.domain.closure import autonomy_tier
from lg_sotf.models.tenant_settings import COPIED_KEYS
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"
ON = {"ai_closure": {"tier": "auto_full_audit"}}


async def _audited_tiers(api: ApiHarness, tenant_id: str) -> list[object]:
    entries = (await api.repos.audit.list(tenant_id, action="tenant.settings_updated")).items
    return [e.details.get("ai_closure_tier") for e in reversed(entries) if "ai_closure" in e.details.get("keys", [])]


async def test_a_tenant_admin_sets_the_tier_and_it_is_audited(api: ApiHarness) -> None:
    assert autonomy_tier((await api.repos.tenants.get(TENANT_A)).settings) == "off"
    admin = await api.login_headers(TENANT_A, "admin")
    on = await api.client.patch(f"{API}/tenant/settings", json=ON, headers=admin)
    assert on.status_code == 200, on.text
    assert on.json()["settings"]["ai_closure"] == {"tier": "auto_full_audit"}
    assert autonomy_tier((await api.repos.tenants.get(TENANT_A)).settings) == "auto_full_audit"
    off = await api.client.patch(f"{API}/tenant/settings", json={"ai_closure": None}, headers=admin)
    assert off.status_code == 200 and "ai_closure" not in off.json()["settings"]
    assert await _audited_tiers(api, TENANT_A) == ["auto_full_audit", "off"]


@pytest.mark.parametrize(
    "value", [{"tier": "auto_sampled"}, {"tier": "on"}, {"tier": "off", "max_likelihood": 50}, "auto_full_audit"]
)
async def test_other_values_are_refused(api: ApiHarness, value: object) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    bad = await api.client.patch(f"{API}/tenant/settings", json={"ai_closure": value}, headers=admin)
    assert bad.status_code == 422 and "ai_closure" in bad.text
    assert autonomy_tier((await api.repos.tenants.get(TENANT_A)).settings) == "off"


async def test_only_an_admin_outside_a_grant_changes_the_tier(api: ApiHarness) -> None:
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.patch(f"{API}/tenant/settings", json=ON, headers=analyst)).status_code == 403
    # An MSSP organisation's admin with an admin grant on the customer tenant.
    await api.repos.tenants.create(ORG, ORG)
    await api.repos.organisations.upsert(ORG, ORG)
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    await api.repos.grants.create(
        TENANT_B, ORG, "admin", reason="cover", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=8),
    )
    under_grant = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/tenant/settings", headers=under_grant)).status_code == 200
    refused = await api.client.patch(f"{API}/tenant/settings", json=ON, headers=under_grant)
    assert refused.status_code == 403
    assert autonomy_tier((await api.repos.tenants.get(TENANT_B)).settings) == "off"
    assert await _audited_tiers(api, TENANT_B) == []


def test_a_new_tenant_never_copies_the_tier() -> None:
    assert "ai_closure" not in COPIED_KEYS
