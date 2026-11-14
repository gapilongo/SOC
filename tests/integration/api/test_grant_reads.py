"""ARCH-E4.1b: reading a customer tenant under a grant, generated over every GET route.

An MSSP analyst (a member of the organisation, an account of its home tenant)
sends ``X-Tenant-ID`` with the customer's id. Without a live grant every GET
route answers 403; with one, every tenant route answers with the customer's
data, under the grant's role. The routes that must never serve a grant
holder (platform, own MFA, grant administration) answer 403 either way.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterator, List, Set, Tuple

import pytest

from lg_sotf.db.repos import User
from lg_sotf.domain.pov import plan_windows
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

ORG = "mssp-org"
API = "/api/v1"
# Never available to someone acting under a grant (403 with or without one).
REFUSED_UNDER_GRANT = re.compile(rf"^{API}/(platform/|onboarding/setup$|auth/mfa$|tenant/grants$|organisation/)")
# Query parameters a route requires, filled like path parameters.
QUERY: Dict[str, Dict[str, str]] = {f"{API}/tickets": {"alert_id": "{alert_id}"}}


def get_routes(api: ApiHarness) -> List[str]:
    """Every GET path of the API contract (health and metrics, outside ``/api/v1``, have no tenant)."""
    paths = api.app.openapi()["paths"]
    return sorted(path for path, operations in paths.items() if "get" in operations and path.startswith(API))


async def _seed_customer(api: ApiHarness) -> Dict[str, str]:
    """One row of every kind a GET route addresses by id, in the customer tenant."""
    alert_id = await make_alert(api.repos, TENANT_B, title="B only")
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_B, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    action, _ = await api.repos.actions.propose(TENANT_B, alert_id, "block_ip", "203.0.113.9", "low")
    source = await api.repos.sources.create(TENANT_B, "webhook", "Hook B", config={"format": "generic"})
    rule = await api.repos.suppressions.create(TENANT_B, "noisy", {"title": "x"})
    integration = await api.repos.integrations.create(TENANT_B, "email", "Mail", config={"recipients": ["a@b.co"]})
    user = await api.user(TENANT_B, "admin")
    now = datetime.now(UTC)
    sampled = await make_alert(api.repos, TENANT_B, title="B sampled")  # its escalations and actions stay hidden
    await api.repos.blind_audit.create_run(
        TENANT_B, since=now - timedelta(days=7), until=now, seed=1, sample_rate=0.02, min_sample=0, fixed_size=None,
        frame_size=1, items=[(sampled, 1, "benign")], trigger="cli", created_by="seed",
    )
    item = (await api.repos.blind_audit.list_items(TENANT_B)).items[0]
    pov = await api.repos.pov_runs.create(
        TENANT_B, "B's proof of value", plan_windows(now, backtest_days=30, shadow_days=14), created_by="seed"
    )
    return {
        "alert_id": alert_id,
        "escalation_id": escalation.id,
        "action_id": str(action.id),
        "source_id": source.id,
        "rule_id": rule.id,
        "integration_id": str(integration.id),
        "user_id": str(user.id),
        "tenant_id": TENANT_B,
        "run_id": "shr_" + "0" * 32,
        "item_id": str(item.id),
        "pov_run_id": str(pov.id),
        "sampled_alert_id": sampled,
    }


async def _staff(api: ApiHarness, role: str = "admin") -> User:
    """A member of the organisation (an account of its home tenant)."""
    if await api.repos.organisations.get(ORG) is None:
        await api.repos.tenants.create(ORG, "MSSP")
        await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, role)
    await api.repos.organisations.add_member(ORG, staff.id)
    return staff


async def _grant(api: ApiHarness, role: str = "admin", tenant_id: str = TENANT_B, **kwargs: Any) -> Any:
    expires_at = kwargs.pop("expires_at", datetime.now(UTC) + timedelta(hours=4))
    return await api.repos.grants.create(
        tenant_id, ORG, role, reason="night shift", created_by="customer-admin", expires_at=expires_at, **kwargs
    )


def _tenant_ids(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "tenant_id" and isinstance(item, str):
                yield item
            else:
                yield from _tenant_ids(item)
    elif isinstance(value, list):
        for item in value:
            yield from _tenant_ids(item)


async def _get_all(api: ApiHarness, headers: Dict[str, str], ids: Dict[str, str]) -> Dict[str, Tuple[int, Any]]:
    results: Dict[str, Tuple[int, Any]] = {}
    for path in get_routes(api):
        url = path.format(**ids)
        params = {k: v.format(**ids) for k, v in QUERY.get(path, {}).items()}
        response = await api.client.get(url, params=params, headers=headers)
        is_json = response.headers.get("content-type", "").startswith("application/json")
        results[path] = (response.status_code, response.json() if is_json else None)
    return results


async def test_grant_reads(api: ApiHarness) -> None:
    ids = await _seed_customer(api)
    staff = await _staff(api)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}

    without = await _get_all(api, headers, ids)
    assert {path: status for path, (status, _) in without.items() if status != 403} == {}

    await _grant(api, "admin")
    granted = await _get_all(api, headers, ids)
    refused = {path for path in granted if REFUSED_UNDER_GRANT.match(path)}
    assert refused, "the refused set must match real routes"
    assert {path: granted[path][0] for path in refused if granted[path][0] != 403} == {}
    served = {path: result for path, result in granted.items() if path not in refused}
    assert len(served) >= 35 and f"{API}/escalations/{{escalation_id}}" in served
    assert {path: (status, body) for path, (status, body) in served.items() if status != 200} == {}
    # The data is the customer's, never the organisation's home tenant's.
    leaked: Set[str] = {t for _, body in served.values() for t in _tenant_ids(body)} - {TENANT_B}
    assert leaked == set()
    alerts = served[f"{API}/alerts"][1]["items"]
    assert sorted(a["id"] for a in alerts) == sorted([ids["alert_id"], ids["sampled_alert_id"]])
    me = served[f"{API}/auth/me"][1]
    assert (me["tenant_id"], me["home_tenant_id"], me["role"]) == (TENANT_B, ORG, "admin")
    assert me["grant_id"] is not None and me["is_platform_admin"] is False

    # Every request under the grant is in the customer's audit log (the refused ones too).
    accesses = (await api.repos.audit.list(TENANT_B, action="grant.tenant_access", limit=500)).items
    assert len(accesses) == len(granted)
    assert {e.actor_id for e in accesses} == {str(staff.id)}
    assert {e.details["organisation_id"] for e in accesses} == {ORG}


async def test_the_grant_role_applies_and_is_capped_by_the_members_own(api: ApiHarness) -> None:
    viewer_grant_staff = await _staff(api, "admin")
    analyst_staff = await _staff(api, "analyst")
    await _grant(api, "viewer", user_id=viewer_grant_staff.id)
    await _grant(api, "admin", user_id=analyst_staff.id)
    for staff, role in ((viewer_grant_staff, "viewer"), (analyst_staff, "analyst")):
        headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
        assert (await api.client.get(f"{API}/alerts", headers=headers)).status_code == 200
        assert (await api.client.get(f"{API}/users", headers=headers)).status_code == 403
        assert (await api.client.get(f"{API}/auth/me", headers=headers)).json()["role"] == role


async def test_no_live_grant_means_403(api: ApiHarness) -> None:
    staff = await _staff(api)
    outsider = await api.user(ORG, "admin")  # an account of the home tenant, not a member
    other_member = await _staff(api)
    past = datetime.now(UTC) - timedelta(days=1)
    await _grant(api, "admin", now=past, expires_at=past + timedelta(hours=1))  # expired
    revoked = await _grant(api, "admin")
    await api.repos.grants.revoke(TENANT_B, revoked.id, revoked_by="customer-admin")
    await _grant(api, "admin", tenant_id=TENANT_A)  # another customer
    await _grant(api, "admin", user_id=other_member.id)  # someone else's personal grant
    for user in (staff, outsider):
        response = await api.client.get(f"{API}/alerts", headers={**api.auth(user), "X-Tenant-ID": TENANT_B})
        assert response.status_code == 403, response.text
    # A customer user cannot use X-Tenant-ID at all, and nobody can reach the organisation's home tenant.
    customer = await api.user(TENANT_A, "admin")
    for headers in ({**api.auth(customer), "X-Tenant-ID": TENANT_B}, {**api.auth(customer), "X-Tenant-ID": ORG}):
        assert (await api.client.get(f"{API}/alerts", headers=headers)).status_code == 403
    # Revocation takes effect on the next request.
    live = await _grant(api, "viewer")
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/alerts", headers=headers)).status_code == 200
    await api.repos.grants.revoke(TENANT_B, live.id, revoked_by="customer-admin")
    assert (await api.client.get(f"{API}/alerts", headers=headers)).status_code == 403


async def test_a_suspended_customer_refuses_grant_holders(api: ApiHarness) -> None:
    staff = await _staff(api)
    await _grant(api, "admin")
    await api.repos.tenants.set_status(TENANT_B, "suspended")
    api.ctx.tenants.invalidate(TENANT_B)
    response = await api.client.get(f"{API}/alerts", headers={**api.auth(staff), "X-Tenant-ID": TENANT_B})
    assert response.status_code == 403 and response.json()["error"]["code"] == "tenant_suspended"
