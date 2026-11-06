"""Regression tests for the adversarial review of the API (findings API-1 to API-7)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.api.routers.auth import REFRESH_COOKIE
from tests.integration.api._support import PASSWORD, TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

NEW_PASSWORD = "an entirely new passphrase 42"


async def _login(api: ApiHarness, email: str, password: str = PASSWORD):
    return await api.client.post("/api/v1/auth/login", json={"email": email, "password": password})


# ------------------------------------------------ API-1: platform-admin takeover


@pytest.mark.parametrize(
    "change",
    [{"password": NEW_PASSWORD}, {"role": "admin"}, {"is_active": False}, {"role": "viewer", "is_active": True}],
)
async def test_tenant_admin_cannot_modify_a_platform_admin(api: ApiHarness, change: dict) -> None:
    platform = await api.user(TENANT_A, "viewer", platform_admin=True)
    tenant_admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.patch(f"/api/v1/users/{platform.id}", json=change, headers=tenant_admin)
    assert response.status_code == 403, response.text
    unchanged = await api.repos.users.get(TENANT_A, platform.id)
    assert (unchanged.role, unchanged.is_active, unchanged.password_hash) == (
        platform.role,
        platform.is_active,
        platform.password_hash,
    )
    assert (await _login(api, platform.email, NEW_PASSWORD)).status_code == 401
    assert (await _login(api, platform.email)).status_code == 200


async def test_tenant_admin_cannot_delete_a_platform_admin(api: ApiHarness) -> None:
    platform = await api.user(TENANT_A, "viewer", platform_admin=True)
    tenant_admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.delete(f"/api/v1/users/{platform.id}", headers=tenant_admin)
    assert response.status_code == 403
    assert (await api.repos.users.get(TENANT_A, platform.id)).is_active is True


async def test_platform_admin_can_still_manage_platform_admins(api: ApiHarness) -> None:
    target = await api.user(TENANT_A, "viewer", platform_admin=True)
    actor = await api.login_headers(TENANT_A, "admin", platform_admin=True)
    response = await api.client.patch(f"/api/v1/users/{target.id}", json={"role": "analyst"}, headers=actor)
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "analyst"


# ------------------------------------------------ API-3: shared-address DoS


async def test_valid_credentials_pass_after_failures_from_the_same_address(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 1})
    garbage = [
        (await api.client.get("/api/v1/alerts", headers={"Authorization": f"Bearer junk-{i}"})) for i in range(25)
    ]
    assert garbage[0].status_code == 401
    assert garbage[-1].status_code == 429
    viewer = await api.login_headers(TENANT_B, "viewer")
    assert (await api.client.get("/api/v1/alerts", headers=viewer)).status_code == 200
    key = await api.key_headers(TENANT_A, ["read"])
    assert (await api.client.get("/api/v1/alerts", headers=key)).status_code == 200


async def test_a_repeatedly_failing_credential_is_refused_before_verification(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 1})
    headers = {"Authorization": "Bearer the-same-bad-token"}
    statuses = [(await api.client.get("/api/v1/alerts", headers=headers)).status_code for _ in range(22)]
    assert statuses[:20] == [401] * 20
    assert statuses[-1] == 429


async def test_login_limit_is_per_account_with_a_looser_address_cap(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 2})
    statuses = [
        (
            await api.client.post("/api/v1/auth/login", json={"email": f"u{i}@a.example.com", "password": "p"})
        ).status_code
        for i in range(20)
    ]
    assert statuses == [401] * 20
    capped = await api.client.post("/api/v1/auth/login", json={"email": "u99@a.example.com", "password": "p"})
    assert capped.status_code == 429
    assert int(capped.headers["retry-after"]) >= 1


async def test_valid_refresh_is_not_throttled_by_other_clients(make_api) -> None:
    api = await make_api(api={"login_rate_limit_per_minute": 1})
    user = await api.user(TENANT_A, "analyst")
    login = await _login(api, user.email)
    assert login.status_code == 200
    good = api.client.cookies.get(REFRESH_COOKIE)
    statuses = []
    for i in range(25):
        api.client.cookies.clear()
        api.client.cookies.set(REFRESH_COOKIE, f"forged-refresh-token-{i}")
        statuses.append((await api.client.post("/api/v1/auth/refresh")).status_code)
    assert statuses[0] == 401 and statuses[-1] == 429
    api.client.cookies.clear()
    api.client.cookies.set(REFRESH_COOKIE, good)
    refreshed = await api.client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200, refreshed.text


# ------------------------------------------------ API-4: platform-admin override writes


async def test_platform_admin_override_writes_carry_no_foreign_user(api: ApiHarness) -> None:
    platform = await api.user(TENANT_A, "admin", platform_admin=True)
    headers = {**api.auth(platform), "X-Tenant-ID": TENANT_B}
    rule = await api.client.post(
        "/api/v1/suppressions", json={"name": "B scanner", "match": {"fingerprint": "fp-b"}}, headers=headers
    )
    assert rule.status_code == 201, rule.text
    assert rule.json()["tenant_id"] == TENANT_B
    assert rule.json()["created_by"] is None
    assert rule.json()["enabled"] is True

    key = await api.client.post("/api/v1/api-keys", json={"name": "B key", "scopes": ["read"]}, headers=headers)
    assert key.status_code == 201, key.text
    assert key.json()["created_by"] is None
    stored = await api.repos.api_keys.get_by_id(TENANT_B, key.json()["id"])
    assert stored is not None and stored.tenant_id == TENANT_B

    audited = (await api.repos.audit.list(TENANT_B, action="suppression.created")).items
    assert audited and audited[0].actor_id == str(platform.id)


async def test_platform_admin_override_cannot_claim_decide_or_approve(api: ApiHarness) -> None:
    alert_b = await make_alert(api.repos, TENANT_B, title="B")
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_B, alert_b, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    action, _ = await api.repos.actions.propose(
        TENANT_B, alert_b, "block_ip", "203.0.113.9", "low", status="awaiting_approval"
    )
    platform = await api.user(TENANT_A, "admin", platform_admin=True)
    headers = {**api.auth(platform), "X-Tenant-ID": TENANT_B}
    current = await api.repos.escalations.get(TENANT_B, escalation.id)
    calls = [
        ("POST", f"/api/v1/escalations/{escalation.id}/claim", {"version": current.version}),
        (
            "POST",
            f"/api/v1/escalations/{escalation.id}/decision",
            {"decision": "true_positive", "version": current.version},
        ),
        ("POST", f"/api/v1/actions/{action.id}/approve", {}),
        ("POST", f"/api/v1/actions/{action.id}/reject", {}),
    ]
    for method, path, body in calls:
        response = await api.client.request(method, path, json=body, headers=headers)
        assert response.status_code == 403, (path, response.text)
        assert "X-Tenant-ID" in response.json()["error"]["message"]
    assert (await api.repos.escalations.get(TENANT_B, escalation.id)).status == "open"
    assert (await api.repos.actions.get(TENANT_B, action.id)).status == "awaiting_approval"
    # Reads under the override still work.
    assert (await api.client.get(f"/api/v1/escalations/{escalation.id}", headers=headers)).status_code == 200


# ------------------------------------------------ API-5: suppression rules


async def test_write_key_and_analyst_rules_are_created_disabled(api: ApiHarness) -> None:
    rule = {"name": "scanner", "match": {"entities.ips": {"cidr": ["198.51.100.0/24"]}}, "enabled": True}
    key = await api.key_headers(TENANT_A, ["write"])
    by_key = await api.client.post("/api/v1/suppressions", json=rule, headers=key)
    assert by_key.status_code == 201, by_key.text
    assert by_key.json()["enabled"] is False
    analyst = await api.login_headers(TENANT_A, "analyst")
    by_analyst = await api.client.post("/api/v1/suppressions", json=rule, headers=analyst)
    assert by_analyst.json()["enabled"] is False
    admin = await api.login_headers(TENANT_A, "admin")
    by_admin = await api.client.post("/api/v1/suppressions", json=rule, headers=admin)
    assert by_admin.json()["enabled"] is True
    enabled = await api.client.patch(
        f"/api/v1/suppressions/{by_key.json()['id']}", json={"enabled": True}, headers=admin
    )
    assert enabled.status_code == 200 and enabled.json()["enabled"] is True
    assert (
        await api.client.patch(f"/api/v1/suppressions/{by_key.json()['id']}", json={"enabled": True}, headers=key)
    ).status_code == 403


@pytest.mark.parametrize(
    "match",
    [
        {"severity": ["info", "low", "medium", "high", "critical"]},
        {"severity": {"in": ["critical", "high", "medium", "low", "info"]}},
        {"title": {"regex": ".*"}},
        {"title": {"regex": "^.+$"}},
        {"entities.ips": {"cidr": ["0.0.0.0/0"]}},
        {"severity": ["info", "low", "medium", "high", "critical"], "title": {"regex": "(?i).*"}},
    ],
)
async def test_catch_all_rules_are_refused_even_for_admins(api: ApiHarness, match: dict) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post("/api/v1/suppressions", json={"name": "all", "match": match}, headers=admin)
    assert created.status_code == 422, created.text
    assert created.json()["error"]["code"] == "invalid_rule"
    existing = await api.client.post(
        "/api/v1/suppressions", json={"name": "ok", "match": {"severity": "info"}}, headers=admin
    )
    assert existing.status_code == 201
    widened = await api.client.patch(
        f"/api/v1/suppressions/{existing.json()['id']}", json={"match": match}, headers=admin
    )
    assert widened.status_code == 422


# ------------------------------------------------ API-6: metrics exposure


async def test_metrics_are_not_served_under_the_api_prefix(api: ApiHarness) -> None:
    assert (await api.client.get("/metrics")).status_code == 200
    assert (await api.client.get("/api/v1/metrics")).status_code == 404
    for path in ("/api/v1/healthz", "/api/v1/readyz"):
        assert (await api.client.get(path)).status_code == 200
