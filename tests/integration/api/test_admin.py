"""Admin resources: sources (write-only secrets), suppressions, users, API keys and tenant settings."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import httpx
import pytest

from lg_sotf.db.repos import LLMUsageDelta
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps, source_secret_context
from lg_sotf.services.connectors.registry import webhook_secret_context
from lg_sotf.tools.enrichment.service import tool_secret_context
from tests.integration.api.conftest import PASSWORD, TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

SPLUNK_SECRET = {"token": "splunk-super-secret-token-value"}


def _offline_ingestion(api: ApiHarness, seen: list) -> None:
    """Swap in an ingestion service that resolves hosts to a public address and answers HTTP locally."""

    async def public_resolver(host: str, port: int) -> list:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"entry": [{"content": {"version": "9.2"}}]})

    ctx = api.ctx
    ctx.ingestion = IngestionService(
        ctx.db,
        ctx.settings,
        secret_box=ctx.secret_box,
        repos=ctx.repos,
        connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(handler)),
    )


async def test_source_secrets_are_encrypted_and_never_returned(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    seen: list = []
    _offline_ingestion(api, seen)
    created = await api.client.post(
        "/api/v1/sources",
        json={
            "id": "splunk-prod",
            "type": "splunk",
            "name": "Splunk prod",
            "config": {"base_url": "https://splunk.example.com:8089", "search": "search index=notable"},
            "secret": SPLUNK_SECRET,
            "poll_interval_s": 120,
        },
        headers=admin,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["has_secret"] is True
    assert "secret" not in body and "secret_ciphertext" not in body
    assert SPLUNK_SECRET["token"] not in created.text

    stored = await api.repos.sources.get(TENANT_A, "splunk-prod")
    assert stored.secret_ciphertext and SPLUNK_SECRET["token"] not in stored.secret_ciphertext
    decrypted = api.ctx.secret_box.decrypt_json(
        stored.secret_ciphertext, context=source_secret_context(TENANT_A, "splunk-prod")
    )
    assert decrypted == SPLUNK_SECRET

    for response in (
        await api.client.get("/api/v1/sources", headers=admin),
        await api.client.get("/api/v1/sources/splunk-prod", headers=admin),
        await api.client.patch("/api/v1/sources/splunk-prod", json={"name": "Renamed"}, headers=admin),
    ):
        assert response.status_code == 200, response.text
        assert SPLUNK_SECRET["token"] not in response.text
        assert "ciphertext" not in response.text
    assert (await api.repos.sources.get(TENANT_A, "splunk-prod")).secret_ciphertext == stored.secret_ciphertext

    tested = await api.client.post("/api/v1/sources/splunk-prod/test", headers=admin)
    assert tested.status_code == 200
    assert tested.json() == {"ok": True, "detail": "connected to Splunk 9.2"}
    assert seen and seen[-1].headers["authorization"].endswith(SPLUNK_SECRET["token"])
    assert SPLUNK_SECRET["token"] not in tested.text

    removed = await api.client.patch("/api/v1/sources/splunk-prod", json={"secret": None}, headers=admin)
    assert removed.status_code == 422  # a Splunk source cannot run without its token
    assert (await api.repos.sources.get(TENANT_A, "splunk-prod")).secret_ciphertext == stored.secret_ciphertext
    audit = (await api.repos.audit.list(TENANT_A, resource_type="source")).items
    assert audit and all(SPLUNK_SECRET["token"] not in json.dumps(e.details) for e in audit)


async def test_webhook_source_crud_and_test(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    body = {"type": "webhook", "name": "Hook", "config": {"format": "generic", "field_map": {"title": "t"}}}
    created = await api.client.post("/api/v1/sources", json=body, headers=admin)
    assert created.status_code == 201, created.text
    source_id = created.json()["id"]
    assert created.json()["has_secret"] is False
    duplicate = await api.client.post("/api/v1/sources", json={**body, "id": source_id}, headers=admin)
    assert duplicate.status_code == 409
    tested = await api.client.post(f"/api/v1/sources/{source_id}/test", headers=admin)
    assert tested.status_code == 200 and tested.json()["ok"] is True
    reserved = await api.client.post("/api/v1/sources", json={**body, "id": "api"}, headers=admin)
    assert reserved.status_code == 422
    credential_in_config = await api.client.post(
        "/api/v1/sources", json={**body, "config": {**body["config"], "password": "x"}}, headers=admin
    )
    assert credential_in_config.status_code == 422
    assert (await api.client.delete(f"/api/v1/sources/{source_id}", headers=admin)).status_code == 204
    assert (await api.client.get(f"/api/v1/sources/{source_id}", headers=admin)).status_code == 404
    assert (await api.client.delete(f"/api/v1/sources/{source_id}", headers=admin)).status_code == 404


async def test_invalid_source_config_is_refused_before_saving(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.post(
        "/api/v1/sources", json={"id": "bad", "type": "splunk", "name": "Bad", "config": {}}, headers=admin
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_source"
    assert (await api.client.get("/api/v1/sources/bad", headers=admin)).status_code == 404


async def test_suppressions_analyst_creates_admin_manages(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    admin = await api.login_headers(TENANT_A, "admin")
    rule = {"name": "Known scanner", "match": {"entities.ips": {"cidr": ["198.51.100.0/24"]}}}
    created = await api.client.post("/api/v1/suppressions", json=rule, headers=api.auth(analyst))
    assert created.status_code == 201, created.text
    rule_id = created.json()["id"]
    assert created.json()["created_by"] == str(analyst.id)
    assert (
        await api.client.patch(f"/api/v1/suppressions/{rule_id}", json={"enabled": False}, headers=api.auth(analyst))
    ).status_code == 403
    invalid = await api.client.post(
        "/api/v1/suppressions", json={"name": "bad", "match": {"title": {"regex": "(a+)+$"}}}, headers=api.auth(analyst)
    )
    assert invalid.status_code == 422

    suggestion = await api.repos.suppressions.create(TENANT_A, "Suggested", {"fingerprint": "fp-1"}, enabled=False)
    enabled = await api.client.patch(f"/api/v1/suppressions/{suggestion.id}", json={"enabled": True}, headers=admin)
    assert enabled.status_code == 200 and enabled.json()["enabled"] is True
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert (
        await api.client.patch(f"/api/v1/suppressions/{rule_id}", json={"expires_at": past}, headers=admin)
    ).status_code == 422
    assert (await api.client.delete(f"/api/v1/suppressions/{rule_id}", headers=admin)).status_code == 204
    listed = await api.client.get("/api/v1/suppressions", headers=api.auth(analyst))
    assert [r["id"] for r in listed.json()] == [suggestion.id]


async def test_users_crud_policy_and_no_hashes(api: ApiHarness) -> None:
    admin_user = await api.user(TENANT_A, "admin")
    admin = api.auth(admin_user)
    weak = await api.client.post(
        "/api/v1/users", json={"email": "new@a.example.com", "role": "analyst", "password": "short"}, headers=admin
    )
    assert weak.status_code == 422
    assert weak.json()["error"]["code"] == "weak_password"
    assert "short" not in weak.text

    created = await api.client.post(
        "/api/v1/users", json={"email": "New@A.example.com", "role": "analyst", "password": PASSWORD}, headers=admin
    )
    assert created.status_code == 201, created.text
    assert created.json()["email"] == "new@a.example.com"
    user_id = created.json()["id"]
    for response in (
        created,
        await api.client.get("/api/v1/users", headers=admin),
        await api.client.get(f"/api/v1/users/{user_id}", headers=admin),
    ):
        assert "password" not in response.text and "argon2" not in response.text
    assert (
        await api.client.post("/api/v1/users", json={"email": "new@a.example.com", "role": "viewer"}, headers=admin)
    ).status_code == 409
    login = await api.client.post("/api/v1/auth/login", json={"email": "new@a.example.com", "password": PASSWORD})
    assert login.status_code == 200

    own_role = await api.client.patch(f"/api/v1/users/{admin_user.id}", json={"role": "viewer"}, headers=admin)
    assert own_role.status_code == 403
    self_disable = await api.client.patch(f"/api/v1/users/{admin_user.id}", json={"is_active": False}, headers=admin)
    assert self_disable.status_code == 403
    assert (await api.client.delete(f"/api/v1/users/{admin_user.id}", headers=admin)).status_code == 403
    platform = await api.client.post(
        "/api/v1/users", json={"email": "pa@a.example.com", "role": "admin", "is_platform_admin": True}, headers=admin
    )
    assert platform.status_code == 403

    promoted = await api.client.patch(f"/api/v1/users/{user_id}", json={"role": "admin"}, headers=admin)
    assert promoted.status_code == 200 and promoted.json()["role"] == "admin"
    reset = await api.client.patch(
        f"/api/v1/users/{user_id}", json={"password": "another long passphrase"}, headers=admin
    )
    assert reset.status_code == 200
    assert (
        await api.client.post("/api/v1/auth/login", json={"email": "new@a.example.com", "password": PASSWORD})
    ).status_code == 401
    assert (await api.client.delete(f"/api/v1/users/{user_id}", headers=admin)).status_code == 204
    assert (await api.client.get(f"/api/v1/users/{user_id}", headers=admin)).status_code == 404


async def test_last_active_admin_cannot_be_removed(api: ApiHarness) -> None:
    from tests.integration.api.conftest import TENANT_B

    only_admin = await api.user(TENANT_A, "admin")
    operator = await api.user(TENANT_B, "admin", platform_admin=True)
    headers = {**api.auth(operator), "X-Tenant-ID": TENANT_A}
    for request in (
        api.client.patch(f"/api/v1/users/{only_admin.id}", json={"role": "viewer"}, headers=headers),
        api.client.patch(f"/api/v1/users/{only_admin.id}", json={"is_active": False}, headers=headers),
        api.client.delete(f"/api/v1/users/{only_admin.id}", headers=headers),
    ):
        response = await request
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "last_admin"
    second = await api.user(TENANT_A, "admin")
    demoted = await api.client.patch(
        f"/api/v1/users/{only_admin.id}", json={"role": "viewer"}, headers=api.auth(second)
    )
    assert demoted.status_code == 200
    assert await api.repos.users.count_active_admins(TENANT_A) == 1


async def test_user_list_is_not_truncated_at_a_thousand(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin", email="admin@a.example.com")
    async with api.repos.db.tenant_tx(TENANT_A) as conn:
        for i in range(1_100):
            await api.repos.users.create(TENANT_A, f"u{i:04d}@a.example.com", "viewer", is_active=i % 2 == 0, conn=conn)
    listed = await api.client.get("/api/v1/users", headers=api.auth(admin))
    assert listed.status_code == 200
    emails = [u["email"] for u in listed.json()]
    assert len(emails) == 1_101 and emails == sorted(emails) and emails[0] == "admin@a.example.com"
    active = await api.client.get("/api/v1/users", params={"include_inactive": False}, headers=api.auth(admin))
    assert len(active.json()) == 551


async def test_api_key_secret_shown_once_and_revocable(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post(
        "/api/v1/api-keys", json={"name": "SIEM", "scopes": ["ingest", "read"]}, headers=admin
    )
    assert created.status_code == 201, created.text
    token = created.json()["key"]
    assert token.startswith("lgk_")
    key_id = created.json()["id"]
    listed = await api.client.get("/api/v1/api-keys", headers=admin)
    assert token not in listed.text and "key_hash" not in listed.text
    assert [k["id"] for k in listed.json()] == [key_id]
    me = await api.client.get("/api/v1/auth/me", headers={"X-API-Key": token})
    assert me.json()["scopes"] == ["ingest", "read"]
    bad_scope = await api.client.post("/api/v1/api-keys", json={"name": "x", "scopes": ["admin"]}, headers=admin)
    assert bad_scope.status_code == 422
    assert (await api.client.delete(f"/api/v1/api-keys/{key_id}", headers=admin)).status_code == 204
    assert (await api.client.get("/api/v1/auth/me", headers={"X-API-Key": token})).status_code == 401
    assert (await api.client.get("/api/v1/api-keys", headers=admin)).json() == []
    # API keys cannot mint API keys.
    key_headers = await api.key_headers(TENANT_A, ["read", "write", "ingest"])
    assert (
        await api.client.post("/api/v1/api-keys", json={"name": "x", "scopes": ["read"]}, headers=key_headers)
    ).status_code == 403


async def test_tenant_settings_validation_and_write_only_secrets(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    invalid = await api.client.patch(
        "/api/v1/tenant/settings",
        json={"autonomy": {"low": "sometimes"}, "response": {"tls_verify": False}},
        headers=admin,
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_settings"
    assert len(invalid.json()["error"]["details"]) >= 2
    unknown = await api.client.patch("/api/v1/tenant/settings", json={"surprise": 1}, headers=admin)
    assert unknown.status_code == 422
    direct = await api.client.patch(
        "/api/v1/tenant/settings", json={"response": {"webhook_secret_ciphertext": "x"}}, headers=admin
    )
    assert direct.status_code == 422

    webhook_secret = "a-webhook-signing-secret-of-good-length"
    vt_key = "virustotal-api-key-value-0123456789"
    patched = await api.client.patch(
        "/api/v1/tenant/settings",
        json={
            "autonomy": {"low": "auto", "critical": "disabled"},
            "protected_assets": {"hosts": ["dc01"], "cidrs": ["10.0.0.0/8"]},
            "llm_daily_token_budget": 500_000,
            "response": {
                "connector": "webhook",
                "webhook_url": "https://soar.example.com/hook",
                "webhook_secret": webhook_secret,
            },
            "tools": {"virustotal": {"api_key": vt_key, "enabled": True}},
        },
        headers=admin,
    )
    assert patched.status_code == 200, patched.text
    settings = patched.json()["settings"]
    assert webhook_secret not in patched.text and vt_key not in patched.text and "ciphertext" not in patched.text
    assert settings["response"]["webhook_secret_configured"] is True
    assert settings["tools"]["virustotal"]["api_key_configured"] is True
    assert settings["autonomy"]["low"] == "auto"
    assert settings["llm_daily_token_budget"] == 500_000

    tenant = await api.repos.tenants.get(TENANT_A)
    box = api.ctx.secret_box
    assert (
        box.decrypt_json(
            tenant.settings["response"]["webhook_secret_ciphertext"], context=webhook_secret_context(TENANT_A)
        )
        == webhook_secret
    )
    assert box.decrypt_json(
        tenant.settings["tools"]["virustotal"]["api_key_ciphertext"],
        context=tool_secret_context(TENANT_A, "virustotal"),
    ) == {"api_key": vt_key}

    # A later patch of the response section keeps the stored secret.
    again = await api.client.patch("/api/v1/tenant/settings", json={"response": {"dry_run": True}}, headers=admin)
    assert again.status_code == 200
    assert again.json()["settings"]["response"]["webhook_secret_configured"] is True
    assert again.json()["settings"]["response"]["dry_run"] is True
    got = await api.client.get("/api/v1/tenant/settings", headers=admin)
    assert got.status_code == 200 and webhook_secret not in got.text
    removed = await api.client.patch("/api/v1/tenant/settings", json={"llm_daily_token_budget": None}, headers=admin)
    assert "llm_daily_token_budget" not in removed.json()["settings"]
    audit = (await api.repos.audit.list(TENANT_A, action="tenant.settings_updated")).items
    assert audit and all(webhook_secret not in json.dumps(e.details) for e in audit)


async def test_dashboard_is_cached_per_tenant_and_usage_sums(api: ApiHarness) -> None:
    from tests.integration.db._support import make_alert

    viewer = await api.login_headers(TENANT_A, "viewer")
    admin = await api.login_headers(TENANT_A, "admin")
    await make_alert(api.repos, TENANT_A, severity="high")
    await api.repos.llm_usage.upsert_daily(
        [
            LLMUsageDelta(
                tenant_id=TENANT_A,
                day=date.today(),
                model="m",
                agent="triage",
                calls=2,
                input_tokens=100,
                output_tokens=50,
                cost_usd=Decimal("0.25"),
            )
        ]
    )
    first = await api.client.get("/api/v1/dashboard/summary", headers=viewer)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["alerts_total"] == 1
    assert body["by_severity"] == {"high": 1}
    assert body["by_disposition"] == {"undecided": 1}
    assert body["llm_tokens"] == 150 and body["llm_cost_usd"] == pytest.approx(0.25)
    await make_alert(api.repos, TENANT_A, severity="low")
    cached = await api.client.get("/api/v1/dashboard/summary", headers=viewer)
    assert cached.json()["alerts_total"] == 1
    assert cached.json()["generated_at"] == body["generated_at"]
    ttl = await api.ctx.redis.ttl(f"{api.ctx.prefix}:t:{TENANT_A}:cache:dashboard:24")
    assert 0 < ttl <= 15
    other_window = await api.client.get("/api/v1/dashboard/summary?window_hours=48", headers=viewer)
    assert other_window.json()["alerts_total"] == 2

    usage = await api.client.get("/api/v1/usage/llm", headers=admin)
    assert usage.status_code == 200
    assert usage.json()["total_calls"] == 2
    assert Decimal(usage.json()["total_cost_usd"]) == Decimal("0.25")
    bad = await api.client.get("/api/v1/usage/llm?from=2025-01-10&to=2025-01-01", headers=admin)
    assert bad.status_code == 400


async def test_concurrent_settings_patches_do_not_lose_updates(api: ApiHarness) -> None:
    """M3: nested sections are merged under a row lock, so both sub-keys survive."""
    import asyncio

    headers = await api.login_headers(TENANT_A, "admin")
    for _ in range(5):
        await api.client.patch("/api/v1/tenant/settings", json={"response": None}, headers=headers)
        first, second = await asyncio.gather(
            api.client.patch("/api/v1/tenant/settings", json={"response": {"max_actions_per_hour": 3}}, headers=headers),
            api.client.patch(
                "/api/v1/tenant/settings", json={"response": {"blast_radius": {"isolate_host": 1}}}, headers=headers
            ),
        )
        assert first.status_code == second.status_code == 200
        stored = (await api.repos.tenants.get(TENANT_A)).settings["response"]
        assert stored.get("max_actions_per_hour") == 3 and stored.get("blast_radius") == {"isolate_host": 1}, stored


async def test_admin_clears_the_verdict_cache(api: ApiHarness) -> None:
    from lg_sotf.core.verdict_cache import VerdictCache

    cache = VerdictCache(api.ctx.redis, api.ctx.prefix)
    await cache.put_analyst_benign(TENANT_A, "fp-1", decision="false_positive", alert_id="a", escalation_id=None, severity="low")
    await cache.put_analyst_benign(TENANT_B, "fp-1", decision="false_positive", alert_id="a", escalation_id=None, severity="low")
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.delete("/api/v1/tenant/verdict-cache", headers=analyst)).status_code == 403
    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.delete("/api/v1/tenant/verdict-cache", headers=admin)
    assert response.status_code == 200 and response.json() == {"removed": 1}
    assert await cache.get(TENANT_A, "fp-1") is None and await cache.get(TENANT_B, "fp-1") is not None
    assert (await api.repos.audit.list(TENANT_A, action="tenant.verdict_cache_cleared")).items
