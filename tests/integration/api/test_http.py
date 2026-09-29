"""Health, readiness, metrics, middleware (request id, headers, CORS, body limits, rate limits) and errors."""

from __future__ import annotations

from typing import AsyncIterator

import httpx
import pytest
from redis.asyncio import Redis

from lg_sotf.db.errors import DatabaseUnavailable
from tests.integration.api.conftest import TENANT_A, UI_ORIGIN, ApiHarness

pytestmark = pytest.mark.integration


async def test_healthz_needs_nothing(api: ApiHarness) -> None:
    for path in ("/healthz", "/api/v1/healthz"):
        response = await api.client.get(path)
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


async def test_readyz_semantics(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = await api.client.get("/readyz")
    assert ok.status_code == 200
    assert ok.json()["checks"] == {"database": "ok", "redis": "ok"}

    async def busy(**_: object) -> None:
        return None

    monkeypatch.setattr(api.ctx.db, "ping", busy)
    saturated = await api.client.get("/readyz")
    assert saturated.status_code == 200
    assert saturated.json()["checks"]["database"] == "busy"

    async def down(**_: object) -> float:
        raise DatabaseUnavailable("database ping failed: OSError")

    monkeypatch.setattr(api.ctx.db, "ping", down)
    unavailable = await api.client.get("/readyz")
    assert unavailable.status_code == 503
    assert unavailable.json()["checks"]["database"] == "error"
    monkeypatch.undo()

    original = api.ctx.redis
    dead = Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.2, socket_timeout=0.2)
    api.ctx.redis = dead
    try:
        no_redis = await api.client.get("/readyz")
    finally:
        api.ctx.redis = original
        await dead.aclose()
    assert no_redis.status_code == 503
    assert no_redis.json()["checks"] == {"database": "ok", "redis": "error"}


async def test_metrics_exposes_http_and_ingestion_series(api: ApiHarness) -> None:
    await api.client.get("/healthz")
    await api.client.get("/api/v1/alerts/some-id")
    response = await api.client.get("/metrics")
    assert response.status_code == 200
    assert "lgsotf_http_requests_total" in response.text
    assert 'route="/healthz"' in response.text
    assert 'route="/api/v1/alerts/{alert_id}"' in response.text  # templates, never ids
    assert "some-id" not in response.text
    assert "# HELP lgsotf_ingest_events_total" in response.text
    assert "# HELP lgsotf_source_polls_total" in response.text


async def test_metrics_token_is_required_when_configured(make_api) -> None:
    api = await make_api(api={"metrics_token": "metrics-scrape-token-0123456789"})
    assert (await api.client.get("/metrics")).status_code == 401
    assert (await api.client.get("/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
    ok = await api.client.get("/metrics", headers={"Authorization": "Bearer metrics-scrape-token-0123456789"})
    assert ok.status_code == 200


@pytest.mark.parametrize("configured", ["", "   "])
async def test_an_empty_metrics_token_fails_closed(make_api, configured: str) -> None:
    """``LG_SOTF_API__METRICS_TOKEN=`` must not turn ``Authorization: Bearer `` into a valid credential."""
    api = await make_api(api={"metrics_token": configured})
    for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Bearer"}, {"Authorization": "Bearer    "}):
        response = await api.client.get("/metrics", headers=headers)
        assert response.status_code == 401, headers
        assert "lgsotf_http_requests_total" not in response.text


async def test_security_headers_and_request_id(api: ApiHarness) -> None:
    response = await api.client.get("/api/v1/alerts", headers={"X-Request-ID": "req-12345678"})
    assert response.status_code == 401
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["strict-transport-security"].startswith("max-age=")
    assert headers["cache-control"] == "no-store"
    assert headers["x-request-id"] == "req-12345678"
    assert response.json()["error"]["request_id"] == "req-12345678"

    generated = await api.client.get("/healthz", headers={"X-Request-ID": "bad id with spaces"})
    assert generated.headers["x-request-id"] != "bad id with spaces"
    assert len(generated.headers["x-request-id"]) == 32

    plain = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://testserver")
    async with plain:
        insecure = await plain.get("/healthz")
    assert "strict-transport-security" not in insecure.headers


async def test_cors_allows_only_configured_origins_with_credentials(make_api) -> None:
    api = await make_api(api={"cors_origins": [UI_ORIGIN, "*"]})
    preflight = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    allowed = await api.client.options("/api/v1/auth/login", headers={"Origin": UI_ORIGIN, **preflight})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == UI_ORIGIN
    assert allowed.headers["access-control-allow-credentials"] == "true"
    denied = await api.client.options("/api/v1/auth/login", headers={"Origin": "https://evil.example", **preflight})
    assert denied.headers.get("access-control-allow-origin") is None
    simple = await api.client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert simple.headers.get("access-control-allow-origin") not in ("*", "https://evil.example")


async def test_body_limits_by_content_length_and_while_streaming(make_api) -> None:
    api = await make_api(api={"max_body_bytes": 1_024, "max_ingest_body_bytes": 64 * 1024})
    admin = await api.login_headers(TENANT_A, "admin")
    big = {"name": "x", "match": {"title": "y" * 4_000}}
    declared = await api.client.post("/api/v1/suppressions", json=big, headers=admin)
    assert declared.status_code == 413
    assert declared.json()["error"]["code"] == "payload_too_large"

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"name": "x", "match": {"title": "'
        for _ in range(10):
            yield b"z" * 512
        yield b'"}}'

    streamed = await api.client.post(
        "/api/v1/suppressions", content=chunks(), headers={**admin, "Content-Type": "application/json"}
    )
    assert streamed.status_code == 413
    assert streamed.json()["error"]["code"] == "payload_too_large"

    ingest_headers = await api.key_headers(TENANT_A, ["ingest"])
    batch = [{"title": "t" * 100, "severity": "low", "source_alert_id": f"id-{i}"} for i in range(20)]
    accepted = await api.client.post("/api/v1/ingest/alerts", json=batch, headers=ingest_headers)
    assert accepted.status_code == 202

    async def ingest_chunks() -> AsyncIterator[bytes]:
        yield b"["
        for _ in range(2_000):
            yield b'{"title": "t", "severity": "low"},'
        yield b'{"title": "t", "severity": "low"}]'

    too_big = await api.client.post(
        "/api/v1/ingest/alerts", content=ingest_chunks(), headers={**ingest_headers, "Content-Type": "application/json"}
    )
    assert too_big.status_code == 413


async def test_per_principal_rate_limit(make_api) -> None:
    api = await make_api(api={"rate_limit_per_minute": 3})
    headers = await api.login_headers(TENANT_A, "viewer")
    other = await api.login_headers(TENANT_A, "viewer")
    statuses = [(await api.client.get("/api/v1/alerts", headers=headers)).status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]
    limited = await api.client.get("/api/v1/alerts", headers=headers)
    assert int(limited.headers["retry-after"]) >= 1
    assert (await api.client.get("/api/v1/alerts", headers=other)).status_code == 200


async def test_ingest_has_its_own_budget(make_api) -> None:
    api = await make_api(api={"rate_limit_per_minute": 1, "ingest_rate_limit_per_minute": 2})
    headers = await api.key_headers(TENANT_A, ["ingest"])
    event = [{"title": "t", "severity": "low"}]
    statuses = [
        (await api.client.post("/api/v1/ingest/alerts", json=event, headers=headers)).status_code for _ in range(3)
    ]
    assert statuses == [202, 202, 429]


async def test_error_envelope_and_no_stack_traces(api: ApiHarness) -> None:
    missing = await api.client.get("/api/v1/nope")
    assert missing.status_code == 404
    assert set(missing.json()["error"]) == {"code", "message", "request_id"}
    wrong_method = await api.client.put("/api/v1/alerts")
    assert wrong_method.status_code == 405

    async def boom() -> None:
        raise RuntimeError("secret internal detail at /srv/app.py line 12")

    api.app.add_api_route("/api/v1/_boom", boom)
    response = await api.client.get("/api/v1/_boom")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "secret internal detail" not in response.text and "Traceback" not in response.text

    viewer = await api.login_headers(TENANT_A, "viewer")
    invalid = await api.client.get("/api/v1/alerts?status=bogus", headers=viewer)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"
    cursor = await api.client.get("/api/v1/alerts?cursor=not-a-cursor", headers=viewer)
    assert cursor.status_code == 400
    assert cursor.json()["error"]["code"] == "invalid_cursor"
    window = await api.client.get(
        "/api/v1/alerts?q=x&from=2024-01-01T00:00:00Z&to=2024-06-01T00:00:00Z", headers=viewer
    )
    assert window.status_code == 400
    assert window.json()["error"]["code"] == "search_window_too_large"
    fine = await api.client.get("/api/v1/alerts?q=x&from=2024-01-01T00:00:00Z&to=2024-02-01T00:00:00Z", headers=viewer)
    assert fine.status_code == 200


async def test_docs_can_be_disabled(make_api) -> None:
    enabled = await make_api()
    assert (await enabled.client.get("/api/v1/openapi.json")).status_code == 200
    disabled = await make_api(api={"docs_enabled": False})
    assert (await disabled.client.get("/api/v1/openapi.json")).status_code == 404
    assert (await disabled.client.get("/docs")).status_code == 404


async def test_alert_listing_filters_and_keyset_pagination(api: ApiHarness) -> None:
    from tests.integration.db._support import make_alert

    viewer = await api.login_headers(TENANT_A, "viewer")
    ids = [
        await make_alert(api.repos, TENANT_A, title=f"Alert {i}", severity="high" if i % 2 else "low") for i in range(5)
    ]
    first = await api.client.get("/api/v1/alerts?limit=2", headers=viewer)
    assert first.status_code == 200
    page1 = first.json()
    assert len(page1["items"]) == 2 and page1["next_cursor"]
    second = await api.client.get("/api/v1/alerts", params={"limit": 2, "cursor": page1["next_cursor"]}, headers=viewer)
    seen = [a["id"] for a in page1["items"]] + [a["id"] for a in second.json()["items"]]
    assert len(set(seen)) == 4
    high = await api.client.get("/api/v1/alerts", params=[("severity", "high")], headers=viewer)
    assert {a["severity"] for a in high.json()["items"]} == {"high"}
    both = await api.client.get("/api/v1/alerts", params=[("severity", "high"), ("severity", "low")], headers=viewer)
    assert len(both.json()["items"]) == 5
    search = await api.client.get("/api/v1/alerts", params={"q": "Alert 3"}, headers=viewer)
    assert [a["id"] for a in search.json()["items"]] == [ids[3]]
    too_many = await api.client.get("/api/v1/alerts?limit=201", headers=viewer)
    assert too_many.status_code == 422
    detail = await api.client.get(f"/api/v1/alerts/{ids[0]}", headers=viewer)
    assert detail.json()["raw"] == {"vendor": "test"}
