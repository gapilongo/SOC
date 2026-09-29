"""App factory: production safety check, CORS origins, docs toggle, route inventory."""

from __future__ import annotations

from typing import Callable

import pytest

from lg_sotf.api.app import cors_origins, create_app
from lg_sotf.settings import Settings


async def test_unsafe_production_settings_refuse_to_start(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(environment="production")
    app = create_app(settings, configure_observability=False)
    with pytest.raises(RuntimeError, match="Unsafe production configuration"):
        async with app.router.lifespan_context(app):
            pass
    assert app.state.ctx is None


def test_wildcard_cors_origin_is_never_used(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(api={"cors_origins": ["*", "https://ui.example.com/", " "]})
    assert cors_origins(settings) == ["https://ui.example.com"]


def test_docs_follow_the_setting(make_settings: Callable[..., Settings]) -> None:
    on = create_app(make_settings(api={"docs_enabled": True}), configure_observability=False)
    off = create_app(make_settings(api={"docs_enabled": False}), configure_observability=False)
    assert on.openapi_url == "/api/v1/openapi.json" and on.docs_url == "/docs"
    assert off.openapi_url is None and off.docs_url is None and off.redoc_url is None


def test_contract_endpoints_are_all_routed(make_settings: Callable[..., Settings]) -> None:
    app = create_app(make_settings(), configure_observability=False)
    paths = set(app.openapi()["paths"])
    for path in (
        "/healthz",
        "/readyz",
        "/metrics",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/ingest/alerts",
        "/api/v1/ingest/webhook/{source_id}",
        "/api/v1/alerts",
        "/api/v1/alerts/{alert_id}",
        "/api/v1/alerts/{alert_id}/events",
        "/api/v1/alerts/{alert_id}/reprocess",
        "/api/v1/alerts/{alert_id}/notes",
        "/api/v1/escalations",
        "/api/v1/escalations/{escalation_id}",
        "/api/v1/escalations/{escalation_id}/claim",
        "/api/v1/escalations/{escalation_id}/decision",
        "/api/v1/actions",
        "/api/v1/actions/{action_id}/approve",
        "/api/v1/actions/{action_id}/reject",
        "/api/v1/sources",
        "/api/v1/sources/{source_id}/test",
        "/api/v1/suppressions",
        "/api/v1/users",
        "/api/v1/api-keys",
        "/api/v1/tenant/settings",
        "/api/v1/dashboard/summary",
        "/api/v1/usage/llm",
    ):
        assert path in paths, path
    ws_paths = {getattr(r, "path", None) for r in app.routes} | {
        getattr(c, "path", None) for r in app.routes for c in getattr(getattr(r, "original_router", None), "routes", [])
    }
    assert "/ws" in ws_paths
