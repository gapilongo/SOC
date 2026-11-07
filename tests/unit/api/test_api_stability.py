"""API stability tiers, the deprecation headers and the oasdiff gate (ARCH-E2.2, docs/api.md)."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
from datetime import date, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterator, Tuple

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from lg_sotf.api import stability
from lg_sotf.api.app import EXPOSED_HEADERS, api_routers, create_app
from lg_sotf.api.errors import ApiError
from lg_sotf.api.routers import health, ingest, onboarding, platform
from lg_sotf.api.stability import (
    STABILITY_KEY,
    STABILITY_LEVELS,
    Deprecation,
    classify,
    route_contract,
)
from lg_sotf.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
GATE = REPO_ROOT / "scripts" / "ci" / "check_api_compat.py"
GOLDEN = REPO_ROOT / "docs" / "openapi.json"
OASDIFF = os.environ.get("OASDIFF") or shutil.which("oasdiff")

SINCE, SUNSET = date(2026, 11, 9), date(2027, 5, 10)
OLD = "/api/v1/_test/old"


def _gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_api_compat", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _operations(document: Dict[str, Any]) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    for path, item in document["paths"].items():
        for method, op in item.items():
            yield path, method, op


@pytest.fixture
def app(make_settings: Callable[..., Settings]) -> FastAPI:
    """The real app plus a deprecated test router (the lifespan does not run: no database)."""
    app = create_app(make_settings(), configure_observability=False)
    router = APIRouter(prefix="/api/v1/_test")
    notice = Deprecation(since=SINCE, sunset=SUNSET)

    @router.get("/old", **route_contract(stability="stable", deprecation=notice))
    async def old() -> Dict[str, bool]:
        return {"ok": True}

    @router.get("/old/missing", **route_contract(stability="stable", deprecation=notice))
    async def old_missing() -> None:
        raise ApiError(404, "not_found", "not found")

    @router.get("/current", **route_contract(stability="beta"))
    async def current() -> Dict[str, bool]:
        return {"ok": True}

    app.include_router(router)
    return app


# --- tiers -------------------------------------------------------------------------------------------


def test_every_operation_declares_a_stability_tier(make_settings: Callable[..., Settings]) -> None:
    document = create_app(make_settings(), configure_observability=False).openapi()
    untiered = [
        f"{m.upper()} {p}" for p, m, op in _operations(document) if op.get(STABILITY_KEY) not in STABILITY_LEVELS
    ]
    assert not untiered, f"declare a tier (lg_sotf.api.app.api_routers or route_contract) for: {untiered}"


def test_the_committed_document_has_every_tier() -> None:
    tiers = {op.get(STABILITY_KEY) for _, _, op in _operations(json.loads(GOLDEN.read_text(encoding="utf-8")))}
    assert tiers == set(STABILITY_LEVELS)


def test_classification_of_representative_routers(make_settings: Callable[..., Settings]) -> None:
    document = create_app(make_settings(), configure_observability=False).openapi()["paths"]
    assert document["/api/v1/ingest/alerts"]["post"][STABILITY_KEY] == "stable"
    assert document["/api/v1/alerts/{alert_id}"]["get"][STABILITY_KEY] == "stable"
    assert document["/healthz"]["get"][STABILITY_KEY] == "stable"
    assert document["/api/v1/platform/tenants"]["post"][STABILITY_KEY] == "beta"
    assert document["/metrics"]["get"][STABILITY_KEY] == "beta"
    assert document["/api/v1/onboarding/status"]["get"][STABILITY_KEY] == "internal"
    tiers = {id(router): level for router, level in api_routers()}
    assert tiers[id(ingest.router)] == "stable" and tiers[id(platform.router)] == "beta"
    assert tiers[id(onboarding.router)] == "internal" and id(health.router) not in tiers


def test_classify_keeps_a_route_s_own_tier_and_is_idempotent() -> None:
    router = APIRouter()

    @router.get("/a")
    async def a() -> None:
        return None

    @router.get("/b", **route_contract(stability="internal"))
    async def b() -> None:
        return None

    classify(router, "stable")
    classify(router, "beta")
    tiers = {route.path: route.openapi_extra[STABILITY_KEY] for route in router.routes}  # type: ignore[attr-defined]
    assert tiers == {"/a": "stable", "/b": "internal"}


def test_deprecated_operations_declare_a_sunset_and_keep_the_window(make_settings: Callable[..., Settings]) -> None:
    """Deprecated through route_contract (so the headers are sent); stable ones for at least
    STABLE_DEPRECATION_DAYS before their sunset."""
    document = create_app(make_settings(), configure_observability=False).openapi()
    for path, method, op in _operations(document):
        if not op.get("deprecated"):
            continue
        notice = Deprecation.from_openapi_extra(op)
        assert notice is not None, f"{method.upper()} {path}: deprecate it with route_contract(deprecation=...)"
        if op[STABILITY_KEY] == "stable":
            window = (notice.sunset - notice.since).days
            assert window >= stability.STABLE_DEPRECATION_DAYS, f"{method.upper()} {path}: {window} days"


# --- deprecation headers -----------------------------------------------------------------------------


def test_a_deprecated_route_sends_deprecation_sunset_and_link(app: FastAPI) -> None:
    response = TestClient(app).get(OLD)
    assert response.status_code == 200
    assert response.headers["Deprecation"] == "@1794182400"  # 2026-11-09T00:00:00Z, RFC 9745
    assert response.headers["Sunset"] == "Mon, 10 May 2027 00:00:00 GMT"  # RFC 8594 HTTP date
    assert parsedate_to_datetime(response.headers["Sunset"]).date() == SUNSET
    assert response.headers["Link"] == f'<{stability.DEPRECATION_DOCS}>; rel="deprecation"; type="text/html"'
    assert response.headers["X-Request-ID"]  # the other middleware still runs


def test_an_error_from_a_deprecated_route_carries_the_headers_too(app: FastAPI) -> None:
    response = TestClient(app).get(f"{OLD}/missing")
    assert response.status_code == 404 and response.json()["error"]["code"] == "not_found"
    assert {"deprecation", "sunset", "link"} <= set(response.headers)


def test_other_routes_send_no_deprecation_headers(app: FastAPI) -> None:
    for path in ("/api/v1/_test/current", "/api/v1/_test/nowhere"):
        response = TestClient(app).get(path)
        assert not {"deprecation", "sunset", "link"} & set(response.headers), path


def test_the_document_marks_a_deprecated_route(app: FastAPI) -> None:
    op = app.openapi()["paths"][OLD]["get"]
    assert op["deprecated"] is True and op[STABILITY_KEY] == "stable"
    assert op["x-sunset"] == "2027-05-10" and op["x-deprecated-since"] == "2026-11-09"
    assert op["externalDocs"]["url"] == stability.DEPRECATION_DOCS
    assert "deprecated" not in app.openapi()["paths"]["/api/v1/_test/current"]["get"]


def test_browsers_may_read_the_deprecation_headers() -> None:
    assert {"Deprecation", "Sunset", "Link"} <= set(EXPOSED_HEADERS)


def test_a_sunset_must_follow_the_deprecation() -> None:
    with pytest.raises(ValueError, match="sunset"):
        Deprecation(since=SUNSET, sunset=SINCE)
    assert Deprecation.from_openapi_extra({STABILITY_KEY: "stable"}) is None


# --- the oasdiff gate --------------------------------------------------------------------------------


def test_the_gate_and_the_app_agree_on_the_window() -> None:
    assert _gate().STABLE_DEPRECATION_DAYS == stability.STABLE_DEPRECATION_DAYS


def test_the_gate_splits_operations_by_tier() -> None:
    gate = _gate()
    document = json.loads(GOLDEN.read_text(encoding="utf-8"))
    stable = gate.select(document, stable=True)
    others = gate.select(document, stable=False)
    assert {op[STABILITY_KEY] for _, _, op in gate.operations(stable)} == {"stable"}
    assert {op[STABILITY_KEY] for _, _, op in gate.operations(others)} == {"beta", "internal"}
    total = sum(1 for _ in gate.operations(document))
    assert sum(1 for _ in gate.operations(stable)) + sum(1 for _ in gate.operations(others)) == total


def test_an_untiered_base_takes_the_revision_s_tiers() -> None:
    gate = _gate()
    revision = {"paths": {"/a": {"get": {STABILITY_KEY: "beta"}}, "/b": {"get": {STABILITY_KEY: "stable"}}}}
    base = {
        "paths": {"/a": {"get": {}}, "/b": {"get": {}}, "/gone": {"get": {}}, "/c": {"get": {STABILITY_KEY: "stable"}}}
    }
    tiers = {path: op[STABILITY_KEY] for path, _, op in gate.operations(gate.adopt_tiers(base, revision))}
    assert tiers == {"/a": "beta", "/b": "stable", "/gone": "stable", "/c": "stable"}


@pytest.mark.skipif(OASDIFF is None, reason="oasdiff is not installed (the CI api-compat job pins it)")
def test_oasdiff_blocks_a_breaking_change_to_a_stable_operation(capsys: pytest.CaptureFixture[str]) -> None:
    """Acceptance (ARCH-E2.2): the gate's self-test on the committed document, plus the deprecation flow."""
    assert OASDIFF is not None
    gate = _gate()
    document = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert gate.self_test(document, binary=OASDIFF) == 0, capsys.readouterr().out

    path = "/api/v1/alerts/{alert_id}"
    removed = {**document, "paths": {p: v for p, v in document["paths"].items() if p != path}}
    assert gate.check(document, removed, binary=OASDIFF, out=lambda _: None) == 1

    def deprecated(sunset: date) -> Dict[str, Any]:
        doc = json.loads(json.dumps(document))
        doc["paths"][path]["get"].update(deprecated=True, **{"x-sunset": sunset.isoformat()})
        return doc

    today = date.today()  # oasdiff measures a new sunset from today
    assert gate.check(document, deprecated(today + timedelta(days=30)), binary=OASDIFF, out=lambda _: None) == 1
    assert gate.check(document, deprecated(today + timedelta(days=200)), binary=OASDIFF, out=lambda _: None) == 0
    assert gate.check(deprecated(today - timedelta(days=1)), removed, binary=OASDIFF, out=lambda _: None) == 0
