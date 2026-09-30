"""Table-driven RBAC matrix: every endpoint against every kind of principal."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tests.integration.api.conftest import TENANT_A, ApiHarness

pytestmark = pytest.mark.integration

X = "does-not-exist"
U = str(uuid.uuid4())

# (method, path, required access, json body)
ENDPOINTS: List[Tuple[str, str, str, Optional[Any]]] = [
    ("GET", "/api/v1/auth/me", "any", None),
    ("POST", "/api/v1/ingest/alerts", "ingest", [{"title": "t", "severity": "low"}]),
    ("POST", "/api/v1/ingest/webhook/no-such-source", "ingest", {"a": 1}),
    ("GET", "/api/v1/alerts", "viewer", None),
    ("GET", f"/api/v1/alerts/{X}", "viewer", None),
    ("GET", f"/api/v1/alerts/{X}/events", "viewer", None),
    ("POST", f"/api/v1/alerts/{X}/notes", "analyst", {"text": "note"}),
    ("POST", f"/api/v1/alerts/{X}/reprocess", "admin", None),
    ("GET", "/api/v1/escalations", "viewer", None),
    ("GET", f"/api/v1/escalations/{X}", "viewer", None),
    ("POST", f"/api/v1/escalations/{X}/claim", "reviewer", {"version": 1}),
    ("POST", f"/api/v1/escalations/{X}/decision", "reviewer", {"decision": "false_positive", "version": 1}),
    ("GET", "/api/v1/actions", "viewer", None),
    ("GET", f"/api/v1/actions/{U}", "viewer", None),
    ("POST", f"/api/v1/actions/{U}/approve", "reviewer", {}),
    ("POST", f"/api/v1/actions/{U}/reject", "reviewer", {}),
    ("GET", "/api/v1/sources", "admin", None),
    ("POST", "/api/v1/sources", "admin", {"type": "webhook"}),
    ("GET", f"/api/v1/sources/{X}", "admin", None),
    ("PATCH", f"/api/v1/sources/{X}", "admin", {"name": "n"}),
    ("DELETE", f"/api/v1/sources/{X}", "admin", None),
    ("POST", f"/api/v1/sources/{X}/test", "admin", None),
    ("GET", "/api/v1/suppressions", "viewer", None),
    ("GET", f"/api/v1/suppressions/{X}", "viewer", None),
    ("POST", "/api/v1/suppressions", "analyst", {"name": "n"}),
    ("PATCH", f"/api/v1/suppressions/{X}", "admin", {"enabled": True}),
    ("DELETE", f"/api/v1/suppressions/{X}", "admin", None),
    ("GET", "/api/v1/users", "admin", None),
    ("GET", f"/api/v1/users/{U}", "admin", None),
    ("POST", "/api/v1/users", "admin", {"email": "x"}),
    ("PATCH", f"/api/v1/users/{U}", "admin_user", {"role": "viewer"}),
    ("DELETE", f"/api/v1/users/{U}", "admin_user", None),
    ("GET", "/api/v1/api-keys", "admin", None),
    ("POST", "/api/v1/api-keys", "admin", {}),
    ("DELETE", f"/api/v1/api-keys/{U}", "admin", None),
    ("GET", "/api/v1/tenant/settings", "admin", None),
    ("PATCH", "/api/v1/tenant/settings", "admin", {}),
    ("DELETE", "/api/v1/tenant/verdict-cache", "admin", None),
    ("GET", "/api/v1/dashboard/summary", "viewer", None),
    ("GET", "/api/v1/usage/llm", "admin", None),
    ("GET", "/api/v1/reports/value", "viewer", None),
    ("GET", "/api/v1/reports/accuracy", "viewer", None),
    ("GET", "/api/v1/reports/detections", "viewer", None),
    (
        "POST",
        "/api/v1/reports/detections/propose-suppression",
        "analyst",
        {"source_id": "s", "rule_field": "rule_name", "rule": "r"},
    ),
    ("GET", "/api/v1/reports/monthly", "viewer", None),
    ("GET", "/api/v1/audit", "admin", None),
    ("GET", "/api/v1/audit/verify", "admin", None),
    ("POST", "/api/v1/platform/tenants", "platform_admin", {"id": "rbac-new", "name": "RBAC new"}),
]
# Reachable without a bearer token (login, cookie-based refresh/logout); covered by test_auth.
PUBLIC_ENDPOINTS = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
}

USER_ROLES = {"viewer": 0, "analyst": 1, "admin": 2, "platform_admin": 2}
REQUIRED_ROLE = {"viewer": 0, "analyst": 1, "reviewer": 1, "admin": 2, "admin_user": 2}
KEY_SCOPE = {"viewer": "read", "analyst": "write", "ingest": "ingest"}


def expected_allowed(principal: str, access: str) -> bool:
    kind, _, value = principal.partition(":")
    if access == "any":
        return True
    if access == "platform_admin":
        return principal == "user:platform_admin"
    if kind == "user":
        if access == "ingest":
            return False
        return USER_ROLES[value] >= REQUIRED_ROLE[access]
    return KEY_SCOPE.get(access) == value


async def _principals(api: ApiHarness) -> Dict[str, Dict[str, str]]:
    headers: Dict[str, Dict[str, str]] = {}
    for role in ("viewer", "analyst", "admin"):
        headers[f"user:{role}"] = await api.login_headers(TENANT_A, role)
    headers["user:platform_admin"] = await api.login_headers(TENANT_A, "admin", platform_admin=True)
    for scope in ("read", "write", "ingest"):
        headers[f"key:{scope}"] = await api.key_headers(TENANT_A, [scope])
    return headers


def test_matrix_covers_every_api_route() -> None:
    from lg_sotf.api.app import create_app
    from lg_sotf.settings import Settings

    app = create_app(Settings(_env_file=None, environment="test"))
    routes = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if path.startswith("/api/v1/") and method.upper() != "HEAD"
    }
    assert ("GET", "/api/v1/alerts") in routes and ("POST", "/api/v1/platform/tenants") in routes
    covered = set(PUBLIC_ENDPOINTS)
    for method, path, _, _ in ENDPOINTS:
        for route_method, template in routes:
            if route_method != method:
                continue
            parts, tparts = path.split("/"), template.split("/")
            if len(parts) == len(tparts) and all(
                t.startswith("{") or t == p for p, t in zip(parts, tparts, strict=True)
            ):
                covered.add((route_method, template))
    assert routes - covered == set()


async def test_rbac_matrix(api: ApiHarness) -> None:
    principals = await _principals(api)
    failures: List[str] = []
    for method, path, access, body in ENDPOINTS:
        for name, headers in principals.items():
            response = await api.client.request(method, path, headers=headers, json=body)
            allowed = expected_allowed(name, access)
            if allowed and response.status_code in (401, 403):
                failures.append(
                    f"{name} {method} {path}: expected access, got {response.status_code} {response.text[:120]}"
                )
            if not allowed and response.status_code != 403:
                failures.append(f"{name} {method} {path}: expected 403, got {response.status_code}")
    assert not failures, "\n".join(failures)


async def test_every_endpoint_requires_authentication(api: ApiHarness) -> None:
    for method, path, _, body in ENDPOINTS:
        response = await api.client.request(method, path, json=body)
        assert response.status_code == 401, f"{method} {path}"
        assert response.json()["error"]["code"] == "unauthorized"
