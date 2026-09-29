"""API integration fixtures: the real app (lifespan included) against the test Postgres and Redis.

Requests go through ``httpx.AsyncClient`` with ``ASGITransport`` to
``https://testserver`` (so ``Secure`` cookies round-trip and HSTS applies).
Access tokens for most tests are minted with the app's own token service;
the auth tests exercise the real login flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, Iterable, List, Optional, Tuple

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from lg_sotf.api.app import create_app
from lg_sotf.api.context import ApiContext
from lg_sotf.db.repos import ApiKey, Repositories, User
from lg_sotf.security.hashing import generate_api_key, hash_password
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B

BASE_URL = "https://testserver"
UI_ORIGIN = "https://ui.example.com"
TEST_JWT_SECRET = "lg-sotf-test-suite-only-jwt-secret-not-for-use"
PASSWORD = "correct horse battery staple"

__all__ = ["BASE_URL", "PASSWORD", "TENANT_A", "TENANT_B", "UI_ORIGIN"]

_HASH_CACHE: Dict[str, str] = {}


def password_hash(password: str) -> str:
    """argon2 is deliberately slow; hash each test password once per session."""
    if password not in _HASH_CACHE:
        _HASH_CACHE[password] = hash_password(password)
    return _HASH_CACHE[password]


@pytest.fixture
def api_settings(
    migrated_database_url: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Callable[..., Settings]:
    def build(**overrides: Any) -> Settings:
        base: Dict[str, Any] = {
            "database": {"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            "redis": {"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            "auth": {"jwt_secret": TEST_JWT_SECRET, "max_login_attempts": 3, "lockout_minutes": 15},
            "api": {
                "cors_origins": [UI_ORIGIN],
                "rate_limit_per_minute": 10_000,
                "ingest_rate_limit_per_minute": 10_000,
                "login_rate_limit_per_minute": 1_000,
            },
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return make_settings(**base)

    return build


@dataclass
class ApiHarness:
    app: FastAPI
    client: httpx.AsyncClient
    repos: Repositories

    @property
    def ctx(self) -> ApiContext:
        return self.app.state.ctx

    async def user(
        self,
        tenant_id: str = TENANT_A,
        role: str = "analyst",
        *,
        email: Optional[str] = None,
        password: Optional[str] = PASSWORD,
        platform_admin: bool = False,
        active: bool = True,
    ) -> User:
        return await self.repos.users.create(
            tenant_id,
            email or f"{role}-{len(await self.repos.users.list(tenant_id)) + 1}@{tenant_id}.example.com",
            role,
            password_hash=password_hash(password) if password else None,
            is_platform_admin=platform_admin,
            is_active=active,
        )

    def token(self, user: User) -> str:
        return self.ctx.tokens.issue_access(user).token

    def auth(self, user: User) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token(user)}"}

    async def login_headers(self, tenant_id: str = TENANT_A, role: str = "analyst", **kwargs: Any) -> Dict[str, str]:
        return self.auth(await self.user(tenant_id, role, **kwargs))

    async def api_key(self, tenant_id: str = TENANT_A, scopes: Iterable[str] = ("ingest",)) -> Tuple[ApiKey, str]:
        generated = generate_api_key()
        key = await self.repos.api_keys.create(
            tenant_id, "test key", generated.prefix, generated.key_hash, list(scopes), key_id=generated.key_id
        )
        return key, generated.token

    async def key_headers(self, tenant_id: str = TENANT_A, scopes: Iterable[str] = ("ingest",)) -> Dict[str, str]:
        _, token = await self.api_key(tenant_id, scopes)
        return {"X-API-Key": token}


@pytest_asyncio.fixture
async def make_api(
    repos: Repositories, redis_client: Any, api_settings: Callable[..., Settings]
) -> AsyncIterator[Callable[..., Any]]:
    """Start an app with settings overrides; every started app is shut down after the test."""
    stack: List[Tuple[FastAPI, Any, httpx.AsyncClient]] = []

    async def start(transport: Optional[httpx.AsyncBaseTransport] = None, **overrides: Any) -> ApiHarness:
        app = create_app(api_settings(**overrides), http_transport=transport, configure_observability=False)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
        stack.append((app, lifespan, client))
        return ApiHarness(app=app, client=client, repos=repos)

    try:
        yield start
    finally:
        for _, lifespan, client in reversed(stack):
            await client.aclose()
            await lifespan.__aexit__(None, None, None)


@pytest_asyncio.fixture
async def api(make_api: Callable[..., Any]) -> ApiHarness:
    return await make_api()
