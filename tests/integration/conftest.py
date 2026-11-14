"""Fixtures shared by every integration test package.

The database named by ``LG_SOTF_TEST_DATABASE_URL`` is reset (public schema
dropped and recreated) and migrated once per session, then truncated before
each test. The Redis database named by ``LG_SOTF_TEST_REDIS_URL`` is flushed
before and after each test that uses it. Tests skip when a variable is unset.

Under pytest-xdist each worker ``gw<N>`` uses its own database
(``<name>_gw<N>``, created when missing) and Redis database (base index + N);
see ``_support.py``. Every ``Settings`` built here carries the test's
``unique_prefix``, because Redis pub/sub channels are shared by all databases.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI

from lg_sotf.api.app import create_app
from lg_sotf.api.context import ApiContext
from lg_sotf.api.ratelimit import RateLimiter
from lg_sotf.db.migrate import setup_checkpointer, upgrade_head
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.integrations.config import encrypt_secret, validate_config
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.connectors.microsoft import MicrosoftClients
from lg_sotf.services.response import ResponseService
from lg_sotf.settings import DatabaseSettings, Settings
from tests.fixtures.microsoft import FakeMicrosoft, fake_config
from tests.integration._support import (
    ensure_database,
    require_unique_prefix,
    worker_database_url,
    worker_redis_url,
    xdist_worker_index,
)
from tests.integration.api._support import BASE_URL, TEST_JWT_SECRET, UI_ORIGIN, ApiClock, ApiHarness
from tests.integration.db._support import (
    TENANT_A,
    TENANT_B,
    assert_rls_applies,
    db_settings,
    ensure_shadow_grants,
    reset_schema,
    shadow_url,
    truncate_all,
)
from tests.integration.integrations._support import no_sleep
from tests.integration.integrations.microsoft._support import (
    DEFAULT_TENANT_SETTINGS,
    MicrosoftEnv,
    MicrosoftEnvFactory,
)
from tests.unit.services.fakes import FakeEvents


def _test_database_url() -> Optional[str]:
    return os.environ.get("LG_SOTF_TEST_DATABASE_URL") or None


def _test_redis_url() -> Optional[str]:
    return os.environ.get("LG_SOTF_TEST_REDIS_URL") or None


@pytest.fixture(autouse=True)
def _plain_tracebacks() -> Iterator[None]:
    """structlog's defaults with plain tracebacks while an integration test runs.

    The app is started without ``configure_logging``, so structlog's default
    renderer applies, and with ``rich`` installed it renders every logged
    exception (``api.unhandled_error``) as a rich traceback with locals: 15 to
    30 s of CPU per 500 response, on the event loop. The audit-atomicity
    tests answer 500 on purpose and took 50 to 120 s each, enough to reach the
    120 s timeout under coverage or load. The same processors, a plain traceback.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(colors=False, exception_formatter=structlog.dev.plain_traceback),
        ]
    )
    yield
    structlog.reset_defaults()


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _test_database_url()
    if not url:
        pytest.skip("LG_SOTF_TEST_DATABASE_URL is not set")
    index = xdist_worker_index()
    worker_url = worker_database_url(url, index)
    if index is not None:
        ensure_database(url, worker_url)
    return worker_url


@pytest.fixture(scope="session")
def migrated_database_url(database_url: str) -> Iterator[str]:
    assert_rls_applies(database_url)
    reset_schema(database_url)
    upgrade_head(database_url, DatabaseSettings())
    yield database_url


@pytest.fixture(scope="session")
def checkpointed_database_url(migrated_database_url: str) -> str:
    """The migrated test database plus LangGraph's checkpoint tables (``lg-sotf migrate`` does both)."""
    asyncio.run(setup_checkpointer(migrated_database_url, DatabaseSettings()))
    return migrated_database_url


@pytest_asyncio.fixture
async def db(migrated_database_url: str) -> AsyncIterator[Database]:
    """The schema owner's pool, plus the shadow runs' pool as the SELECT-only shadow role (AI-E1.5c)."""
    settings = db_settings(migrated_database_url, shadow_url=shadow_url(migrated_database_url))
    database = Database(settings, application_name="lg-sotf-tests")
    await database.open()
    if await ensure_shadow_grants(database, migrated_database_url):
        await database.open_shadow()
    await truncate_all(database)
    try:
        yield database
    finally:
        await database.close()


@pytest_asyncio.fixture
async def repos(db: Database) -> Repositories:
    r = Repositories.create(db)
    await r.tenants.create(TENANT_A, "Tenant A")
    await r.tenants.create(TENANT_B, "Tenant B")
    return r


@pytest.fixture(scope="session")
def redis_url() -> str:
    url = _test_redis_url()
    if not url:
        pytest.skip("LG_SOTF_TEST_REDIS_URL is not set")
    return worker_redis_url(url, xdist_worker_index())


@pytest.fixture
def make_settings(make_settings: Callable[..., Settings], unique_prefix: str) -> Callable[..., Settings]:
    """The root ``make_settings`` with ``redis.key_prefix`` defaulting to this test's ``unique_prefix``.

    Any other prefix fails the test (``require_unique_prefix``): pub/sub ignores Redis database indexes.
    """

    def build(**overrides: Any) -> Settings:
        redis = {"key_prefix": unique_prefix, **dict(overrides.pop("redis", None) or {})}
        return require_unique_prefix(make_settings(redis=redis, **overrides), unique_prefix)

    return build


@pytest_asyncio.fixture
async def redis_client(redis_url: str) -> AsyncIterator[aioredis.Redis]:
    client = aioredis.Redis.from_url(redis_url, decode_responses=False)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


# ------------------------------------------------------------------- API harness

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


@pytest.fixture
def api_clock() -> ApiClock:
    return ApiClock()


@pytest_asyncio.fixture
async def make_api(
    repos: Repositories, redis_client: Any, api_settings: Callable[..., Settings], api_clock: ApiClock
) -> AsyncIterator[Callable[..., Any]]:
    """Start an app with settings overrides; every started app is shut down after the test.

    Every app's rate limiter reads ``api_clock`` (shared by the apps of one test).
    """
    stack: List[Tuple[FastAPI, Any, httpx.AsyncClient]] = []

    async def start(transport: Optional[httpx.AsyncBaseTransport] = None, **overrides: Any) -> ApiHarness:
        app = create_app(api_settings(**overrides), http_transport=transport, configure_observability=False)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        ctx: ApiContext = app.state.ctx
        ctx.limiter = RateLimiter(ctx.redis, ctx.prefix, clock=api_clock)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
        stack.append((app, lifespan, client))
        return ApiHarness(app=app, client=client, repos=repos, clock=api_clock)

    try:
        yield start
    finally:
        for _, lifespan, client in reversed(stack):
            await client.aclose()
            await lifespan.__aexit__(None, None, None)


@pytest_asyncio.fixture
async def api(make_api: Callable[..., Any]) -> ApiHarness:
    return await make_api()


# ----------------------------------------------------- Microsoft response environment

@pytest.fixture
def microsoft_env(
    repos: Repositories, make_settings: Callable[..., Settings], migrated_database_url: str
) -> MicrosoftEnvFactory:
    """``await microsoft_env(capabilities, live=True, **options)``: see the module docstring.

    ``capabilities`` maps capability keys to ``{"options": {...}}`` (and may
    set ``enabled``/``live`` per capability). Keyword options: ``cloud``,
    ``geo``, ``credential``, ``tenant_settings``, ``settings`` (overrides of
    the install settings).
    """

    async def build(
        capabilities: Mapping[str, Mapping[str, Any]],
        live: bool = True,
        *,
        cloud: str = "global",
        geo: Optional[str] = None,
        credential: str = "client_secret",
        tenant_settings: Optional[Dict[str, Any]] = None,
        settings: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> MicrosoftEnv:
        install = make_settings(
            database={"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            response={"dry_run": False, "microsoft_retries": 1, "microsoft_timeout_s": 5.0,
                      **dict((settings or {}).get("response", {}))},
            **{k: v for k, v in (settings or {}).items() if k != "response"},
        )
        await repos.tenants.update_settings(TENANT_A, tenant_settings or DEFAULT_TENANT_SETTINGS)
        caps = {
            key: {"enabled": value.get("enabled", True), "live": value.get("live", live),
                  "options": dict(value.get("options") or {})}
            for key, value in capabilities.items()
        }
        config, secret = fake_config(credential=credential, capabilities=caps, cloud=cloud)
        if geo:
            config["defender_geo"] = geo
        config = validate_config("microsoft", config, require_https=True)
        box = SecretBox.from_settings(install)
        integration_id = uuid.uuid4()
        integration = await repos.integrations.create(
            TENANT_A,
            "microsoft",
            "Microsoft 365",
            integration_id=integration_id,
            config=config,
            secret_ciphertext=encrypt_secret(box, TENANT_A, integration_id, secret),
            events=[],
            enabled=enabled,
        )
        fake = FakeMicrosoft(cloud=cloud, geo=geo)
        clients = MicrosoftClients.create(install, transport=fake.transport(), resolver=fake.resolver(), sleep=no_sleep)
        events = FakeEvents()
        service = ResponseService(repos, install, events, microsoft=clients, secret_box=box)
        return MicrosoftEnv(
            service=service, fake=fake, tenant_id=TENANT_A, repos=repos, settings=install, integration=integration,
            box=box, secret=secret, events=events,
        )

    return build
