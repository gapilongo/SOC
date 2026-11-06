"""FastAPI application factory (``lg-sotf api`` runs ``create_app`` with ``factory=True``).

The API process authenticates, scopes every query to the caller's tenant and
enqueues work; it never runs a workflow in-process (contract section 1).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional, Tuple

import httpx
from fastapi import APIRouter, FastAPI
from starlette.middleware.cors import CORSMiddleware

from lg_sotf import __version__
from lg_sotf.api.auth.oidc import OIDCVerifier
from lg_sotf.api.auth.tokens import TokenService
from lg_sotf.api.context import ApiContext, TenantCache, allowed_origins
from lg_sotf.api.errors import install_error_handlers
from lg_sotf.api.middleware import BodyLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from lg_sotf.api.ratelimit import RateLimiter
from lg_sotf.api.routers import (
    alerts,
    audit,
    auth,
    compliance,
    dashboard,
    health,
    identity,
    ingest,
    integrations,
    mfa,
    onboarding,
    platform,
    reports,
    review,
    sources,
    suppressions,
    tenant,
    triage,
    ws,
)
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.email import EmailLimits
from lg_sotf.observability.logging import configure_logging, get_logger, is_configured
from lg_sotf.observability.tracing import setup_tracing, shutdown_tracing
from lg_sotf.settings import Settings, get_settings

log = get_logger(__name__)

API_PREFIX = "/api/v1"
INGEST_PREFIX = f"{API_PREFIX}/ingest/"
EMAIL_INGEST_PATH = f"{API_PREFIX}/ingest/email"
ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID", "X-Request-ID"]
EXPOSED_HEADERS = ["X-Request-ID", "Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"]


def cors_origins(settings: Settings) -> list[str]:
    """The configured origins without ``*`` (credentials are allowed, so a wildcard is never used)."""
    if "*" in (o.strip() for o in settings.api.cors_origins):
        log.warning("api.cors_wildcard_ignored")
    return allowed_origins(settings)


async def build_context(settings: Settings, *, http_transport: Optional[httpx.AsyncBaseTransport] = None) -> ApiContext:
    from lg_sotf.ingestion.service import IngestionService
    from lg_sotf.llm import TokenBudget
    from lg_sotf.queue.events import EventBus
    from lg_sotf.queue.producer import WorkQueue
    from lg_sotf.queue.redis import create_redis
    from lg_sotf.security.crypto import load_secret_box
    from lg_sotf.services.review import ReviewService

    db = Database(settings.database, application_name="lg-sotf-api")
    await db.open()
    redis = create_redis(settings)
    try:
        repos = Repositories.create(db)
        events = EventBus(redis, settings)
        box = load_secret_box(settings)
        oidc = OIDCVerifier(settings.auth, transport=http_transport) if settings.auth.oidc_issuer else None
        return ApiContext(
            settings=settings,
            db=db,
            repos=repos,
            redis=redis,
            queue=WorkQueue(redis, settings),
            events=events,
            ingestion=IngestionService(
                db,
                settings,
                secret_box=box,
                repos=repos,
                budget=TokenBudget(redis, settings, usage_seed=repos.llm_usage.day_tokens),
            ),
            review=ReviewService(repos, settings, events, secret_box=box),
            tokens=TokenService(settings),
            limiter=RateLimiter(redis, settings.redis.key_prefix),
            tenants=TenantCache(repos),
            secret_box=box,
            oidc=oidc,
        )
    except BaseException:
        await redis.aclose()
        await db.close()
        raise


async def close_context(ctx: ApiContext) -> None:
    for step in (ctx.events.aclose, ctx.ingestion.close):
        try:
            await step()
        except Exception as exc:  # noqa: BLE001 - keep closing the rest
            log.warning("api.shutdown_step_failed", error_type=type(exc).__name__)
    if ctx.oidc is not None:
        await ctx.oidc.aclose()
    await ctx.redis.aclose()
    await ctx.db.close()


def api_routers() -> Tuple[APIRouter, ...]:
    """The ``/api/v1`` routers, in matching order (the first route that matches a path wins)."""
    return (
        auth.router,
        mfa.router,
        ingest.router,
        alerts.router,
        # Before review.escalations: /escalations/groups and /escalations/bulk/... are not escalation ids.
        triage.router,
        review.escalations,
        review.actions,
        sources.router,
        suppressions.router,
        identity.users,
        identity.api_keys,
        tenant.router,
        dashboard.dashboard,
        dashboard.usage,
        audit.router,
        platform.router,
        onboarding.router,
        compliance.alerts,
        compliance.platform,
        integrations.router,
        integrations.tickets,
        reports.router,
    )


def create_app(
    settings: Optional[Settings] = None,
    *,
    http_transport: Optional[httpx.AsyncBaseTransport] = None,
    configure_observability: bool = True,
) -> FastAPI:
    """Build the API. ``http_transport`` (tests) serves the OIDC issuer's JWKS."""
    s = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        s.assert_safe()
        if configure_observability:
            if not is_configured():
                configure_logging(s)
            setup_tracing(s)
        ctx = await build_context(s, http_transport=http_transport)
        app.state.ctx = ctx
        log.info(
            "api.started", environment=s.environment, oidc=ctx.oidc is not None, encryption=ctx.secret_box is not None
        )
        try:
            yield
        finally:
            app.state.ctx = None
            await close_context(ctx)
            if configure_observability:
                shutdown_tracing()
            log.info("api.stopped")

    docs = s.api.docs_enabled
    app = FastAPI(
        title="LG-SOTF API",
        version=__version__,
        description="Multi-tenant AI triage for security alerts. See docs/api.md for authentication and conventions.",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url=f"{API_PREFIX}/openapi.json" if docs else None,
        swagger_ui_oauth2_redirect_url=None,
    )
    app.state.ctx = None
    install_error_handlers(app)

    api = APIRouter(prefix=API_PREFIX)
    for router in api_routers():
        api.include_router(router)
    app.include_router(health.router)
    app.include_router(health.metrics_router)
    # Probes only: /metrics stays off /api/v1, which the public ingress routes here.
    app.include_router(health.router, prefix=API_PREFIX, include_in_schema=False)
    app.include_router(api)
    app.include_router(ws.router)
    app.include_router(ws.router, prefix=API_PREFIX, include_in_schema=False)

    max_body = s.api.max_body_bytes
    max_ingest = max(s.api.max_ingest_body_bytes, max_body)
    try:
        # A raw reported message may be as large as ingestion.email.max_message_bytes (the route enforces that).
        max_email = max(max_ingest, EmailLimits.from_settings(s.ingestion).max_message_bytes)
    except ValueError:
        max_email = max_ingest  # invalid email settings are reported by the ingestion service

    def limit_for(path: str) -> int:
        if path.rstrip("/") == EMAIL_INGEST_PATH:
            return max_email
        return max_ingest if path.startswith(INGEST_PREFIX) else max_body

    # Added innermost first: the last one added wraps everything.
    app.add_middleware(BodyLimitMiddleware, limit_for=limit_for)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins(s),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=ALLOWED_HEADERS,
        expose_headers=EXPOSED_HEADERS,
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware, force_hsts=s.api.public_url.startswith("https://"))
    app.add_middleware(RequestContextMiddleware)
    return app
