"""Process-wide API dependencies, created by the app lifespan and stored on ``app.state.ctx``."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from redis.asyncio import Redis
from starlette.requests import HTTPConnection

from lg_sotf.api.auth.oidc import OIDCVerifier
from lg_sotf.api.auth.tokens import TokenService
from lg_sotf.api.ratelimit import RateLimiter
from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories, Tenant
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings

TENANT_CACHE_TTL_S = 15.0


def allowed_origins(settings: Settings) -> list[str]:
    """Normalised browser origins (no trailing ``/``, never ``*``), shared by CORS and the WebSocket check."""
    origins = [o.strip().rstrip("/") for o in settings.api.cors_origins if o.strip()]
    return [o for o in origins if o != "*"]


@dataclass
class WebSocketOptions:
    heartbeat_s: float = 25.0
    send_timeout_s: float = 10.0
    max_message_bytes: int = 4_096


class TenantCache:
    """Short-lived cache of tenant rows (status checks on every request)."""

    def __init__(
        self, repos: Repositories, *, ttl_s: float = TENANT_CACHE_TTL_S, clock: Callable[[], float] = time.monotonic
    ):
        self._repos = repos
        self._ttl = ttl_s
        self._clock = clock
        self._entries: Dict[str, Tuple[float, Optional[Tenant]]] = {}

    async def get(self, tenant_id: str) -> Optional[Tenant]:
        now = self._clock()
        hit = self._entries.get(tenant_id)
        if hit is not None and hit[0] > now:
            return hit[1]
        try:
            tenant: Optional[Tenant] = await self._repos.tenants.get(tenant_id)
        except NotFound:
            tenant = None
        if len(self._entries) > 10_000:
            self._entries.clear()
        self._entries[tenant_id] = (now + self._ttl, tenant)
        return tenant

    def invalidate(self, tenant_id: str) -> None:
        self._entries.pop(tenant_id, None)


@dataclass
class ApiContext:
    settings: Settings
    db: Database
    repos: Repositories
    redis: Redis
    queue: WorkQueue
    events: EventBus
    ingestion: IngestionService
    review: ReviewService
    tokens: TokenService
    limiter: RateLimiter
    tenants: TenantCache
    secret_box: Optional[SecretBox] = None
    oidc: Optional[OIDCVerifier] = None
    ws: WebSocketOptions = field(default_factory=WebSocketOptions)

    @property
    def prefix(self) -> str:
        return self.settings.redis.key_prefix


def get_ctx(conn: HTTPConnection) -> ApiContext:
    ctx = getattr(conn.app.state, "ctx", None)
    if ctx is None:
        raise RuntimeError("API context is not initialised (lifespan not started)")
    return ctx
