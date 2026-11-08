"""Health and metrics HTTP server embedded in the worker and scheduler processes.

Serves ``/metrics`` (Prometheus exposition of the observability registry and
the ingestion registry, which the scheduler's source polls feed),
``/healthz`` (the event loop answers and the role's main loop is alive) and
``/readyz`` (dependency pings) on the process's own event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import Awaitable, Callable, Dict, Iterator, Optional

import uvicorn
from prometheus_client import generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from lg_sotf.db.pool import Database
from lg_sotf.ingestion.metrics import REGISTRY as INGESTION_REGISTRY
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import render_latest
from lg_sotf.security.shadow import allow, egress

log = get_logger(__name__)

ReadinessCheck = Callable[[], Awaitable[None]]
LivenessCheck = Callable[[], bool]
PING_TIMEOUT_S = 2.0


def database_check(db: Database) -> ReadinessCheck:
    async def check() -> None:
        await db.ping(acquire_timeout_s=PING_TIMEOUT_S)

    return check


def redis_check(redis: object) -> ReadinessCheck:
    async def check() -> None:
        await redis.ping()  # type: ignore[attr-defined]

    return check


def build_health_app(checks: Dict[str, ReadinessCheck], live: Optional[LivenessCheck] = None) -> Starlette:
    async def healthz(_: Request) -> Response:
        if live is not None and not live():
            return JSONResponse({"status": "unhealthy"}, status_code=503)
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        results: Dict[str, str] = {}
        for name, check in checks.items():
            try:
                await asyncio.wait_for(check(), timeout=PING_TIMEOUT_S)
                results[name] = "ok"
            except Exception as exc:  # noqa: BLE001 - any failure means not ready; reported, not raised
                results[name] = "error"
                log_failure(log, "health.not_ready", exc, level="warning", dependency=name)
        ok = all(v == "ok" for v in results.values())
        return JSONResponse(
            {"status": "ok" if ok else "unavailable", "checks": results}, status_code=200 if ok else 503
        )

    async def metrics(_: Request) -> Response:
        payload, content_type = render_latest()
        return Response(payload + generate_latest(INGESTION_REGISTRY), media_type=content_type)

    return Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
            Route("/metrics", metrics, methods=["GET"]),
        ]
    )


class _EmbeddedServer(uvicorn.Server):
    """uvicorn server that leaves signal handling to the owning process."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


class HealthServer:
    """Runs the health app on ``host:port`` as a task on the current loop."""

    def __init__(
        self,
        checks: Dict[str, ReadinessCheck],
        *,
        host: str = "0.0.0.0",  # noqa: S104 - probes and Prometheus scrape the pod IP
        port: int = 9100,
        live: Optional[LivenessCheck] = None,
    ) -> None:
        config = uvicorn.Config(
            build_health_app(checks, live),
            host=host,
            port=port,
            lifespan="off",
            log_config=None,
            access_log=False,
            server_header=False,
        )
        self._server = _EmbeddedServer(config)
        self._host = host
        self._port = port
        self._socket: Optional[socket.socket] = None
        self._task: Optional[asyncio.Task[None]] = None

    @property
    def port(self) -> int:
        """Bound port (useful when started with port 0)."""
        if self._socket is not None:
            return int(self._socket.getsockname()[1])
        return self._port

    @egress("health_listener", allow("binds the local health and metrics listener; sends nothing"))
    def _bind(self) -> socket.socket:
        # Bound here rather than by uvicorn, which calls sys.exit() when the port is taken.
        family = socket.AF_INET6 if ":" in self._host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
        except OSError:
            sock.close()
            raise
        sock.set_inheritable(True)
        return sock

    async def start(self) -> None:
        self._socket = self._bind()
        self._task = asyncio.create_task(self._server.serve(sockets=[self._socket]), name="health-server")
        while not self._server.started:
            if self._task.done():
                self._task.result()
                raise RuntimeError("health server exited during startup")
            await asyncio.sleep(0.01)
        log.info("health.server_started", port=self.port)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._server.should_exit = True
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except TimeoutError:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self._task = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    async def __aenter__(self) -> HealthServer:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()
