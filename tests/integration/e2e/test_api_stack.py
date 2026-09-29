"""The whole product through its HTTP API: in-process app, real worker, real Postgres and Redis.

This is the scripted, repeatable twin of ``scripts/smoke_stack.sh`` (which
runs the same driver, ``scripts/smoke_stack.py``, against the docker compose
stack). Here the API is the ASGI app served in-process (HTTP through
``httpx.ASGITransport``, the WebSocket through an in-process uvicorn server)
and alerts are processed by a real :class:`~lg_sotf.runtime.worker.Worker`
with the workflow engine and the fake LLM.

* ``test_customer_flow``: login, API keys, canonical and vendor ingest, the
  WebSocket stream, escalation claim/decision, dry-run approvals, closure,
  dashboard, LLM usage, audit log and chain, metrics, tenant isolation,
  refresh rotation and logout; every step through HTTP only.
* ``test_worker_restart_mid_processing_loses_no_alert``: the worker is
  cancelled while runs are in flight and a fresh one takes over.
* ``test_readiness_follows_redis``: ``/readyz`` goes 503 while Redis is
  unreachable and recovers.
* ``test_approval_committed_during_execution_is_not_lost``: regression for a
  race found by the docker smoke run (see the test's docstring).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, AsyncIterator, Callable, Dict, List

import httpx
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr

from lg_sotf.api.app import create_app
from lg_sotf.db.repos import Repositories
from lg_sotf.runtime.worker import Worker
from lg_sotf.security.hashing import hash_password
from lg_sotf.services.response import ResponseService
from lg_sotf.services.review import ReviewService
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.e2e.conftest import Stack, eventually, running

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
JWT_SECRET = "lg-sotf-test-suite-only-jwt-secret-not-for-use"
METRICS_TOKEN = "lg-sotf-test-suite-only-metrics-token"
ADMIN_EMAIL = "admin@a.example.com"
ADMIN_PASSWORD = "correct horse battery staple a"
B_EMAIL = "admin@b.example.com"
B_PASSWORD = "correct horse battery staple b"


def _load_driver() -> ModuleType:
    """``scripts/smoke_stack.py`` is a standalone script, not a package module; load it by path."""
    name = "lg_sotf_smoke_driver"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "smoke_stack.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = _load_driver()


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:  # pragma: no cover - uvicorn API differs by version
        pass


@asynccontextmanager
async def serve(app: FastAPI) -> AsyncIterator[str]:
    """Serve an already-started app (lifespan off) on an ephemeral port for WebSocket clients."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    server = _Server(uvicorn.Config(app, lifespan="off", log_config=None, access_log=False))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)
        sock.close()


@dataclass
class Platform:
    stack: Stack
    app: FastAPI
    client: httpx.AsyncClient
    ws_base_url: str
    engine: Any = None

    def smoke(self, timeout: float = 60.0) -> Any:
        return driver.Smoke(self.client, "https://testserver", timeout=timeout, ws_base_url=self.ws_base_url)

    def worker(self, name: str) -> Worker:
        return self.stack.worker(self.engine, name, usage_flush_interval_s=0.5)


@pytest_asyncio.fixture
async def platform(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Platform]:
    stack = stack_factory()
    s = stack.settings
    stack.settings = s.model_copy(
        update={
            "auth": s.auth.model_copy(update={"jwt_secret": SecretStr(JWT_SECRET)}),
            "api": s.api.model_copy(
                update={
                    "cors_origins": ["https://ui.example.com"],
                    "metrics_token": SecretStr(METRICS_TOKEN),
                    "rate_limit_per_minute": 10_000,
                    "ingest_rate_limit_per_minute": 10_000,
                    "login_rate_limit_per_minute": 1_000,
                }
            ),
        }
    )
    await repos.users.create(
        TENANT_A, ADMIN_EMAIL, "admin", password_hash=hash_password(ADMIN_PASSWORD), is_platform_admin=True
    )
    await repos.users.create(TENANT_B, B_EMAIL, "admin", password_hash=hash_password(B_PASSWORD))
    for key, value in {
        "SMOKE_ADMIN_EMAIL": ADMIN_EMAIL,
        "SMOKE_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "SMOKE_METRICS_TOKEN": METRICS_TOKEN,
        "SMOKE_TENANT_B": TENANT_B,
        "SMOKE_TENANT_B_EMAIL": B_EMAIL,
        "SMOKE_TENANT_B_PASSWORD": B_PASSWORD,
        "SMOKE_EXPECT_SECURE_COOKIE": "1",
    }.items():
        monkeypatch.setenv(key, value)

    app = create_app(stack.settings, configure_observability=False)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        async with serve(app) as ws_base_url:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://testserver", cookies=driver.no_cookie_jar()
            ) as client:
                platform = Platform(stack=stack, app=app, client=client, ws_base_url=ws_base_url)
                platform.engine = await stack.engine()
                yield platform
    finally:
        await lifespan.__aexit__(None, None, None)


async def test_customer_flow(platform: Platform, repos: Repositories) -> None:
    async with running(platform.worker("w1")):
        await platform.smoke().flow()

    # What the HTTP flow did is really in the database, in the right tenants.
    alerts_a = (await repos.alerts.list(TENANT_A, limit=200)).items
    assert alerts_a and all(a.status == "closed" for a in alerts_a)
    assert {a.disposition for a in alerts_a} <= {"malicious", "benign"}
    assert "malicious" in {a.disposition for a in alerts_a}
    alerts_b = (await repos.alerts.list(TENANT_B, limit=200)).items
    assert [a.title for a in alerts_b] == ["Tenant B scheduled backup"]
    executed = [a for a in (await repos.actions.list(TENANT_A, limit=200)).items if a.status == "dry_run"]
    assert executed and all(a.approved_by for a in executed)
    assert (await repos.audit.verify_chain(TENANT_A)).ok and (await repos.audit.verify_chain(TENANT_B)).ok


async def test_worker_restart_mid_processing_loses_no_alert(
    platform: Platform, repos: Repositories, tmp_path: Path
) -> None:
    state = tmp_path / "burst.json"
    smoke = platform.smoke()
    first = platform.worker("w1")
    task = asyncio.create_task(first.run())
    try:
        await smoke.burst(30, state)
        ids: List[str] = json.loads(state.read_text())["alert_ids"]

        async def some_in_flight() -> bool:
            statuses = [(await repos.runs.get(TENANT_A, a)).status for a in ids]
            return "running" in statuses and "queued" in statuses

        await eventually(some_in_flight, within=30, interval=0.01)
    finally:
        # Crash: the task is cancelled with runs in flight (no drain, no acks for them).
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    in_flight = [a for a in ids if (await repos.runs.get(TENANT_A, a)).status in ("queued", "running")]
    assert in_flight, "the crash must happen mid-processing"

    async with running(platform.worker("w2")):
        await smoke.settled(state)
    runs = {a: (await repos.runs.get(TENANT_A, a)).status for a in ids}
    assert set(runs.values()) <= {"completed", "waiting_human", "waiting_approval"}, runs
    assert len(runs) == len(ids)


async def test_readiness_follows_redis(platform: Platform, monkeypatch: pytest.MonkeyPatch) -> None:
    client, redis = platform.client, platform.app.state.ctx.redis
    assert (await client.get("/readyz")).status_code == 200

    async def down() -> None:
        raise ConnectionError("redis is down")

    with monkeypatch.context() as patch:
        patch.setattr(redis, "ping", down)
        response = await client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "checks": {"database": "ok", "redis": "error"}}
        assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/readyz")).json()["status"] == "ok"


async def test_approval_committed_during_execution_is_not_lost(
    platform: Platform, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Approve two actions one after the other while the worker is between execute() and awaiting().

    Found by ``scripts/smoke_stack.sh``: an analyst approving several actions
    quickly left one ``approved`` forever and the alert re-escalated (L3,
    "automatic response left the threat without a human or a completed
    action") without ever executing it. Expected: every approved action runs.
    """
    stack = platform.stack
    admin = (await repos.users.list(TENANT_A))[0]
    review = ReviewService(repos, stack.settings, stack.events)
    result = await stack.ingest(TENANT_A, "api", [driver.beacon_event("race", 1)])
    alert_id = result.inserted[0].alert_id
    await stack.dispatch(TENANT_A, result)

    async with running(platform.worker("w1")):
        await eventually(lambda: _run_is(repos, alert_id, ("waiting_approval", "waiting_human")), within=30)
        if (await repos.runs.get(TENANT_A, alert_id)).status == "waiting_human":
            esc = await repos.escalations.get_active_for_alert(TENANT_A, alert_id)
            assert esc is not None
            for rid, payload in await review.decide(
                TENANT_A, esc.id, admin.id, "admin", "true_positive", None, [], esc.version
            ):
                await stack.queue.enqueue_resume(TENANT_A, rid, payload)
            await eventually(lambda: _run_is(repos, alert_id, ("waiting_approval",)), within=30)
        pending = [
            str(a.id)
            for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
            if a.status == "awaiting_approval"
        ]
        assert len(pending) >= 2
        first, late = pending[0], pending[1:]

        # The late approvals commit exactly between the execute pass and the awaiting() re-read.
        original = ResponseService.awaiting
        injected: Dict[str, bool] = {}

        async def awaiting_after_concurrent_approval(self: ResponseService, *args: Any, **kwargs: Any) -> Any:
            if not injected:
                injected["done"] = True
                for rid, payload in await review.approve_actions(TENANT_A, late, admin.id, "admin"):
                    await stack.queue.enqueue_resume(TENANT_A, rid, payload)
            return await original(self, *args, **kwargs)

        monkeypatch.setattr(ResponseService, "awaiting", awaiting_after_concurrent_approval)
        for rid, payload in await review.approve_actions(TENANT_A, [first], admin.id, "admin"):
            await stack.queue.enqueue_resume(TENANT_A, rid, payload)
        await eventually(lambda: _run_is(repos, alert_id, ("completed", "waiting_human")), within=30)

        async def all_executed() -> bool:
            actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
            return all(a.status == "dry_run" for a in actions if str(a.id) in pending)

        # Every approved action must run; with the race the late ones stay ``approved`` forever.
        await eventually(all_executed, within=15)
    assert injected


async def _run_is(repos: Repositories, alert_id: str, statuses: tuple[str, ...]) -> bool:
    return (await repos.runs.get(TENANT_A, alert_id)).status in statuses
