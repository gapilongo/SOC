from __future__ import annotations

import httpx

from lg_sotf.observability.metrics import record_run
from lg_sotf.runtime.health import HealthServer, build_health_app


async def _ok() -> None:
    return None


async def _down() -> None:
    raise ConnectionError("no route to host")


async def test_readyz_reports_each_dependency() -> None:
    app = build_health_app({"database": _ok, "redis": _down})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["checks"] == {"database": "ok", "redis": "error"}
        assert "no route" not in resp.text

    app = build_health_app({"database": _ok})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/readyz")).status_code == 200


async def test_healthz_follows_liveness_callback() -> None:
    alive = {"v": True}
    app = build_health_app({}, live=lambda: alive["v"])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/healthz")).status_code == 200
        alive["v"] = False
        assert (await client.get("/healthz")).status_code == 503


async def test_metrics_exposes_registry_over_real_socket() -> None:
    record_run("completed")
    server = HealthServer({"database": _ok}, host="127.0.0.1", port=0)
    async with server:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{server.port}") as client:
            resp = await client.get("/metrics")
            assert resp.status_code == 200
            assert "lgsotf_runs_total" in resp.text
            assert (await client.get("/healthz")).json() == {"status": "ok"}
