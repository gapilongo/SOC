"""Install rehearsal: from a fresh database to the first triaged alert through the first-run setup wizard.

PRD-13.1 acceptance: a fresh install triages its first alerts in 30 minutes
or less. The test starts from an empty database, runs ``lg-sotf migrate``
(schema plus the bootstrap tenant and admin from the settings), then makes,
over HTTP, the calls the setup wizard makes in the web UI (the Playwright
spec ``src/lg_front/e2e/wizard.spec.ts`` clicks through the same steps):

1. sign in as the bootstrap admin; setup is not done yet;
2. name the organisation and the first tenant, pick the default model profile
   (EU-hosted);
3. test the configured model (the fake model here);
4. send the sample alerts; a real worker triages them until the first
   verdict (an alert closed, or waiting for an analyst or an approval: the
   moment ``make quickstart`` measures too);
5. finish setup.

It records the elapsed time against the 30-minute budget: as the
``time_to_first_triage_s`` property of the JUnit report and as JSON in
``$LG_SOTF_REHEARSAL_REPORT`` (default: the test's temporary directory).
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr

from lg_sotf.api.app import create_app
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.onboarding.llm_profiles import DEFAULT_PROFILE, PROFILES
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.ops import migrate
from lg_sotf.settings import Settings
from tests.integration.e2e._support import Stack, TappedBus, eventually, running

pytestmark = pytest.mark.integration

BUDGET_S = 30 * 60
API = "/api/v1"
JWT_SECRET = "lg-sotf-test-suite-only-jwt-secret-not-for-use"
ADMIN_EMAIL = "admin@first-run.example.com"
PASSWORD = f"test-only-{secrets.token_urlsafe(12)}"


@pytest_asyncio.fixture
async def fresh_stack(e2e_settings: Callable[..., Settings], db: Database, redis_client: Any) -> AsyncIterator[Stack]:
    """A platform instance over an empty database (``stack_factory`` would create the test tenants)."""
    base = e2e_settings()
    settings = base.model_copy(
        update={
            "auth": base.auth.model_copy(
                update={
                    "jwt_secret": SecretStr(JWT_SECRET),
                    "bootstrap_admin_email": ADMIN_EMAIL,
                    "bootstrap_admin_password": SecretStr(PASSWORD),
                    "bootstrap_tenant_id": "default",
                    "bootstrap_tenant_name": "Default",
                }
            )
        }
    )
    bus = EventBus(redis_client, settings)
    stack = Stack(
        settings=settings,
        db=db,
        redis=redis_client,
        repos=Repositories.create(db),
        queue=WorkQueue(redis_client, settings),
        events=TappedBus(bus),
        ingestion=IngestionService(db, settings),
    )
    try:
        yield stack
    finally:
        for engine in stack.engines:
            await engine.close()
        await stack.ingestion.close()
        await bus.aclose()


async def _ok(response: httpx.Response, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


async def test_fresh_install_triages_its_first_alert_within_30_minutes(
    fresh_stack: Stack,
    db: Database,
    tmp_path: Path,
    record_property: Callable[[str, object], None],
) -> None:
    started = time.monotonic()
    marks: Dict[str, float] = {}

    def mark(step: str) -> None:
        marks[step] = round(time.monotonic() - started, 3)

    async with db.connection() as conn:
        assert await conn.fetchval("SELECT count(*) FROM tenants") == 0, "the rehearsal starts from an empty database"
    stack = fresh_stack
    report = await migrate(stack.settings)
    assert report.tenant_created and report.admin_created == ADMIN_EMAIL
    mark("migrated")

    app = create_app(stack.settings, configure_observability=False)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            login = await _ok(await client.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": PASSWORD}))
            client.headers["Authorization"] = f"Bearer {login['access_token']}"

            # 1. Confirm the admin: setup is not done, the model on offer by default is EU-hosted.
            setup = await _ok(await client.get(f"{API}/onboarding/setup"))
            assert setup["completed"] is False and setup["tenant_id"] == "default"
            default = next(p for p in setup["llm_profiles"] if p["id"] == setup["default_llm_profile"])
            assert default["id"] == DEFAULT_PROFILE and default["residency"] in ("eu", "local")
            mark("admin_confirmed")

            # 2. Organisation and first tenant, 3. model profile.
            saved = await _ok(
                await client.put(
                    f"{API}/onboarding/setup",
                    json={"organisation": "Example Org", "tenant_name": "Example SOC", "llm_profile": DEFAULT_PROFILE},
                )
            )
            assert (saved["organisation"], saved["tenant_name"], saved["llm_profile"]) == (
                "Example Org",
                "Example SOC",
                DEFAULT_PROFILE,
            )
            assert {p["id"] for p in saved["llm_profiles"]} == {p.id for p in PROFILES}
            tested = await _ok(await client.post(f"{API}/tenant/llm/test"))
            assert tested["ok"] is True, tested
            mark("model_tested")

            # 4. Sample alerts, triaged by a real worker.
            engine = await stack.engine()
            async with running(stack.worker(engine, "first-run")):
                samples = await _ok(await client.post(f"{API}/onboarding/sample-alerts"))
                assert samples["inserted"] > 0 and samples["enqueued"] == samples["inserted"]
                mark("samples_sent")

                async def first_verdict() -> bool:
                    return bool((await _ok(await client.get(f"{API}/onboarding/status")))["first_verdict"])

                await eventually(first_verdict, within=180, interval=0.25)
                mark("first_alert_triaged")

            # 5. Finish: from now on the Overview links to the proof of value instead of the wizard.
            done = await _ok(await client.post(f"{API}/onboarding/setup/complete", json={}))
            assert done["completed"] is True and done["completed_at"]
            mark("setup_completed")
    finally:
        await lifespan.__aexit__(None, None, None)

    elapsed = marks["first_alert_triaged"]
    result = _record(marks, tmp_path)
    record_property("time_to_first_triage_s", elapsed)
    assert elapsed <= BUDGET_S, result


def _record(marks: Dict[str, float], tmp_path: Path) -> Dict[str, Any]:
    """Write the timings as JSON (``$LG_SOTF_REHEARSAL_REPORT`` or the test's temporary directory) and print them."""
    elapsed = marks["first_alert_triaged"]
    result = {
        "budget_s": BUDGET_S,
        "time_to_first_triage_s": elapsed,
        "within_budget": elapsed <= BUDGET_S,
        "steps": marks,
    }
    out = Path(os.environ.get("LG_SOTF_REHEARSAL_REPORT") or tmp_path / "first-run-rehearsal.json")
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"first-run rehearsal: first alert triaged after {elapsed:.1f} s (budget {BUDGET_S} s); {out}")
    return result
