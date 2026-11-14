"""Shadow mode (AI-E1.5a), review of #295: the probes of the review, asserting the safe behaviour.

Each test is one finding of the review. It failed against the first version of shadow mode and passes now.
The review's "fresh context escapes the scope" probe is a property of Python, not of the platform: the safe
behaviour is that no platform code runs work in a fresh context or on a context-dropping hop, which
``tests/unit/architecture/test_shadow_egress.py::test_no_code_drops_the_run_mode_on_a_thread_or_fresh_context``
enforces on the source.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
from datetime import UTC, datetime
from typing import Any, Dict, List

import pytest
import redis.asyncio as aioredis
from asyncpg.exceptions import InsufficientPrivilegeError, ReadOnlySQLTransactionError

from lg_sotf.core import shadow as core_shadow
from lg_sotf.core.shadow import ShadowRunner
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.llm_usage import LLMUsageDelta
from lg_sotf.llm.usage import get_usage_recorder
from lg_sotf.observability import metrics as m
from lg_sotf.security.hashing import _run_bounded
from lg_sotf.security.shadow import ShadowEffect, ShadowEgressRefused, ShadowRun, in_shadow, shadow_scope
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import SUSPICIOUS_ENTITIES

pytestmark = pytest.mark.integration


async def suspicious(repos: Repositories) -> str:
    return await make_alert(
        repos, TENANT_A, title="Possible C2 beacon from workstation", severity="high",
        normalized={"entities": SUSPICIOUS_ENTITIES}, raw={"vendor": "edr"},
    )


async def usage_rows(db: Database) -> int:
    async with db.tenant_tx(TENANT_A) as conn:
        return int(await conn.fetchval("SELECT count(*) FROM llm_usage_daily"))


async def flush_usage(repos: Repositories, settings: Settings) -> None:
    """What the worker's usage-flush task does, live, outside any shadow scope."""

    async def sink(rows: List[Any]) -> None:
        await repos.llm_usage.upsert_daily([LLMUsageDelta(**row) for row in rows])

    await get_usage_recorder(settings).flush(sink)


async def test_shadow_llm_usage_never_reaches_llm_usage_daily(
    engine_factory: Any, engine_settings: Settings, repos: Repositories, db: Database
) -> None:
    engine: WorkflowEngine = await engine_factory()
    alert_id = await suspicious(repos)
    recorder = get_usage_recorder(engine_settings)
    recorder.reset()
    before = await usage_rows(db)

    outcome = await ShadowRunner(engine.node_deps).run(TENANT_A, alert_id)

    assert [r for r in recorder.pending_rows() if r["tenant_id"] == TENANT_A] == []
    await flush_usage(repos, engine_settings)
    assert await usage_rows(db) == before
    assert outcome.llm_calls > 0 and outcome.llm_tokens > 0, "the run keeps its own LLM use"


async def test_shadow_tokens_never_seed_the_production_budget(
    engine_factory: Any, engine_settings: Settings, repos: Repositories
) -> None:
    engine: WorkflowEngine = await engine_factory()
    budget = engine.node_deps.budget
    assert budget is not None
    alert_id = await suspicious(repos)
    get_usage_recorder(engine_settings).reset()

    await ShadowRunner(engine.node_deps).run(TENANT_A, alert_id)
    await flush_usage(repos, engine_settings)

    assert await repos.llm_usage.day_tokens(TENANT_A, datetime.now(UTC).date()) == 0
    await budget.check_and_reserve(TENANT_A, 1)  # the first production reservation seeds from llm_usage_daily
    assert await budget.used(TENANT_A) == 1


async def test_a_task_started_in_a_shadow_run_stays_in_shadow_mode() -> None:
    """The safe direction: work a shadow run started never turns live, even after the scope ended."""
    seen: List[bool] = []
    go = asyncio.Event()

    async def background_worker() -> None:
        await go.wait()
        seen.append(in_shadow())

    with shadow_scope(ShadowRun("shadow/leak")):
        task = asyncio.create_task(background_worker())
    assert not in_shadow()
    go.set()
    await task
    assert seen == [True]


async def test_the_platform_executor_hop_keeps_the_shadow_flag() -> None:
    """``loop.run_in_executor`` drops the context; the platform's only executor hop carries it over."""
    with shadow_scope(ShadowRun("shadow/exec")):
        assert await _run_bounded(in_shadow) is True
        assert await asyncio.to_thread(in_shadow) is True
        loop = asyncio.get_running_loop()
        assert await loop.run_in_executor(None, contextvars.copy_context().run, in_shadow) is True


async def test_shadow_transactions_refuse_what_read_only_lets_through(db: Database) -> None:
    with shadow_scope(ShadowRun("shadow/ro")):
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.fetchval("SELECT pg_notify('lgsotf_probe', 'x') IS NULL")
        async with db.tenant_tx(TENANT_A) as conn:
            assert await conn.fetchval("SELECT pg_try_advisory_xact_lock(4242)") is True  # ends with the transaction
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ReadOnlySQLTransactionError):
                await conn.execute("CREATE SEQUENCE IF NOT EXISTS probe_seq")
        async with db.tenant_tx(TENANT_A) as conn:  # the shadow role has no sequence privilege either (AI-E1.5c)
            with pytest.raises((ReadOnlySQLTransactionError, InsufficientPrivilegeError)):
                await conn.fetchval("SELECT nextval(pg_get_serial_sequence('alert_events', 'id'))")
        async with db.connection() as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.execute("SET TRANSACTION READ WRITE")
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.execute("SET TRANSACTION READ WRITE")
        async with db.connection() as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.execute("COMMIT")


async def test_shadow_effects_rls(db: Database, repos: Repositories) -> None:
    """Tenant A's shadow effects are invisible to tenant B, and cannot be written for another tenant."""
    alert_id = await make_alert(repos, TENANT_A, title="x", severity="low")
    effect = (ShadowEffect(0, "alert", "AlertsRepo.update", "sunk", {}),)
    await repos.shadow_effects.append(TENANT_A, alert_id, "shadow/abc", effect)
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.fetchval("SELECT count(*) FROM shadow_effects") == 0
    with pytest.raises(Exception):  # noqa: B017 - the foreign key or RLS, whichever PostgreSQL checks first
        await repos.shadow_effects.append(TENANT_B, alert_id, "shadow/abc", effect)


async def test_a_shadow_run_cannot_notify(db: Database) -> None:
    got: List[str] = []

    def heard(*args: Any) -> None:
        got.append(args[-1])

    async with db.connection() as listener:
        await listener.add_listener("lgsotf_probe", heard)
        with shadow_scope(ShadowRun("shadow/notify")):
            async with db.tenant_tx(TENANT_A) as conn:
                with pytest.raises(ShadowEgressRefused):
                    await conn.execute("SELECT pg_notify('lgsotf_probe', 'from-shadow')")
            async with db.tenant_tx(TENANT_A) as conn:
                with pytest.raises(ShadowEgressRefused):
                    await conn.execute("NOTIFY lgsotf_probe, 'from-shadow-2'")
        await asyncio.sleep(0.3)
        await listener.remove_listener("lgsotf_probe", heard)
    assert got == []


async def test_commit_cannot_escape_the_read_only_transaction(repos: Repositories, db: Database) -> None:
    with shadow_scope(ShadowRun("shadow/commit")):
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.execute("COMMIT")
            with pytest.raises(ShadowEgressRefused):
                await conn.execute("SELECT 1; COMMIT; UPDATE tenants SET name = 'pwned' WHERE id = 'tenant-a'")
    assert (await repos.tenants.get(TENANT_A)).name == "Tenant A"


def _total(metric: Any, suffix: str, mode: str) -> float:
    return sum(
        s.value for fam in metric.collect() for s in fam.samples if s.name.endswith(suffix) and s.labels["mode"] == mode
    )


async def test_a_shadow_run_moves_only_the_shadow_metric_series(
    engine_factory: Any, engine_settings: Settings, repos: Repositories
) -> None:
    engine: WorkflowEngine = await engine_factory()
    alert_id = await suspicious(repos)
    live = (_total(m.LLM_CALLS, "_total", "live"), _total(m.NODE_SECONDS, "_count", "live"))
    shadow = (_total(m.LLM_CALLS, "_total", "shadow"), _total(m.NODE_SECONDS, "_count", "shadow"))

    await ShadowRunner(engine.node_deps).run(TENANT_A, alert_id)

    assert (_total(m.LLM_CALLS, "_total", "live"), _total(m.NODE_SECONDS, "_count", "live")) == live
    assert _total(m.LLM_CALLS, "_total", "shadow") > shadow[0]
    assert _total(m.NODE_SECONDS, "_count", "shadow") > shadow[1]
    for metric in (m.LLM_CALLS, m.LLM_TOKENS, m.LLM_COST_USD, m.NODE_SECONDS, m.LLM_REFUSALS, m.LLM_SKIPPED,
                   m.ENRICHMENT_LOOKUPS):
        assert "mode" in metric._labelnames


async def test_a_shadow_run_with_the_production_budget_still_charges_nothing(
    engine_factory: Any, repos: Repositories, redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression the review constructed: a runner that keeps the production budget. Its Redis write is refused."""
    engine: WorkflowEngine = await engine_factory()
    budget = engine.node_deps.budget
    assert budget is not None
    alert_id = await suspicious(repos)
    await budget.add(TENANT_A, 10)  # production already spent tokens today: the key exists
    used = await budget.used(TENANT_A)
    original = dataclasses.replace

    def keep_budget(obj: Any, **changes: Any) -> Any:
        changes.pop("budget", None)
        return original(obj, **changes)

    monkeypatch.setattr(core_shadow.dataclasses, "replace", keep_budget)
    runner = ShadowRunner(engine.node_deps)
    monkeypatch.setattr(core_shadow.dataclasses, "replace", original)
    try:
        await runner.run(TENANT_A, alert_id)
    except ShadowEgressRefused as exc:
        assert exc.boundary == "token_budget"
    assert await budget.used(TENANT_A) == used


async def test_shadow_transactions_keep_no_session_state(db: Database) -> None:
    out: Dict[str, Any] = {}
    with shadow_scope(ShadowRun("shadow/tmp")):
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ReadOnlySQLTransactionError):
                await conn.execute("CREATE TEMP TABLE probe_t (a int)")
        async with db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(ShadowEgressRefused):
                await conn.fetchval("SELECT pg_try_advisory_lock(777)")
            with pytest.raises(ShadowEgressRefused):
                await conn.fetchval("SELECT set_config('app.probe', 'x', false)")
    async with db.system_tx(readonly=True) as conn:
        out["locks"] = await conn.fetchval("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 777")
    assert out == {"locks": 0}
