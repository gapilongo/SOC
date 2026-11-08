"""The review of PR #308, as the production runtime role: a blind audit's rows cannot be forged or rewritten.

The reviewer's proof inserted pre-labelled items into a finished run; here every such write is refused
(column-level INSERT and UPDATE grants, the label-once and insert triggers, and RLS).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict

import asyncpg
import pytest

from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio


async def _closed(app: Repositories, owner: Repositories, tenant: str) -> str:
    alert_id = await make_alert(app, tenant)
    async with owner.db.system_tx() as conn:
        await conn.execute("UPDATE alerts SET status='closed', disposition='benign', closed_at=now() - interval '1 hour' "
                           "WHERE tenant_id=$1 AND id=$2", tenant, alert_id)
    return alert_id


async def _attempt(app: Repositories, sql: str, *args: object) -> str:
    try:
        async with app.db.tenant_tx(TENANT_A) as conn:
            await conn.execute(sql, *args)
    except asyncpg.PostgresError as exc:
        return type(exc).__name__
    return "ALLOWED"


async def test_runtime_role_blind_audit_integrity(app: Repositories, repos: Repositories) -> None:
    a1, a2, _ = [await _closed(app, repos, TENANT_A) for _ in range(3)]
    b1 = await _closed(app, repos, TENANT_B)
    now = datetime.now(UTC)
    run = await app.blind_audit.create_run(
        TENANT_A, since=now - timedelta(days=1), until=now, seed=1, sample_rate=None, min_sample=0, fixed_size=1,
        frame_size=3, items=[(a1, 1, "benign")], trigger="api", created_by="t",
    )
    assert run.seed_source == "server"
    [item] = (await app.blind_audit.list_items(TENANT_A)).items
    assert await app.blind_audit.label(TENANT_A, item.id, label="benign", notes=None, agreement=True, labelled_by=None,
                                       labelled_by_actor="t", escalation_id=None, now=now)
    results: Dict[str, str] = {}
    for stmt in (
        "UPDATE blind_audit_items SET label = 'malicious' WHERE id = $1",
        "UPDATE blind_audit_items SET labelled_at = now() WHERE id = $1",
        "UPDATE blind_audit_items SET ai_class = 'malicious' WHERE id = $1",
        "DELETE FROM blind_audit_items WHERE id = $1",
    ):
        results[stmt] = await _attempt(app, stmt, item.id)
    for stmt in ("DELETE FROM blind_audit_runs", "UPDATE blind_audit_runs SET frame_size = 0"):
        results[stmt] = await _attempt(app, stmt)
    results["insert prelabelled"] = await _attempt(
        app,
        "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class, label, agreement,"
        " labelled_at, labelled_by_actor) VALUES ($1, $2, $3, 2, 'benign', 'benign', true, now(), 'x')",
        TENANT_A, run.id, a2,
    )
    results["insert beyond the run's sample"] = await _attempt(
        app,
        "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class) VALUES ($1, $2, $3, 2, 'benign')",
        TENANT_A, run.id, a2,
    )
    results["cross-tenant insert"] = await _attempt(
        app,
        "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class) VALUES ($1, $2, $3, 1, 'benign')",
        TENANT_B, run.id, b1,
    )
    results["recorded seed claimed by a caller"] = await _attempt(
        app,
        "INSERT INTO blind_audit_runs (tenant_id, window_start, window_end, seed, seed_source, min_sample, frame_size, "
        "sample_size, trigger) VALUES ($1, now() - interval '2 days', now() - interval '1 day', 1, 'server', 0, 0, 0, 'api')",
        TENANT_A,
    )
    results["delete labelled alert"] = await _attempt(app, "DELETE FROM alerts WHERE id = $1", a1)
    allowed = [k for k, v in results.items() if v == "ALLOWED"]
    assert allowed == [], results
    assert results["insert prelabelled"] == "InsufficientPrivilegeError"
    assert results["insert beyond the run's sample"] == "CheckViolationError"
    stored = await app.blind_audit.get_item(TENANT_A, item.id)
    assert stored.label == "benign" and stored.labelled_at is not None
    async with repos.db.system_tx() as conn:
        assert await conn.fetchval("SELECT count(*) FROM blind_audit_items") == 1
