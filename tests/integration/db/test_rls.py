"""Row-level security: tenants can never see or touch each other's rows."""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import asyncpg
import pytest

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, Repositories
from lg_sotf.db.repos.integrations import NewOutboxEntry
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

TENANT_TABLES = (
    "users",
    "user_mfa",
    "refresh_tokens",
    "api_keys",
    "sources",
    "alerts",
    "alert_events",
    "workflow_runs",
    "escalations",
    "analyst_feedback",
    "response_actions",
    "suppression_rules",
    "indicator_sightings",
    "llm_usage_daily",
    "usage_daily",
    "audit_log",
    "integrations",
    "notification_outbox",
    "external_tickets",
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def seed_everything(repos: Repositories, tenant_id: str) -> str:
    """One row in every tenant-owned table for ``tenant_id``; returns the alert id."""
    now = datetime.now(UTC)
    user = await repos.users.create(tenant_id, f"analyst@{tenant_id}.test", "analyst", password_hash="x")
    await repos.user_mfa.set_pending(tenant_id, user.id, f"ciphertext-{tenant_id}")
    await repos.refresh_tokens.create(tenant_id, user.id, _sha(f"rt-{tenant_id}"), now + timedelta(days=1))
    await repos.api_keys.create(tenant_id, "ingest", "lgk_abcd", _sha(f"key-{tenant_id}"), ["ingest"])
    await repos.sources.create(tenant_id, "splunk", "Splunk")
    alert_id = await make_alert(repos, tenant_id)
    await repos.alert_events.append(tenant_id, alert_id, "ingested")
    await repos.runs.upsert_queued(tenant_id, alert_id)
    esc, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="uncertain")
    fb, _ = await repos.feedback.create(tenant_id, esc.id, alert_id, "false_positive", user_id=user.id)
    await repos.actions.propose(tenant_id, alert_id, "block_ip", "203.0.113.7", "medium")
    await repos.suppressions.create(tenant_id, "noisy", {"title": "Suspicious login"}, source_feedback_id=fb.id)
    await repos.indicators.add_sightings(tenant_id, alert_id, [("ip", _sha("203.0.113.7"), "203.0.113.x", now)])
    await repos.llm_usage.upsert_daily(
        [
            LLMUsageDelta(
                tenant_id=tenant_id,
                day=date.today(),
                model="m",
                agent="triage",
                calls=1,
                cost_usd=Decimal("0.01"),
            )
        ]
    )
    await repos.usage.add_ingested(tenant_id, 1)
    await repos.audit.append(tenant_id, "user", str(user.id), "alert.viewed", "alert", alert_id)
    integration = await repos.integrations.create(tenant_id, "email", "Mail", config={"recipients": ["a@b.co"]})
    await repos.integrations.enqueue(
        tenant_id,
        [NewOutboxEntry(integration_id=integration.id, event_id=uuid4(), event_type="escalation.created",
                        operation="notify", dedupe_key=f"seed:{esc.id}", alert_id=alert_id, payload={"k": 1})],
    )
    await repos.integrations.add_ticket(
        tenant_id, integration.id, system="jira", alert_id=alert_id, escalation_id=esc.id, external_key="SOC-1"
    )
    return alert_id


async def _counts(conn: asyncpg.Connection) -> dict:
    return {t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in TENANT_TABLES}  # noqa: S608


async def test_unfiltered_queries_only_see_own_tenant(db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_A)

    async with db.tenant_tx(TENANT_B) as conn:
        assert set((await _counts(conn)).values()) == {0}
        assert [r["id"] for r in await conn.fetch("SELECT id FROM tenants")] == [TENANT_B]

    async with db.tenant_tx(TENANT_A) as conn:
        counts = await _counts(conn)
        assert all(n >= 1 for n in counts.values()), counts
        assert [r["id"] for r in await conn.fetch("SELECT id FROM tenants")] == [TENANT_A]


async def test_transaction_without_tenant_sees_nothing(db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_A)
    async with db.connection() as conn:
        async with conn.transaction():
            assert set((await _counts(conn)).values()) == {0}
            assert await conn.fetchval("SELECT count(*) FROM tenants") == 0
        assert await conn.fetchval("SELECT count(*) FROM alerts") == 0


async def test_system_tx_sees_all_tenants(db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_A)
    await seed_everything(repos, TENANT_B)
    async with db.system_tx() as conn:
        counts = await _counts(conn)
        assert all(n >= 2 for n in counts.values()), counts
        tenants = {r["tenant_id"] for r in await conn.fetch("SELECT DISTINCT tenant_id FROM alerts")}
        assert tenants == {TENANT_A, TENANT_B}


async def test_cannot_update_or_delete_other_tenant_rows(db: Database, repos: Repositories) -> None:
    alert_id = await seed_everything(repos, TENANT_A)
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.execute("UPDATE alerts SET title = 'pwned'") == "UPDATE 0"
        assert await conn.execute("DELETE FROM alerts") == "DELETE 0"
        assert await conn.execute("UPDATE tenants SET name = 'B renamed'") == "UPDATE 1"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.title == "Suspicious login"
    assert (await repos.tenants.get(TENANT_A)).name == "Tenant A"


async def test_cannot_insert_rows_for_another_tenant(db: Database, repos: Repositories) -> None:
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_B) as conn:
            await conn.execute(
                "INSERT INTO alerts (tenant_id, source_id, source_alert_id, fingerprint, title, severity, occurred_at) "
                "VALUES ($1, 's', '1', 'f', 't', 'low', now())",
                TENANT_A,
            )


async def test_cannot_move_row_to_another_tenant(db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_B)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_B) as conn:
            await conn.execute("UPDATE suppression_rules SET tenant_id = $1", TENANT_A)


async def test_repositories_do_not_leak_across_tenants(repos: Repositories) -> None:
    alert_id = await seed_everything(repos, TENANT_A)
    with pytest.raises(NotFound):
        await repos.alerts.get(TENANT_B, alert_id)
    page = await repos.alerts.list(TENANT_B)
    assert page.items == []
    assert await repos.users.get_by_email(TENANT_B, f"analyst@{TENANT_A}.test") is None
    with pytest.raises(NotFound):
        await repos.runs.get(TENANT_B, alert_id)


async def test_self_references_cannot_point_into_another_tenant(db: Database, repos: Repositories) -> None:
    """Composite (tenant_id, id) foreign keys: no cross-tenant links and no existence oracle."""
    now = datetime.now(UTC)
    a_user = await repos.users.create(TENANT_A, "a@x.io", "analyst")
    b_user = await repos.users.create(TENANT_B, "b@x.io", "analyst")
    a_token = await repos.refresh_tokens.create(TENANT_A, a_user.id, _sha("a-tok"), now + timedelta(days=1))
    b_token = await repos.refresh_tokens.create(TENANT_B, b_user.id, _sha("b-tok"), now + timedelta(days=1))
    for target in (b_token.id, uuid4()):
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute("UPDATE refresh_tokens SET replaced_by = $1 WHERE id = $2", target, a_token.id)
    async with db.tenant_tx(TENANT_A) as conn:
        await conn.execute("UPDATE refresh_tokens SET replaced_by = id WHERE id = $1", a_token.id)
    async with db.system_tx() as conn:
        rows = await conn.fetch(
            "SELECT conname FROM pg_constraint WHERE contype = 'f' AND conrelid = ANY($1::regclass[]) "
            "AND array_length(conkey, 1) = 1 AND confrelid <> 'tenants'::regclass",
            list(TENANT_TABLES),
        )
    assert rows == [], "every intra-tenant foreign key must include tenant_id"


async def test_direct_partition_access_is_also_isolated(db: Database, repos: Repositories) -> None:
    await seed_everything(repos, TENANT_A)
    async with db.system_tx() as conn:
        partition = await conn.fetchval(
            "SELECT tableoid::regclass::text FROM alert_events WHERE tenant_id = $1 LIMIT 1", TENANT_A
        )
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.fetchval(f"SELECT count(*) FROM {partition}") == 0  # noqa: S608
    async with db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval(f"SELECT count(*) FROM {partition}") == 1  # noqa: S608


async def test_checkpoint_tables_are_tenant_isolated(db: Database, repos: Repositories, migrated_database_url: str) -> None:
    """AUTHZ-5: LangGraph checkpoints (full alert state) are under the same RLS as tenant tables."""
    from lg_sotf.db.migrate import setup_checkpointer

    await setup_checkpointer(migrated_database_url)
    await setup_checkpointer(migrated_database_url)  # idempotent re-apply
    thread_b = f"{TENANT_B}:alert-1"
    async with db.system_tx() as conn:
        for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
            await conn.execute(f"DELETE FROM {table}")  # noqa: S608
        await conn.execute(
            "INSERT INTO checkpoints (thread_id, checkpoint_id, checkpoint) VALUES ($1, 'c1', '{}'::jsonb)", thread_b
        )
        await conn.execute(
            "INSERT INTO checkpoint_blobs (thread_id, channel, version, type) VALUES ($1, 'ch', '1', 'empty')", thread_b
        )
        await conn.execute(
            "INSERT INTO checkpoint_writes (thread_id, checkpoint_id, task_id, idx, channel, blob) "
            "VALUES ($1, 'c1', 't', 0, 'ch', '\\x00'::bytea)",
            thread_b,
        )
        flags = await conn.fetch(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname IN ('checkpoints', 'checkpoint_blobs', 'checkpoint_writes')"
        )
    assert len(flags) == 3 and all(r["relrowsecurity"] and r["relforcerowsecurity"] for r in flags)
    try:
        for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes"):
            async with db.tenant_tx(TENANT_A) as conn:
                assert await conn.fetchval(f"SELECT count(*) FROM {table}") == 0  # noqa: S608
                assert await conn.execute(f"DELETE FROM {table}") == "DELETE 0"  # noqa: S608
            async with db.tenant_tx(TENANT_B) as conn:
                assert await conn.fetchval(f"SELECT count(*) FROM {table}") == 1  # noqa: S608
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with db.tenant_tx(TENANT_A) as conn:
                await conn.execute(
                    "INSERT INTO checkpoints (thread_id, checkpoint_id, checkpoint) VALUES ($1, 'c2', '{}'::jsonb)",
                    thread_b,
                )
    finally:
        async with db.system_tx() as conn:
            for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                await conn.execute(f"DELETE FROM {table}")  # noqa: S608
