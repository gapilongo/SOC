"""Helpers shared by the database tests (and the integration fixtures that reset, migrate and truncate)."""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import uuid4

import psycopg
import pytest
from pydantic import SecretStr

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import LLMUsageDelta, NewAlert, Repositories
from lg_sotf.db.repos.outbox import NewOutboxEntry
from lg_sotf.db.urls import database_name, to_libpq_url
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.settings import DatabaseSettings

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
# Acts like the production API/worker role (see tests/integration/db/conftest.py, ``app_db``).
RUNTIME_ROLE = "pg_database_owner"


def db_settings(url: str, **overrides: object) -> DatabaseSettings:
    values = {"url": SecretStr(url), "pool_min": 1, "pool_max": 8, "command_timeout_s": 30.0}
    values.update(overrides)
    return DatabaseSettings(**values)  # type: ignore[arg-type]


def new_alert(
    source_alert_id: Optional[str] = None,
    *,
    source_id: str = "splunk-prod",
    title: str = "Suspicious login",
    severity: str = "high",
    ingested_at: Optional[datetime] = None,
    occurred_at: Optional[datetime] = None,
    raw: Optional[Dict[str, Any]] = None,
    normalized: Optional[Dict[str, Any]] = None,
    **extra: object,
) -> NewAlert:
    return NewAlert(
        source_id=source_id,
        source_alert_id=source_alert_id or uuid4().hex,
        fingerprint=f"fp-{source_alert_id or 'x'}",
        title=title,
        severity=severity,
        occurred_at=occurred_at or datetime.now(UTC),
        ingested_at=ingested_at,
        raw={"vendor": "test"} if raw is None else raw,
        normalized={"title": title} if normalized is None else normalized,
        **extra,  # type: ignore[arg-type]
    )


async def make_alert(repos: Repositories, tenant_id: str, **kwargs: object) -> str:
    alert = new_alert(**kwargs)  # type: ignore[arg-type]
    ids = await repos.alerts.insert_many_if_absent(tenant_id, [alert])
    assert ids == [alert.id]
    return alert.id


ALL_TABLES = (
    "blind_audit_items",
    "blind_audit_runs",
    "investigation_steps",
    "tenant_grants",
    "organisation_members",
    "organisations",
    "external_tickets",
    "notification_outbox",
    "integrations",
    "audit_log",
    "usage_daily",
    "llm_usage_daily",
    "indicator_sightings",
    "suppression_rules",
    "response_actions",
    "analyst_feedback",
    "escalations",
    "workflow_runs",
    "alert_events",
    "alerts",
    "sources",
    "api_keys",
    "refresh_tokens",
    "user_mfa",
    "users",
    "tenants",
)

# Created by AsyncPostgresSaver.setup(); truncated only when present.
CHECKPOINT_TABLES = ("checkpoint_writes", "checkpoint_blobs", "checkpoints")


def reset_schema(url: str) -> None:
    name = database_name(url)
    if "test" not in name:
        pytest.fail(f"refusing to reset database {name!r}: its name must contain 'test'")
    with psycopg.connect(to_libpq_url(url), autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")


def assert_rls_applies(url: str) -> None:
    """Row-level security tests are meaningless for a role that bypasses RLS."""
    with psycopg.connect(to_libpq_url(url), autocommit=True) as conn:
        row = conn.execute(
            "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
    assert row is not None
    name, is_super, bypass = row
    if is_super or bypass:
        pytest.fail(
            f"LG_SOTF_TEST_DATABASE_URL connects as {name!r}, which is a superuser or has BYPASSRLS; "
            "row-level security would not apply. Use a plain role (NOSUPERUSER NOBYPASSRLS CREATEDB) "
            "that owns the test database."
        )


async def truncate_all(db: Database) -> None:
    async with db.system_tx() as conn:
        await conn.execute(f"TRUNCATE {', '.join(ALL_TABLES)} RESTART IDENTITY CASCADE")
        present = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1::text[])",
            list(CHECKPOINT_TABLES),
        )
        if present:
            await conn.execute(f"TRUNCATE {', '.join(r['tablename'] for r in present)}")


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
    "investigation_steps",
    "organisations",
    "organisation_members",
    "tenant_grants",
    "blind_audit_runs",
    "blind_audit_items",
)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def seed_everything(repos: Repositories, tenant_id: str) -> str:
    """One row in every tenant-owned table for ``tenant_id``; returns the alert id."""
    now = datetime.now(UTC)
    user = await repos.users.create(tenant_id, f"analyst@{tenant_id}.test", "analyst", password_hash="x")
    await repos.user_mfa.set_pending(tenant_id, user.id, f"ciphertext-{tenant_id}")
    await repos.refresh_tokens.create(tenant_id, user.id, sha256_hex(f"rt-{tenant_id}"), now + timedelta(days=1))
    await repos.api_keys.create(tenant_id, "ingest", "lgk_abcd", sha256_hex(f"key-{tenant_id}"), ["ingest"])
    await repos.sources.create(tenant_id, "splunk", "Splunk")
    alert_id = await make_alert(repos, tenant_id)
    await repos.alert_events.append(tenant_id, alert_id, "ingested")
    await repos.runs.upsert_queued(tenant_id, alert_id)
    esc, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="uncertain")
    fb, _ = await repos.feedback.create(tenant_id, esc.id, alert_id, "false_positive", user_id=user.id)
    await repos.actions.propose(tenant_id, alert_id, "block_ip", "203.0.113.7", "medium")
    await repos.suppressions.create(tenant_id, "noisy", {"title": "Suspicious login"}, source_feedback_id=fb.id)
    await repos.indicators.add_sightings(tenant_id, alert_id, [("ip", sha256_hex("203.0.113.7"), "203.0.113.x", now)])
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
    await repos.outbox.enqueue(
        tenant_id,
        [NewOutboxEntry(integration_id=integration.id, event_id=uuid4(), event_type="escalation.created",
                        operation="notify", dedupe_key=f"seed:{esc.id}", alert_id=alert_id, payload={"k": 1})],
    )
    await repos.tickets.add(
        tenant_id, integration.id, system="jira", alert_id=alert_id, escalation_id=esc.id, external_key="SOC-1"
    )
    await repos.investigation_steps.append(
        tenant_id, alert_id, f"{tenant_id}:{alert_id}",
        [NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash=sha256_hex("in"), outcome="success",
                      started_at=now)],
    )
    run = await repos.blind_audit.create_run(
        tenant_id, since=now - timedelta(days=7), until=now, seed=7, sample_rate=0.02, min_sample=5, fixed_size=None,
        frame_size=1, items=[(alert_id, 1, "benign")], trigger="cli", created_by="seed",
    )
    item = (await repos.blind_audit.list_items(tenant_id)).items[0]
    await repos.blind_audit.label(
        tenant_id, item.id, label="benign", notes=None, agreement=True, labelled_by=user.id,
        labelled_by_actor=str(user.id), escalation_id=None, now=now,
    )
    assert item.run_id == run.id
    # The tenant is an MSSP organisation with one member, and it has opened itself to another organisation.
    await repos.organisations.upsert(tenant_id, f"MSSP {tenant_id}")
    await repos.organisations.add_member(tenant_id, user.id)
    mssp = f"{tenant_id}-mssp"
    await repos.tenants.provision(mssp, "Another MSSP")
    await repos.organisations.upsert(mssp, "Another MSSP")
    await repos.grants.create(
        tenant_id, mssp, "analyst", reason="seed", created_by="seed", expires_at=now + timedelta(days=1)
    )
    return alert_id
