"""Tenant limits in the database layer: retention bounds at purge time, usage retention, quota-paused polling."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.retention import purge_expired
from lg_sotf.settings import RetentionSettings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

NOW = datetime.now(UTC)


async def _closed(repos: Repositories, tenant_id: str, days_ago: int) -> str:
    alert_id = await make_alert(repos, tenant_id)
    for status in ("queued", "processing"):
        await repos.alerts.update_status(tenant_id, alert_id, status)
    await repos.alerts.update_status(tenant_id, alert_id, "closed", now=NOW - timedelta(days=days_ago))
    return alert_id


async def test_stored_override_below_the_minimum_is_raised_to_it(repos: Repositories, db: Database) -> None:
    # Written before the bound existed (or directly): 1 day, below the default minimum of 7.
    await repos.tenants.update_settings(TENANT_B, {"retention": {"alerts_days": 1}})
    three_days = await _closed(repos, TENANT_B, 3)
    ten_days = await _closed(repos, TENANT_B, 10)

    report = await purge_expired(db, RetentionSettings(), now=NOW)

    assert report.alerts == 1
    assert [a.id for a in (await repos.alerts.list(TENANT_B)).items] == [three_days]
    assert ten_days not in {a.id for a in (await repos.alerts.list(TENANT_B)).items}


async def test_stored_override_above_the_maximum_is_lowered_to_it(repos: Repositories, db: Database) -> None:
    await repos.tenants.update_settings(TENANT_A, {"retention": {"alerts_days": 5000}})
    old = await _closed(repos, TENANT_A, 40)

    kept = await purge_expired(db, RetentionSettings(tenant_max_days=60), now=NOW)
    assert kept.alerts == 0
    purged = await purge_expired(db, RetentionSettings(tenant_max_days=30), now=NOW)
    assert purged.alerts == 1
    assert old not in {a.id for a in (await repos.alerts.list(TENANT_A)).items}


async def test_usage_counters_follow_their_own_retention(repos: Repositories, db: Database) -> None:
    await repos.usage.add_ingested(TENANT_A, 3, day=date(2020, 1, 1))
    await repos.usage.add_ingested(TENANT_A, 2)
    report = await purge_expired(db, RetentionSettings(usage_days=400), now=NOW)
    assert report.usage_rows == 1
    assert [d.alerts_ingested for d in await repos.usage.list_range(TENANT_A, date(2019, 1, 1), NOW.date())] == [2]


async def test_pull_sources_wait_while_the_daily_alert_quota_is_used_up(repos: Repositories) -> None:
    await repos.sources.create(TENANT_A, "splunk", "siem-a", config={"url": "https://siem.example.com"})
    await repos.sources.create(TENANT_B, "splunk", "siem-b", config={"url": "https://siem.example.com"})
    await repos.tenants.update_admin(TENANT_B, max_alerts_per_day=5)
    await repos.usage.add_ingested(TENANT_B, 5)

    assert [s.tenant_id for s in await repos.sources.list_due_sources_all_tenants()] == [TENANT_A]

    await repos.tenants.update_admin(TENANT_B, max_alerts_per_day=6)
    assert {s.tenant_id for s in await repos.sources.list_due_sources_all_tenants()} == {TENANT_A, TENANT_B}
    await repos.tenants.update_admin(TENANT_B, max_alerts_per_day=None)
    await repos.usage.add_ingested(TENANT_B, 1_000)
    assert {s.tenant_id for s in await repos.sources.list_due_sources_all_tenants()} == {TENANT_A, TENANT_B}


async def test_quota_counts(repos: Repositories) -> None:
    """``ensure_capacity`` counts every source (disabled ones too) and only active users, per tenant."""
    sources, users = await repos.sources.count(TENANT_A), await repos.users.count_active(TENANT_A)
    other_sources, other_users = await repos.sources.count(TENANT_B), await repos.users.count_active(TENANT_B)
    await repos.sources.create(TENANT_A, "splunk", "on")
    await repos.sources.create(TENANT_A, "splunk", "off", enabled=False)
    await repos.users.create(TENANT_A, "active@x.io", "analyst")
    await repos.users.create(TENANT_A, "inactive@x.io", "analyst", is_active=False)
    assert (await repos.sources.count(TENANT_A), await repos.users.count_active(TENANT_A)) == (sources + 2, users + 1)
    assert (await repos.sources.count(TENANT_B), await repos.users.count_active(TENANT_B)) == (other_sources, other_users)
