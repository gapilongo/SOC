"""``lg-sotf audit-sample``: a blind-audit run from the command line (the proof-of-value random-sample flow)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.blind_audit import draw
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, db_settings, make_alert, truncate_all

pytestmark = pytest.mark.integration

START = datetime(2026, 10, 5, tzinfo=UTC)


async def _with_repos(url: str, fn: Callable[[Repositories], Any]) -> Any:
    db = Database(db_settings(url), application_name="lg-sotf-tests")
    await db.open()
    try:
        return await fn(Repositories.create(db))
    finally:
        await db.close()


@pytest.fixture
def frame(
    settings_env: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> List[str]:
    """Twelve alerts closed by automation in the week of 2026-10-05, in tenant-a."""

    async def seed(repos: Repositories) -> List[str]:
        await truncate_all(repos.db)
        await repos.tenants.create(TENANT_A, "A")
        ids = []
        for i in range(12):
            alert_id = await make_alert(repos, TENANT_A, title=f"closed {i}")
            async with repos.db.system_tx() as conn:
                await conn.execute(
                    "UPDATE alerts SET status = 'closed', disposition = 'benign', closed_at = $2 WHERE id = $1",
                    alert_id, START + timedelta(hours=i),
                )
            ids.append(alert_id)
        return ids

    ids: List[str] = asyncio.run(_with_repos(migrated_database_url, seed))
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL=migrated_database_url,
        LG_SOTF_REDIS__URL=redis_url,
        LG_SOTF_REDIS__KEY_PREFIX=unique_prefix,
        LG_SOTF_SECURITY__INDICATOR_HMAC_KEY="lg-sotf-test-suite-only-indicator-hmac-key",
    )
    return ids


def test_audit_sample_draws_a_seeded_sample_and_records_the_frame(frame: List[str], migrated_database_url: str) -> None:
    runner = CliRunner()
    args = ["audit-sample", "--tenant", TENANT_A, "--from", "2026-10-05", "--to", "2026-10-12", "--seed", "99"]

    result = runner.invoke(cli, [*args, "--size", "4", "--json"])

    assert result.exit_code == 0, result.output
    run = json.loads(result.stdout)
    assert (run["frame_size"], run["sample_size"], run["seed"], run["trigger"]) == (12, 4, 99, "cli")
    assert run["window_start"] == "2026-10-05T00:00:00Z" and run["window_end"] == "2026-10-12T00:00:00Z"

    async def read(repos: Repositories) -> Any:
        items = (await repos.blind_audit.list_items(TENANT_A)).items
        actions = [(e.action, e.actor_id) for e in (await repos.audit.list(TENANT_A)).items]
        return items, actions

    items, actions = asyncio.run(_with_repos(migrated_database_url, read))
    assert [i.alert_id for i in sorted(items, key=lambda i: i.sample_rank)] == draw(frame, 99, 4)
    assert ("blind_audit.sampled", "cli") in actions

    again = runner.invoke(cli, args)
    assert again.exit_code != 0 and "already sampled" in again.output
    missing = runner.invoke(cli, ["audit-sample", "--tenant", "no-such-tenant"])
    assert missing.exit_code != 0 and "does not exist" in missing.output
