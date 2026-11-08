"""``shadow_verdicts`` (migration 0014, AI-E1.5b): tenant RLS, append-only for the runtime role, checked columns."""

from __future__ import annotations

import asyncio

import asyncpg
import pytest

from lg_sotf.db.errors import DatabaseError
from lg_sotf.db.migrate import grant_runtime_privileges
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.shadow_agreement import Comparison, Verdict
from lg_sotf.settings import DatabaseSettings
from tests.integration.db._support import SEED_REPORT_ID, TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

REPORT = "shr_" + "1" * 32
RUNTIME_ROLE = "pg_database_owner"


def comparison(alert_id: str) -> Comparison:
    return Comparison(
        alert_id=alert_id, severity="high", production=Verdict(route="escalate", confidence=70.0),
        candidate=Verdict(route="close", disposition="benign", actions=("block_ip:203.0.113.7",)),
    )


async def test_rows_are_isolated_by_tenant(db: Database, repos: Repositories) -> None:
    a = await make_alert(repos, TENANT_A)
    b = await make_alert(repos, TENANT_B)
    await repos.shadow_verdicts.append(TENANT_A, REPORT, "cand", comparison(a), run_id="shadow/a")
    await repos.shadow_verdicts.append(TENANT_B, REPORT, "cand", comparison(b), run_id="shadow/b")

    # The same report id in two tenants: each sees only its own row.
    assert [r.alert_id for r in await repos.shadow_verdicts.list_for_report(TENANT_A, REPORT)] == [a]
    assert [r.alert_id for r in await repos.shadow_verdicts.list_for_report(TENANT_B, REPORT)] == [b]
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.fetchval("SELECT count(*) FROM shadow_verdicts") == 1
        assert await conn.execute("UPDATE shadow_verdicts SET cand_route = 'escalate' WHERE tenant_id = $1",
                                  TENANT_A) == "UPDATE 0"
        assert await conn.execute("DELETE FROM shadow_verdicts WHERE tenant_id = $1", TENANT_A) == "DELETE 0"
    async with db.connection() as conn:
        async with conn.transaction():
            assert await conn.fetchval("SELECT count(*) FROM shadow_verdicts") == 0
    [row] = await repos.shadow_verdicts.list_for_report(TENANT_A, REPORT)
    assert row.comparison() == comparison(a).model_copy(update={"severity": row.severity})


async def test_a_tenant_cannot_write_another_tenants_row(db: Database, repos: Repositories) -> None:
    a = await make_alert(repos, TENANT_A)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_B) as conn:
            await conn.execute(
                "INSERT INTO shadow_verdicts (tenant_id, alert_id, report_id, candidate) VALUES ($1, $2, $3, 'x')",
                TENANT_A, a, REPORT,
            )
    # Through the repository, the row lands in the tenant named, and an alert of another tenant is not found.
    with pytest.raises(DatabaseError):
        await repos.shadow_verdicts.append(TENANT_B, REPORT, "cand", comparison(a))


async def test_runtime_role_may_read_and_insert_only(db: Database, migrated_database_url: str) -> None:
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url, DatabaseSettings())
    async with db.connection() as conn:
        for privilege, allowed in (("SELECT", True), ("INSERT", True), ("UPDATE", False), ("DELETE", False),
                                   ("TRUNCATE", False)):
            assert await conn.fetchval(
                "SELECT has_table_privilege($1, 'shadow_verdicts', $2)", RUNTIME_ROLE, privilege
            ) is allowed, privilege


async def test_rows_go_with_their_alert_and_columns_are_checked(db: Database, repos: Repositories) -> None:
    alert_id = await make_alert(repos, TENANT_A)
    await repos.shadow_verdicts.append(TENANT_A, SEED_REPORT_ID, "cand", comparison(alert_id))
    with pytest.raises(DatabaseError):  # one row per alert per report
        await repos.shadow_verdicts.append(TENANT_A, SEED_REPORT_ID, "cand", comparison(alert_id))
    bad = comparison(alert_id).model_copy(update={"candidate": Verdict(route="ignore")})
    with pytest.raises(DatabaseError):
        await repos.shadow_verdicts.append(TENANT_A, REPORT, "cand", bad)
    with pytest.raises(ValueError, match="shr_"):
        await repos.shadow_verdicts.append(TENANT_A, "shadow/not-a-report", "cand", comparison(alert_id))
    async with db.system_tx() as conn:
        await conn.execute("DELETE FROM alerts WHERE id = $1", alert_id)
    assert await repos.shadow_verdicts.list_for_report(TENANT_A, SEED_REPORT_ID) == []
