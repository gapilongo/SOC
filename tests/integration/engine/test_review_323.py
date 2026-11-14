"""Review of PR #323 (AI-E1.5c): an unusable shadow login stops ``shadow-run``; what makes a role unfit.

Adopted from the review: a ``database.shadow_url`` that is set but cannot be used (a role that may write, a
wrong password) refuses the replay before anything is read, audited or stored; a column-level write grant makes
a role unfit to be the shadow role; ``database.shadow_url`` takes the URL forms ``database.url`` takes.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Dict

import pytest
from pydantic import SecretStr

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import DatabaseError, ShadowRoleRequired
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.runtime.shadow_replay import ShadowRunOptions, run_shadow_replay
from lg_sotf.security.shadow import ShadowRun, shadow_scope
from lg_sotf.settings import Settings
from tests.integration.db._support import ALL_TABLES, SHADOW_ROLE, TENANT_A, db_settings, make_alert, shadow_url

pytestmark = pytest.mark.integration


async def counts(db: Database) -> Dict[str, int]:
    async with db.system_tx(readonly=True) as conn:
        return {t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in ALL_TABLES}  # noqa: S608


def profile(tmp_path: Path) -> Path:
    path = tmp_path / "same-pipeline.yaml"
    path.write_text("name: same pipeline\nllm:\n  provider: fake\n  allow_fake: true\n")
    return path


async def _decided_alert(engine: WorkflowEngine, repos: Repositories) -> str:
    benign = await make_alert(
        repos, TENANT_A, title="Scheduled backup maintenance test job", severity="low",
        normalized={"rule_name": "scheduled-backup-maintenance-test", "entities": {"hosts": ["backup-01"]}},
    )
    assert (await engine.run(TENANT_A, benign)).alert_status == "closed"
    return benign


@pytest.mark.parametrize("broken", ["writable_role", "wrong_password"])
async def test_shadow_run_refuses_to_start_when_the_shadow_url_is_set_but_unusable(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, db: Database, tmp_path: Path, broken: str,
) -> None:
    """database.shadow_url is set (the gate passes) but its role may write, or cannot log in: the command
    refuses, writing nothing: no audit entry, no verdict row, no report."""
    await _decided_alert(engine, repos)
    url = engine_settings.database.url.get_secret_value()
    bad = url if broken == "writable_role" else shadow_url(url).replace(f"{SHADOW_ROLE}:", f"{SHADOW_ROLE}:wrong-")
    settings = engine_settings.model_copy(
        update={"database": engine_settings.database.model_copy(update={"shadow_url": SecretStr(bad)})}
    )
    before = await counts(db)
    with pytest.raises(DatabaseError):  # ShadowRoleRequired, or DatabaseUnavailable for the failed login
        await run_shadow_replay(
            settings, ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(days=1))
        )
    assert await counts(db) == before


async def test_open_shadow_refuses_a_role_with_a_column_level_write_grant(
    db: Database, repos: Repositories, migrated_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A column-level grant (the form the runtime role itself has on tenant_grants and blind_audit_*) is
    invisible to has_table_privilege. Were the role accepted, a statement past the guard (the proven '--'
    bypass) would commit a write from the shadow session."""
    async with db.connection() as conn:
        await conn.execute(f"GRANT UPDATE (name) ON tenants TO {SHADOW_ROLE}")
    try:
        fresh = Database(
            db.__dict__["_settings"].model_copy(update={"shadow_url": SecretStr(shadow_url(migrated_database_url))}),
            application_name="rev323", min_size=0, max_size=1,
        )
        await fresh.open()
        try:
            refused = True
            try:
                await fresh.open_shadow()
                refused = False
            except ShadowRoleRequired as exc:
                assert "may write to tenants" in str(exc)
            if not refused:
                monkeypatch.setattr("lg_sotf.db.pool.shadow_connection", lambda c: c)  # the guard, bypassed
                with shadow_scope(ShadowRun("shadow/rev323")):
                    async with fresh.connection() as conn:
                        try:
                            await conn.execute(
                                "SELECT '--'; COMMIT; BEGIN READ WRITE; "
                                "SELECT set_config('app.tenant_id', 'tenant-a', false); "
                                "UPDATE tenants SET name = 'pwned' WHERE id = 'tenant-a'; COMMIT"
                            )
                        except Exception:  # noqa: BLE001, S110 - the assertion below reports the tenant name
                            pass
        finally:
            await fresh.close()
        name = (await repos.tenants.get(TENANT_A)).name
    finally:
        async with db.connection() as conn:
            await conn.execute(f"REVOKE UPDATE (name) ON tenants FROM {SHADOW_ROLE}")
            await conn.execute("SELECT set_config('app.tenant_id', 'tenant-a', false)")
            await conn.execute("UPDATE tenants SET name = 'Tenant A' WHERE id = 'tenant-a'")
            await conn.execute("RESET app.tenant_id")
    assert refused, f"open_shadow accepted a role with a column-level UPDATE grant; tenant name is now {name!r}"


@pytest.mark.parametrize("scheme", ["postgresql+asyncpg", "postgresql+psycopg", "postgres"])
async def test_the_shadow_url_takes_the_url_forms_the_database_url_takes(
    migrated_database_url: str, repos: Repositories, scheme: str
) -> None:
    def with_scheme(url: str) -> str:
        return scheme + "://" + url.split("://", 1)[1]

    fresh = Database(
        db_settings(with_scheme(migrated_database_url), pool_min=0, pool_max=1,
                    shadow_url=SecretStr(with_scheme(shadow_url(migrated_database_url)))),
        application_name="rev323-scheme",
    )
    await fresh.open()
    try:
        await fresh.open_shadow()
        with shadow_scope(ShadowRun("shadow/rev323-scheme")):
            async with fresh.tenant_tx(TENANT_A) as conn:
                assert await conn.fetchval("SELECT current_user") == SHADOW_ROLE
    finally:
        await fresh.close()
