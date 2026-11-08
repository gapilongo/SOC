"""``lg-sotf verify-invariants`` on a freshly migrated database (SEC9.1)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import AsyncIterator, Callable, Iterator

import psycopg
import pytest
import pytest_asyncio
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer
from lg_sotf.db.pool import Database
from lg_sotf.db.posture import RoleAttributes, current_role_attributes
from lg_sotf.db.repos import Repositories
from lg_sotf.db.urls import to_libpq_url
from lg_sotf.invariants import checks
from lg_sotf.invariants.checks import CHECKS, run_checks
from lg_sotf.settings import DatabaseSettings, Settings
from tests.integration.db._support import TENANT_A, db_settings, make_alert, truncate_all

pytestmark = pytest.mark.integration

RUNTIME_ROLE = "pg_database_owner"


async def _seed_other_tenant(url: str) -> None:
    """Truncate, then give TENANT_A an alert and an audit entry the probe tenant must never see."""
    db = Database(db_settings(url), application_name="lg-sotf-tests")
    await db.open()
    try:
        await truncate_all(db)
        repos = Repositories.create(db)
        await repos.tenants.ensure(TENANT_A, "A")
        alert_id = await make_alert(repos, TENANT_A)
        await repos.audit.append(TENANT_A, "system", None, "seed", "alert", alert_id)
    finally:
        await db.close()


@pytest.fixture
def cli_env(
    settings_env: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> str:
    asyncio.run(_seed_other_tenant(migrated_database_url))
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL=migrated_database_url,
        LG_SOTF_REDIS__URL=redis_url,
        LG_SOTF_REDIS__KEY_PREFIX=unique_prefix,
        LG_SOTF_SECURITY__INDICATOR_HMAC_KEY="lg-sotf-test-suite-only-indicator-hmac-key",
    )
    return migrated_database_url


def test_verify_invariants_passes_on_a_fresh_install(cli_env: str) -> None:
    """Acceptance (SEC9.1): migrate a database, then every runtime check passes or does not apply."""
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0

    result = runner.invoke(cli, ["verify-invariants"])
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    for check, invariant in CHECKS.items():
        assert any(line.split()[1:3] == [invariant, check] for line in lines), check
    assert "FAIL" not in result.stdout
    # The test database's login role owns the schema: a single-role install.
    assert {line.split()[2] for line in lines if line.startswith("SKIP")} == {"runtime_role", "audit_append_only"}
    assert lines[-1].endswith("12 invariants registered"), "none pending: INV-09 is enforced since AI-E1.5a"

    report = json.loads(runner.invoke(cli, ["verify-invariants", "--json"]).stdout)
    assert {r["check"] for r in report["results"]} == set(CHECKS) and report["pending"] == []
    by_check = {r["check"]: r for r in report["results"]}
    assert by_check["evidence_seal"]["detail"].endswith("signed (HMAC-SHA256)")
    assert by_check["kill_switch"]["detail"].startswith("install kill switch on")


@pytest.fixture
def connects_as_superuser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Report the connected role as a superuser: RLS would not apply to it at all.

    The test database's login role cannot be made a superuser, so only the
    attributes are faked; the second tenant's rows are real.
    """

    async def superuser(conn: object) -> RoleAttributes:
        return dataclasses.replace(await current_role_attributes(conn), superuser=True)  # type: ignore[arg-type]

    monkeypatch.setattr(checks, "current_role_attributes", superuser)


@pytest.mark.usefixtures("connects_as_superuser")
def test_a_single_role_superuser_install_with_tenant_data_skips_the_probe(cli_env: str) -> None:
    result = CliRunner().invoke(cli, ["verify-invariants"])
    assert result.exit_code == 0, result.stdout
    outcomes = {line.split()[2]: line.split()[0] for line in result.stdout.splitlines() if line[:4] in ("PASS", "SKIP")}
    assert outcomes["rls_probe"] == "SKIP" and outcomes["runtime_role"] == "SKIP"
    assert "FAIL" not in result.stdout


@pytest.mark.usefixtures("connects_as_superuser")
def test_a_split_role_install_whose_runtime_role_ignores_rls_fails(
    cli_env: str, settings_env: Callable[..., Settings]
) -> None:
    settings_env(LG_SOTF_DATABASE__RUNTIME_ROLE="lgsotf_app")
    result = CliRunner().invoke(cli, ["verify-invariants"])
    assert result.exit_code == 1
    failed = {line.split()[2] for line in result.stdout.splitlines() if line.startswith("FAIL")}
    assert failed == {"runtime_role", "rls_probe", "audit_append_only"}, result.stdout


@pytest.fixture
def no_forced_rls_on_alerts(cli_env: str) -> Iterator[None]:
    with psycopg.connect(to_libpq_url(cli_env), autocommit=True) as conn:
        conn.execute("ALTER TABLE alerts NO FORCE ROW LEVEL SECURITY")
    try:
        yield
    finally:
        with psycopg.connect(to_libpq_url(cli_env), autocommit=True) as conn:
            conn.execute("ALTER TABLE alerts FORCE ROW LEVEL SECURITY")


@pytest.mark.usefixtures("no_forced_rls_on_alerts")
def test_a_table_without_forced_rls_fails_the_check() -> None:
    result = CliRunner().invoke(cli, ["verify-invariants"])
    assert result.exit_code == 1
    failed = {line.split()[2]: line for line in result.stdout.splitlines() if line.startswith("FAIL")}
    assert set(failed) == {"rls_catalog", "rls_probe"}, result.stdout
    assert failed["rls_catalog"].endswith("without forced RLS and a policy: alerts")
    # The schema owner is no longer bound by RLS on alerts, so the probe tenant sees TENANT_A's alert.
    assert failed["rls_probe"].endswith("the probe tenant sees rows of other tenants in: alerts")


@pytest_asyncio.fixture
async def runtime_db(migrated_database_url: str) -> AsyncIterator[Database]:
    """A pool that acts as a least-privilege runtime role (see tests/integration/db/test_runtime_role.py)."""
    await _seed_other_tenant(migrated_database_url)
    await setup_checkpointer(migrated_database_url, DatabaseSettings())
    await asyncio.to_thread(grant_runtime_privileges, RUNTIME_ROLE, migrated_database_url, DatabaseSettings())
    db = Database(db_settings(migrated_database_url, pool_min=0, pool_max=2), server_settings={"role": RUNTIME_ROLE})
    await db.open()
    try:
        yield db
    finally:
        await db.close()


async def test_a_two_role_install_passes_every_check(
    runtime_db: Database, make_settings: Callable[..., Settings], migrated_database_url: str
) -> None:
    settings = make_settings(database={"url": migrated_database_url, "runtime_role": RUNTIME_ROLE})
    results = await run_checks(settings, db=runtime_db)
    by_check = {r.check: r.detail for r in results}
    # Only the CLI configures logging; here the redaction check sees the test's plain structlog setup.
    assert {r.check: r.outcome for r in results} == {**dict.fromkeys(CHECKS, "pass"), "log_redaction": "fail"}
    assert by_check["log_redaction"] == "logging is not configured with the redaction processors"
    assert "even with app.bypass_rls set" in by_check["rls_probe"]
    assert by_check["audit_append_only"].startswith("the runtime role may only SELECT and INSERT")
