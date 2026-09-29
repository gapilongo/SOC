from __future__ import annotations

import asyncio
from typing import Any, Callable, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.security.hashing import verify_password
from lg_sotf.settings import Settings
from tests.integration.conftest import truncate_all
from tests.integration.db._support import TENANT_A, db_settings, new_alert

ADMIN_PASSWORD = "correct horse battery staple"


def _db(url: str) -> Database:
    return Database(db_settings(url), application_name="lg-sotf-tests")


async def _reset(url: str) -> None:
    db = _db(url)
    await db.open()
    try:
        await truncate_all(db)
    finally:
        await db.close()


async def _users(url: str, tenant: str) -> List[Any]:
    db = _db(url)
    await db.open()
    try:
        return await Repositories.create(db).users.list(tenant)
    finally:
        await db.close()


@pytest.fixture
def cli_env(
    settings_env: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> str:
    asyncio.run(_reset(migrated_database_url))
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL=migrated_database_url,
        LG_SOTF_REDIS__URL=redis_url,
        LG_SOTF_REDIS__KEY_PREFIX=unique_prefix,
        LG_SOTF_AUTH__BOOTSTRAP_TENANT_ID="acme",
        LG_SOTF_AUTH__BOOTSTRAP_TENANT_NAME="Acme Corp",
        LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL="Admin@Acme.example",
        LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD=ADMIN_PASSWORD,
    )
    return migrated_database_url


def test_migrate_is_idempotent_and_bootstraps_once(cli_env: str) -> None:
    runner = CliRunner()
    first = runner.invoke(cli, ["migrate"])
    assert first.exit_code == 0, first.output
    assert "tenant: acme (created)" in first.output
    assert "bootstrap admin created: admin@acme.example" in first.output

    second = runner.invoke(cli, ["migrate"])
    assert second.exit_code == 0, second.output
    assert "tenant: acme (exists)" in second.output
    assert "bootstrap admin" not in second.output

    users = asyncio.run(_users(cli_env, "acme"))
    assert [(u.email, u.role, u.is_platform_admin) for u in users] == [("admin@acme.example", "admin", True)]
    assert users[0].password_hash is not None and users[0].password_hash.startswith("$argon2id$")
    assert verify_password(users[0].password_hash, ADMIN_PASSWORD)
    assert ADMIN_PASSWORD not in first.output + second.output


def test_create_admin_from_stdin_and_duplicate_rejected(cli_env: str) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    args = [
        "create-admin",
        "--tenant",
        "acme",
        "--email",
        "analyst@acme.example",
        "--role",
        "analyst",
        "--password-stdin",
    ]
    created = runner.invoke(cli, args, input="another long passphrase\n")
    assert created.exit_code == 0, created.output
    assert "created analyst analyst@acme.example in tenant acme" in created.output

    duplicate = runner.invoke(cli, args, input="another long passphrase\n")
    assert duplicate.exit_code != 0
    assert "already exists" in duplicate.output

    missing = runner.invoke(
        cli,
        ["create-admin", "--tenant", "nope", "--email", "x@y.example", "--password-stdin"],
        input="long enough pass\n",
    )
    assert missing.exit_code != 0
    assert "does not exist" in missing.output

    users = {u.email: u for u in asyncio.run(_users(cli_env, "acme"))}
    assert users["analyst@acme.example"].role == "analyst"
    assert not users["analyst@acme.example"].is_platform_admin


def test_create_admin_prompts_with_confirmation(cli_env: str) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    result = runner.invoke(
        cli,
        ["create-admin", "--tenant", "acme", "--email", "second@acme.example"],
        input=f"{ADMIN_PASSWORD}x\n{ADMIN_PASSWORD}x\n",
    )
    assert result.exit_code == 0, result.output
    assert ADMIN_PASSWORD not in result.output


async def _seed_alert(url: str) -> str:
    db = _db(url)
    await db.open()
    try:
        repos = Repositories.create(db)
        await repos.tenants.create(TENANT_A, "Tenant A")
        alert = new_alert(severity="critical")
        await repos.alerts.insert_many_if_absent(TENANT_A, [alert])
        return alert.id
    finally:
        await db.close()


async def _read_and_dead_letter(settings: Settings) -> List[str]:
    from lg_sotf.queue.redis import create_redis

    redis = create_redis(settings)
    try:
        consumer = StreamConsumer(redis, settings, "ops-test")
        await consumer.ensure_groups()
        msgs = await consumer.read(10)
        for msg in msgs:
            await consumer.dead_letter(msg, "exceeded 5 deliveries")
        return [m.alert_id for m in msgs]
    finally:
        await redis.aclose()


async def _run_status(url: str, alert_id: str) -> str:
    db = _db(url)
    await db.open()
    try:
        return (await Repositories.create(db).runs.get(TENANT_A, alert_id)).status
    finally:
        await db.close()


def test_enqueue_and_dlq_requeue(cli_env: str, settings_env: Callable[..., Settings]) -> None:
    settings = settings_env()
    runner = CliRunner()
    alert_id = asyncio.run(_seed_alert(cli_env))

    result = runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id])
    assert result.exit_code == 0, result.output
    assert asyncio.run(_run_status(cli_env, alert_id)) == "queued"
    assert asyncio.run(_read_and_dead_letter(settings)) == [alert_id]

    listed = runner.invoke(cli, ["dlq", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    assert alert_id in listed.output and "exceeded 5 deliveries" in listed.output
    entry_id = listed.output.split('"entry_id": "')[1].split('"')[0]

    requeued = runner.invoke(cli, ["dlq", "requeue", "0-1", entry_id])
    assert requeued.exit_code == 1
    assert "0-1 failed: dead letter 0-1 not found" in requeued.output
    assert f"{entry_id} -> " in requeued.output
    assert "1 of 2 dead letters were not requeued" in requeued.output
    assert runner.invoke(cli, ["dlq", "list"]).output.strip() == "dead-letter queue is empty"
    assert asyncio.run(_read_and_dead_letter(settings)) == [alert_id]

    unknown = runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", "does-not-exist"])
    assert unknown.exit_code != 0
    assert "not found" in unknown.output


def test_enqueue_refuses_finished_run_without_force(cli_env: str, settings_env: Callable[..., Settings]) -> None:
    runner = CliRunner()
    alert_id = asyncio.run(_seed_alert(cli_env))

    async def complete() -> None:
        db = _db(cli_env)
        await db.open()
        try:
            repos = Repositories.create(db)
            await repos.runs.start(TENANT_A, alert_id, "w", lease_s=30)
            await repos.runs.complete(TENANT_A, alert_id)
        finally:
            await db.close()

    asyncio.run(complete())
    refused = runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id])
    assert refused.exit_code != 0
    assert "--force" in refused.output
    forced = runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id, "--force"])
    assert forced.exit_code == 0, forced.output
    assert asyncio.run(_run_status(cli_env, alert_id)) == "queued"
