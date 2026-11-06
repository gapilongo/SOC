from __future__ import annotations

import asyncio
from typing import Any, Callable, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.audit import AuditRepo
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
        return (await Repositories.create(db).users.list(tenant)).items
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


async def _tenant_state(url: str, tenant: str) -> Any:
    db = _db(url)
    await db.open()
    try:
        repos = Repositories.create(db)
        audit = (await repos.audit.list(tenant, resource_type="tenant")).items
        return await repos.tenants.get(tenant), (await repos.users.list(tenant)).items, [e.action for e in audit]
    finally:
        await db.close()


def test_create_tenant_with_admin_and_duplicate_rejected(cli_env: str) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    args = ["create-tenant", "--id", "globex", "--name", "Globex Corp", "--admin-email", "Root@Globex.example"]

    created = runner.invoke(cli, [*args, "--password-stdin"], input=f"{ADMIN_PASSWORD}\n")

    assert created.exit_code == 0, created.output
    assert "created tenant globex (Globex Corp)" in created.output
    assert "created admin root@globex.example in tenant globex" in created.output
    assert ADMIN_PASSWORD not in created.output
    tenant, users, audited = asyncio.run(_tenant_state(cli_env, "globex"))
    assert (tenant.name, tenant.status) == ("Globex Corp", "active")
    assert [(u.email, u.role, u.is_platform_admin) for u in users] == [("root@globex.example", "admin", False)]
    assert verify_password(users[0].password_hash, ADMIN_PASSWORD)
    assert audited == ["tenant.created"]

    duplicate = runner.invoke(cli, ["create-tenant", "--id", "globex", "--name", "Other"])
    assert duplicate.exit_code != 0
    assert "tenant 'globex' already exists; nothing was changed" in duplicate.output
    assert asyncio.run(_tenant_state(cli_env, "globex"))[0].name == "Globex Corp"


def test_create_tenant_validates_input(cli_env: str) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0

    bare = runner.invoke(cli, ["create-tenant", "--id", "initech", "--name", "Initech"])
    assert bare.exit_code == 0, bare.output
    assert "created admin" not in bare.output
    assert asyncio.run(_tenant_state(cli_env, "initech"))[1] == []

    for argv, message in (
        (["--id", "Bad Id", "--name", "x"], "invalid tenant id 'Bad Id'"),
        (["--id", "ok-id", "--name", "  "], "tenant name must be"),
        (["--id", "ok-id", "--name", "x", "--password-stdin"], "--password-stdin needs --admin-email"),
        (["--id", "ok-id", "--name", "x", "--admin-email", "a@b.example", "--password-stdin"], "at least"),
    ):
        result = runner.invoke(cli, ["create-tenant", *argv], input="short\n")
        assert result.exit_code != 0, argv
        assert message in result.output, (argv, result.output)


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


async def _audit_actions(url: str, tenant: str) -> List[Any]:
    db = _db(url)
    await db.open()
    try:
        repos = Repositories.create(db)
        return [(e.action, e.actor_id, e.details) for e in (await repos.audit.list(tenant, limit=100)).items]
    finally:
        await db.close()


def test_cli_account_creation_and_reprocess_are_audited(cli_env: str) -> None:
    """AUTHZ-6: accounts created by migrate/create-admin/create-tenant and CLI reprocessing leave audit entries."""
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    boot = asyncio.run(_audit_actions(cli_env, "acme"))
    assert {a for a, _, _ in boot} >= {"user.created", "platform.admin_granted"}
    assert any(a == "user.created" and actor == "migrate" for a, actor, _ in boot)

    created = runner.invoke(
        cli,
        ["create-admin", "--tenant", "acme", "--email", "shadow@acme.example", "--platform-admin", "--password-stdin"],
        input=f"{ADMIN_PASSWORD}\n",
    )
    assert created.exit_code == 0, created.output
    entries = asyncio.run(_audit_actions(cli_env, "acme"))
    shadow = [(a, d) for a, actor, d in entries if actor == "cli" and d.get("email") == "shadow@acme.example"]
    assert {a for a, _ in shadow} == {"user.created", "platform.admin_granted"}
    assert any(d.get("platform_admin") is True for _, d in shadow)

    tenant = runner.invoke(
        cli,
        ["create-tenant", "--id", "globex", "--name", "Globex", "--admin-email", "boss@globex.example", "--password-stdin"],
        input=f"{ADMIN_PASSWORD}\n",
    )
    assert tenant.exit_code == 0, tenant.output
    actions = [a for a, _, _ in asyncio.run(_audit_actions(cli_env, "globex"))]
    assert "tenant.created" in actions and "user.created" in actions

    alert_id = asyncio.run(_seed_alert(cli_env))
    assert runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id]).exit_code == 0
    assert "alert.reprocess_requested" in [a for a, _, _ in asyncio.run(_audit_actions(cli_env, TENANT_A))]


def _fail_audit(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    """Make the audit append of ``action`` raise, as a full disk or a lost connection would."""
    original = AuditRepo.append

    async def append(self: AuditRepo, tenant_id: str, actor_type: str, actor_id: Any, act: str, *a: Any, **kw: Any) -> Any:
        if act == action:
            raise RuntimeError("audit_log unavailable")
        return await original(self, tenant_id, actor_type, actor_id, act, *a, **kw)

    monkeypatch.setattr(AuditRepo, "append", append)


async def _run_state(url: str, tenant: str, alert_id: str) -> Any:
    db = _db(url)
    await db.open()
    try:
        try:
            return (await Repositories.create(db).runs.get(tenant, alert_id)).status
        except NotFound:
            return None
    finally:
        await db.close()


def test_cli_changes_roll_back_when_their_audit_entry_fails(cli_env: str, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    args = ["create-admin", "--tenant", "acme", "--email", "shadow@acme.example", "--platform-admin", "--password-stdin"]
    _fail_audit(monkeypatch, "platform.admin_granted")
    failed = runner.invoke(cli, args, input=f"{ADMIN_PASSWORD}\n")
    assert failed.exit_code != 0
    assert "shadow@acme.example" not in [u.email for u in asyncio.run(_users(cli_env, "acme"))]
    assert not [d for _, _, d in asyncio.run(_audit_actions(cli_env, "acme")) if d.get("email") == "shadow@acme.example"]

    alert_id = asyncio.run(_seed_alert(cli_env))
    _fail_audit(monkeypatch, "alert.reprocess_requested")
    assert runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id]).exit_code != 0
    assert asyncio.run(_run_state(cli_env, TENANT_A, alert_id)) is None

    monkeypatch.undo()
    assert runner.invoke(cli, args, input=f"{ADMIN_PASSWORD}\n").exit_code == 0
    assert runner.invoke(cli, ["enqueue", "--tenant", TENANT_A, "--alert", alert_id]).exit_code == 0
    assert asyncio.run(_run_state(cli_env, TENANT_A, alert_id)) == "queued"


async def _tenant_left_behind(url: str, tenant: str) -> List[Any]:
    db = _db(url)
    await db.open()
    try:
        repos = Repositories.create(db)
        rows: List[Any] = [t for t in await repos.tenants.list_all_tenants() if t.id == tenant]
        return rows + (await repos.users.list(tenant)).items + list((await repos.audit.list(tenant)).items)
    finally:
        await db.close()


def test_create_tenant_leaves_nothing_behind_when_the_admin_fails(
    cli_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["migrate"]).exit_code == 0
    args = ["create-tenant", "--id", "globex", "--name", "Globex", "--admin-email", "Root@Globex.example"]
    _fail_audit(monkeypatch, "user.created")
    failed = runner.invoke(cli, [*args, "--password-stdin"], input=f"{ADMIN_PASSWORD}\n")
    assert failed.exit_code != 0
    assert asyncio.run(_tenant_left_behind(cli_env, "globex")) == []

    monkeypatch.undo()
    retried = runner.invoke(cli, [*args, "--password-stdin"], input=f"{ADMIN_PASSWORD}\n")
    assert retried.exit_code == 0, retried.output
    entries = {a: (actor, d) for a, actor, d in asyncio.run(_audit_actions(cli_env, "globex"))}
    assert entries["tenant.created"] == (
        "cli",
        {"name": "Globex", "with_admin": True, "settings_keys": [], "via": "cli"},
    )
    assert entries["user.created"] == (
        "cli",
        {"email": "root@globex.example", "role": "admin", "platform_admin": False, "sso_only": False, "via": "cli"},
    )
