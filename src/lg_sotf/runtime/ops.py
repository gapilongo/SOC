"""Operations behind the one-shot CLI commands (migrate, create-admin, enqueue, DLQ)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer, upgrade_head
from lg_sotf.db.partitions import ensure_partitions
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories, User
from lg_sotf.db.repos.users import ROLES
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.dlq import DeadLetter, DeadLetterQueue
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.queue.redis import create_redis
from lg_sotf.security.hashing import ahash_password
from lg_sotf.settings import Settings

log = get_logger(__name__)


class OperationError(Exception):
    """A user-facing failure of an operations command (bad input or state)."""


def owner_url(settings: Settings) -> str:
    url = settings.database.migration_url or settings.database.url
    return url.get_secret_value()


def owner_database(settings: Settings, application_name: str) -> Database:
    return Database(
        settings.database, dsn=owner_url(settings), application_name=application_name, min_size=0, max_size=2
    )


def check_password(settings: Settings, password: str) -> None:
    if len(password) < settings.auth.password_min_length:
        raise OperationError(f"password must be at least {settings.auth.password_min_length} characters")


@dataclass
class MigrateReport:
    runtime_role_granted: Optional[str] = None
    tenant_id: str = ""
    tenant_created: bool = False
    admin_created: Optional[str] = None
    partitions_created: List[str] = field(default_factory=list)


async def migrate(settings: Settings) -> MigrateReport:
    """Schema upgrade, checkpointer tables, runtime grants and bootstrap tenant/admin. Idempotent."""
    url = owner_url(settings)
    report = MigrateReport(tenant_id=settings.auth.bootstrap_tenant_id)
    await asyncio.to_thread(upgrade_head, url)
    await setup_checkpointer(url)
    role = settings.database.runtime_role
    if role:
        await asyncio.to_thread(grant_runtime_privileges, role, url)
        report.runtime_role_granted = role

    db = owner_database(settings, "lg-sotf-migrate")
    await db.open()
    try:
        repos = Repositories.create(db)
        async with db.system_tx() as conn:
            report.partitions_created = await ensure_partitions(conn)
        auth = settings.auth
        existed = True
        try:
            await repos.tenants.get(auth.bootstrap_tenant_id)
        except NotFound:
            existed = False
        await repos.tenants.ensure(auth.bootstrap_tenant_id, auth.bootstrap_tenant_name)
        report.tenant_created = not existed
        if auth.bootstrap_admin_email and auth.bootstrap_admin_password is not None:
            if not await repos.users.list(auth.bootstrap_tenant_id, limit=1):
                password = auth.bootstrap_admin_password.get_secret_value()
                check_password(settings, password)
                user = await repos.users.create(
                    auth.bootstrap_tenant_id,
                    auth.bootstrap_admin_email,
                    "admin",
                    password_hash=await ahash_password(password),
                    is_platform_admin=True,
                )
                report.admin_created = user.email
    finally:
        await db.close()
    log.info(
        "migrate.done",
        tenant_created=report.tenant_created,
        admin_created=report.admin_created is not None,
        runtime_role=report.runtime_role_granted,
    )
    return report


async def create_user(
    settings: Settings,
    *,
    tenant_id: str,
    email: str,
    role: str,
    password: str,
    platform_admin: bool = False,
) -> User:
    if role not in ROLES:
        raise OperationError(f"role must be one of {', '.join(ROLES)}")
    check_password(settings, password)
    db = owner_database(settings, "lg-sotf-cli")
    await db.open()
    try:
        repos = Repositories.create(db)
        try:
            await repos.tenants.get(tenant_id)
        except NotFound as exc:
            raise OperationError(f"tenant {tenant_id!r} does not exist") from exc
        try:
            return await repos.users.create(
                tenant_id, email, role, password_hash=await ahash_password(password), is_platform_admin=platform_admin
            )
        except Conflict as exc:
            raise OperationError("a user with this email already exists in the tenant") from exc
    finally:
        await db.close()


async def _requeue_run(repos: Repositories, tenant_id: str, alert_id: str, *, force: bool) -> str:
    """Make the run claimable by a ``process`` message and return the alert severity."""
    try:
        alert = await repos.alerts.get(tenant_id, alert_id)
    except NotFound as exc:
        raise OperationError(f"alert {alert_id!r} not found in tenant {tenant_id!r}") from exc
    run = await repos.runs.upsert_queued(tenant_id, alert_id, requeue_terminal=force)
    if run.status not in ("queued", "failed"):
        hint = "; pass --force to reprocess a finished run" if run.status in ("completed", "dead_lettered") else ""
        raise OperationError(f"run is {run.status}{hint}")
    try:
        await repos.alerts.update_status(tenant_id, alert_id, "queued")
    except InvalidTransition:
        log.info("ops.alert_status_kept", status=alert.status)
    return alert.severity


async def enqueue_alert(settings: Settings, *, tenant_id: str, alert_id: str, force: bool = False) -> str:
    """Queue a ``process`` message for an alert (operations; ``force`` reprocesses finished runs)."""
    db = owner_database(settings, "lg-sotf-cli")
    redis = create_redis(settings)
    await db.open()
    try:
        repos = Repositories.create(db)
        severity = await _requeue_run(repos, tenant_id, alert_id, force=force)
        return await WorkQueue(redis, settings).enqueue_process(tenant_id, alert_id, severity)
    finally:
        await redis.aclose()
        await db.close()


async def dlq_list(settings: Settings, *, limit: int) -> List[DeadLetter]:
    redis = create_redis(settings)
    try:
        return await DeadLetterQueue(redis, settings).list(limit=limit)
    finally:
        await redis.aclose()


@dataclass(frozen=True)
class RequeueResult:
    entry_id: str
    new_entry_id: Optional[str] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


async def _requeue_letter(repos: Repositories, dlq: DeadLetterQueue, queue: WorkQueue, entry_id: str) -> str:
    letter = await dlq.get(entry_id)
    if letter is None:
        raise OperationError(f"dead letter {entry_id} not found")
    run_reset = True
    try:
        severity = await _requeue_run(repos, letter.tenant_id, letter.alert_id, force=True)
    except OperationError as exc:
        if letter.kind != "resume":
            raise
        # e.g. the run is still waiting: the resume message alone continues it.
        run_reset = False
        severity = "high"
        log.info("ops.dlq_resume_run_state", detail=str(exc))
    if letter.kind == "resume" and run_reset:
        # The run restarts from its checkpoint and interrupts again; the resume then applies.
        await queue.enqueue_process(letter.tenant_id, letter.alert_id, severity)
    try:
        return await dlq.requeue(letter)
    except ValueError as exc:
        raise OperationError(str(exc)) from exc


async def dlq_requeue(settings: Settings, entry_ids: List[str]) -> List[RequeueResult]:
    """Return dead letters to the work queue, resetting their runs so they can be claimed again.

    Each entry is handled on its own; one failure does not stop the others,
    and every entry's result (new entry id or error) is returned.
    """
    db = owner_database(settings, "lg-sotf-cli")
    redis = create_redis(settings)
    await db.open()
    try:
        repos = Repositories.create(db)
        dlq = DeadLetterQueue(redis, settings)
        queue = WorkQueue(redis, settings)
        results: List[RequeueResult] = []
        for entry_id in entry_ids:
            try:
                new_id = await _requeue_letter(repos, dlq, queue, entry_id)
            except OperationError as exc:
                results.append(RequeueResult(entry_id, error=str(exc)))
                continue
            results.append(RequeueResult(entry_id, new_entry_id=new_id))
        return results
    finally:
        await redis.aclose()
        await db.close()
