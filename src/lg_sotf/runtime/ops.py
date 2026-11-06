"""Operations behind the one-shot CLI commands (migrate, create-admin, enqueue, DLQ)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db import Connection
from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.migrate import grant_runtime_privileges, setup_checkpointer, upgrade_head
from lg_sotf.db.partitions import ensure_partitions
from lg_sotf.db.pool import owner_database, owner_dsn
from lg_sotf.db.repos import Repositories, User
from lg_sotf.db.repos.users import ROLES, normalize_email
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.errors import OperationError
from lg_sotf.models.vocabulary import TERMINAL_RUN_STATUSES
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.dlq import DeadLetter, DeadLetterQueue
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.queue.redis import create_redis
from lg_sotf.security.hashing import ahash_password
from lg_sotf.services.tenancy import TenantRequest, provision_tenant
from lg_sotf.settings import Settings

log = get_logger(__name__)

MAX_TENANT_NAME_CHARS = 200


def check_password(settings: Settings, password: str) -> None:
    if len(password) < settings.auth.password_min_length:
        raise OperationError(f"password must be at least {settings.auth.password_min_length} characters")


async def audit_user_created(repos: Repositories, user: User, *, via: str, conn: Connection) -> None:
    """Hash-chained audit entries for an account created outside the API (CLI, migrate).

    ``user.created`` always; ``platform.admin_granted`` as well when the account
    is a platform admin (the cross-tenant super-user flag). ``conn`` is the
    transaction that created the account.
    """
    audit = AuditLogger(repos)
    details = {
        "email": user.email,
        "role": user.role,
        "platform_admin": user.is_platform_admin,
        "sso_only": user.password_hash is None,
        "via": via,
    }
    await audit.record(
        user.tenant_id,
        "user.created",
        "user",
        str(user.id),
        actor_type="system",
        actor_id=via,
        details=details,
        conn=conn,
    )
    if user.is_platform_admin:
        await audit.record(
            user.tenant_id,
            "platform.admin_granted",
            "user",
            str(user.id),
            actor_type="system",
            actor_id=via,
            details={"email": user.email, "via": via},
            conn=conn,
        )


async def audit_reprocess(
    repos: Repositories, tenant_id: str, alert_id: str, *, via: str, conn: Optional[Connection], **details: object
) -> None:
    """``alert.reprocess_requested``, on ``conn`` when the request requeued the run in that transaction.

    ``conn=None`` records a request that changed nothing in the database
    (a rebuilt resume message only), before the message is queued.
    """
    audit = AuditLogger(repos)
    entry: Dict[str, Any] = {"actor_type": "system", "actor_id": "cli", "details": {"via": via, **details}}
    if conn is None:
        await audit.record_event(tenant_id, "alert.reprocess_requested", "alert", alert_id, **entry)
    else:
        await audit.record(tenant_id, "alert.reprocess_requested", "alert", alert_id, **entry, conn=conn)


@dataclass
class MigrateReport:
    runtime_role_granted: Optional[str] = None
    tenant_id: str = ""
    tenant_created: bool = False
    admin_created: Optional[str] = None
    partitions_created: List[str] = field(default_factory=list)


async def migrate(settings: Settings) -> MigrateReport:
    """Schema upgrade, checkpointer tables, runtime grants and bootstrap tenant/admin. Idempotent."""
    url = owner_dsn(settings)
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
            if not (await repos.users.list(auth.bootstrap_tenant_id, limit=1)).items:
                password = auth.bootstrap_admin_password.get_secret_value()
                check_password(settings, password)
                password_hash = await ahash_password(password)
                async with db.tenant_tx(auth.bootstrap_tenant_id) as conn:
                    user = await repos.users.create(
                        auth.bootstrap_tenant_id,
                        auth.bootstrap_admin_email,
                        "admin",
                        password_hash=password_hash,
                        is_platform_admin=True,
                        conn=conn,
                    )
                    await audit_user_created(repos, user, via="migrate", conn=conn)
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
        password_hash = await ahash_password(password)
        try:
            async with db.tenant_tx(tenant_id) as conn:
                user = await repos.users.create(
                    tenant_id, email, role, password_hash=password_hash, is_platform_admin=platform_admin, conn=conn
                )
                await audit_user_created(repos, user, via="cli", conn=conn)
        except Conflict as exc:
            raise OperationError("a user with this email already exists in the tenant") from exc
        return user
    finally:
        await db.close()


@dataclass
class MfaResetReport:
    user_id: str
    email: str
    was_enabled: bool
    revoked_sessions: int


async def reset_mfa(settings: Settings, *, tenant_id: str, email: str) -> MfaResetReport:
    """Remove a user's MFA (lost device, break-glass) and end their sessions; audited as ``auth.mfa_reset``."""
    if not is_valid_tenant_id(tenant_id):
        raise OperationError(f"invalid tenant id {tenant_id!r}")
    db = owner_database(settings, "lg-sotf-cli")
    await db.open()
    try:
        repos = Repositories.create(db)
        try:
            user = await repos.users.get_by_email(tenant_id, email)
        except ValueError as exc:
            raise OperationError("email is not a valid address") from exc
        if user is None:
            raise OperationError(f"no user with this email in tenant {tenant_id!r}")
        async with db.tenant_tx(tenant_id) as conn:
            state = await repos.user_mfa.get(tenant_id, user.id, conn=conn)
            await repos.user_mfa.delete(tenant_id, user.id, conn=conn)
            revoked = await repos.refresh_tokens.revoke_all_for_user(tenant_id, user.id, conn=conn)
            was_enabled = state is not None and state.enabled
            await AuditLogger(repos).record(
                tenant_id,
                "auth.mfa_reset",
                "user",
                str(user.id),
                actor_type="system",
                actor_id="cli",
                details={"was_enabled": was_enabled, "revoked_sessions": revoked, "via": "cli"},
                conn=conn,
            )
        return MfaResetReport(user_id=str(user.id), email=user.email, was_enabled=was_enabled, revoked_sessions=revoked)
    finally:
        await db.close()


@dataclass
class TenantReport:
    tenant_id: str
    name: str
    admin: Optional[User] = None


async def create_tenant(
    settings: Settings,
    *,
    tenant_id: str,
    name: str,
    admin_email: Optional[str] = None,
    admin_password: Optional[str] = None,
) -> TenantReport:
    """Create a tenant (and optionally its first admin) with the schema-owner connection.

    One transaction (:func:`lg_sotf.services.tenancy.provision_tenant`, as
    for the API): a failure leaves no tenant behind and the command can be
    run again.
    """
    if not is_valid_tenant_id(tenant_id):
        raise OperationError(
            f"invalid tenant id {tenant_id!r}: use 2-63 lowercase letters, digits, '-' or '_', "
            "starting with a letter or digit"
        )
    name = name.strip()
    if not 1 <= len(name) <= MAX_TENANT_NAME_CHARS:
        raise OperationError(f"tenant name must be 1-{MAX_TENANT_NAME_CHARS} characters")
    request = await _tenant_request(settings, tenant_id, name, admin_email, admin_password)
    db = owner_database(settings, "lg-sotf-cli")
    await db.open()
    try:
        repos = Repositories.create(db)
        try:
            created = await provision_tenant(repos, AuditLogger(repos), request)
        except Conflict as exc:
            raise OperationError(f"tenant {tenant_id!r} already exists; nothing was changed") from exc
        return TenantReport(tenant_id=created.tenant.id, name=created.tenant.name, admin=created.admin)
    finally:
        await db.close()


async def _tenant_request(
    settings: Settings, tenant_id: str, name: str, admin_email: Optional[str], admin_password: Optional[str]
) -> TenantRequest:
    """The CLI's provisioning request: input checked and the password hashed before any transaction.

    The audit entries carry ``via: cli``; the admin's ``user.created`` also
    names the email and platform flag, as for every account the CLI creates.
    """
    email = None
    password_hash = None
    if admin_email is not None:
        try:
            email = normalize_email(admin_email)
        except ValueError as exc:
            raise OperationError("admin email is not a valid address") from exc
        if admin_password is not None:
            check_password(settings, admin_password)
            password_hash = await ahash_password(admin_password)
    return TenantRequest(
        tenant_id=tenant_id,
        name=name,
        actor=Actor("system", "cli"),
        admin_email=email,
        admin_password_hash=password_hash,
        audit_details={"via": "cli"},
        admin_audit_details={"email": email, "platform_admin": False},
    )


async def _requeue_run(repos: Repositories, tenant_id: str, alert_id: str, *, force: bool, conn: Connection) -> str:
    """Make the run claimable by a ``process`` message (in ``conn``'s transaction) and return the alert severity."""
    try:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
    except NotFound as exc:
        raise OperationError(f"alert {alert_id!r} not found in tenant {tenant_id!r}") from exc
    run = await repos.runs.upsert_queued(tenant_id, alert_id, requeue_terminal=force, conn=conn)
    if run.status not in ("queued", "failed"):
        hint = "; pass --force to reprocess a finished run" if run.status in TERMINAL_RUN_STATUSES else ""
        raise OperationError(f"run is {run.status}{hint}")
    try:
        await repos.alerts.update_status(tenant_id, alert_id, "queued", conn=conn)
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
        async with db.tenant_tx(tenant_id) as conn:
            severity = await _requeue_run(repos, tenant_id, alert_id, force=force, conn=conn)
            await audit_reprocess(repos, tenant_id, alert_id, via="enqueue", force=force, conn=conn)
        return await WorkQueue(redis, settings).enqueue_process(tenant_id, alert_id, severity)
    finally:
        await redis.aclose()
        await db.close()


async def enqueue_lost_resume(settings: Settings, *, tenant_id: str, alert_id: str) -> str:
    """Rebuild the resume a waiting run should have received (decided escalation or approved actions)."""
    from lg_sotf.runtime.resumes import rebuild_resume_payload

    db = owner_database(settings, "lg-sotf-cli")
    redis = create_redis(settings)
    await db.open()
    try:
        repos = Repositories.create(db)
        payload = await rebuild_resume_payload(repos, tenant_id, alert_id)
        if payload is None:
            try:
                run = await repos.runs.get(tenant_id, alert_id)
            except NotFound as exc:
                raise OperationError(f"no workflow run for alert {alert_id!r} in tenant {tenant_id!r}") from exc
            raise OperationError(f"run is {run.status}; there is no decided escalation or approval to resume with")
        await audit_reprocess(
            repos, tenant_id, alert_id, via="enqueue_resume", resume_type=payload["type"], conn=None
        )
        return await WorkQueue(redis, settings).enqueue_resume(tenant_id, alert_id, payload)
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
    async with repos.db.tenant_tx(letter.tenant_id) as conn:
        try:
            severity = await _requeue_run(repos, letter.tenant_id, letter.alert_id, force=True, conn=conn)
        except OperationError as exc:
            if letter.kind != "resume":
                raise
            # e.g. the run is still waiting: the resume message alone continues it.
            run_reset = False
            severity = "high"
            log.info("ops.dlq_resume_run_state", detail=str(exc))
        await audit_reprocess(
            repos, letter.tenant_id, letter.alert_id, via="dlq_requeue", kind=letter.kind, conn=conn
        )
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
