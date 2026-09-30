"""Operations behind ``lg-sotf tenant-export``, ``tenant-erase`` and ``evidence-verify``.

The commands run with the schema-owner connection (like ``create-tenant``).
There is no platform-admin account behind a CLI call, so export and erasure
are audited as ``actor_type=system, actor_id=cli`` in the target tenant's
chain and, as the platform-level record, in the bootstrap tenant's chain
(``auth.bootstrap_tenant_id``, the operator's tenant) when it exists and is
not the tenant being erased.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.compliance.canonical import Verification, optional_signing_key, verify
from lg_sotf.compliance.tenant_data import (
    ErasureRefused,
    ErasureReport,
    erase_tenant,
    erasure_blockers,
    export_tenant_zip,
)
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Repositories, Tenant
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.queue.redis import create_redis
from lg_sotf.runtime.ops import OperationError, owner_database
from lg_sotf.settings import Settings

CLI_ACTOR = "cli"
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024


def _check_id(tenant_id: str) -> None:
    if not is_valid_tenant_id(tenant_id):
        raise OperationError(f"invalid tenant id {tenant_id!r}")


async def _tenant(repos: Repositories, tenant_id: str) -> Tenant:
    try:
        return await repos.tenants.get(tenant_id)
    except NotFound as exc:
        raise OperationError(f"tenant {tenant_id!r} does not exist") from exc


async def _audit(
    settings: Settings, repos: Repositories, tenant_id: str, action: str, platform_action: str, details: Mapping[str, Any]
) -> None:
    audit = AuditLogger(repos)
    await audit.record(tenant_id, action, "tenant", tenant_id, actor_type="system", actor_id=CLI_ACTOR, details=details)
    home = settings.auth.bootstrap_tenant_id
    if home and home != tenant_id:
        try:
            await repos.tenants.get(home)
        except NotFound:
            return
        await audit.record(
            home, platform_action, "tenant", tenant_id, actor_type="system", actor_id=CLI_ACTOR, details=details
        )


@dataclass
class ExportResult:
    path: Path
    bytes_written: int


async def tenant_export(settings: Settings, *, tenant_id: str, output: Path, overwrite: bool = False) -> ExportResult:
    """Write the tenant's export ZIP to ``output`` (mode 0600), streaming."""
    _check_id(tenant_id)
    db = owner_database(settings, "lg-sotf-cli")
    await db.open()
    try:
        repos = Repositories.create(db)
        tenant = await _tenant(repos, tenant_id)
        await _audit(
            settings, repos, tenant.id, "tenant.data_exported", "platform.tenant_exported",
            {"via": "cli", "filename": output.name, "tenant_status": tenant.status},
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | (0 if overwrite else os.O_EXCL)
        try:
            fd = os.open(output, flags, 0o600)
        except FileExistsError as exc:
            raise OperationError(f"{output} exists; pass --force to overwrite it") from exc
        written = 0
        with os.fdopen(fd, "wb") as handle:
            async for chunk in export_tenant_zip(db, tenant, exported_by={"actor_type": "system", "actor_id": CLI_ACTOR}):
                handle.write(chunk)
                written += len(chunk)
        return ExportResult(path=output, bytes_written=written)
    finally:
        await db.close()


async def tenant_erase(settings: Settings, *, tenant_id: str, confirm: str) -> ErasureReport:
    """Erase a suspended tenant (rows, checkpoints, Redis state); the audit log is kept."""
    _check_id(tenant_id)
    if confirm != tenant_id:
        raise OperationError("--confirm must repeat the tenant id exactly")
    db = owner_database(settings, "lg-sotf-cli")
    await db.open()
    redis = create_redis(settings)
    try:
        repos = Repositories.create(db)
        tenant = await _tenant(repos, tenant_id)
        blockers = await erasure_blockers(db, tenant)
        if blockers:
            raise OperationError("cannot erase: " + "; ".join(blockers))
        await _audit(settings, repos, tenant.id, "tenant.erasure_started", "platform.tenant_erasure_started",
                     {"via": "cli", "tenant_name": tenant.name})
        try:
            report = await erase_tenant(db, redis, settings.redis.key_prefix, tenant.id)
        except ErasureRefused as exc:
            raise OperationError(str(exc)) from exc
        await _audit(
            settings, repos, tenant.id, "tenant.erased", "platform.tenant_erased",
            {
                "via": "cli",
                "rows_deleted": report.total_rows,
                "deleted": report.deleted,
                "redis_keys": report.redis_keys,
                "queue_entries": report.queue_entries,
                "audit_entries_retained": report.audit_entries_retained,
            },
        )
        return report
    finally:
        await redis.aclose()
        await db.close()


def verify_evidence_file(settings: Settings, path: Path) -> tuple[Mapping[str, Any], Verification]:
    """Load an evidence pack JSON file and verify its digest and signature with this install's key."""
    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise OperationError(f"{path} is larger than {MAX_EVIDENCE_FILE_BYTES} bytes")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationError(f"{path} is not a JSON evidence pack: {type(exc).__name__}") from exc
    if not isinstance(document, dict) or "integrity" not in document:
        raise OperationError(f"{path} is not a sealed evidence pack (no 'integrity' member)")
    return document, verify(document, optional_signing_key(settings))


__all__ = ["ExportResult", "tenant_erase", "tenant_export", "verify_evidence_file"]
