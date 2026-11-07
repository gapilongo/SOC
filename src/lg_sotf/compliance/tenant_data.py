"""Tenant data export (GDPR Art. 15/20) and erasure (Art. 17) for platform operators.

Export
    :func:`export_tenant_zip` yields a ZIP archive of JSON Lines files, one
    per table, built while it streams: rows are read in keyset-ordered
    batches (each its own short tenant-scoped transaction) and compressed
    into the archive as they arrive, so memory stays bounded whatever the
    tenant's size. Secrets never leave: users are exported from a column
    allow-list (no password hash, no lockout counters, nothing added later
    such as MFA secrets), sources and integrations without
    ``secret_ciphertext`` (``has_secret`` instead), tenant
    settings without ``*_ciphertext`` values, and connector parameters and
    results, source and integration configuration and settings go through the credential
    redactor as well. ``manifest.json``, written last, lists every file
    with its row count and SHA-256.

Erasure
    :func:`erase_tenant` deletes every row of a *suspended* tenant through
    the ``lgsotf_erase_tenant_batch`` database function (migration 0006):
    bounded batches, children first, LangGraph checkpoints included. It
    then removes the tenant's Redis keys (``{prefix}:t:{tenant}:*`` with
    ``SCAN``, never ``KEYS``) and its entries in the work and dead-letter
    streams. The hash-chained audit log is kept (see ``docs/compliance.md``
    for the legal basis) and the ``tenants`` row stays as a tombstone whose
    settings only say when it was erased.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, AsyncIterator, Callable, Dict, List, Mapping, Optional, Tuple

import asyncpg
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from lg_sotf.compliance.canonical import jsonable
from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Tenant
from lg_sotf.db.tenancy import validate_tenant_id
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.streams import CONSUMER_GROUP, FIELD_TENANT, QueueStreams
from lg_sotf.security.redaction import redact

log = get_logger(__name__)

EXPORT_FORMAT = "lg-sotf.tenant-export"
EXPORT_VERSION = 1
EXPORT_BATCH = 1_000
ERASE_BATCH = 5_000
REDIS_SCAN_COUNT = 500
STREAM_PAGE = 500
CIPHERTEXT_SUFFIX = "_ciphertext"
ACTIVE_RUN_STATUSES = ("running",)

Transform = Callable[[Dict[str, Any]], Dict[str, Any]]


def strip_secrets(value: Any) -> Any:
    """``value`` without ``*_ciphertext`` members (replaced by ``*_configured: true``), then redacted."""

    def walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            out: Dict[str, Any] = {}
            for key, item in node.items():
                if isinstance(key, str) and key.endswith(CIPHERTEXT_SUFFIX):
                    if item:
                        out[key[: -len(CIPHERTEXT_SUFFIX)] + "_configured"] = True
                    continue
                out[str(key)] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    redacted, _ = redact(walk(value))
    return redacted


def _redact_fields(*names: str) -> Transform:
    def transform(row: Dict[str, Any]) -> Dict[str, Any]:
        for name in names:
            if row.get(name) is not None:
                row[name] = strip_secrets(row[name])
        return row

    return transform


@dataclass(frozen=True)
class ExportTable:
    """One JSONL file: ``SELECT <columns> FROM <table>`` keyset-paginated on ``keys`` (unique, indexed with tenant_id)."""

    file: str
    table: str
    columns: str
    keys: Tuple[Tuple[str, str], ...]
    transform: Optional[Transform] = None


_ID_TEXT = (("id", "text"),)
_ID_UUID = (("id", "uuid"),)
_ID_BIGINT = (("id", "bigint"),)

EXPORT_TABLES: Tuple[ExportTable, ...] = (
    ExportTable(
        "users.jsonl",
        "users",
        "id, tenant_id, email, role, is_platform_admin, is_active, oidc_subject, last_login_at, created_at, updated_at",
        _ID_UUID,
    ),
    ExportTable(
        "api_keys.jsonl",
        "api_keys",
        "id, tenant_id, name, prefix, scopes, created_by, last_used_at, revoked_at, created_at",
        _ID_UUID,
    ),
    ExportTable(
        "sources.jsonl",
        "sources",
        "id, tenant_id, type, name, enabled, config, poll_interval_s, cursor_watermark, last_polled_at, "
        "consecutive_failures, last_error, health, created_at, updated_at, (secret_ciphertext IS NOT NULL) AS has_secret",
        _ID_TEXT,
        _redact_fields("config"),
    ),
    ExportTable("alerts.jsonl", "alerts", "*", _ID_TEXT),
    ExportTable(
        "alert_events.jsonl", "alert_events", "*", (("alert_id", "text"), ("ts", "timestamptz"), ("id", "bigint"))
    ),
    ExportTable("escalations.jsonl", "escalations", "*", _ID_TEXT),
    ExportTable("feedback.jsonl", "analyst_feedback", "*", _ID_TEXT),
    # Every ledger column; the connector's state and verification detail hold ids and observed state (no secrets)
    # and are redacted like the result.
    ExportTable(
        "actions.jsonl", "response_actions", "*", _ID_UUID,
        _redact_fields("params", "result", "external_ref", "verification_detail"),
    ),
    ExportTable("suppressions.jsonl", "suppression_rules", "*", _ID_TEXT),
    ExportTable(
        "integrations.jsonl",
        "integrations",
        "id, tenant_id, kind, name, enabled, config, events, min_severity, created_by, created_at, updated_at, "
        "(secret_ciphertext IS NOT NULL) AS has_secret",
        _ID_UUID,
        _redact_fields("config"),
    ),
    # Delivery summaries only (the outbox never stores the rendered message or credentials).
    ExportTable("notification_outbox.jsonl", "notification_outbox", "*", _ID_UUID),
    ExportTable("external_tickets.jsonl", "external_tickets", "*", _ID_UUID),
    # The investigation trace: hashes, token counts and redacted, size-capped result digests.
    ExportTable("investigation_steps.jsonl", "investigation_steps", "*", _ID_UUID),
    ExportTable("usage_daily.jsonl", "usage_daily", "*", (("day", "date"),)),
    ExportTable(
        "llm_usage_daily.jsonl", "llm_usage_daily", "*", (("day", "date"), ("model", "text"), ("agent", "text"))
    ),
    ExportTable("audit_log.jsonl", "audit_log", "*", _ID_BIGINT),
    # Indicator values as displayed (IPs, emails, user and host names) seen on each alert: personal data.
    ExportTable(
        "indicator_sightings.jsonl",
        "indicator_sightings",
        "*",
        (("alert_id", "text"), ("indicator_type", "text"), ("value_hash", "text")),
    ),
)

# Tenant-scoped tables deliberately left out of the export, with the reason the manifest gives.
NOT_EXPORTED: Dict[str, str] = {
    "user_mfa": "password hashes, API key hashes, MFA and other authentication secrets",
    "refresh_tokens": "password hashes, API key hashes, MFA and other authentication secrets",
    "workflow_runs": "workflow run bookkeeping (status, attempts, lease) and LangGraph checkpoints",
}


class _Sink:
    """Write-only file object that collects what ``zipfile`` writes until it is drained."""

    def __init__(self) -> None:
        self._chunks: List[bytes] = []
        self._size = 0

    def write(self, data: bytes) -> int:
        if data:
            self._chunks.append(bytes(data))
            self._size += len(data)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def drain(self) -> bytes:
        out = b"".join(self._chunks)
        self._chunks.clear()
        self._size = 0
        return out

    @property
    def pending(self) -> int:
        return self._size


def _line(row: Mapping[str, Any]) -> bytes:
    return json.dumps(jsonable(row), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _page_sql(spec: ExportTable) -> str:
    columns = ", ".join(k for k, _ in spec.keys)
    bounds = ", ".join(f"${i + 3}::{cast}" for i, (_, cast) in enumerate(spec.keys))
    return (
        f"SELECT {spec.columns} FROM {spec.table} "  # noqa: S608 - fixed identifiers from EXPORT_TABLES
        f"WHERE tenant_id = $1 AND ($2 OR ({columns}) > ({bounds})) "
        f"ORDER BY {columns} LIMIT ${len(spec.keys) + 3}"
    )


async def _rows(db: Database, tenant_id: str, spec: ExportTable, batch: int) -> AsyncIterator[Dict[str, Any]]:
    sql = _page_sql(spec)
    last: List[Any] = [None] * len(spec.keys)
    first = True
    while True:
        async with db.tenant_tx(tenant_id, readonly=True) as conn:
            rows = await conn.fetch(sql, tenant_id, first, *last, batch)
        for record in rows:
            row = dict(record)
            yield spec.transform(row) if spec.transform else row
        if len(rows) < batch:
            return
        first = False
        last = [rows[-1][k] for k, _ in spec.keys]


async def export_tenant_zip(
    db: Database,
    tenant: Tenant,
    *,
    exported_by: Mapping[str, Any],
    batch: int = EXPORT_BATCH,
    chunk_bytes: int = 256 * 1024,
    now: Optional[datetime] = None,
) -> AsyncIterator[bytes]:
    """Stream the tenant's data as a ZIP of JSONL files (bounded memory)."""
    sink = _Sink()
    manifest_files: List[Dict[str, Any]] = []
    with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        tenant_row = {
            "id": tenant.id,
            "name": tenant.name,
            "status": tenant.status,
            "settings": strip_secrets(tenant.settings),
            "created_at": tenant.created_at,
            "updated_at": tenant.updated_at,
        }
        body = json.dumps(jsonable(tenant_row), ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        archive.writestr("tenant.json", body)
        manifest_files.append({"file": "tenant.json", "rows": 1, "sha256": hashlib.sha256(body).hexdigest()})
        yield sink.drain()
        for spec in EXPORT_TABLES:
            digest = hashlib.sha256()
            count = 0
            with archive.open(spec.file, mode="w", force_zip64=True) as member:
                async for row in _rows(db, tenant.id, spec, batch):
                    line = _line(row)
                    member.write(line)
                    digest.update(line)
                    count += 1
                    if sink.pending >= chunk_bytes:
                        yield sink.drain()
            manifest_files.append({"file": spec.file, "rows": count, "sha256": digest.hexdigest()})
            yield sink.drain()
        manifest = {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "tenant_id": tenant.id,
            "exported_at": (now or datetime.now(UTC)).isoformat(),
            "exported_by": jsonable(dict(exported_by)),
            "files": manifest_files,
            "excluded": [
                "password hashes, API key hashes, MFA and other authentication secrets",
                "encrypted source and integration credentials and tenant secrets (shown as has_secret / *_configured)",
                "workflow run bookkeeping (status, attempts, lease) and LangGraph checkpoints",
                "queue entries and caches",
            ],
        }
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    yield sink.drain()


def export_filename(tenant_id: str, now: Optional[datetime] = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"lg-sotf-tenant-{validate_tenant_id(tenant_id)}-{stamp}.zip"


# ------------------------------------------------------------------ erasure


class ErasureRefused(Exception):
    """The tenant cannot be erased now (``code`` is the API error code)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ErasureReport:
    tenant_id: str
    erased_at: Optional[datetime] = None
    deleted: Dict[str, int] = field(default_factory=dict)
    redis_keys: int = 0
    queue_entries: int = 0
    audit_entries_retained: int = 0

    @property
    def total_rows(self) -> int:
        return sum(self.deleted.values())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "erased_at": self.erased_at,
            "deleted": dict(sorted(self.deleted.items())),
            "redis_keys": self.redis_keys,
            "queue_entries": self.queue_entries,
            "audit_entries_retained": self.audit_entries_retained,
        }


def erased_at(tenant: Tenant) -> Optional[str]:
    value = tenant.settings.get("erased_at") if isinstance(tenant.settings, Mapping) else None
    return value if isinstance(value, str) else None


async def erasure_blockers(db: Database, tenant: Tenant, *, home_tenant_id: Optional[str] = None) -> List[str]:
    """Why ``tenant`` cannot be erased right now (empty when it can)."""
    blockers: List[str] = []
    if tenant.status != "suspended":
        blockers.append("the tenant must be suspended first")
    if home_tenant_id is not None and tenant.id == home_tenant_id:
        blockers.append("a platform admin cannot erase their own home tenant")
    async with db.tenant_tx(tenant.id, readonly=True) as conn:
        running = await conn.fetchval(
            "SELECT count(*) FROM workflow_runs WHERE tenant_id = $1 AND status = ANY($2::text[])",
            tenant.id,
            list(ACTIVE_RUN_STATUSES),
        )
    if running:
        blockers.append(f"{running} workflow run(s) are still running; wait for them to finish")
    return blockers


def _refusal(exc: asyncpg.PostgresError) -> Optional[ErasureRefused]:
    if isinstance(exc, asyncpg.ObjectNotInPrerequisiteStateError):
        return ErasureRefused("tenant_not_suspended", "the tenant must be suspended before it is erased")
    if isinstance(exc, asyncpg.NoDataFoundError):
        return ErasureRefused("not_found", "tenant not found")
    return None


async def erase_tenant_rows(db: Database, tenant_id: str, *, batch: int = ERASE_BATCH) -> Dict[str, int]:
    """Delete every row of a suspended tenant except its audit log and tenant row; returns counts per table."""
    validate_tenant_id(tenant_id)
    deleted: Dict[str, int] = {}
    while True:
        try:
            async with db.connection() as conn:
                row = await conn.fetchrow("SELECT * FROM lgsotf_erase_tenant_batch($1, $2)", tenant_id, batch)
        except asyncpg.PostgresError as exc:
            refusal = _refusal(exc)
            if refusal is None:
                raise
            raise refusal from exc
        if row is None or row["table_name"] is None:
            return deleted
        deleted[row["table_name"]] = deleted.get(row["table_name"], 0) + int(row["deleted"])


async def purge_tenant_redis(redis: Redis, prefix: str, tenant_id: str) -> Tuple[int, int]:
    """Remove the tenant's keys and queue entries; returns (keys, stream entries) removed."""
    validate_tenant_id(tenant_id)
    keys = 0
    batch: List[Any] = []
    async for key in redis.scan_iter(match=f"{prefix}:t:{tenant_id}:*", count=REDIS_SCAN_COUNT):
        batch.append(key)
        if len(batch) >= REDIS_SCAN_COUNT:
            keys += int(await redis.unlink(*batch))
            batch.clear()
    if batch:
        keys += int(await redis.unlink(*batch))
    entries = 0
    streams = QueueStreams(prefix)
    for stream in (*streams.work, streams.dlq):
        entries += await _purge_stream(redis, stream, tenant_id, grouped=stream != streams.dlq)
    return keys, entries


async def _purge_stream(redis: Redis, stream: str, tenant_id: str, *, grouped: bool) -> int:
    removed = 0
    start = "-"
    target = tenant_id.encode()
    while True:
        page: Any = await redis.xrange(stream, min=start, max="+", count=STREAM_PAGE)
        if not page:
            return removed
        doomed = [
            entry_id
            for entry_id, fields in page
            if (fields.get(FIELD_TENANT.encode()) or fields.get(FIELD_TENANT)) in (target, tenant_id)
        ]
        if doomed:
            if grouped:
                try:
                    await redis.xack(stream, CONSUMER_GROUP, *doomed)
                except ResponseError:
                    log.debug("tenant_erasure.no_consumer_group", stream=stream)
            removed += int(await redis.xdel(stream, *doomed))
        if len(page) < STREAM_PAGE:
            return removed
        last = page[-1][0]
        last_text = last.decode() if isinstance(last, bytes) else str(last)
        start = f"({last_text}"


async def count_audit_entries(db: Database, tenant_id: str) -> int:
    async with db.tenant_tx(tenant_id, readonly=True) as conn:
        return int(await conn.fetchval("SELECT count(*) FROM audit_log WHERE tenant_id = $1", tenant_id))


async def erase_tenant(
    db: Database,
    redis: Optional[Redis],
    prefix: str,
    tenant_id: str,
    *,
    batch: int = ERASE_BATCH,
) -> ErasureReport:
    """Erase a suspended tenant's rows, checkpoints and Redis state (see module docs)."""
    report = ErasureReport(tenant_id=tenant_id)
    report.deleted = await erase_tenant_rows(db, tenant_id, batch=batch)
    if redis is not None:
        report.redis_keys, report.queue_entries = await purge_tenant_redis(redis, prefix, tenant_id)
    report.audit_entries_retained = await count_audit_entries(db, tenant_id)
    async with db.tenant_tx(tenant_id, readonly=True) as conn:
        row = await conn.fetchrow("SELECT settings FROM tenants WHERE id = $1", tenant_id)
    if row is None:
        raise NotFound("tenant", tenant_id)
    stamp = (row["settings"] or {}).get("erased_at")
    report.erased_at = datetime.fromisoformat(stamp) if isinstance(stamp, str) else datetime.now(UTC)
    return report


__all__ = [
    "EXPORT_TABLES",
    "NOT_EXPORTED",
    "ErasureRefused",
    "ErasureReport",
    "erase_tenant",
    "erase_tenant_rows",
    "erased_at",
    "erasure_blockers",
    "export_filename",
    "export_tenant_zip",
    "purge_tenant_redis",
    "strip_secrets",
]
