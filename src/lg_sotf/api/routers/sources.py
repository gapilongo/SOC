# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/sources``: alert source administration (admin).

Credentials (``secret``) are write-only: they are encrypted with the
install's :class:`~lg_sotf.security.crypto.SecretBox`, bound to the tenant
and source id, and never returned (responses carry ``has_secret``). A source
is validated (configuration, credentials present, destination policy) before
it is saved. Creating a source beyond the tenant's ``max_sources`` quota is
refused with ``409 quota_exceeded``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request, Response

from lg_sotf.api.auth.deps import ADMIN, ADMIN_NOT_UNDER_GRANT, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.quotas import quota_conflict
from lg_sotf.api.schemas import SourceCreateIn, SourceOut, SourceTestOut, SourceUpdateIn
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Source
from lg_sotf.ingestion.service import is_reserved_source_id
from lg_sotf.ingestion.sources import encrypt_source_secret
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services import sources as source_changes
from lg_sotf.services.tenancy import QuotaExceeded

router = APIRouter(prefix="/sources", tags=["sources"])

MAX_CONFIG_KEYS = 100


def source_out(source: Source) -> SourceOut:
    out = SourceOut.model_validate(source)
    return out.model_copy(update={"has_secret": bool(source.secret_ciphertext)})


def _box(ctx: ApiContext) -> SecretBox:
    if ctx.secret_box is None:
        raise ApiError(503, "encryption_unavailable", "secret encryption is not configured on this server")
    return ctx.secret_box


def _check_config(config: Dict[str, Any]) -> None:
    if len(config) > MAX_CONFIG_KEYS:
        raise ApiError(422, "invalid_source", f"config may have at most {MAX_CONFIG_KEYS} keys")
    for key in config:
        if "secret" in key.lower() or "password" in key.lower() or key.lower() in ("token", "api_key", "client_secret"):
            raise ApiError(422, "invalid_source", f"config.{key[:64]} looks like a credential; send it in 'secret'")


def _draft(tenant_id: str, source_id: str, now: datetime, **fields: Any) -> Source:
    """An unsaved :class:`Source` for validation before the insert/update."""
    base: Dict[str, Any] = {
        "id": source_id,
        "tenant_id": tenant_id,
        "cursor": None,
        "cursor_watermark": None,
        "last_polled_at": None,
        "next_poll_at": None,
        "consecutive_failures": 0,
        "last_error": None,
        "health": "unknown",
        "created_at": now,
        "updated_at": now,
    }
    base.update(fields)
    return Source.model_validate(base)


@router.get("", response_model=List[SourceOut], summary="List sources")
async def list_sources(request: Request, principal: Principal = Depends(require(ADMIN))) -> List[SourceOut]:
    return [source_out(s) for s in await get_ctx(request).repos.sources.list(principal.tenant_id)]


@router.get("/{source_id}", response_model=SourceOut, summary="Source detail")
async def get_source(source_id: str, request: Request, principal: Principal = Depends(require(ADMIN))) -> SourceOut:
    return source_out(await get_ctx(request).repos.sources.get(principal.tenant_id, source_id))


@router.post("", status_code=201, response_model=SourceOut, summary="Create a source")
async def create_source(
    body: SourceCreateIn, request: Request, principal: Principal = Depends(require(ADMIN_NOT_UNDER_GRANT))
) -> SourceOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    source_id = body.id or str(uuid.uuid4())
    if is_reserved_source_id(source_id):
        raise ApiError(422, "invalid_source", "source ids 'api', 'api:*', 'email', 'email:*' and 'demo:samples' are reserved")
    _check_config(body.config)
    ciphertext = encrypt_source_secret(_box(ctx), tenant_id, source_id, body.secret) if body.secret else None
    draft = _draft(
        tenant_id,
        source_id,
        datetime.now(UTC),
        type=body.type,
        name=body.name,
        enabled=body.enabled,
        config=body.config,
        secret_ciphertext=ciphertext,
        poll_interval_s=body.poll_interval_s,
    )
    await ctx.ingestion.validate_source(tenant_id, draft)
    try:
        source = await source_changes.create_source(
            ctx.repos,
            AuditLogger(ctx.repos),
            tenant_id,
            principal.actor,
            source_type=body.type,
            name=body.name,
            source_id=source_id,
            config=body.config,
            secret_ciphertext=ciphertext,
            poll_interval_s=body.poll_interval_s,
            enabled=body.enabled,
        )
    except QuotaExceeded as exc:
        raise quota_conflict(exc) from exc
    return source_out(source)


@router.patch("/{source_id}", response_model=SourceOut, summary="Update a source")
async def update_source(
    source_id: str,
    body: SourceUpdateIn,
    request: Request,
    principal: Principal = Depends(require(ADMIN_NOT_UNDER_GRANT)),
) -> SourceOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    current = await ctx.repos.sources.get(tenant_id, source_id)
    fields = body.model_fields_set
    for name in ("name", "enabled", "config", "poll_interval_s"):
        if name in fields and getattr(body, name) is None:
            raise ApiError(422, "validation_error", f"{name} cannot be null")
    changes: Dict[str, Any] = {
        name: getattr(body, name) for name in ("name", "enabled", "config", "poll_interval_s") if name in fields
    }
    if "secret" in fields:
        changes["secret_ciphertext"] = (
            encrypt_source_secret(_box(ctx), tenant_id, source_id, body.secret) if body.secret else None
        )
    if "config" in changes:
        _check_config(changes["config"])
    await ctx.ingestion.validate_source(tenant_id, current.model_copy(update=changes))
    source = await source_changes.update_source(
        ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, source_id, changes, fields=fields
    )
    return source_out(source)


@router.delete("/{source_id}", status_code=204, summary="Delete a source")
async def delete_source(source_id: str, request: Request, principal: Principal = Depends(require(ADMIN))) -> Response:
    ctx = get_ctx(request)
    if not await source_changes.delete_source(
        ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, source_id
    ):
        raise NotFound("source", source_id)
    return Response(status_code=204)


@router.post(
    "/{source_id}/test", response_model=SourceTestOut, summary="Check a source's configuration and connectivity"
)
async def test_source(
    source_id: str, request: Request, principal: Principal = Depends(require(ADMIN))
) -> SourceTestOut:
    ctx = get_ctx(request)
    source = await ctx.repos.sources.get(principal.tenant_id, source_id)
    health = await ctx.ingestion.test_source(principal.tenant_id, source)
    # A connectivity check, not a change: recorded on its own.
    await AuditLogger(ctx.repos).record_event(
        principal.tenant_id,
        "source.tested",
        "source",
        source_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={"ok": health.ok},
    )
    return SourceTestOut(ok=health.ok, detail=health.detail)
