# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/integrations`` (admin) and ``/tickets`` (viewer): notification channels, ticketing and their delivery log.

Credentials (``secret``) are write-only: validated, encrypted with the
install's :class:`~lg_sotf.security.crypto.SecretBox` bound to the tenant
and the integration id, and never returned (responses carry
``secrets: {field: configured}``). On update, ``secret`` is a merge patch:
a value replaces that field, ``null`` removes it, absent fields are kept.
Every change and every test is written to the audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.api.auth.deps import ADMIN, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import ExternalTicket, Integration, OutboxEntry
from lg_sotf.db.repos.integrations import NewOutboxEntry
from lg_sotf.integrations.channels import send_notification
from lg_sotf.integrations.config import (
    NOTIFY_KINDS,
    IntegrationConfigError,
    decrypt_secret,
    encrypt_secret,
    merge_secret,
    secret_fields,
    validate_config,
    validate_events,
    validate_secret,
)
from lg_sotf.integrations.events import (
    ACTION_AWAITING_APPROVAL,
    ESCALATION_CREATED,
    ESCALATION_DECIDED,
    ESCALATION_SLA_BREACHED,
    TEST_EVENT,
    make_test_event,
    ui_base_url,
)
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp, tls_verify
from lg_sotf.integrations.ticketing import ticket_client
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])
tickets = APIRouter(prefix="/tickets", tags=["integrations"])

Kind = Literal["slack", "teams", "email", "webhook", "jira", "servicenow"]
Severity = Literal["info", "low", "medium", "high", "critical"]
OutboxStatus = Literal["pending", "sent", "failed", "dead"]
MAX_CONFIG_KEYS = 30
MAX_INTEGRATIONS_PER_TENANT = 50
DEFAULT_EVENTS: Dict[str, List[str]] = {
    "notify": [ESCALATION_CREATED, ESCALATION_SLA_BREACHED, ACTION_AWAITING_APPROVAL],
    "ticketing": [ESCALATION_CREATED, ESCALATION_DECIDED],
}


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IntegrationCreateIn(_In):
    kind: Kind
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    events: Optional[List[str]] = Field(default=None, max_length=16)
    min_severity: Severity = "low"
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: Optional[Dict[str, Optional[str]]] = Field(
        default=None, description="Credentials (webhook URLs, tokens, passwords); write-only, never returned."
    )


class IntegrationUpdateIn(_In):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    enabled: Optional[bool] = None
    events: Optional[List[str]] = Field(default=None, max_length=16)
    min_severity: Optional[Severity] = None
    config: Optional[Dict[str, Any]] = Field(default=None, description="Replaces the whole config.")
    secret: Optional[Dict[str, Optional[str]]] = Field(
        default=None, description="Merge patch of the credentials: a value replaces, null removes. Write-only."
    )


class IntegrationOut(BaseModel):
    id: UUID
    tenant_id: str
    kind: str
    name: str
    enabled: bool
    events: List[str]
    min_severity: str
    config: Dict[str, Any]
    secrets: Dict[str, bool] = Field(description="Which credential fields are configured (values are never returned).")
    created_at: datetime
    updated_at: datetime


class IntegrationTestOut(BaseModel):
    ok: bool
    detail: str
    http_status: Optional[int] = None


class DeliveryOut(BaseModel):
    id: UUID
    event_id: UUID
    event_type: str
    operation: str
    status: str
    attempts: int
    next_attempt_at: datetime
    last_error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    alert_id: Optional[str] = None
    escalation_id: Optional[str] = None
    title: Optional[str] = None
    created_at: datetime
    sent_at: Optional[datetime] = None


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    integration_id: UUID
    system: str
    alert_id: str
    escalation_id: Optional[str] = None
    external_key: str
    external_url: Optional[str] = None
    external_status: Optional[str] = None
    resolved: bool
    resolved_by: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    created_at: datetime


def _invalid(exc: Exception) -> ApiError:
    return ApiError(422, "invalid_integration", str(exc)[:1_000])


def _require_https(ctx: ApiContext) -> bool:
    return ctx.settings.is_production


def _secrets_state(ctx: ApiContext, integration: Integration) -> Dict[str, bool]:
    fields = secret_fields(integration.kind)
    if not integration.secret_ciphertext:
        return {f: False for f in fields}
    try:
        values = decrypt_secret(ctx.secret_box, integration.tenant_id, integration.id, integration.secret_ciphertext)
    except IntegrationConfigError:
        # Stored, but unreadable with this install's keys: report it as set so nobody assumes it is empty.
        return {f: True for f in fields}
    return {f: bool(values.get(f)) for f in fields}


def integration_out(ctx: ApiContext, integration: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=integration.id,
        tenant_id=integration.tenant_id,
        kind=integration.kind,
        name=integration.name,
        enabled=integration.enabled,
        events=list(integration.events),
        min_severity=integration.min_severity,
        config=dict(integration.config),
        secrets=_secrets_state(ctx, integration),
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


def _check_config(ctx: ApiContext, kind: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if len(config) > MAX_CONFIG_KEYS:
        raise ApiError(422, "invalid_integration", f"config may have at most {MAX_CONFIG_KEYS} keys")
    try:
        normalised = validate_config(kind, config, require_https=_require_https(ctx))
        if normalised.get("ca_cert_pem"):
            tls_verify(normalised)
    except (IntegrationConfigError, DeliveryError) as exc:
        raise _invalid(exc) from None
    return normalised


def _events(kind: str, events: Optional[List[str]]) -> List[str]:
    if events is None:
        return list(DEFAULT_EVENTS["notify" if kind in NOTIFY_KINDS else "ticketing"])
    try:
        return validate_events(kind, events)
    except IntegrationConfigError as exc:
        raise _invalid(exc) from None


def _encrypt(ctx: ApiContext, kind: str, tenant_id: str, integration_id: UUID, values: Dict[str, Any]) -> Optional[str]:
    try:
        checked = validate_secret(kind, values, require_https=_require_https(ctx))
    except IntegrationConfigError as exc:
        raise _invalid(exc) from None
    if not checked:
        return None
    if ctx.secret_box is None:
        raise ApiError(503, "encryption_unavailable", "secret encryption is not configured on this server")
    return encrypt_secret(ctx.secret_box, tenant_id, integration_id, checked)


async def _audit(
    ctx: ApiContext, principal: Principal, action: str, integration_id: UUID, details: Dict[str, Any]
) -> None:
    await AuditLogger(ctx.repos).record(
        principal.tenant_id,
        action,
        "integration",
        str(integration_id),
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details=details,
    )


def _http(request: Request) -> IntegrationHttp:
    """Test hook: ``app.state.integrations_http`` replaces the default client."""
    injected = getattr(request.app.state, "integrations_http", None)
    return injected if injected is not None else IntegrationHttp(get_ctx(request).settings)


@router.get("", response_model=List[IntegrationOut], summary="List integrations")
async def list_integrations(request: Request, principal: Principal = Depends(require(ADMIN))) -> List[IntegrationOut]:
    ctx = get_ctx(request)
    return [integration_out(ctx, i) for i in await ctx.repos.integrations.list(principal.tenant_id)]


@router.get("/{integration_id}", response_model=IntegrationOut, summary="Integration detail")
async def get_integration(
    integration_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))
) -> IntegrationOut:
    ctx = get_ctx(request)
    return integration_out(ctx, await ctx.repos.integrations.get(principal.tenant_id, integration_id))


@router.post("", status_code=201, response_model=IntegrationOut, summary="Create an integration")
async def create_integration(
    body: IntegrationCreateIn, request: Request, principal: Principal = Depends(require(ADMIN))
) -> IntegrationOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    if len(await ctx.repos.integrations.list(tenant_id)) >= MAX_INTEGRATIONS_PER_TENANT:
        raise ApiError(409, "conflict", f"a tenant may have at most {MAX_INTEGRATIONS_PER_TENANT} integrations")
    config = _check_config(ctx, body.kind, body.config)
    events = _events(body.kind, body.events)
    integration_id = uuid.uuid4()
    ciphertext = _encrypt(ctx, body.kind, tenant_id, integration_id, merge_secret({}, body.secret or {}))
    integration = await ctx.repos.integrations.create(
        tenant_id,
        body.kind,
        body.name,
        integration_id=integration_id,
        config=config,
        secret_ciphertext=ciphertext,
        events=events,
        min_severity=body.min_severity,
        enabled=body.enabled,
        created_by=principal.local_user_id,
    )
    await _audit(
        ctx, principal, "integration.created", integration.id,
        {"kind": integration.kind, "name": integration.name, "events": events, "has_secret": ciphertext is not None},
    )
    return integration_out(ctx, integration)


@router.patch("/{integration_id}", response_model=IntegrationOut, summary="Update an integration")
async def update_integration(
    integration_id: UUID, body: IntegrationUpdateIn, request: Request, principal: Principal = Depends(require(ADMIN))
) -> IntegrationOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    current = await ctx.repos.integrations.get(tenant_id, integration_id)
    fields = body.model_fields_set
    for name in ("name", "enabled", "events", "min_severity", "config"):
        if name in fields and getattr(body, name) is None:
            raise ApiError(422, "validation_error", f"{name} cannot be null")
    changes: Dict[str, Any] = {name: getattr(body, name) for name in ("name", "enabled", "min_severity") if name in fields}
    if "config" in fields and body.config is not None:
        changes["config"] = _check_config(ctx, current.kind, body.config)
    if "events" in fields:
        changes["events"] = _events(current.kind, body.events)
    changed_secrets: List[str] = []
    if "secret" in fields:
        patch = body.secret or {}
        unknown = [k for k in patch if k not in secret_fields(current.kind)]
        if unknown:
            raise ApiError(422, "invalid_integration", f"secret.{unknown[0][:64]} is not a {current.kind} credential")
        try:
            existing = decrypt_secret(ctx.secret_box, tenant_id, integration_id, current.secret_ciphertext)
        except IntegrationConfigError:
            existing = {}
        changes["secret_ciphertext"] = _encrypt(
            ctx, current.kind, tenant_id, integration_id, merge_secret(existing, patch)
        )
        changed_secrets = sorted(patch)
    integration = await ctx.repos.integrations.update(tenant_id, integration_id, **changes)
    await _audit(
        ctx, principal, "integration.updated", integration_id,
        {"fields": sorted(f for f in fields if f != "secret"), "secret_fields": changed_secrets},
    )
    return integration_out(ctx, integration)


@router.delete("/{integration_id}", status_code=204, summary="Delete an integration (its delivery log and ticket links)")
async def delete_integration(
    integration_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))
) -> Response:
    ctx = get_ctx(request)
    current = await ctx.repos.integrations.get(principal.tenant_id, integration_id)
    if not await ctx.repos.integrations.delete(principal.tenant_id, integration_id):
        raise NotFound("integration", integration_id)
    await _audit(ctx, principal, "integration.deleted", integration_id, {"kind": current.kind, "name": current.name})
    return Response(status_code=204)


@router.post("/{integration_id}/test", response_model=IntegrationTestOut, summary="Send a test message now")
async def test_integration(
    integration_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))
) -> IntegrationTestOut:
    """Notification kinds get a test message; ticketing kinds check the credentials and project (no ticket)."""
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    integration = await ctx.repos.integrations.get(tenant_id, integration_id)
    payload = make_test_event(tenant_id, integration.name)
    http = _http(request)
    ok, detail, status, result = False, "", None, {}
    try:
        secret = decrypt_secret(ctx.secret_box, tenant_id, integration.id, integration.secret_ciphertext)
        if integration.kind in NOTIFY_KINDS:
            result = await send_notification(
                integration.kind,
                http=http,
                settings=ctx.settings,
                payload=payload,
                base_url=ui_base_url(ctx.settings),
                config=integration.config,
                secret=secret,
                delivery_id=str(uuid.uuid4()),
                retries=1,
                smtp_factory=getattr(request.app.state, "integrations_smtp", None),
            )
            detail = "test message delivered"
        else:
            result = await ticket_client(integration, http, secret, retries=1).check()
            detail = "credentials and project accepted"
        ok = True
        status = result.get("http_status") if isinstance(result.get("http_status"), int) else None
    except DeliveryError as exc:
        detail, status = str(exc), exc.status
    except IntegrationConfigError as exc:
        detail = str(exc)
    await ctx.repos.integrations.record_test(
        tenant_id,
        NewOutboxEntry(
            integration_id=integration.id,
            event_id=UUID(payload["id"]),
            event_type=TEST_EVENT,
            operation="test",
            dedupe_key=f"{TEST_EVENT}:{payload['id']}",
            payload=payload,
        ),
        ok=ok,
        error=None if ok else detail,
        result=result if ok else ({"http_status": status} if status else None),
    )
    await _audit(ctx, principal, "integration.tested", integration_id, {"ok": ok, "http_status": status})
    return IntegrationTestOut(ok=ok, detail=detail[:500], http_status=status)


def delivery_out(entry: OutboxEntry) -> DeliveryOut:
    alert = entry.payload.get("alert") if isinstance(entry.payload.get("alert"), dict) else {}
    return DeliveryOut(
        id=entry.id,
        event_id=entry.event_id,
        event_type=entry.event_type,
        operation=entry.operation,
        status=entry.status,
        attempts=entry.attempts,
        next_attempt_at=entry.next_attempt_at,
        last_error=entry.last_error,
        result=entry.result,
        alert_id=entry.alert_id,
        escalation_id=entry.escalation_id,
        title=(alert or {}).get("title"),
        created_at=entry.created_at,
        sent_at=entry.sent_at,
    )


@router.get("/{integration_id}/deliveries", response_model=List[DeliveryOut], summary="Recent deliveries (newest first)")
async def list_deliveries(
    integration_id: UUID,
    request: Request,
    status: Optional[List[OutboxStatus]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(require(ADMIN)),
) -> List[DeliveryOut]:
    ctx = get_ctx(request)
    await ctx.repos.integrations.get(principal.tenant_id, integration_id)
    entries = await ctx.repos.integrations.deliveries(principal.tenant_id, integration_id, status=status, limit=limit)
    return [delivery_out(e) for e in entries]


def ticket_out(ticket: ExternalTicket) -> TicketOut:
    return TicketOut.model_validate(ticket)


@tickets.get("", response_model=List[TicketOut], summary="External tickets linked to an alert or escalations")
async def list_tickets(
    request: Request,
    alert_id: Optional[str] = Query(default=None, max_length=256),
    escalation_id: Optional[List[str]] = Query(default=None, max_length=200),
    principal: Principal = Depends(require(VIEWER)),
) -> List[TicketOut]:
    if alert_id is None and not escalation_id:
        raise ApiError(400, "invalid_request", "pass alert_id or escalation_id")
    ctx = get_ctx(request)
    found = await ctx.repos.integrations.tickets(
        principal.tenant_id, alert_id=alert_id, escalation_ids=escalation_id or None
    )
    return [ticket_out(t) for t in found]
