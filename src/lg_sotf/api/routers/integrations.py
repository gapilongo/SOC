# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/integrations`` (admin) and ``/tickets`` (viewer): notification channels, ticketing and their delivery log.

Credentials (``secret``) are write-only: validated, encrypted with the
install's :class:`~lg_sotf.security.crypto.SecretBox` bound to the tenant
and the integration id, and never returned (responses carry
``secrets: {field: configured}``). On update, ``secret`` is a merge patch:
a value replaces that field, ``null`` removes it, absent fields are kept.
Every change and every test is written to the audit log.

``POST /integrations/slack/interactions`` is the Request URL of a Slack
app's Interactivity: it is authenticated by the app's signing secret, not
by a bearer token (see :mod:`lg_sotf.integrations.slack`).

The ``microsoft`` kind is the direct response connector
(``docs/microsoft.md``): at most one per tenant (409 ``integration_exists``),
no events, its capabilities described by ``GET
/integrations/microsoft/catalog``. Its audit entries record which
capabilities were enabled or disabled, went live or stopped being live,
their options and whether the credential was rotated (never the
credential). ``POST /integrations/{id}/test`` runs the Microsoft connection
test (token requests and GETs only) and returns its report as
``microsoft``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.api.auth.deps import ADMIN, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.payload_schemas import MicrosoftCatalogOut
from lg_sotf.api.routers._slack import decide_from_slack, reply_text
from lg_sotf.api.schemas import (
    DeliveryOperationStr,
    DeliveryStatusStr,
    IntegrationEventStr,
    IntegrationKindStr,
    SeverityStr,
    TicketingKindStr,
)
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import NotFound
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos import ExternalTicket, Integration, OutboxEntry
from lg_sotf.db.repos.integrations import IntegrationExists
from lg_sotf.db.repos.outbox import NewOutboxEntry
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.domain.connectors import ConnectorConfigError
from lg_sotf.integrations.channels import send_notification
from lg_sotf.integrations.config import (
    MICROSOFT_KIND,
    NOTIFY_KINDS,
    IntegrationConfigError,
    certificate_details,
    check_secret_binding,
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
    ACTION_VERIFICATION_FAILED,
    ESCALATION_CREATED,
    ESCALATION_DECIDED,
    ESCALATION_SLA_BREACHED,
    TEST_EVENT,
    make_test_event,
    ui_base_url,
)
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp, tls_verify
from lg_sotf.integrations.microsoft.catalog import catalog_out
from lg_sotf.integrations.microsoft.connection_test import MicrosoftTestReport
from lg_sotf.integrations.slack import (
    MAX_BODY_BYTES,
    REPLAY_TTL_S,
    SlackRequestError,
    parse_interaction,
    replay_key,
    reply,
    verify_slack_request,
)
from lg_sotf.integrations.ticketing import ticket_client
from lg_sotf.models.vocabulary import Severity
from lg_sotf.observability.logging import get_logger
from lg_sotf.services import integrations as integration_changes
from lg_sotf.services.connectors.microsoft import MicrosoftClients, build_microsoft_connector

log = get_logger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])
tickets = APIRouter(prefix="/tickets", tags=["integrations"])

Kind = Literal["slack", "teams", "email", "webhook", "jira", "servicenow", "microsoft"]
OutboxStatus = Literal["pending", "sent", "failed", "dead"]
MAX_CONFIG_KEYS = 30
MAX_INTEGRATIONS_PER_TENANT = 50
DEFAULT_EVENTS: Dict[str, List[str]] = {
    "notify": [ESCALATION_CREATED, ESCALATION_SLA_BREACHED, ACTION_AWAITING_APPROVAL, ACTION_VERIFICATION_FAILED],
    "ticketing": [ESCALATION_CREATED, ESCALATION_DECIDED],
    "microsoft": [],
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
    kind: IntegrationKindStr
    name: str
    enabled: bool
    events: List[IntegrationEventStr]
    min_severity: SeverityStr
    config: Dict[str, Any]
    secrets: Dict[str, bool] = Field(description="Which credential fields are configured (values are never returned).")
    created_at: datetime
    updated_at: datetime


class IntegrationTestOut(BaseModel):
    ok: bool
    detail: str
    http_status: Optional[int] = None
    microsoft: Optional[MicrosoftTestReport] = None


class DeliveryOut(BaseModel):
    id: UUID
    event_id: UUID
    event_type: str
    operation: DeliveryOperationStr
    status: DeliveryStatusStr
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
    system: TicketingKindStr
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


def _config_out(integration: Integration) -> Dict[str, Any]:
    config = dict(integration.config)
    pem = config.get("certificate_pem")
    if integration.kind == MICROSOFT_KIND and isinstance(pem, str) and pem:
        try:
            details = certificate_details(pem)
        except IntegrationConfigError:
            details = None
        config["certificate"] = (
            {k: details[k] for k in ("thumbprint_sha1", "thumbprint_sha256", "not_after")} if details else None
        )
    return config


def integration_out(ctx: ApiContext, integration: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=integration.id,
        tenant_id=integration.tenant_id,
        kind=integration.kind,
        name=integration.name,
        enabled=integration.enabled,
        events=list(integration.events),
        min_severity=integration.min_severity,
        config=_config_out(integration),
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
        if kind == MICROSOFT_KIND:
            return []
        return list(DEFAULT_EVENTS["notify" if kind in NOTIFY_KINDS else "ticketing"])
    try:
        return validate_events(kind, events)
    except IntegrationConfigError as exc:
        raise _invalid(exc) from None


def _encrypt(
    ctx: ApiContext,
    kind: str,
    tenant_id: str,
    integration_id: UUID,
    values: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    try:
        checked = validate_secret(kind, values, require_https=_require_https(ctx), config=config)
    except IntegrationConfigError as exc:
        raise _invalid(exc) from None
    if not checked:
        return None
    if ctx.secret_box is None:
        raise ApiError(503, "encryption_unavailable", "secret encryption is not configured on this server")
    return encrypt_secret(ctx.secret_box, tenant_id, integration_id, checked)


def _capability_flags(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    caps = config.get("capabilities") if isinstance(config.get("capabilities"), dict) else {}
    return {str(k): v for k, v in (caps or {}).items() if isinstance(v, dict)}


def microsoft_audit(
    before: Dict[str, Any], after: Dict[str, Any], *, credential_rotated: bool
) -> Dict[str, Any]:
    """What a Microsoft integration change did to its capabilities (never its credential)."""
    old, new = _capability_flags(before), _capability_flags(after)

    def keys(caps: Dict[str, Dict[str, Any]], flag: str) -> set[str]:
        return {k for k, v in caps.items() if v.get("enabled") is True and (flag == "enabled" or v.get("live") is True)}

    options = {
        k: v.get("options") for k, v in new.items() if v.get("options") != (old.get(k) or {}).get("options")
    }
    return {
        "capabilities_enabled": sorted(keys(new, "enabled") - keys(old, "enabled")),
        "capabilities_disabled": sorted(keys(old, "enabled") - keys(new, "enabled")),
        "live_enabled": sorted(keys(new, "live") - keys(old, "live")),
        "live_disabled": sorted(keys(old, "live") - keys(new, "live")),
        "credential_rotated": credential_rotated,
        "options": options,
        "cloud": after.get("cloud"),
        "credential": after.get("credential"),
    }


def _microsoft_clients(request: Request) -> MicrosoftClients:
    """Test hook: ``app.state.microsoft_clients`` replaces the process's Microsoft HTTP factory and token cache."""
    injected = getattr(request.app.state, "microsoft_clients", None)
    return injected if injected is not None else get_ctx(request).review.responses.microsoft


def _http(request: Request) -> IntegrationHttp:
    """Test hook: ``app.state.integrations_http`` replaces the default client."""
    injected = getattr(request.app.state, "integrations_http", None)
    return injected if injected is not None else IntegrationHttp(get_ctx(request).settings)


@router.get("", response_model=List[IntegrationOut], summary="List integrations")
async def list_integrations(request: Request, principal: Principal = Depends(require(ADMIN))) -> List[IntegrationOut]:
    ctx = get_ctx(request)
    return [integration_out(ctx, i) for i in await ctx.repos.integrations.list(principal.tenant_id)]


@router.post(
    "/slack/interactions",
    status_code=200,
    summary="Slack Interactivity Request URL (approve or reject actions from Slack)",
    response_class=Response,
)
async def slack_interactions(
    request: Request,
    tenant: str = Query(max_length=63),
    integration: UUID = Query(),
) -> Response:
    """Verified with the Slack app's signing secret (v0 HMAC, 5-minute window, replay cache); see the module docstring."""
    ctx = get_ctx(request)
    denied = ApiError(401, "unauthorized", "invalid Slack request")
    client = request.client.host if request.client else "unknown"
    await ctx.limiter.enforce("slack", client, ctx.settings.api.rate_limit_per_minute)
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise ApiError(413, "payload_too_large", "Slack interaction payload too large")
    if not is_valid_tenant_id(tenant):
        raise denied
    tenant_row = await ctx.tenants.get(tenant)
    if tenant_row is None or tenant_row.status != "active":
        raise denied
    try:
        item = await ctx.repos.integrations.get(tenant, integration)
        secret = decrypt_secret(ctx.secret_box, tenant, item.id, item.secret_ciphertext)
    except (NotFound, IntegrationConfigError):
        raise denied from None
    if item.kind != "slack" or not item.enabled or not item.config.get("interactive_approvals"):
        raise denied
    signing_secret, bot_token = secret.get("signing_secret"), secret.get("bot_token")
    signature = request.headers.get("X-Slack-Signature")
    if not signing_secret or not bot_token or not signature:
        raise denied
    if not verify_slack_request(signing_secret, request.headers.get("X-Slack-Request-Timestamp"), body, signature):
        log.warning("integrations.slack_signature_invalid")
        raise denied
    if not await ctx.redis.set(replay_key(ctx.prefix, tenant, signature), b"1", nx=True, ex=REPLAY_TTL_S):
        log.warning("integrations.slack_replay_refused")
        raise denied
    try:
        interaction = parse_interaction(body)
    except SlackRequestError as exc:
        return JSONResponse({"response_type": "ephemeral", "text": f"LG-SOTF: {exc}"})
    http = _http(request)
    user, acted, outcome = await decide_from_slack(ctx, http, bot_token, tenant, interaction)
    await AuditLogger(ctx.repos).record_event(
        tenant,
        "integration.slack_interaction",
        "response_action",
        str(interaction.action_id),
        actor_type="user" if user is not None else "system",
        actor_id=str(user.id) if user is not None else f"slack:{interaction.slack_user_id}",
        details={
            "integration_id": str(item.id),
            "slack_user_id": interaction.slack_user_id,
            "slack_team_id": interaction.slack_team_id,
            "requested": "approve" if interaction.approve else "reject",
            "outcome": outcome,
        },
    )
    await reply(http, interaction.response_url, reply_text(ctx, interaction.approve, outcome, acted))
    return Response(status_code=200)


@router.get(
    "/microsoft/catalog",
    summary="Microsoft direct-response capabilities, clouds and Defender geos",
    response_model=None,
    responses={200: {"model": MicrosoftCatalogOut}},
)
async def microsoft_catalog(principal: Principal = Depends(require(ADMIN))) -> Dict[str, Any]:
    """Every capability the Microsoft integration can enable: actions, permissions, options schema, clouds."""
    return catalog_out()


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
    existing = await ctx.repos.integrations.list(tenant_id)
    if len(existing) >= MAX_INTEGRATIONS_PER_TENANT:
        raise ApiError(409, "conflict", f"a tenant may have at most {MAX_INTEGRATIONS_PER_TENANT} integrations")
    if body.kind == MICROSOFT_KIND and any(i.kind == MICROSOFT_KIND for i in existing):
        raise ApiError(409, "integration_exists", "this tenant already has a Microsoft integration")
    config = _check_config(ctx, body.kind, body.config)
    events = _events(body.kind, body.events)
    integration_id = uuid.uuid4()
    ciphertext = _encrypt(ctx, body.kind, tenant_id, integration_id, merge_secret({}, body.secret or {}), config)
    details: Dict[str, Any] = {
        "kind": body.kind, "name": body.name, "events": events, "has_secret": ciphertext is not None,
    }
    if body.kind == MICROSOFT_KIND:
        details.update(microsoft_audit({}, config, credential_rotated=ciphertext is not None))
    try:
        integration = await integration_changes.create_integration(
            ctx.repos,
            AuditLogger(ctx.repos),
            tenant_id,
            principal.actor,
            kind=body.kind,
            name=body.name,
            details=details,
            integration_id=integration_id,
            config=config,
            secret_ciphertext=ciphertext,
            events=events,
            min_severity=body.min_severity,
            enabled=body.enabled,
            created_by=principal.local_user_id,
        )
    except IntegrationExists as exc:
        raise ApiError(409, "integration_exists", str(exc)) from None
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
        try:
            check_secret_binding(current.kind, current.config, changes["config"], body.secret or {})
        except IntegrationConfigError as exc:
            raise _invalid(exc) from None
    if "events" in fields:
        changes["events"] = _events(current.kind, body.events)
    changed_secrets: List[str] = []
    new_config: Dict[str, Any] = changes.get("config", dict(current.config))
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
            ctx, current.kind, tenant_id, integration_id, merge_secret(existing, patch), new_config
        )
        changed_secrets = sorted(patch)
    details: Dict[str, Any] = {"fields": sorted(f for f in fields if f != "secret"), "secret_fields": changed_secrets}
    if current.kind == MICROSOFT_KIND:
        details.update(
            microsoft_audit(dict(current.config), new_config, credential_rotated=bool(changed_secrets))
        )
    integration = await integration_changes.update_integration(
        ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, integration_id, changes, details=details
    )
    return integration_out(ctx, integration)


@router.delete("/{integration_id}", status_code=204, summary="Delete an integration (its delivery log and ticket links)")
async def delete_integration(
    integration_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))
) -> Response:
    ctx = get_ctx(request)
    current = await ctx.repos.integrations.get(principal.tenant_id, integration_id)
    details: Dict[str, Any] = {"kind": current.kind, "name": current.name}
    if current.kind == MICROSOFT_KIND:
        details.update(microsoft_audit(dict(current.config), {}, credential_rotated=False))
    if not await integration_changes.delete_integration(
        ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, integration_id, details=details
    ):
        raise NotFound("integration", integration_id)
    return Response(status_code=204)


@router.post("/{integration_id}/test", response_model=IntegrationTestOut, summary="Send a test message now")
async def test_integration(
    integration_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))
) -> IntegrationTestOut:
    """Notification kinds get a test message; ticketing kinds check the credentials and project (no ticket)."""
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    integration = await ctx.repos.integrations.get(tenant_id, integration_id)
    if integration.kind == MICROSOFT_KIND:
        return await _test_microsoft(request, ctx, principal, integration)
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
    await integration_changes.record_test(
        ctx.repos,
        AuditLogger(ctx.repos),
        tenant_id,
        principal.actor,
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
        details={"ok": ok, "http_status": status},
    )
    return IntegrationTestOut(ok=ok, detail=detail[:500], http_status=status)


async def _test_microsoft(
    request: Request, ctx: ApiContext, principal: Principal, integration: Integration
) -> IntegrationTestOut:
    """The Microsoft connection test: token requests and GETs only; the report is stored and audited."""
    tenant_id = principal.tenant_id
    clients = _microsoft_clients(request)
    report: Optional[MicrosoftTestReport] = None
    try:
        connector = build_microsoft_connector(
            ctx.repos, ctx.settings, ctx.secret_box, integration, tokens=clients.tokens, http=clients.http,
            checkpoints=ctx.repos.actions,
        )
        report = await connector.probe_all()
        ok = report.ok
        enabled = [k for k, c in report.capabilities.items() if c.enabled]
        detail = (
            "credentials accepted; " + (f"{len(enabled)} enabled capabilities checked" if enabled else "no capability enabled")
            if ok else "the connection test found problems (see the report)"
        )
    except ConnectorConfigError as exc:
        ok, detail = False, str(exc)
    event_id = uuid.uuid4()
    result: Dict[str, Any] = report.model_dump(mode="json") if report is not None else {}
    await integration_changes.record_test(
        ctx.repos,
        AuditLogger(ctx.repos),
        tenant_id,
        principal.actor,
        NewOutboxEntry(
            integration_id=integration.id,
            event_id=event_id,
            event_type=TEST_EVENT,
            operation="test",
            dedupe_key=f"{TEST_EVENT}:{event_id}",
            payload={"event": TEST_EVENT, "kind": MICROSOFT_KIND},
        ),
        ok=ok,
        error=None if ok else detail,
        result=result,
        details={
            "ok": ok,
            "tokens": {api: t.status for api, t in report.tokens.items()} if report is not None else {},
            "capabilities": {k: c.status for k, c in report.capabilities.items() if c.enabled} if report else {},
        },
    )
    return IntegrationTestOut(ok=ok, detail=detail[:500], microsoft=report)


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
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(ADMIN)),
) -> List[DeliveryOut]:
    ctx = get_ctx(request)
    await ctx.repos.integrations.get(principal.tenant_id, integration_id)
    entries = await ctx.repos.outbox.deliveries(principal.tenant_id, integration_id, status=status, limit=limit)
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
    found = await ctx.repos.tickets.list(
        principal.tenant_id, alert_id=alert_id, escalation_ids=escalation_id or None
    )
    return [ticket_out(t) for t in found]
