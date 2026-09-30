# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/ingest``: pushing alerts with an API key that has the ``ingest`` scope.

``POST /ingest/alerts`` takes canonical-format alerts, either as a JSON array
or as ``{"alerts": [...]}``, at most ``api.max_ingest_batch`` per request.
They are stored under the source id ``api:<api key id>`` (chosen by the
server, never the client). ``POST /ingest/webhook/{source_id}`` takes a
vendor-native payload (one JSON object or an array of them) for a push
source (``webhook``/``guardduty``) registered in the key's tenant.
``POST /ingest/email`` takes one raw email (``message/rfc822`` or
``application/octet-stream``, at most ``ingestion.email.max_message_bytes``),
usually a user's report with the suspicious message attached; the optional
``reporter`` query parameter names the reporting user. It is parsed
server-side and stored under ``email:<api key id>``, deduplicated on the
reported message's Message-ID plus the reporter.

New alerts are queued for the workers before the 202 response; the response
lists one result per submitted event, in order. At most
``api.max_inflight_ingest`` ingest requests are processed at once per API
process; more are refused at once with ``503 overloaded`` and
``Retry-After`` rather than queueing on the database pool. Batch events
(tens per request) for throughput.

A tenant whose ``max_alerts_per_day`` quota is used up gets ``429
quota_exceeded`` (``Retry-After``: seconds to the next UTC day); the first
refusal of the day is audited as ``tenant.quota_exceeded``. A suspended
tenant's keys are refused with ``403 tenant_suspended`` at authentication.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Iterator, List, Mapping, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from lg_sotf.api.auth.deps import INGEST, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import IngestItemOut, IngestOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.pagination import MAX_PAGE_SIZE
from lg_sotf.ingestion.entities import normalize_email
from lg_sotf.ingestion.service import (
    SOURCE_ID_PATTERN,
    IngestResult,
    api_source_id,
    email_source_id,
    is_reserved_source_id,
)
from lg_sotf.models.alert import IngestedAlert
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.services.tenancy import alert_quota_exceeded

log = get_logger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

_RESPONSES: dict[int | str, dict[str, Any]] = {
    202: {"model": IngestOut, "description": "Accepted; per-event results in input order"},
}


async def _json_body(request: Request) -> Any:
    content_type = request.headers.get("content-type", "")
    if content_type and "json" not in content_type.lower():
        raise ApiError(415, "unsupported_media_type", "send application/json")
    raw = await request.body()
    if not raw:
        raise ApiError(400, "invalid_json", "request body is empty")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ApiError(400, "invalid_json", "request body is not valid JSON") from exc


RETRY_AFTER_S = 1
EMAIL_CONTENT_TYPES = frozenset({"message/rfc822", "application/octet-stream"})


@contextmanager
def _admitted(ctx: ApiContext) -> Iterator[None]:
    admission = ctx.ingest_admission
    assert admission is not None
    if not admission.try_acquire():
        log.warning("ingest.overloaded", inflight=admission.inflight)
        raise ApiError(
            503,
            "overloaded",
            "too many ingest requests in flight; retry shortly (batch events to send more per request)",
            headers={"Retry-After": str(RETRY_AFTER_S)},
        )
    try:
        yield
    finally:
        admission.release()


def _batch(ctx: ApiContext, events: Any) -> List[Mapping[str, Any]]:
    if not isinstance(events, list):
        raise ApiError(400, "invalid_request", "expected a JSON array of events")
    if not events:
        raise ApiError(400, "invalid_request", "no events submitted")
    limit = ctx.settings.api.max_ingest_batch
    if len(events) > limit:
        raise ApiError(400, "batch_too_large", f"at most {limit} events per request")
    return events


async def _stranded_duplicates(
    ctx: ApiContext, tenant_id: str, source_id: str, result: IngestResult
) -> List[IngestedAlert]:
    """Duplicates whose alert was stored but never queued (an earlier call failed between the two).

    A client that retries after such a failure gets ``duplicate`` for every
    event; without this the alerts would stay ``new`` forever. Dispatch is
    idempotent, so re-dispatching is safe.
    """
    inserted = {a.alert_id for a in result.inserted}
    duplicate_ids = {i.alert_id for i in result.items if i.status == "duplicate" and i.alert_id} - inserted
    if not duplicate_ids:
        return []
    page = await ctx.repos.alerts.list(
        tenant_id, status="new", source_id=source_id, limit=min(MAX_PAGE_SIZE, max(len(duplicate_ids), 1) * 4)
    )
    stranded = [IngestedAlert(alert_id=a.id, severity=a.severity) for a in page.items if a.id in duplicate_ids]
    if stranded:
        log.warning("ingest.stranded_alerts_dispatched", count=len(stranded))
    return stranded


def seconds_to_next_utc_day(now: datetime) -> int:
    tomorrow = (now.astimezone(UTC) + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((tomorrow - now).total_seconds()))


async def _enforce_alert_quota(ctx: ApiContext, principal: Principal, received: int) -> None:
    tenant = await ctx.tenants.get(principal.tenant_id)
    if tenant is None:
        return
    exceeded = await alert_quota_exceeded(ctx.repos, tenant)
    if exceeded is None:
        return
    if await ctx.repos.usage.record_quota_rejection(tenant.id, received):
        await AuditLogger(ctx.repos).record(
            tenant.id,
            "tenant.quota_exceeded",
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"quota": exceeded.quota, "limit": exceeded.limit, "used": exceeded.used},
        )
    log.warning("ingest.quota_exceeded", limit=exceeded.limit, used=exceeded.used)
    raise ApiError(
        429,
        "quota_exceeded",
        f"the tenant's daily alert quota ({exceeded.limit}) is used up; ingestion resumes at 00:00 UTC",
        headers={"Retry-After": str(seconds_to_next_utc_day(datetime.now(UTC)))},
    )


async def _ingest_and_dispatch(
    ctx: ApiContext, principal: Principal, source_id: str, events: List[Mapping[str, Any]]
) -> JSONResponse:
    await _enforce_alert_quota(ctx, principal, len(events))
    result: IngestResult = await ctx.ingestion.ingest(principal.tenant_id, source_id, events)
    return await _dispatch(ctx, principal, source_id, len(events), result)


async def _dispatch(
    ctx: ApiContext, principal: Principal, source_id: str, received: int, result: IngestResult
) -> JSONResponse:
    tenant_id = principal.tenant_id
    to_dispatch = list(result.inserted) + await _stranded_duplicates(ctx, tenant_id, source_id, result)
    enqueued = await dispatch_new_alerts(ctx.repos, ctx.queue, tenant_id, to_dispatch, events=ctx.events)
    body = IngestOut(
        source_id=source_id,
        received=received,
        inserted=len(result.inserted),
        duplicates=result.duplicates,
        rejected=len(result.rejected),
        enqueued=enqueued,
        items=[
            IngestItemOut(index=i.index, status=i.status, alert_id=i.alert_id, reason=i.reason) for i in result.items
        ],
    )
    return JSONResponse(body.model_dump(mode="json"), status_code=202)


@router.post("/alerts", status_code=202, responses=_RESPONSES, summary="Push canonical alerts")
async def ingest_alerts(request: Request, principal: Principal = Depends(require(INGEST))) -> JSONResponse:
    ctx = get_ctx(request)
    with _admitted(ctx):
        payload = await _json_body(request)
        if isinstance(payload, dict):
            if set(payload) != {"alerts"}:
                raise ApiError(400, "invalid_request", "expected a JSON array or an object with only 'alerts'")
            payload = payload["alerts"]
        events = _batch(ctx, payload)
        assert principal.api_key_id is not None
        return await _ingest_and_dispatch(ctx, principal, api_source_id(str(principal.api_key_id)), events)


@router.post(
    "/webhook/{source_id}", status_code=202, responses=_RESPONSES, summary="Push a vendor payload to a push source"
)
async def ingest_webhook(
    source_id: str, request: Request, principal: Principal = Depends(require(INGEST))
) -> JSONResponse:
    ctx = get_ctx(request)
    if is_reserved_source_id(source_id) or not SOURCE_ID_PATTERN.match(source_id):
        raise ApiError(404, "source_not_found", "no push source with this id")
    with _admitted(ctx):
        payload = await _json_body(request)
        events = _batch(ctx, [payload] if isinstance(payload, dict) else payload)
        return await _ingest_and_dispatch(ctx, principal, source_id, events)


@router.post(
    "/email",
    status_code=202,
    responses=_RESPONSES,
    summary="Push one raw email (a user-reported message) for phishing triage",
)
async def ingest_email(
    request: Request,
    reporter: Optional[str] = Query(
        default=None, max_length=320, description="Email address of the user who reported the message"
    ),
    principal: Principal = Depends(require(INGEST)),
) -> JSONResponse:
    ctx = get_ctx(request)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in EMAIL_CONTENT_TYPES:
        raise ApiError(415, "unsupported_media_type", "send the raw message as message/rfc822")
    reporter_address: Optional[str] = None
    if reporter is not None:
        reporter_address = normalize_email(reporter)
        if reporter_address is None:
            raise ApiError(422, "validation_error", "reporter must be an email address")
    with _admitted(ctx):
        raw = await request.body()
        if not raw:
            raise ApiError(400, "invalid_request", "request body is empty")
        limit = ctx.ingestion.email_limits.max_message_bytes
        if len(raw) > limit:
            raise ApiError(413, "payload_too_large", f"message is larger than {limit} bytes")
        assert principal.api_key_id is not None
        source_id = email_source_id(str(principal.api_key_id))
        await _enforce_alert_quota(ctx, principal, 1)
        result = await ctx.ingestion.ingest_email(principal.tenant_id, source_id, [raw], reporter=reporter_address)
        return await _dispatch(ctx, principal, source_id, 1, result)
