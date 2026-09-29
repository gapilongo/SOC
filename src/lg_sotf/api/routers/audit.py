# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/audit`` (admin): the tenant's hash-chained audit log, read-only.

``GET /audit`` lists entries newest first with keyset pagination and exact
filters; ``GET /audit/verify`` recomputes the tenant's hash chain and reports
the first entry that does not match. Entries never carry secrets or raw alert
bodies (writers guarantee this), so they are returned as stored.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from lg_sotf.api.auth.deps import ADMIN, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.routers.alerts import aware
from lg_sotf.api.schemas import Out, PageOut

router = APIRouter(prefix="/audit", tags=["audit"])

MAX_LIMIT = 200


class AuditEntryOut(Out):
    id: int
    tenant_id: str
    ts: datetime
    actor_type: str
    actor_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: Optional[str] = None
    hash: str


class AuditVerifyOut(BaseModel):
    ok: bool
    first_bad_id: Optional[int] = None
    since: Optional[datetime] = None


@router.get("", response_model=PageOut[AuditEntryOut], summary="Audit log (newest first, keyset pagination)")
async def list_audit(
    request: Request,
    action: Optional[str] = Query(default=None, max_length=128),
    resource_type: Optional[str] = Query(default=None, max_length=64),
    resource_id: Optional[str] = Query(default=None, max_length=256),
    actor_id: Optional[str] = Query(default=None, max_length=256),
    since: Optional[datetime] = Query(default=None, alias="from"),
    until: Optional[datetime] = Query(default=None, alias="to"),
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    principal: Principal = Depends(require(ADMIN)),
) -> PageOut[AuditEntryOut]:
    since, until = aware(since), aware(until)
    if since is not None and until is not None and until <= since:
        raise ApiError(400, "invalid_window", "'to' must be after 'from'")
    page = await get_ctx(request).repos.audit.list(
        principal.tenant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        since=since,
        until=until,
        limit=limit,
        cursor=cursor,
    )
    return PageOut[AuditEntryOut](
        items=[AuditEntryOut.model_validate(e) for e in page.items], next_cursor=page.next_cursor
    )


@router.get("/verify", response_model=AuditVerifyOut, summary="Recompute the tenant's audit hash chain")
async def verify_audit(
    request: Request,
    since: Optional[datetime] = Query(default=None, alias="from"),
    principal: Principal = Depends(require(ADMIN)),
) -> AuditVerifyOut:
    since = aware(since)
    result = await get_ctx(request).repos.audit.verify_chain(principal.tenant_id, since)
    return AuditVerifyOut(ok=result.ok, first_bad_id=result.first_bad_id, since=since)
