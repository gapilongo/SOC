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
from lg_sotf.api.common import aware
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import AuditActorTypeStr, Out, PageOut
from lg_sotf.db.pagination import API_MAX_LIMIT

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEntryOut(Out):
    id: int
    tenant_id: str
    ts: datetime
    actor_type: AuditActorTypeStr
    actor_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: Optional[str] = None
    hash: str
    #: Details were cut for a caller acting under an MSSP grant, so the entry no longer matches ``hash``.
    redacted: bool = False


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
    limit: int = Query(default=100, ge=1, le=API_MAX_LIMIT),
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
    items = [_visible(AuditEntryOut.model_validate(e), principal) for e in page.items]
    return PageOut[AuditEntryOut](items=[e for e in items if e is not None], next_cursor=page.next_cursor)


def _visible(entry: AuditEntryOut, principal: Principal) -> Optional[AuditEntryOut]:
    """Under an MSSP grant the customer's grant register (``grant.*``) and other organisations' work are hidden.

    A page may then hold fewer than ``limit`` entries; ``next_cursor`` still continues it.
    """
    if not principal.delegated:
        return entry
    if entry.action.startswith("grant."):
        return None
    delegation = entry.details.get("delegation")
    if isinstance(delegation, dict) and delegation.get("organisation_id") != principal.home_tenant_id:
        details = {k: v for k, v in entry.details.items() if k != "delegation"}
        return entry.model_copy(update={"details": details, "redacted": True})
    return entry


@router.get("/verify", response_model=AuditVerifyOut, summary="Recompute the tenant's audit hash chain")
async def verify_audit(
    request: Request,
    since: Optional[datetime] = Query(default=None, alias="from"),
    principal: Principal = Depends(require(ADMIN)),
) -> AuditVerifyOut:
    since = aware(since)
    result = await get_ctx(request).repos.audit.verify_chain(principal.tenant_id, since)
    return AuditVerifyOut(ok=result.ok, first_bad_id=result.first_bad_id, since=since)
