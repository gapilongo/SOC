# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/suppressions``: rules that close matching alerts as benign.

Analysts (and API keys with the ``write`` scope) create rules; admins manage
them (update, enable, delete). Only an admin can create a rule that is active
immediately: a rule created by anyone else is stored disabled whatever
``enabled`` says, and becomes active when an admin enables it
(``PATCH {"enabled": true}``). Rules suggested from false-positive decisions
are also created disabled. A rule whose every predicate matches any alert
(all severities, ``.*``, a ``/0`` network) is refused with 422, for admins
too: it would close every alert as benign.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping

from fastapi import APIRouter, Depends, Query, Request, Response

from lg_sotf.api.auth.deps import ADMIN, ANALYST, VIEWER, require
from lg_sotf.api.auth.principal import Principal, role_at_least
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.routers.alerts import aware
from lg_sotf.api.schemas import SuppressionCreateIn, SuppressionOut, SuppressionUpdateIn
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.suppression import InvalidRule, validate_rule_match
from lg_sotf.db.errors import NotFound
from lg_sotf.queue.streams import SEVERITIES

router = APIRouter(prefix="/suppressions", tags=["suppressions"])

_SEVERITY_PATHS = frozenset({"severity", "normalized.severity"})
_FLAGS = re.compile(r"^\(\?[a-zA-Z]+\)")
_UNIVERSAL_PATTERNS = frozenset({"", ".*", ".+", "(.*)", "(.+)", ".*?", "[\\s\\S]*", "[\\s\\S]+"})


def _values(predicate: Any) -> List[Any]:
    if isinstance(predicate, Mapping):
        if "in" in predicate and isinstance(predicate["in"], (list, tuple)):
            return list(predicate["in"])
        if "eq" in predicate:
            return [predicate["eq"]]
        return []
    if isinstance(predicate, (list, tuple)):
        return list(predicate)
    return [predicate]


def _universal(path: str, predicate: Any) -> bool:
    """Whether ``predicate`` matches (practically) every alert."""
    if path in _SEVERITY_PATHS:
        values = {v.lower() for v in _values(predicate) if isinstance(v, str)}
        if set(SEVERITIES) <= values:
            return True
    if isinstance(predicate, Mapping):
        pattern = predicate.get("regex")
        if isinstance(pattern, str):
            body = _FLAGS.sub("", pattern.strip())
            body = body.removeprefix("^").removesuffix("$")
            if body in _UNIVERSAL_PATTERNS:
                return True
        networks = predicate.get("cidr")
        if networks is not None:
            items = networks if isinstance(networks, (list, tuple)) else [networks]
            for item in items:
                try:
                    if isinstance(item, str) and ipaddress.ip_network(item, strict=False).prefixlen == 0:
                        return True
                except ValueError:
                    continue
    return False


def reject_catch_all(match: Mapping[str, Any]) -> None:
    """Refuse a rule whose every predicate matches any alert."""
    if match and all(_universal(str(path), predicate) for path, predicate in match.items()):
        raise InvalidRule("the rule matches every alert; add a narrower predicate")


def _may_enable(principal: Principal) -> bool:
    return principal.is_user and role_at_least(principal.role, "admin")


async def _audit(ctx: ApiContext, principal: Principal, action: str, rule_id: str, details: Dict[str, Any]) -> None:
    await AuditLogger(ctx.repos).record(
        principal.tenant_id,
        action,
        "suppression_rule",
        rule_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details=details,
    )


def _future(value: datetime) -> datetime:
    value = aware(value)  # type: ignore[assignment]
    if value <= datetime.now(UTC):
        raise ApiError(422, "validation_error", "expires_at must be in the future")
    return value


@router.get("", response_model=List[SuppressionOut], summary="List suppression rules")
async def list_rules(
    request: Request,
    include_disabled: bool = Query(default=True),
    principal: Principal = Depends(require(VIEWER)),
) -> List[SuppressionOut]:
    rules = await get_ctx(request).repos.suppressions.list(principal.tenant_id, include_disabled=include_disabled)
    return [SuppressionOut.model_validate(r) for r in rules]


@router.get("/{rule_id}", response_model=SuppressionOut, summary="Suppression rule detail")
async def get_rule(rule_id: str, request: Request, principal: Principal = Depends(require(VIEWER))) -> SuppressionOut:
    return SuppressionOut.model_validate(await get_ctx(request).repos.suppressions.get(principal.tenant_id, rule_id))


@router.post("", status_code=201, response_model=SuppressionOut, summary="Create a suppression rule")
async def create_rule(
    body: SuppressionCreateIn, request: Request, principal: Principal = Depends(require(ANALYST))
) -> SuppressionOut:
    ctx = get_ctx(request)
    validate_rule_match(body.match)
    reject_catch_all(body.match)
    # Only admins create active rules; anything else waits for an admin to enable it.
    enabled = body.enabled and _may_enable(principal)
    rule = await ctx.repos.suppressions.create(
        principal.tenant_id,
        body.name,
        body.match,
        created_by=principal.local_user_id,
        expires_at=_future(body.expires_at) if body.expires_at else None,
        enabled=enabled,
    )
    await _audit(
        ctx,
        principal,
        "suppression.created",
        rule.id,
        {"enabled": rule.enabled, "requested_enabled": body.enabled, "fields": sorted(body.match)[:20]},
    )
    return SuppressionOut.model_validate(rule)


@router.patch("/{rule_id}", response_model=SuppressionOut, summary="Update or enable/disable a rule")
async def update_rule(
    rule_id: str, body: SuppressionUpdateIn, request: Request, principal: Principal = Depends(require(ADMIN))
) -> SuppressionOut:
    ctx = get_ctx(request)
    fields = body.model_fields_set
    for name in ("name", "match", "enabled"):
        if name in fields and getattr(body, name) is None:
            raise ApiError(422, "validation_error", f"{name} cannot be null")
    if body.match is not None:
        validate_rule_match(body.match)
        reject_catch_all(body.match)
    changes: Dict[str, Any] = {name: getattr(body, name) for name in ("name", "match", "enabled") if name in fields}
    if "expires_at" in fields:
        changes["expires_at"] = _future(body.expires_at) if body.expires_at else None
    rule = await ctx.repos.suppressions.update(principal.tenant_id, rule_id, **changes)
    await _audit(ctx, principal, "suppression.updated", rule_id, {"fields": sorted(fields), "enabled": rule.enabled})
    return SuppressionOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=204, summary="Delete a rule")
async def delete_rule(rule_id: str, request: Request, principal: Principal = Depends(require(ADMIN))) -> Response:
    ctx = get_ctx(request)
    if not await ctx.repos.suppressions.delete(principal.tenant_id, rule_id):
        raise NotFound("suppression rule", rule_id)
    await _audit(ctx, principal, "suppression.deleted", rule_id, {})
    return Response(status_code=204)
