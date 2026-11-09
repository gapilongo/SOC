"""Helpers shared by several routers (routers never import each other).

Response builders, query timestamps, the sign-in cookie and failed-login
limit (auth and mfa), the password policy as an API error (identity and
platform), the catch-all suppression rule check (suppressions and reports) and
dropping cached verdicts once an analyst finds a threat (review and blind audit).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set
from uuid import UUID

from fastapi import Request, Response
from redis.exceptions import RedisError

from lg_sotf.api.auth.authenticate import client_ip
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import AlertDetailOut, AlertOut, EntitiesPreviewOut, EscalationOut, FindingOut, RoutingOut
from lg_sotf.audit.logger import Actor
from lg_sotf.core.benign_learning import forget_benign_learning
from lg_sotf.core.retro_reopen import reopen_counted
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Alert, AlertListItem, Escalation
from lg_sotf.domain.blind_audit import (
    HIDDEN,
    HIDDEN_ALERT_FIELDS,
    HIDDEN_KEY,
    related_alert_ids,
    without_pending_related,
)
from lg_sotf.domain.digests import entities_preview, findings
from lg_sotf.domain.suppression import InvalidRule
from lg_sotf.models.vocabulary import SEVERITIES
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import REVOCATION_FAILURES
from lg_sotf.security.passwords import password_problem
from lg_sotf.services.escalation_views import EscalationView, escalation_views

log = get_logger(__name__)


async def invalidate_verdicts(
    ctx: ApiContext, tenant_id: str, alert_ids: Sequence[str], actor: Actor, *, escalation_id: Optional[str] = None,
    path: str = "api",
) -> int:
    """An analyst confirmed a threat: drop these alerts' cached benign verdicts and disable the rules matching them.

    The decision is already recorded, so a failure does not fail the request:
    it is logged as an error and counted in ``lgsotf_revocation_failures_total``
    (path ``api``), and the run's ``plan_response`` revokes again. Returns the
    number of alerts that failed.

    Decision policy v3: the alerts the models closed alone on these alerts' entities reopen too, attached to
    ``escalation_id`` (:mod:`lg_sotf.core.retro_reopen`); a failure there is counted in
    ``lgsotf_retro_reopen_failures_total`` (``path``), not raised.
    """
    cache = VerdictCache(ctx.redis, ctx.prefix)
    failed = 0
    for alert_id in alert_ids:
        try:
            alert = await ctx.repos.alerts.get(tenant_id, alert_id)
            await forget_benign_learning(ctx.repos, cache, tenant_id, alert, actor=actor)
        except Exception as exc:  # noqa: BLE001 - counted and logged as an error: an alerting rule can page on it
            failed += 1
            REVOCATION_FAILURES.labels(path="api").inc()
            log_failure(
                log, "api.revocation_failed", exc, level="error", alert_id=alert_id, error_type=type(exc).__name__,
            )
            continue
        for reopened in await reopen_counted(ctx.repos, tenant_id, alert, actor=actor, path=path,
                                             escalation_id=escalation_id):
            await enqueue_reopened(ctx, tenant_id, reopened)
    return failed


async def enqueue_reopened(ctx: ApiContext, tenant_id: str, alert_id: str) -> None:
    """Queue a reopened alert's new run now (the orphan sweep would pick it up later otherwise)."""
    try:
        alert = await ctx.repos.alerts.get(tenant_id, alert_id)
        if alert.status != "queued":
            return  # folded into an open case: no run to start
        await ctx.queue.enqueue_process(tenant_id, alert_id, alert.severity)
    except Exception as exc:  # noqa: BLE001 - the run is queued in the database; the orphan sweep dispatches it
        log_failure(log, "api.reopen_enqueue_failed", exc, alert_id=alert_id, error_type=type(exc).__name__)


def user_ref(principal: Principal, value: Optional[str], name: str) -> Optional[UUID]:
    """A user filter: a user id, or ``me`` (the caller's account in this tenant)."""
    if value is None:
        return None
    if value == "me":
        if principal.local_user_id is None:
            raise ApiError(400, "invalid_request", "'me' needs a user account in this tenant")
        return principal.local_user_id
    try:
        return UUID(value)
    except ValueError as exc:
        raise ApiError(400, "invalid_request", f"{name} must be a user id or 'me'") from exc


def alert_out(alert: AlertListItem, *, view: Optional[BlindView] = None) -> AlertOut:
    """``view``: which alerts wait for their blind-audit label (this one's AI side is then withheld, and
    another's correlation digest no longer names them)."""
    preview = entities_preview(alert.entities)
    out = AlertOut.model_validate(alert).model_copy(
        update={"entities_preview": EntitiesPreviewOut.model_validate(preview) if preview else None}
    )
    if view is None:
        return out
    if view.hides(alert.id):
        return out.model_copy(update=_hidden_fields())
    return out.model_copy(update={"summary": without_pending_related(alert.summary, view.pending)})


def alert_detail_out(alert: Alert, *, view: Optional[BlindView] = None) -> AlertDetailOut:
    preview = entities_preview(alert.entities)
    out = AlertDetailOut.model_validate(alert).model_copy(
        update={
            "entities_preview": EntitiesPreviewOut.model_validate(preview) if preview else None,
            "findings": [FindingOut.model_validate(f) for f in findings(alert.summary)],
        }
    )
    if view is None:
        return out
    if view.hides(alert.id):
        return out.model_copy(update={**_hidden_fields(), "findings": []})
    return out.model_copy(update={"summary": without_pending_related(alert.summary, view.pending)})


@dataclass(frozen=True)
class BlindView:
    """The pending blind-audit samples among some alerts and the alerts their correlation digests name."""

    pending: Mapping[str, Optional[str]]

    def hides(self, alert_id: str) -> bool:
        return alert_id in self.pending


async def blind_view(ctx: ApiContext, tenant_id: str, alerts: Sequence[AlertListItem]) -> BlindView:
    ids = [a.id for a in alerts] + [r for a in alerts for r in related_alert_ids(a.summary)]
    return BlindView(await ctx.repos.blind_audit.pending_dispositions(tenant_id, ids))


# Cached tenant figures that leave pending blind-audit samples out (dashboard summary, reports).
FIGURE_CACHES = ("dashboard", "reports")


def dashboard_cache_key(ctx: ApiContext, tenant_id: str, window_hours: int) -> str:
    return f"{ctx.prefix}:t:{tenant_id}:cache:dashboard:{window_hours}"


async def forget_cached_figures(ctx: ApiContext, tenant_id: str) -> None:
    """Drop the tenant's cached dashboard and report figures: they leave pending blind-audit samples out, so a
    run drawn or a sample labelled changes them, and a cached copy would show the counts from before.
    Redis being unavailable only means the copies expire on their own (15 and 60 seconds)."""
    try:
        for kind in FIGURE_CACHES:
            keys = [key async for key in ctx.redis.scan_iter(match=f"{ctx.prefix}:t:{tenant_id}:cache:{kind}:*")]
            if keys:
                await ctx.redis.unlink(*keys)
    except (RedisError, OSError, TimeoutError) as exc:
        log_failure(log, "api.figure_cache_unavailable", exc, level="warning", error_type=type(exc).__name__)


async def refuse_hidden(ctx: ApiContext, tenant_id: str, alert_id: str, resource: str, resource_id: str) -> None:
    """``NotFound`` for a resource of an alert waiting for its blind-audit label (it would name the verdict)."""
    if await hidden_alert_ids(ctx, tenant_id, [alert_id]):
        raise NotFound(resource, resource_id)


def _hidden_fields() -> Dict[str, Any]:
    return {**{key: None for key in HIDDEN_ALERT_FIELDS}, "summary": dict(HIDDEN), HIDDEN_KEY: True}


async def hidden_alert_ids(ctx: ApiContext, tenant_id: str, alert_ids: Sequence[str]) -> Set[str]:
    """The alerts among ``alert_ids`` that wait for a blind-audit label: nobody in the tenant sees their AI side."""
    return await ctx.repos.blind_audit.pending_alert_ids(tenant_id, alert_ids)


def escalation_out(escalation: Escalation, view: Optional[EscalationView]) -> EscalationOut:
    out = EscalationOut.model_validate(escalation)
    if view is None:
        return out
    return out.model_copy(
        update={
            "assigned_to_email": view.assigned_to_email,
            "decided_by_email": view.decided_by_email,
            "alert_severity": view.alert_severity,
            "rule": view.rule,
            "source_id": view.source_id,
            "source_name": view.source_name,
            "entities_preview": EntitiesPreviewOut.model_validate(view.entities_preview) if view.entities_preview else None,
            "ai_reason": view.ai_reason,
            "ai_reason_source": view.ai_reason_source,
            "routing": RoutingOut.model_validate(view.routing) if view.routing else None,
        }
    )


async def escalations_out(ctx: ApiContext, tenant_id: str, escalations: Sequence[Escalation]) -> List[EscalationOut]:
    """Escalations with their owners' addresses and their alerts' digests (two lookups per call)."""
    views = await escalation_views(ctx.repos, tenant_id, escalations)
    return [escalation_out(e, views.get(e.id)) for e in escalations]


async def one_escalation_out(ctx: ApiContext, tenant_id: str, escalation: Escalation) -> EscalationOut:
    return (await escalations_out(ctx, tenant_id, [escalation]))[0]


# ------------------------------------------------------------------ timestamps


def aware(value: Optional[datetime]) -> Optional[datetime]:
    """Query timestamps without an offset are taken as UTC."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


# ------------------------------------------------------------------ sign-in (auth and mfa routers)

REFRESH_COOKIE = "lgsotf_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"
LOGIN_IP_BUCKET = "login-ip"
LOGIN_IP_MULTIPLIER = 10


def set_refresh_cookie(ctx: ApiContext, response: Response, token: str) -> None:
    auth = ctx.settings.auth
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=int(auth.refresh_token_ttl_s),
        path=REFRESH_COOKIE_PATH,
        domain=auth.cookie_domain,
        secure=auth.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def login_ip_limit(ctx: ApiContext) -> int:
    return ctx.settings.api.login_rate_limit_per_minute * LOGIN_IP_MULTIPLIER


async def count_failed_login(ctx: ApiContext, request: Request) -> None:
    await ctx.limiter.hit(LOGIN_IP_BUCKET, client_ip(request), login_ip_limit(ctx))


def check_password(ctx: ApiContext, password: str) -> None:
    """The local-account password policy (:mod:`lg_sotf.security.passwords`) as a 422 ``weak_password``."""
    problem = password_problem(password, ctx.settings.auth.password_min_length)
    if problem is not None:
        raise ApiError(422, "weak_password", problem)


# ------------------------------------------------------------------ suppression rules (suppressions and reports)

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
