# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/reports``: value, accuracy on the tenant's own data, detection tuning and the monthly report.

All reads are viewer-level, aggregate in SQL over a window of at most 366
days and are cached for 60 seconds per tenant and window (see
:class:`~lg_sotf.services.reporting.ReportService`). ``format=csv`` exports
the value daily series and the detections table; the monthly report is a
self-contained HTML page (or JSON). Proposing a suppression from the
detections report is analyst-level and goes through the same suggestion
service as a false-positive decision: the rule is created disabled and an
admin enables it.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Literal, Optional, Union

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from lg_sotf import __version__
from lg_sotf.api.auth.deps import ANALYST, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import reject_catch_all
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import SuppressionOut
from lg_sotf.db.errors import NotFound
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.domain.suppression import InvalidRule
from lg_sotf.services.report_render import REPORT_CSP, detections_csv, monthly_html, value_csv
from lg_sotf.services.reporting import (
    AccuracyReport,
    DetectionsReport,
    MonthlyReport,
    ReportService,
    ReportWindow,
    ReportWindowError,
    ValueReport,
    resolve_reporting_policy,
    resolve_window,
    suppression_match,
)

router = APIRouter(prefix="/reports", tags=["reports"])

CSV_MEDIA_TYPE = "text/csv; charset=utf-8"
HTML_MEDIA_TYPE = "text/html; charset=utf-8"


class ProposeSuppressionIn(BaseModel):
    """A detection from the detections report (``source_id``, ``rule_field``, ``rule``) and its window."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source_id: str = Field(min_length=1, max_length=128)
    rule_field: Literal["rule_name", "title"]
    rule: str = Field(min_length=1, max_length=1024)
    start: Optional[date] = Field(default=None, alias="from")
    end: Optional[date] = Field(default=None, alias="to")


def service(ctx: ApiContext) -> ReportService:
    return ReportService(ctx.repos, ctx.redis, ctx.prefix, RoutingThresholds.from_settings(ctx.settings.routing))


def window(start: Optional[date], end: Optional[date]) -> ReportWindow:
    try:
        return resolve_window(start, end)
    except ReportWindowError as exc:
        raise ApiError(400, "invalid_window", str(exc)) from exc


async def minutes_per_alert(ctx: ApiContext, tenant_id: str) -> int:
    tenant = await ctx.tenants.get(tenant_id)
    return resolve_reporting_policy(tenant.settings if tenant else None).minutes_per_alert


def attachment(body: str, media_type: str, filename: str) -> Response:
    # Filenames are built from dates and validated tenant ids only.
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/value",
    response_model=ValueReport,
    summary="Automation outcomes, analyst hours saved, MTTA/MTTR and cost per alert, by day",
    responses={200: {"content": {"text/csv": {}}}},
)
async def value_report(
    request: Request,
    start: Optional[date] = Query(default=None, alias="from"),
    end: Optional[date] = Query(default=None, alias="to"),
    format: Literal["json", "csv"] = Query(default="json"),  # noqa: A002 - public query parameter name
    principal: Principal = Depends(require(VIEWER)),
) -> Union[ValueReport, Response]:
    ctx = get_ctx(request)
    w = window(start, end)
    report = await service(ctx).value(
        principal.tenant_id, w, minutes_per_alert=await minutes_per_alert(ctx, principal.tenant_id)
    )
    if format == "csv":
        return attachment(
            value_csv(report), CSV_MEDIA_TYPE, f"lg-sotf-value-{principal.tenant_id}-{w.start}-{w.end}.csv"
        )
    return report


@router.get(
    "/accuracy",
    response_model=AccuracyReport,
    summary="AI verdict against analyst decisions: confusion matrix, agreement, false-negative rate",
)
async def accuracy_report(
    request: Request,
    start: Optional[date] = Query(default=None, alias="from"),
    end: Optional[date] = Query(default=None, alias="to"),
    principal: Principal = Depends(require(VIEWER)),
) -> AccuracyReport:
    ctx = get_ctx(request)
    return await service(ctx).accuracy(principal.tenant_id, window(start, end))


@router.get(
    "/detections",
    response_model=DetectionsReport,
    summary="Per source and rule: volume, benign rate, analyst false positives and a tuning suggestion",
    responses={200: {"content": {"text/csv": {}}}},
)
async def detections_report(
    request: Request,
    start: Optional[date] = Query(default=None, alias="from"),
    end: Optional[date] = Query(default=None, alias="to"),
    format: Literal["json", "csv"] = Query(default="json"),  # noqa: A002 - public query parameter name
    principal: Principal = Depends(require(VIEWER)),
) -> Union[DetectionsReport, Response]:
    ctx = get_ctx(request)
    w = window(start, end)
    report = await service(ctx).detections(principal.tenant_id, w)
    if format == "csv":
        return attachment(
            detections_csv(report), CSV_MEDIA_TYPE, f"lg-sotf-detections-{principal.tenant_id}-{w.start}-{w.end}.csv"
        )
    return report


@router.post(
    "/detections/propose-suppression",
    response_model=SuppressionOut,
    status_code=201,
    summary="Propose a (disabled) suppression rule for a detection; an admin enables it",
)
async def propose_suppression(
    body: ProposeSuppressionIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(require(ANALYST)),
) -> SuppressionOut:
    ctx = get_ctx(request)
    w = window(body.start, body.end)
    row = await ctx.repos.reports.detection(
        principal.tenant_id, w.since, w.until, source_id=body.source_id, rule_field=body.rule_field, rule=body.rule
    )
    if row is None:
        raise NotFound("detection", f"{body.source_id}:{body.rule[:64]}")
    if row.max_confirmed_benign_rank is None:
        raise ApiError(
            422,
            "no_confirmed_benign",
            "no alert of this detection was confirmed benign by an analyst in the window; "
            "a suppression proposal needs that evidence",
        )
    match = suppression_match(row)
    try:
        reject_catch_all(match)
        rule, created = await ctx.review.propose_suppression(
            principal.tenant_id,
            name=f"Proposed from detection report: {row.rule}",
            match=match,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            created_by=principal.local_user_id,
            details={
                "source": "detection_report",
                "source_id": row.source_id,
                "rule_field": row.rule_field,
                "window": f"{w.start.isoformat()}/{w.end.isoformat()}",
                "decided": row.decided,
                "benign": row.benign,
            },
            reuse_existing=True,
        )
    except InvalidRule as exc:
        raise ApiError(422, "invalid_rule", str(exc)) from exc
    if not created:
        response.status_code = 200
    return SuppressionOut.model_validate(rule)


@router.get(
    "/monthly",
    response_model=MonthlyReport,
    summary="Monthly report (value, accuracy, detections) as print-friendly HTML or JSON",
    responses={200: {"content": {"text/html": {}}}},
)
async def monthly_report(
    request: Request,
    month: Optional[str] = Query(default=None, pattern=r"^\d{4}-\d{2}$", description="YYYY-MM (UTC); default: this month"),
    format: Literal["html", "json"] = Query(default="html"),  # noqa: A002 - public query parameter name
    principal: Principal = Depends(require(VIEWER)),
) -> Union[MonthlyReport, Response]:
    ctx = get_ctx(request)
    month = month or datetime.now(UTC).strftime("%Y-%m")
    tenant = await ctx.repos.tenants.get(principal.tenant_id)
    try:
        report = await service(ctx).monthly(
            principal.tenant_id,
            tenant.name,
            month,
            minutes_per_alert=resolve_reporting_policy(tenant.settings).minutes_per_alert,
        )
    except ReportWindowError as exc:
        raise ApiError(400, "invalid_window", str(exc)) from exc
    if format == "json":
        return report
    return Response(
        content=monthly_html(report, version=__version__),
        media_type=HTML_MEDIA_TYPE,
        headers={
            "Content-Security-Policy": REPORT_CSP,
            "Content-Disposition": f'inline; filename="lg-sotf-report-{principal.tenant_id}-{month}.html"',
        },
    )
