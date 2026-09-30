"""Repositories, one per aggregate.

Conventions:

* Tenant methods take ``tenant_id`` first, run inside ``db.tenant_tx`` (RLS)
  and also filter ``tenant_id`` explicitly. They accept ``conn=`` to join a
  caller's transaction.
* Methods that span tenants end in ``_all_tenants``. Scheduler and platform
  methods use ``db.system_tx`` and need the schema owner role; the three
  credential lookups (``users.find_by_email_all_tenants``,
  ``refresh_tokens.get_by_hash_all_tenants``, ``api_keys.get_by_id_all_tenants``)
  go through SECURITY DEFINER functions and also work for the runtime role.
* Driver errors caused by input are raised as ``ReferenceNotFound``,
  ``InvalidValue`` or ``Conflict``, never as raw asyncpg exceptions.
* ``get`` raises :class:`~lg_sotf.db.errors.NotFound`; ``get_by_*``/``find_*``
  return ``None``/empty when nothing matches.
* Paged ``list`` methods return :class:`~lg_sotf.db.pagination.Page`
  (unpacks as ``items, next_cursor``).
"""

from __future__ import annotations

from dataclasses import dataclass

from lg_sotf.db.pool import Database
from lg_sotf.db.repos._base import UNSET
from lg_sotf.db.repos.actions import ActionsRepo, ResponseAction, action_idempotency_key
from lg_sotf.db.repos.alert_events import AlertEvent, AlertEventsRepo, NewAlertEvent
from lg_sotf.db.repos.alerts import Alert, AlertListItem, AlertsRepo, DashboardCounts, NewAlert, ResponseTimes
from lg_sotf.db.repos.api_keys import ApiKey, ApiKeysRepo
from lg_sotf.db.repos.audit import AuditEntry, AuditRepo, ChainVerification
from lg_sotf.db.repos.escalations import Escalation, EscalationsRepo
from lg_sotf.db.repos.feedback import Feedback, FeedbackRepo, FeedbackStats
from lg_sotf.db.repos.indicators import IndicatorSighting, IndicatorsRepo, RelatedAlert
from lg_sotf.db.repos.llm_usage import LLMUsageDay, LLMUsageDelta, LLMUsageRepo, LLMUsageTotals
from lg_sotf.db.repos.platform import PlatformEscalation, PlatformRepo, TenantStats, TenantUsage
from lg_sotf.db.repos.refresh_tokens import RefreshToken, RefreshTokensRepo
from lg_sotf.db.repos.runs import RunsRepo, StaleRunSweep, WorkflowRun
from lg_sotf.db.repos.sources import Source, SourcesRepo
from lg_sotf.db.repos.suppressions import SuppressionRule, SuppressionsRepo
from lg_sotf.db.repos.tenants import Tenant, TenantsRepo
from lg_sotf.db.repos.usage import UsageDay, UsageRepo
from lg_sotf.db.repos.user_mfa import UserMfa, UserMfaRepo
from lg_sotf.db.repos.users import User, UsersRepo


@dataclass(frozen=True)
class Repositories:
    """All repositories bound to one :class:`Database`."""

    db: Database
    tenants: TenantsRepo
    users: UsersRepo
    user_mfa: UserMfaRepo
    refresh_tokens: RefreshTokensRepo
    api_keys: ApiKeysRepo
    sources: SourcesRepo
    alerts: AlertsRepo
    alert_events: AlertEventsRepo
    runs: RunsRepo
    escalations: EscalationsRepo
    feedback: FeedbackRepo
    actions: ActionsRepo
    suppressions: SuppressionsRepo
    indicators: IndicatorsRepo
    llm_usage: LLMUsageRepo
    audit: AuditRepo
    usage: UsageRepo
    platform: PlatformRepo

    @classmethod
    def create(cls, db: Database) -> Repositories:
        return cls(
            db=db,
            tenants=TenantsRepo(db),
            users=UsersRepo(db),
            user_mfa=UserMfaRepo(db),
            refresh_tokens=RefreshTokensRepo(db),
            api_keys=ApiKeysRepo(db),
            sources=SourcesRepo(db),
            alerts=AlertsRepo(db),
            alert_events=AlertEventsRepo(db),
            runs=RunsRepo(db),
            escalations=EscalationsRepo(db),
            feedback=FeedbackRepo(db),
            actions=ActionsRepo(db),
            suppressions=SuppressionsRepo(db),
            indicators=IndicatorsRepo(db),
            llm_usage=LLMUsageRepo(db),
            audit=AuditRepo(db),
            usage=UsageRepo(db),
            platform=PlatformRepo(db),
        )


__all__ = [
    "ActionsRepo",
    "Alert",
    "AlertEvent",
    "AlertEventsRepo",
    "AlertListItem",
    "AlertsRepo",
    "ApiKey",
    "ApiKeysRepo",
    "AuditEntry",
    "AuditRepo",
    "ChainVerification",
    "DashboardCounts",
    "Escalation",
    "EscalationsRepo",
    "Feedback",
    "FeedbackRepo",
    "FeedbackStats",
    "IndicatorSighting",
    "IndicatorsRepo",
    "LLMUsageDay",
    "LLMUsageDelta",
    "LLMUsageRepo",
    "LLMUsageTotals",
    "NewAlert",
    "NewAlertEvent",
    "PlatformEscalation",
    "PlatformRepo",
    "RefreshToken",
    "RefreshTokensRepo",
    "RelatedAlert",
    "Repositories",
    "ResponseAction",
    "ResponseTimes",
    "RunsRepo",
    "Source",
    "SourcesRepo",
    "StaleRunSweep",
    "SuppressionRule",
    "SuppressionsRepo",
    "Tenant",
    "TenantStats",
    "TenantUsage",
    "TenantsRepo",
    "UNSET",
    "UsageDay",
    "UsageRepo",
    "User",
    "UserMfa",
    "UserMfaRepo",
    "UsersRepo",
    "WorkflowRun",
    "action_idempotency_key",
]
