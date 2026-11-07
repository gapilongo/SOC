"""Response planning, guardrails, approval and execution over the action ledger (contract section 11).

``plan`` turns the investigation outcome into typed actions, resolves each
action's risk level against the tenant's autonomy policy, applies the
guardrails and writes every action to the ledger (idempotent per tenant,
alert, action type and target). ``execute`` runs approved actions through the
tenant's connector (:mod:`lg_sotf.services.connectors`). Every ledger
transition is audited and every decision is explained on the ledger row:
``blocked_reason`` holds a stable code from :data:`GUARDRAIL_REASONS` and
``params["explanation"]`` (plan time) or ``result`` (execution time) the
specifics.

Tenant policy (``tenants.settings``)::

    {"autonomy": {"low": "auto", "medium": "approval", "high": "approval", "critical": "disabled"},
     "protected_assets": {"hosts": ["dc-*", "ws-ceo"], "users": ["administrator", "svc-backup"],
                          "cidrs": ["203.0.113.0/24"], "domains": ["example.com"]},
     "response": {"allow_internal_ip_blocks": false,
                  "allowed_actions": ["block_ip", "create_ticket"],     # optional allowlist
                  "max_actions_per_hour": 20,                         # capped by the install limit
                  "blast_radius": {"isolate_host": 3},                # per action type, per hour
                  "connector": "webhook", "dry_run": false, ...}}

The legacy forms ``protected_assets: [..]`` (a flat list of names/CIDRs) and
``protected_cidrs: [..]`` are still honoured. :class:`ResponsePolicySettings`
and :class:`ProtectedAssetsSettings` are the schemas of these sections; the
settings API validates writes with :func:`validate_response_settings`.

Malformed policy fails closed, and the guardrails apply in a fixed order
(:mod:`lg_sotf.services.response.guardrails`).

Rate limits: the per-tenant hourly cap and the per-action blast-radius
limits (``DEFAULT_BLAST_RADIUS``, e.g. at most 5 hosts isolated per hour)
turn would-be automatic actions into approvals at planning time and, for real
connectors, are enforced atomically at execution time under a per-tenant
advisory lock: an approved action over a limit is blocked
(``hourly_cap_reached`` / ``blast_radius_exceeded``), never left pending.
Guardrails 0-6 are evaluated again right before execution, so an asset
protected after approval is still safe. ``settings.response.dry_run`` forces
the dry-run connector everywhere.

Which connector executes an action is decided per action by
:mod:`lg_sotf.services.connectors.routing` (kill switches, onboarding
samples, pinned rows, ``response.routes``, ticketing, Microsoft
capabilities, the tenant default). The workflow executes the rows it owns
(``execution_owner='workflow'``); the scheduler
(:mod:`lg_sotf.services.background`) executes rollbacks
(:mod:`lg_sotf.services.rollback`), retries, approvals that arrived after
the alert's run ended, and executions a stateful connector deferred. A
connector's ``verify`` plan is written with ``succeeded`` and proven later
by :mod:`lg_sotf.services.verification`.

Execution within the workflow step's budget, and how stateful (Microsoft)
actions are deferred, held or reconciled: :mod:`lg_sotf.services.response.execution`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence
from uuid import UUID

from lg_sotf.db import AlreadyInState, Connection, InvalidTransition, locks
from lg_sotf.domain.actions import (
    ACTION_CATALOG,
    ACTION_TARGET_KINDS,
    APPROVAL_EXPIRED_REASON,
    APPROVAL_SUPERSEDED_REASON,
    BLAST_RADIUS_REASON,
    DEFAULT_BLAST_RADIUS,
    FORWARD_OF,
    GUARDRAIL_REASONS,
    HOURLY_CAP_REASON,
    POLICY_INVALID_REASON,
    PROTECTED_INVALID_REASON,
    ActionSpec,
    TargetKind,
)
from lg_sotf.domain.events import EventPublisher
from lg_sotf.models import vocabulary
from lg_sotf.models.vocabulary import POLICY_APPROVER, SCHEDULER_OWNER, WORKFLOW_OWNER
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.services.connectors import Connector, ConnectorRegistry, ConnectorResult, DryRunConnector
from lg_sotf.services.connectors.microsoft import MicrosoftClients, microsoft_connector_for
from lg_sotf.services.connectors.routing import ConnectorRouter, RoutingSnapshot
from lg_sotf.services.response.execution import (
    EXECUTION_BUDGET_FRACTION,
    EXECUTION_CONCURRENCY,
    ActionExecutor,
    bounded_detail,
    cap_reached,
)
from lg_sotf.services.response.guardrails import GuardrailBlock, check_guardrails
from lg_sotf.services.response.ledger import ActionLedger
from lg_sotf.services.response.planner import (
    HOST_SCOPED_ACTIONS,
    MAX_SCOPE_HOSTS,
    AutoBudget,
    Candidate,
    Disposition,
    Evidence,
    PlanContext,
    PlanResult,
    actions_from_recommendations,
    build_candidates,
    candidate_targets,
    detect_threat_type,
    dispose,
    plan_entities,
)
from lg_sotf.services.response.policy import (
    ANALYST_APPROVAL_RISKS,
    MICROSOFT_CONNECTOR_NAME,
    ResponsePolicy,
    ResponsePolicyError,
    ResponsePolicySettings,
    approval_allowed,
    preapproval_allowed,
    resolve_autonomy,
    validate_response_settings,
)
from lg_sotf.services.response.protected import (
    MAX_PROTECTED_ENTRIES,
    ProtectedAssets,
    ProtectedAssetsSettings,
    protected_lookup,
)
from lg_sotf.services.response.targets import ip_block_class, loose_ipv4, validate_target
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Integration, Repositories, ResponseAction

# The public surface (tests/unit/services/test_response_api.py): the pre-split names, plus what importers use.
__all__ = [
    "ACTION_CATALOG", "ACTION_TARGET_KINDS", "ANALYST_APPROVAL_RISKS", "APPROVAL_EXPIRED_REASON",
    "APPROVAL_SUPERSEDED_REASON", "ActionRequestError", "ActionSpec", "AutoBudget", "BLAST_RADIUS_REASON",
    "Candidate", "Connector", "ConnectorResult", "DEFAULT_BLAST_RADIUS", "Disposition", "DryRunConnector",
    "EXECUTION_CONCURRENCY", "Evidence", "FORWARD_OF", "GUARDRAIL_REASONS", "GuardrailBlock", "HOURLY_CAP_REASON",
    "MAX_PROTECTED_ENTRIES", "POLICY_INVALID_REASON", "PROTECTED_INVALID_REASON", "PlanContext", "PlanResult",
    "ProtectedAssets", "ProtectedAssetsSettings", "ResponsePolicy", "ResponsePolicyError", "ResponsePolicySettings",
    "ResponseService", "TargetKind", "actions_from_recommendations", "approval_allowed", "bounded_detail",
    "build_candidates", "candidate_targets", "check_guardrails", "detect_threat_type", "dispose", "ip_block_class",
    "loose_ipv4", "plan_entities", "preapproval_allowed", "protected_lookup", "resolve_autonomy",
    "validate_response_settings", "validate_target",
]

log = get_logger(__name__)

PENDING_WORK_STATUSES = frozenset({"awaiting_approval", "approved"})


# --------------------------------------------------------------------------- service


class ActionRequestError(Exception):
    """A request on one action cannot be served now (``status`` 409/429; ``code`` and message are safe to return)."""

    def __init__(self, status: int, code: str, message: str, *, reason: Optional[str] = None) -> None:
        super().__init__(message[:300])
        self.status = status
        self.code = code
        self.reason = reason


class ResponseService:
    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        events: Optional[EventPublisher] = None,
        *,
        connectors: Optional[Mapping[str, Connector]] = None,
        registry: Optional[ConnectorRegistry] = None,
        ticketing: Any = None,
        router: Optional[ConnectorRouter] = None,
        microsoft: Optional[MicrosoftClients] = None,
        secret_box: Optional[SecretBox] = None,
    ) -> None:
        """``connectors`` override built-in connectors by name (see :class:`ConnectorRegistry`).

        ``ticketing`` (a :class:`~lg_sotf.integrations.ticketing.TicketService`)
        executes ``create_ticket`` through the tenant's ticketing integration;
        built on first use when not given. ``microsoft`` holds the process's
        Microsoft HTTP factory and token cache (built here when not given);
        ``secret_box`` decrypts integration credentials (from the settings
        when not given). ``router`` replaces the connector routing (tests).
        """
        self._repos = repos
        self._ticketing = ticketing
        self._settings = settings
        self._events = events
        self._ledger = ActionLedger(repos, events)
        self._registry = registry or ConnectorRegistry(
            settings,
            overrides=connectors, secret_box=secret_box,
            target_kinds={name: spec.target_kind for name, spec in ACTION_CATALOG.items()},
        )
        self._execution_budget_s = float(settings.worker.node_timeout_s) * EXECUTION_BUDGET_FRACTION
        self._microsoft = microsoft
        self._box = secret_box
        self._box_loaded = secret_box is not None
        self._router = router or ConnectorRouter(
            self._registry, repos, tickets=self._ticket_connector, microsoft=self._microsoft_connector
        )
        self._executor = ActionExecutor(repos, settings, self._ledger, self._router, budget_s=self._execution_budget_s)

    @property
    def registry(self) -> ConnectorRegistry:
        return self._registry

    @property
    def router(self) -> ConnectorRouter:
        return self._router

    @property
    def repos(self) -> Repositories:
        return self._repos

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def events(self) -> Optional[EventPublisher]:
        return self._events

    @property
    def microsoft(self) -> MicrosoftClients:
        """The Microsoft HTTP factory and token cache (built on first use)."""
        if self._microsoft is None:
            self._microsoft = MicrosoftClients.create(self._settings)
        return self._microsoft

    @property
    def execution_budget_s(self) -> float:
        """Wall time one :meth:`execute` call may spend in connectors (a share of the node timeout)."""
        return self._execution_budget_s

    def policy(self, tenant_settings: Mapping[str, Any]) -> ResponsePolicy:
        return ResponsePolicy.resolve(tenant_settings, self._settings)

    def connector_for(self, tenant_id: str, tenant_settings: Mapping[str, Any]) -> Connector:
        """The tenant's default connector (routing step 8); per-action routing is :meth:`routing`."""
        return self._registry.for_tenant(tenant_id, tenant_settings)

    async def routing(self, tenant_id: str, tenant_settings: Mapping[str, Any]) -> RoutingSnapshot:
        """The tenant's routing snapshot (loads its integrations once; database errors propagate)."""
        return await self._router.snapshot(tenant_id, tenant_settings)

    def secret_box(self) -> Optional[SecretBox]:
        """The install's secret box, or ``None`` when no encryption keys are configured."""
        if not self._box_loaded:
            self._box_loaded = True
            if self._settings.security.encryption_keys is not None:
                log.warning("security.secret_box_lazy_load", component="ResponseService")
            try:
                self._box = SecretBox.from_settings(self._settings)
            except SecurityConfigError:
                self._box = None
        return self._box

    def _ticket_connector(self, integration: Integration) -> Connector:
        from lg_sotf.integrations.ticketing import TicketConnector, TicketService

        if self._ticketing is None:
            self._ticketing = TicketService(self._repos, self._settings, retries=1, secret_box=self._box)
        return TicketConnector(self._ticketing, integration)

    async def _microsoft_connector(
        self, tenant_id: str, integration: Integration, tenant_settings: Mapping[str, Any]
    ) -> Connector:
        clients = self.microsoft
        connector = await microsoft_connector_for(
            self._repos,
            self._settings,
            self.secret_box(),
            tenant_id,
            tokens=clients.tokens,
            http=clients.http,
            checkpoints=self._repos.actions,
            integration=integration,
            protected=protected_lookup(tenant_settings),
        )
        assert connector is not None  # an integration was given
        return connector

    # ------------------------------------------------------------------ plan

    async def plan(
        self, tenant_id: str, alert_id: str, ctx: PlanContext, *, now: Optional[datetime] = None
    ) -> PlanResult:
        window_start = now - timedelta(hours=1) if now is not None else None
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        threat_type, candidates = build_candidates(ctx, alert_id)
        result = PlanResult(threat_type=threat_type)
        used_total, used_by_type = await self._repos.actions.executed_counts(tenant_id, window_start)
        budget = AutoBudget.remaining(policy, used_total, used_by_type)

        for cand in candidates:
            spec = ACTION_CATALOG[cand.action_type]
            params: Dict[str, Any] = {
                **cand.params, "alert": {"severity": ctx.severity, "title": ctx.title[:200]}, "evidence": ctx.evidence,
            }
            if cand.action_type in HOST_SCOPED_ACTIONS:
                params["scope"] = {"hosts": list(dict.fromkeys(str(h) for h in ctx.hosts))[:MAX_SCOPE_HOSTS]}
            autonomy = policy.autonomy[spec.risk]
            block = check_guardrails(cand.action_type, cand.target, policy)
            reason = block.code if block else None
            disposition = dispose(cand, spec, ctx, policy, block, budget)
            status, approved_by = disposition.status, disposition.approved_by
            if disposition.approval_reason is not None:
                params["approval_reason"] = disposition.approval_reason
            params["explanation"] = disposition.explanation

            # Approved rows are written as 'proposed' first so approved_by lands in the
            # ledger column; a re-run finds the row still 'proposed' and finishes it.
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                action, created = await self._repos.actions.propose(
                    tenant_id, alert_id, cand.action_type, cand.target, spec.risk, params=params,
                    requested_by=vocabulary.REQUESTED_BY, status="proposed" if status == "approved" else status,
                    blocked_reason=reason, conn=conn,
                )
                if created:
                    await self._ledger.record_transition(
                        tenant_id, action, "response_action.proposed", {"approved_by": approved_by, "autonomy": autonomy},
                        conn=conn,
                    )
            if created:
                await self.publish_action(tenant_id, action)
            if action.status == "proposed":
                if status == "approved" and approved_by:
                    action = await self._approve_proposed(tenant_id, action, approved_by)
                else:
                    action = await self._settle_proposed(tenant_id, action, status, reason)
            self._classify(result, str(action.id), action.status)
        return result

    async def _settle_proposed(
        self, tenant_id: str, action: ResponseAction, status: str, reason: Optional[str]
    ) -> ResponseAction:
        """A row left 'proposed' by an interrupted approval whose decision changed on re-plan."""
        try:
            return await self._ledger.transition_audited(
                tenant_id, action.id, status, details={"replanned": True}, expected_from="proposed", blocked_reason=reason
            )
        except (AlreadyInState, InvalidTransition):
            return await self._repos.actions.get(tenant_id, action.id)

    async def _approve_proposed(self, tenant_id: str, action: ResponseAction, approved_by: str) -> ResponseAction:
        policy = approved_by == POLICY_APPROVER
        try:
            return await self._ledger.transition_audited(
                tenant_id, action.id, "approved", details={"approved_by": approved_by[:128], "preapproved": not policy},
                actor_type="agent" if policy else "user", actor_id=approved_by, expected_from="proposed",
                approved_by=approved_by[:128],
            )
        except (AlreadyInState, InvalidTransition):
            return await self._repos.actions.get(tenant_id, action.id)

    @staticmethod
    def _classify(result: PlanResult, action_id: str, status: str) -> None:
        if status == "approved":
            result.auto.append(action_id)
        elif status in ("awaiting_approval", "proposed"):
            result.awaiting.append(action_id)
        elif status in ("blocked", "rejected"):
            result.blocked.append(action_id)
        else:
            result.done.append(action_id)

    # -------------------------------------------------------------- approval

    async def apply_approval(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        pending_ids: Sequence[str],
        approved_ids: Sequence[str],
        rejected_ids: Sequence[str],
        decided_by: str,
        reject_remaining: bool = False,
    ) -> Dict[str, str]:
        """Apply an approval decision (a resume payload) to this alert's pending actions.

        Per-action semantics: only actions named in ``approved_ids`` /
        ``rejected_ids`` change; other pending actions stay awaiting approval
        (and the run returns to ``await_approval``) unless
        ``reject_remaining`` is set, which rejects them explicitly. Ids of
        other alerts and actions no longer pending are ignored, and so are
        scheduler-owned rows (rollbacks and handed-off actions are not the
        run's work). Actions the API already approved or rejected through
        :class:`~lg_sotf.services.review.ReviewService` are reported with
        their current status. Returns ``{action_id: status}``.
        """
        approved = {str(i) for i in approved_ids}
        rejected = {str(i) for i in rejected_ids}
        foreign = (approved | rejected) - {str(i) for i in pending_ids}
        if foreign:
            log.warning("response.approval_foreign_ids", count=len(foreign))
        actions = await self._repos.actions.get_many(tenant_id, [UUID(i) for i in pending_ids])
        outcome: Dict[str, str] = {}
        for action in actions:
            action_id = str(action.id)
            if action.alert_id != alert_id or action.execution_owner != WORKFLOW_OWNER:
                continue
            if action.status != "awaiting_approval":
                outcome[action_id] = action.status
                continue
            if action_id in approved:
                target, extra = "approved", {"approved_by": decided_by[:128]}
            elif action_id in rejected:
                target, extra = "rejected", {"blocked_reason": "rejected_by_reviewer"}
            elif reject_remaining:
                target, extra = "rejected", {"blocked_reason": "rejected_with_remaining"}
            else:
                continue
            try:
                updated = await self._ledger.transition_audited(
                    tenant_id, action.id, target,
                    details={"decided_by": decided_by[:128], "reject_remaining": reject_remaining and action_id not in rejected},
                    actor_type="user", actor_id=decided_by, expected_from="awaiting_approval", **extra,
                )
            except (AlreadyInState, InvalidTransition):
                current = await self._repos.actions.get(tenant_id, action.id)
                outcome[action_id] = current.status
                continue
            outcome[action_id] = updated.status
        return outcome

    async def awaiting(self, tenant_id: str, alert_id: str, action_ids: Sequence[str]) -> List[str]:
        """Which of ``action_ids`` (this alert's workflow rows) are still pending work, in ledger order.

        Pending work is an action awaiting approval or one approved but not
        yet executed: an approval can commit at any moment (the API does not
        wait for the run), so an ``approved`` row is work the run still owes.
        Scheduler-owned rows are never the run's work.
        """
        if not action_ids:
            return []
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        return [
            str(a.id)
            for a in actions
            if a.alert_id == alert_id and a.status in PENDING_WORK_STATUSES and a.execution_owner == WORKFLOW_OWNER
        ]

    # ------------------------------------------------------------- execution (lg_sotf.services.response.execution)

    async def execute(
        self, tenant_id: str, alert_id: str, action_ids: Sequence[str], *, now: Optional[datetime] = None,
        budget_s: Optional[float] = None,
    ) -> Dict[str, str]:
        """Run this alert's approved workflow actions (:meth:`ActionExecutor.execute`); ``{action_id: status}``."""
        return await self._executor.execute(tenant_id, alert_id, action_ids, now=now, budget_s=budget_s)

    async def execute_background(self, tenant_id: str, action_id: UUID, *, deadline_s: float) -> str:
        return await self._executor.execute_background(tenant_id, action_id, deadline_s=deadline_s)

    async def fail_orphaned_executing(self, tenant_id: Optional[str] = None, *, limit: int = 100) -> int:
        return await self._executor.fail_orphaned_executing(tenant_id, limit=limit)

    async def hand_off(
        self, tenant_id: str, action_ids: Sequence[UUID], *, reason: str, conn: Optional[Connection] = None
    ) -> List[UUID]:
        return await self._ledger.hand_off(tenant_id, action_ids, reason=reason, conn=conn)

    async def block_approved(
        self, tenant_id: str, action_id: UUID, code: str, detail: Mapping[str, Any]
    ) -> Optional[ResponseAction]:
        return await self._ledger.block_approved(tenant_id, action_id, code, detail)

    async def _run_connector(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, *, timeout_s: Optional[float] = None
    ) -> str:
        return await self._executor._run_connector(tenant_id, executing, connector, timeout_s=timeout_s)

    # -------------------------------------------------------------- retry

    async def retry(self, tenant_id: str, action_id: UUID, *, user: UUID, role: str, reason: str) -> ResponseAction:
        """Run a failed Microsoft action again (``failed -> executing``, by the scheduler).

        Allowed when the failure is retryable (``result.retryable``) or
        ``partial``, the caller's role may approve the action's risk, and no
        rollback of the action exists (``rollback_exists``: retrying would
        redo what the rollback undoes, and the rollback could never be
        repeated for the redone part). The row is locked while this is
        decided, as a rollback request locks it. Guardrails and caps are
        checked again under the cap lock; a block raises
        :class:`ActionRequestError` (409) without touching the row. The retry
        starts a fresh attempt count and is audited
        ``response_action.retry_requested``.
        """
        action = await self._repos.actions.get(tenant_id, action_id)
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        self._check_retryable(action)
        if not approval_allowed(action.risk_level, role, policy.autonomy.get(action.risk_level)):
            raise ActionRequestError(
                403, "forbidden", f"role {role!r} may not approve {action.risk_level} risk actions"
            )
        spec = ACTION_CATALOG.get(action.action_type)
        restorative = bool(spec is not None and spec.restorative and action.rollback_of is not None)
        now = datetime.now(UTC)
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            action = await self._repos.actions.lock(tenant_id, action_id, conn=conn)
            self._check_retryable(action)  # it may have moved on since it was read
            if await self._repos.actions.live_rollback(tenant_id, action.id, conn=conn) is not None:
                raise ActionRequestError(
                    409, "retry_unavailable", "a rollback of this action exists: it cannot be retried",
                    reason="rollback_exists",
                )
            result = action.result or {}
            await locks.tenant_xact_lock(conn, locks.ACTION_CAP, tenant_id)
            guard = check_guardrails(action.action_type, action.target, policy, restorative=restorative)
            if guard is not None:
                raise ActionRequestError(409, "guardrail_blocked", guard.explanation[:300], reason=guard.code)
            used, by_type = await self._repos.actions.executed_counts(tenant_id, conn=conn)
            cap_block = cap_reached(policy, action.action_type, used, by_type)
            if cap_block is not None:
                raise ActionRequestError(
                    409, "cap_reached", GUARDRAIL_REASONS.get(cap_block[0], cap_block[0]), reason=cap_block[0]
                )
            updated = await self._repos.actions.transition(
                tenant_id,
                action.id,
                "executing",
                expected_from="failed",
                execution_owner=SCHEDULER_OWNER,
                lease_until=now,
                reset_attempts=True,
                conn=conn,
            )
            await self._ledger.audit_action(
                tenant_id, updated, "response_action.retry_requested",
                {"reason": reason[:500], "role": role, "previous_error": result.get("error")},
                actor_type="user", actor_id=str(user), conn=conn,
            )
        await self.publish_action(tenant_id, updated)
        return updated

    @staticmethod
    def _check_retryable(action: ResponseAction) -> None:
        result = action.result or {}
        retryable = result.get("retryable") is True or result.get("error") == "partial"
        if action.status != "failed" or action.connector != MICROSOFT_CONNECTOR_NAME or not retryable:
            raise ActionRequestError(
                409, "retry_unavailable", "only failed Microsoft actions whose failure is retryable can be retried",
                reason="not_retryable",
            )

    # ---------------------------------------------------------------- ledger (lg_sotf.services.response.ledger)

    async def audit_action(
        self, tenant_id: str, action: ResponseAction, audit_action: str, details: Mapping[str, Any], *,
        actor_type: str, actor_id: Optional[str], conn: Connection,
    ) -> None:
        """Audit a request about an action made by another service (rollback, verification), in ``conn``'s tx."""
        await self._ledger.audit_action(
            tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=conn
        )

    async def record_transition(
        self, tenant_id: str, action: ResponseAction, audit_action: str, details: Mapping[str, Any], *,
        actor_type: str = "agent", actor_id: Optional[str] = None, conn: Optional[Connection] = None,
    ) -> None:
        """Audit a ledger transition made by another service (the review service); see ``publish_action``."""
        await self._ledger.record_transition(
            tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=conn
        )

    async def record_verification_outcome(
        self, tenant_id: str, action: ResponseAction, *, conn: Connection, notify: bool = True
    ) -> None:
        await self._ledger.record_verification_outcome(tenant_id, action, conn=conn, notify=notify)

    async def publish_action(self, tenant_id: str, action: ResponseAction) -> None:
        await self._ledger.publish_action(tenant_id, action)
