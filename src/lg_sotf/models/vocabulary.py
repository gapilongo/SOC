"""Domain vocabulary: every value set shared across packages, declared once.

Each vocabulary is one ``Literal`` type plus the tuple of its values in
canonical order (``ALERT_STATUSES = get_args(AlertStatus)``); derived subsets
sit next to it. Everything else imports from here instead of repeating the
strings. ``Literal`` rather than ``StrEnum``: workflow state is checkpointed
by LangGraph, whose serializer records an ``Enum`` member by its import path,
so persisted checkpoints would depend on module names (ADR-0004).

Database migrations do not import this module: a migration is a frozen record
of the schema at its revision. ``tests/integration/db/test_vocabulary_constraints.py``
checks that the live ``CHECK`` constraints still list these values.

This module is a leaf: standard library only, no ``lg_sotf`` import.
"""

from __future__ import annotations

from typing import FrozenSet, Literal, Mapping, Tuple, get_args

# ------------------------------------------------------------------ access

#: User roles, lowest privilege first; ``ROLE_RANK`` orders them.
Role = Literal["viewer", "analyst", "admin"]
ROLES: Tuple[Role, ...] = get_args(Role)
ROLE_RANK: Mapping[str, int] = {role: rank for rank, role in enumerate(ROLES)}
#: Roles that may decide escalations and approve response actions.
REVIEWER_ROLES: FrozenSet[str] = frozenset({"analyst", "admin"})

#: API key scopes.
Scope = Literal["ingest", "read", "write"]
SCOPES: Tuple[Scope, ...] = get_args(Scope)

# ------------------------------------------------------------------ alerts

#: Canonical alert severity, lowest first; ``SEVERITY_RANK`` orders them.
Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: Tuple[Severity, ...] = get_args(Severity)
SEVERITY_RANK: Mapping[str, int] = {severity: rank for rank, severity in enumerate(SEVERITIES)}
HIGH_SEVERITIES: FrozenSet[str] = frozenset({"high", "critical"})

AlertStatus = Literal["new", "queued", "processing", "waiting_human", "waiting_approval", "closed", "failed"]
ALERT_STATUSES: Tuple[AlertStatus, ...] = get_args(AlertStatus)

#: The AI verdict and the final disposition of an alert.
Disposition = Literal["malicious", "benign", "inconclusive"]
DISPOSITIONS: Tuple[Disposition, ...] = get_args(Disposition)

#: The workflow's routing decision after analysis.
Route = Literal["escalate", "plan_response", "close"]
ROUTES: Tuple[Route, ...] = get_args(Route)

# ------------------------------------------------------------- escalations

#: An analyst's decision on an escalation (also stored as feedback).
Decision = Literal["true_positive", "false_positive", "benign_positive", "needs_more_info"]
DECISIONS: Tuple[Decision, ...] = get_args(Decision)
BENIGN_DECISIONS: FrozenSet[str] = frozenset({"false_positive", "benign_positive"})

EscalationStatus = Literal["open", "claimed", "decided", "expired", "cancelled"]
ESCALATION_STATUSES: Tuple[EscalationStatus, ...] = get_args(EscalationStatus)

#: Escalation tiers, first tier first.
EscalationLevel = Literal["L1", "L2", "L3"]
ESCALATION_LEVELS: Tuple[EscalationLevel, ...] = get_args(EscalationLevel)

# ---------------------------------------------------------------- response

ActionStatus = Literal[
    "proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "dry_run", "blocked"
]
ACTION_STATUSES: Tuple[ActionStatus, ...] = get_args(ActionStatus)
#: Statuses an action never leaves (the targets-free states of ``ActionsRepo``'s state machine).
TERMINAL_ACTION_STATUSES: Tuple[ActionStatus, ...] = ("succeeded", "rejected", "dry_run", "blocked")
#: Statuses in which an action has done its work (for real or as a dry run).
COMPLETED_ACTION_STATUSES: FrozenSet[str] = frozenset({"succeeded", "dry_run"})

#: Risk level of a response action, lowest first.
RiskLevel = Literal["low", "medium", "high", "critical"]
RISK_LEVELS: Tuple[RiskLevel, ...] = get_args(RiskLevel)

#: What the policy does with an action of a given risk level.
AutonomyMode = Literal["auto", "approval", "disabled"]
AUTONOMY_MODES: Tuple[AutonomyMode, ...] = get_args(AutonomyMode)

#: Post-execution verification of a succeeded action.
VerificationState = Literal["pending", "verified", "failed", "inconclusive"]
VERIFICATION_STATES: Tuple[VerificationState, ...] = get_args(VerificationState)
FINAL_VERIFICATION_STATES: Tuple[VerificationState, ...] = ("verified", "failed", "inconclusive")

#: Who executes an approved action: the alert's workflow run, or the scheduler (background and rollbacks).
ExecutionOwner = Literal["workflow", "scheduler"]
WORKFLOW_OWNER: ExecutionOwner = "workflow"
SCHEDULER_OWNER: ExecutionOwner = "scheduler"
EXECUTION_OWNERS: Tuple[ExecutionOwner, ...] = get_args(ExecutionOwner)

#: ``requested_by`` of the actions the workflow proposes.
REQUESTED_BY = "agent:workflow"
#: ``approved_by`` of an action the autonomy policy approved (no human).
POLICY_APPROVER = "policy:auto"

# ----------------------------------------------------------- workflow runs

RunStatus = Literal["queued", "running", "waiting_human", "waiting_approval", "completed", "failed", "dead_lettered"]
RUN_STATUSES: Tuple[RunStatus, ...] = get_args(RunStatus)
#: A run in one of these statuses has ended: nothing will process or resume it again.
TERMINAL_RUN_STATUSES: Tuple[RunStatus, ...] = ("completed", "dead_lettered")
WAITING_RUN_STATUSES: Tuple[RunStatus, ...] = ("waiting_human", "waiting_approval")

# ----------------------------------------------------------------- sources

SourceType = Literal[
    "splunk", "qradar", "sentinel", "wazuh", "crowdstrike", "guardduty", "webhook", "file", "m365_mailbox", "imap"
]
SOURCE_TYPES: Tuple[SourceType, ...] = get_args(SourceType)
#: Source types that only receive pushed alerts; the scheduler never polls them.
PUSH_SOURCE_TYPES: Tuple[SourceType, ...] = ("webhook", "guardduty")

__all__ = [
    "ACTION_STATUSES",
    "ALERT_STATUSES",
    "AUTONOMY_MODES",
    "BENIGN_DECISIONS",
    "COMPLETED_ACTION_STATUSES",
    "DECISIONS",
    "DISPOSITIONS",
    "ESCALATION_LEVELS",
    "ESCALATION_STATUSES",
    "EXECUTION_OWNERS",
    "FINAL_VERIFICATION_STATES",
    "HIGH_SEVERITIES",
    "POLICY_APPROVER",
    "PUSH_SOURCE_TYPES",
    "REQUESTED_BY",
    "REVIEWER_ROLES",
    "RISK_LEVELS",
    "ROLES",
    "ROLE_RANK",
    "ROUTES",
    "RUN_STATUSES",
    "SCHEDULER_OWNER",
    "SCOPES",
    "SEVERITIES",
    "SEVERITY_RANK",
    "SOURCE_TYPES",
    "TERMINAL_ACTION_STATUSES",
    "TERMINAL_RUN_STATUSES",
    "VERIFICATION_STATES",
    "WAITING_RUN_STATUSES",
    "WORKFLOW_OWNER",
    "ActionStatus",
    "AlertStatus",
    "AutonomyMode",
    "Decision",
    "Disposition",
    "EscalationLevel",
    "EscalationStatus",
    "ExecutionOwner",
    "RiskLevel",
    "Role",
    "Route",
    "RunStatus",
    "Scope",
    "Severity",
    "SourceType",
    "VerificationState",
]
