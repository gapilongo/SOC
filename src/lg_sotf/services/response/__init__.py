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

Execution runs up to :data:`EXECUTION_CONCURRENCY` actions at a time within
an execution budget of :data:`EXECUTION_BUDGET_FRACTION` of
``worker.node_timeout_s``, so the ``execute_actions`` node is never cancelled
half-way through a connector call. An action still running when the budget
ends is recorded ``failed`` (``error="deadline"``, outcome unknown: the
receiver deduplicates a later retry by action id); one the budget leaves no
time to start is recorded ``failed`` with ``error="execution_budget_exhausted"``
without being sent. A stateful (Microsoft) action is never abandoned that
way: running out of budget mid-call, or too little budget to start with the
connector's own margins, defers it to the scheduler, which re-runs and
reconciles it; a database error during the call propagates (the row stays
``executing`` and is run again). A stateful row that already started is
never recorded ``dry_run`` or a plain misconfiguration when it is run again:
while a kill switch is on it is held (``deferred``, ``halted``) until its
attempts run out, a misconfigured integration fails it retryably, and every
such failure keeps what its checkpoints show was done (``partial``,
reversible). :meth:`ResponseService.fail_orphaned_executing` settles actions
left ``executing`` by a run that will never finish them.

Approval rules: containment on LLM-only evidence is never automatic; an
analyst's pre-approval covers only low and medium risk; high and critical
need ``approver_role="admin"`` (:func:`approval_allowed`).
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from uuid import UUID

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db import AlreadyInState, Connection, InvalidTransition, locks
from lg_sotf.db.repos._base import UNSET
from lg_sotf.db.repos.actions import VerificationWrite
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
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
    guardrail_result,
)
from lg_sotf.domain.connectors import call_deadline
from lg_sotf.domain.events import EventPublisher, publish_event
from lg_sotf.domain.indicators import extract_indicators
from lg_sotf.domain.phishing import email_block_targets, plan_email_entities
from lg_sotf.integrations.events import (
    ACTION_AWAITING_APPROVAL,
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_VERIFICATION_FAILED,
)
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.models import vocabulary
from lg_sotf.models.vocabulary import POLICY_APPROVER, SCHEDULER_OWNER, WORKFLOW_OWNER
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import record_action
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.services.connectors import (
    STATEFUL_CONNECTORS,
    Connector,
    ConnectorRegistry,
    ConnectorResult,
    DryRunConnector,
    LedgerUnavailable,
    MisconfiguredConnector,
    VerifyPlan,
)
from lg_sotf.services.connectors.microsoft import (
    DEADLINE_MARGIN_S,
    MIN_HANDLER_S,
    MicrosoftClients,
    microsoft_connector_for,
    started,
    with_progress,
)
from lg_sotf.services.connectors.routing import ConnectorRouter, RoutingSnapshot
from lg_sotf.services.response.guardrails import GuardrailBlock, check_guardrails
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
from lg_sotf.services.response.targets import (
    clean,
    ip_block_class,
    loose_ipv4,
    process_base,
    target_corroborated,
    target_key,
    validate_target,
)
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Integration, Repositories, ResponseAction

__all__ = [
    "ACTION_CATALOG",
    "ACTION_TARGET_KINDS",
    "ANALYST_APPROVAL_RISKS",
    "APPROVAL_EXPIRED_REASON",
    "APPROVAL_SUPERSEDED_REASON",
    "ActionRequestError",
    "ActionSpec",
    "AutoBudget",
    "BLAST_RADIUS_REASON",
    "Connector",
    "ConnectorResult",
    "DEFAULT_BLAST_RADIUS",
    "Disposition",
    "DryRunConnector",
    "FORWARD_OF",
    "GUARDRAIL_REASONS",
    "GuardrailBlock",
    "HOURLY_CAP_REASON",
    "MAX_PROTECTED_ENTRIES",
    "POLICY_INVALID_REASON",
    "PROTECTED_INVALID_REASON",
    "PlanContext",
    "PlanResult",
    "ProtectedAssets",
    "ProtectedAssetsSettings",
    "ResponsePolicy",
    "ResponsePolicyError",
    "ResponsePolicySettings",
    "ResponseService",
    "TargetKind",
    "approval_allowed",
    "bounded_detail",
    "candidate_targets",
    "check_guardrails",
    "dispose",
    "ip_block_class",
    "loose_ipv4",
    "plan_entities",
    "preapproval_allowed",
    "protected_lookup",
    "resolve_autonomy",
    "validate_response_settings",
    "validate_target",
]

log = get_logger(__name__)

Evidence = Literal["rules", "llm_only", "analyst"]
MAX_TARGETS_PER_TYPE = 3
MAX_ACTIONS = 15
PENDING_WORK_STATUSES = frozenset({"awaiting_approval", "approved"})
# Ledger statuses that raise an integration event (lg_sotf.integrations), written with their audit entry.
ACTION_EVENTS: Dict[str, str] = {
    "awaiting_approval": ACTION_AWAITING_APPROVAL,
    "succeeded": ACTION_EXECUTED,
    "dry_run": ACTION_EXECUTED,
    "failed": ACTION_FAILED,
}
# Execution: parallel connector calls per node run, and the share of the node timeout they may use.
EXECUTION_CONCURRENCY = 4
EXECUTION_BUDGET_FRACTION = 0.75
MIN_EXECUTION_S = 1.0
# A stateful connector keeps DEADLINE_MARGIN_S for its ledger write and needs MIN_HANDLER_S for the handler;
# a request may overrun its timeout by 0.5 s. With less budget left, the action is deferred to the scheduler.
MIN_STATEFUL_EXECUTION_S = DEADLINE_MARGIN_S + MIN_HANDLER_S + 0.5
# How long a started stateful row waits while a kill switch holds it (each wait counts one attempt).
HALTED_RETRY_S = 300.0
ORPHAN_GRACE_S = 60.0
SCHEDULER_ACTOR = "scheduler"
# Connector results are stored in response_actions.result; larger details keep their essential keys.
MAX_RESULT_BYTES = 8 * 1024
MAX_VERIFICATION_DETAIL_BYTES = 12 * 1024
RESULT_ESSENTIAL_KEYS = (
    "connector", "capability", "integration_id", "live", "summary", "changed", "already", "error", "http_status",
    "ms_code", "request_id", "retryable", "hint", "deferred", "rehearsal", "would_execute", "attempts",
)


PLAYBOOKS: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...] = (
    # First: an email alert's category is "phishing", whatever its attachment or link is about.
    (
        "phishing",
        ("phishing", "spear phishing", "spearphishing", "business email compromise", "credential harvesting"),
        ("purge_message", "block_sender", "block_url", "notify_reporter", "create_ticket"),
    ),
    (
        "credential_access",
        ("mimikatz", "credential dump", "credential_dump", "lsass", "credential access", "kerberoast", "dcsync"),
        ("isolate_host", "terminate_process", "reset_password", "revoke_sessions", "collect_forensics", "create_ticket"),
    ),
    (
        "lateral_movement",
        ("lateral movement", "lateral_movement", "privilege escalation", "privilege_escalation", "psexec"),
        ("isolate_host", "disable_user", "create_ticket"),
    ),
    (
        "malware",
        ("malware", "ransomware", "trojan", "backdoor", "command and control", "c2", "beacon", "cobalt strike"),
        ("isolate_host", "block_ip", "block_domain", "terminate_process", "quarantine_file", "collect_forensics", "create_ticket"),
    ),
    (
        "web_attack",
        ("sql injection", "sql_injection", "web attack", "xss", "webshell"),
        ("block_ip", "send_alert", "create_ticket"),
    ),
    (
        "reconnaissance",
        ("port scan", "port_scan", "network scan", "reconnaissance"),
        ("block_ip", "send_alert"),
    ),
)
GENERIC_PLAYBOOK = ("send_alert", "create_ticket", "collect_forensics")

RECOMMENDATION_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), a)
    for p, a in (
        (r"\bblock\b.*\b(ip|ips|address|network|indicator)", "block_ip"),
        (r"\bblock\b.*\bdomain", "block_domain"),
        (r"\bblock\b.*\burl", "block_url"),
        (r"\bisolat", "isolate_host"),
        (r"\bquarantin", "quarantine_file"),
        (r"\b(terminate|kill)\b.*\bprocess", "terminate_process"),
        (r"\bdisable\b.*\b(user|account)", "disable_user"),
        (r"\breset\b.*\bpassword", "reset_password"),
        (r"\brevoke\b.*\bsession", "revoke_sessions"),
        (r"\bforensic", "collect_forensics"),
        (r"\bticket\b", "create_ticket"),
        (r"\bblock\b.*\bsenders?\b", "block_sender"),
        (r"\b(purge|remove|delete|pull)\b.*\b(message|email|e-mail)s?\b", "purge_message"),
        (r"\b(notify|inform|tell)\b.*\breporter\b", "notify_reporter"),
        (r"\b(confirm|mark)\b.*\bcompromised\b", "confirm_compromised"),
    )
)


# Raw-event keys that describe the ancestry of the detected activity (parent/grandparent
# process, its image and hash). Their values are context, never response targets.
_LINEAGE_KEY_RE = re.compile(r"(?:^|[_\-. ])(?:grand)?parent", re.IGNORECASE)
_LINEAGE_CAMEL_RE = re.compile(r"[a-z](?:Grand)?Parent")
_MAX_LINEAGE_SCAN = 2_000
MAX_SCOPE_HOSTS = 10


# --------------------------------------------------------------------------- planning inputs


@dataclass(frozen=True)
class Candidate:
    action_type: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanContext:
    """What the planner knows about the case. ``entities`` maps target kinds to values."""

    severity: str
    evidence: Evidence
    title: str = ""
    category: Optional[str] = None
    entities: Mapping[str, Sequence[str]] = field(default_factory=dict)
    recommended_actions: Sequence[str] = ()
    threat_texts: Sequence[str] = ()
    approved_actions: Sequence[str] = ()
    approved_by: Optional[str] = None
    approver_role: Optional[str] = None
    # Targets the rule evidence is *about* (kind, value): threat-intel or history verdicts on
    # that indicator, the executable and host a behavioural rule observed. With "rules"
    # evidence, automatic containment is limited to these; ``None`` = not computed (legacy).
    corroborated_targets: Optional[FrozenSet[Tuple[str, str]]] = None
    # Hosts the alert concerns; host-local actions (terminate_process, quarantine_file) are
    # scoped to them in the ledger params and the signed webhook body.
    hosts: Sequence[str] = ()
    # Email alerts: sender and subject of the reported message, so a purge never matches by id alone.
    message: Mapping[str, str] = field(default_factory=dict)


HOST_SCOPED_ACTIONS = frozenset({"terminate_process", "quarantine_file"})


@dataclass
class PlanResult:
    threat_type: str
    auto: List[str] = field(default_factory=list)
    awaiting: List[str] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)
    done: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "threat_type": self.threat_type,
            "auto": self.auto,
            "awaiting": self.awaiting,
            "blocked": self.blocked,
            "done": self.done,
        }


def detect_threat_type(texts: Iterable[str]) -> Tuple[str, Tuple[str, ...]]:
    text = " ".join(t.lower() for t in texts if t)
    for name, keywords, actions in PLAYBOOKS:
        if any(re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", text) for k in keywords):
            return name, actions
    return "generic", GENERIC_PLAYBOOK


def actions_from_recommendations(recommendations: Iterable[str]) -> List[str]:
    out: List[str] = []
    for rec in recommendations:
        lowered = rec.lower()
        for pattern, action in RECOMMENDATION_PATTERNS:
            if pattern.search(lowered) and action not in out:
                out.append(action)
    return out


def plan_entities(alert: Mapping[str, Any]) -> Dict[str, List[str]]:
    """Response targets by kind in a canonical alert (the extraction correlation uses)."""
    by_kind: Dict[str, List[str]] = {}
    for indicator in extract_indicators(alert):
        by_kind.setdefault(indicator.type, []).append(indicator.value)
    # Email alerts: sender and Reply-To addresses, the message and the reporter.
    by_kind.update(plan_email_entities(alert))
    # Email alerts: a URL, domain or IP is blocked only when the message leads there or came from there,
    # never one only shown as the text of a link that goes elsewhere (the look the sender borrowed, often
    # a legitimate site), whatever entity list or model recommendation would bring it in.
    for kind, allowed in email_block_targets(alert).items():
        if kind in by_kind:
            keys = {form for value in allowed for form in target_key(kind, value)}
            by_kind[kind] = [v for v in by_kind[kind] if keys.intersection(target_key(kind, v))]
    lineage = lineage_only_values(alert.get("raw"))
    if lineage:
        # Parent/grandparent processes and their hashes are the context of the detection, not
        # its subject: terminating explorer.exe or quarantining services.exe's hash fleet-wide
        # because a child misbehaved is never the intended response.
        for kind in ("process", "hash"):
            kept = [v for v in by_kind.get(kind, []) if not (_entity_keys(kind, v) & lineage)]
            if kind in by_kind:
                by_kind[kind] = kept
    return by_kind


def _entity_keys(kind: str, value: str) -> FrozenSet[str]:
    return frozenset({process_base(value) if kind == "process" else clean(value)})


def lineage_only_values(raw: Any) -> FrozenSet[str]:
    """Normalised process base names and hashes that occur *only* under parent/grandparent keys of the raw event."""
    lineage: set[str] = set()
    primary: set[str] = set()
    budget = [_MAX_LINEAGE_SCAN]

    def add(bucket: set[str], value: str) -> None:
        text = value.strip()
        if not text or len(text) > 1_024:
            return
        bucket.add(clean(text))
        bucket.add(process_base(text))

    def walk(node: Any, in_lineage: bool, depth: int) -> None:
        if budget[0] <= 0 or depth > 8:
            return
        budget[0] -= 1
        if isinstance(node, Mapping):
            for key, value in node.items():
                name = str(key)[:64]
                walk(value, in_lineage or bool(_LINEAGE_KEY_RE.search(name) or _LINEAGE_CAMEL_RE.search(name)), depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node[:100]:
                walk(item, in_lineage, depth + 1)
        elif isinstance(node, str):
            add(lineage if in_lineage else primary, node)

    walk(raw, False, 0)
    return frozenset(lineage - primary)


def candidate_targets(action_type: str, entities: Mapping[str, Sequence[str]], alert_id: str) -> List[str]:
    """The targets the planner proposes ``action_type`` for (at most :data:`MAX_TARGETS_PER_TYPE`)."""
    spec = ACTION_CATALOG[action_type]
    targets = [f"alert:{alert_id}"] if spec.target_kind == "alert" else list(entities.get(spec.target_kind, ()))
    return list(dict.fromkeys(str(t) for t in targets))[:MAX_TARGETS_PER_TYPE]


def action_params(action_type: str, target: str, ctx: PlanContext) -> Dict[str, Any]:
    """Extra ledger params an action needs besides its target (what the connector must match on)."""
    spec = ACTION_CATALOG[action_type]
    params: Dict[str, Any] = {}
    if spec.requires:
        params[spec.requires] = str(list(ctx.entities.get(spec.requires) or [""])[0])[:320]
    if spec.target_kind == "message":
        params["match"] = {"internet_message_id": target, **{k: str(v)[:320] for k, v in ctx.message.items()}}
    return params


def build_candidates(ctx: PlanContext, alert_id: str) -> Tuple[str, List[Candidate]]:
    threat_type, playbook = detect_threat_type(
        [ctx.title, ctx.category or "", *ctx.threat_texts, *ctx.recommended_actions]
    )
    wanted = list(playbook) + [a for a in actions_from_recommendations(ctx.recommended_actions) if a not in playbook]
    candidates: List[Candidate] = []
    for action_type in wanted:
        if not ACTION_CATALOG[action_type].plannable:
            continue
        requires = ACTION_CATALOG[action_type].requires
        if requires and not ctx.entities.get(requires):
            continue
        for target in candidate_targets(action_type, ctx.entities, alert_id):
            params = {"playbook": threat_type, **action_params(action_type, target, ctx)}
            candidates.append(Candidate(action_type, target, params))
    return threat_type, candidates[:MAX_ACTIONS]


# --------------------------------------------------------------------------- guardrails


# --------------------------------------------------------------------------- policy


def _is_preapproved(candidate: Candidate, approved: Sequence[str]) -> bool:
    """``action_type:target`` names exactly this action; a bare ``action_type`` covers every target of this alert."""
    return candidate.action_type in approved or f"{candidate.action_type}:{candidate.target}" in approved


# --------------------------------------------------------------------------- disposition


@dataclass(frozen=True)
class Disposition:
    """What the planner decides for one candidate: the ledger status, why, and who approved it."""

    status: Literal["blocked", "approved", "awaiting_approval"]
    explanation: str
    approved_by: Optional[str] = None
    approval_reason: Optional[str] = None


def _awaiting(explanation: str, approval_reason: Optional[str] = None) -> Disposition:
    return Disposition("awaiting_approval", f"awaiting approval: {explanation}", None, approval_reason)


@dataclass
class AutoBudget:
    """Automatic approvals left this hour: in total (hourly cap) and per action type (blast radius)."""

    total: int
    per_type: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def remaining(cls, policy: ResponsePolicy, used_total: int, used_by_type: Mapping[str, int]) -> AutoBudget:
        per_type = {t: max(0, limit - used_by_type.get(t, 0)) for t, limit in policy.blast_radius.items()}
        return cls(max(0, policy.max_actions_per_hour - used_total), per_type)

    def can_auto(self, action_type: str) -> bool:
        return self.total > 0 and self.per_type.get(action_type, 1) > 0

    def consume(self, action_type: str) -> None:
        self.total -= 1
        if action_type in self.per_type:
            self.per_type[action_type] -= 1


def dispose(
    cand: Candidate, spec: ActionSpec, ctx: PlanContext, policy: ResponsePolicy, block: Optional[GuardrailBlock],
    budget: AutoBudget,
) -> Disposition:
    """Blocked, approved (by the analyst or the policy) or awaiting approval; only ``auto`` consumes ``budget``.

    ``auto`` still needs an approval for containment on LLM-only evidence, for
    a target the rule evidence does not concern, and over the hourly cap or
    the type's blast radius.
    """
    if block is not None:
        return Disposition("blocked", f"blocked: {block.explanation}")
    if _is_preapproved(cand, ctx.approved_actions) and ctx.approved_by:
        if preapproval_allowed(spec.risk, ctx.approver_role):
            explanation = f"approved: pre-approved by the analyst decision ({spec.risk} risk)"
            return Disposition("approved", explanation, ctx.approved_by)
        return _awaiting(f"{spec.risk} risk needs an admin approval", "admin_approval_required")
    if policy.autonomy[spec.risk] != "auto":
        return _awaiting(f"tenant autonomy for {spec.risk} risk is 'approval'")
    if spec.containment and ctx.evidence == "llm_only":
        return _awaiting("containment on LLM-only evidence is never automatic", "llm_only_evidence")
    corroborated = ctx.corroborated_targets
    if spec.containment and ctx.evidence == "rules" and corroborated is not None and not target_corroborated(
        spec.target_kind, cand.target, corroborated
    ):
        explanation = "the rule evidence does not concern this target, so containing it is not automatic"
        return _awaiting(explanation, "target_not_corroborated")
    if budget.total <= 0:
        return _awaiting(f"hourly cap of {policy.max_actions_per_hour} reached", HOURLY_CAP_REASON)
    if not budget.can_auto(cand.action_type):
        limit = policy.blast_radius[cand.action_type]
        return _awaiting(f"at most {limit} {cand.action_type} per hour", BLAST_RADIUS_REASON)
    budget.consume(cand.action_type)
    return Disposition("approved", f"approved: tenant autonomy for {spec.risk} risk is 'auto'", POLICY_APPROVER)


# --------------------------------------------------------------------------- service


class ActionRequestError(Exception):
    """A request on one action cannot be served now (``status`` 409/429; ``code`` and message are safe to return)."""

    def __init__(self, status: int, code: str, message: str, *, reason: Optional[str] = None) -> None:
        super().__init__(message[:300])
        self.status = status
        self.code = code
        self.reason = reason


def bounded_detail(detail: Mapping[str, Any], limit: int = MAX_RESULT_BYTES) -> Dict[str, Any]:
    """``detail`` as stored in ``response_actions.result``: at most ``limit`` bytes of JSON.

    An oversized detail keeps its essential keys (who, what, error) and
    records ``truncated: true``.
    """
    out = dict(detail)
    if len(json.dumps(out, default=str)) <= limit:
        return out
    kept = {k: out[k] for k in RESULT_ESSENTIAL_KEYS if k in out}
    kept = {k: (v[:500] if isinstance(v, str) else v) for k, v in kept.items()}
    kept["truncated"] = True
    if len(json.dumps(kept, default=str)) > limit:
        kept = {"error": str(out.get("error") or "")[:100] or None, "truncated": True}
    return kept


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
        self._audit = AuditLogger(repos)
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
                    await self._record_transition(
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
            return await self._transition_audited(
                tenant_id, action.id, status, details={"replanned": True}, expected_from="proposed", blocked_reason=reason
            )
        except (AlreadyInState, InvalidTransition):
            return await self._repos.actions.get(tenant_id, action.id)

    async def _approve_proposed(self, tenant_id: str, action: ResponseAction, approved_by: str) -> ResponseAction:
        policy = approved_by == POLICY_APPROVER
        try:
            return await self._transition_audited(
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
                updated = await self._transition_audited(
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

    # ------------------------------------------------------------- execution

    async def _is_sample(self, tenant_id: str, alert_id: str) -> bool:
        return (await self._repos.alerts.get(tenant_id, alert_id)).source_id == SAMPLE_SOURCE_ID

    async def execute(
        self,
        tenant_id: str,
        alert_id: str,
        action_ids: Sequence[str],
        *,
        now: Optional[datetime] = None,
        budget_s: Optional[float] = None,
    ) -> Dict[str, str]:
        """Run this alert's approved workflow actions. Returns ``{action_id: status}`` for the actions considered.

        Guardrails are evaluated again before each claim. Actions left
        ``executing`` by an interrupted earlier attempt are run again with the
        connector recorded on the row: connectors are idempotent per action
        id, and the alert's run lease guarantees no other worker is executing
        them. Terminal actions are never executed twice. Scheduler-owned
        rows are skipped (the background executor runs them).

        Each action's connector comes from one routing snapshot
        (:mod:`lg_sotf.services.connectors.routing`). A stateful connector
        may answer ``deferred``: the row stays ``executing``, is handed to
        the scheduler and is reported as ``executing``.

        Up to :data:`EXECUTION_CONCURRENCY` actions run at once, and all of
        them within ``budget_s`` (default :attr:`execution_budget_s`): a
        connector call still running when the budget ends is abandoned and
        recorded ``failed`` (``error="deadline"``), and an action there is no
        time left to start is recorded ``failed`` without being sent
        (``error="execution_budget_exhausted"``).
        """
        if not action_ids:
            return {}
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        mine = [a for a in actions if a.alert_id == alert_id and a.execution_owner == WORKFLOW_OWNER]
        if not mine:
            return {}
        snapshot = await self.routing(tenant_id, tenant.settings)
        sample = await self._is_sample(tenant_id, alert_id) if snapshot.needs_sample_check(mine) else False
        loop = asyncio.get_running_loop()
        ends_at = loop.time() + (self._execution_budget_s if budget_s is None else budget_s)
        slots = asyncio.Semaphore(EXECUTION_CONCURRENCY)

        async def run(action: ResponseAction) -> str:
            async with slots:
                connector = snapshot.connector_for(action, sample=sample)
                return await self._execute_one(tenant_id, action, connector, policy, now, ends_at)

        tasks = [asyncio.create_task(run(a)) for a in mine]
        try:
            statuses = await asyncio.gather(*tasks)
        except BaseException:
            # The first failure propagates unchanged (retry policies match on its type); stop the rest first.
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return {str(a.id): status for a, status in zip(mine, statuses, strict=True)}

    async def _execute_one(
        self,
        tenant_id: str,
        action: ResponseAction,
        connector: Connector,
        policy: ResponsePolicy,
        now: Optional[datetime],
        ends_at: float,
    ) -> str:
        if action.status == "executing":
            log.warning("response.resuming_interrupted_action", action_type=action.action_type)
            executing: Optional[ResponseAction] = action
            held = self._rerun_held(action, connector)
            if held is not None:
                return await self._finish(tenant_id, action, connector, held)
        elif action.status == "approved":
            executing = await self._claim(tenant_id, action, connector, policy, now)
        else:
            return action.status
        if executing is None:
            return (await self._repos.actions.get(tenant_id, action.id)).status
        remaining = ends_at - asyncio.get_running_loop().time()
        if connector.name in STATEFUL_CONNECTORS and remaining < MIN_STATEFUL_EXECUTION_S:
            # Not sent: the scheduler runs it with a full deadline (never abandoned half-way).
            log.warning("response.execution_budget_exhausted", action_type=action.action_type, deferred=True)
            result = ConnectorResult(
                "deferred",
                {"connector": connector.name, "deferred": "execution_budget", "changed": False,
                 "summary": "not started: too little of this workflow step's budget was left; the scheduler runs it"},
                retry_after_s=30.0,
            )
            return await self._finish(tenant_id, executing, connector, result)
        if remaining < MIN_EXECUTION_S and not isinstance(connector, DryRunConnector):
            log.warning("response.execution_budget_exhausted", action_type=action.action_type)
            result = ConnectorResult(
                "failed",
                {
                    "error": "execution_budget_exhausted",
                    "note": "not sent: the execution budget of this workflow step ran out before it could start",
                },
            )
            return await self._finish(tenant_id, executing, connector, result)
        return await self._run_connector(tenant_id, executing, connector, timeout_s=max(remaining, MIN_EXECUTION_S))

    async def execute_background(self, tenant_id: str, action_id: UUID, *, deadline_s: float) -> str:
        """Run one scheduler-owned row the background executor claimed (its lease is held).

        ``approved`` rows go through :meth:`_claim` (guardrails, restorative
        exemptions for rollbacks, caps, blast radius); ``executing`` rows are
        run again with their pinned connector, or failed with
        ``attempts_exhausted`` after ``response.max_execution_attempts``.
        Returns the row's status afterwards.
        """
        action = await self._repos.actions.get(tenant_id, action_id)
        if action.execution_owner != SCHEDULER_OWNER or action.status not in ("approved", "executing"):
            return action.status
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        snapshot = await self.routing(tenant_id, tenant.settings)
        sample = await self._is_sample(tenant_id, action.alert_id) if snapshot.needs_sample_check([action]) else False
        connector = snapshot.connector_for(action, sample=sample)
        limit = int(self._settings.response.max_execution_attempts)
        if action.status == "approved":
            executing = await self._claim(tenant_id, action, connector, policy, None)
            if executing is None:
                return (await self._repos.actions.get(tenant_id, action.id)).status
        elif action.attempts >= limit:
            held = self._rerun_held(action, connector)
            if held is not None and held.status == "failed":
                return await self._finish(tenant_id, action, connector, held)  # its integration is unavailable
            halted = held is not None  # still held by a kill switch
            result = ConnectorResult(
                "failed",
                {
                    "connector": action.connector,
                    "error": "halted" if halted else "attempts_exhausted",
                    "attempts": action.attempts,
                    "retryable": True,
                    "summary": f"not run again: {action.attempts} attempts already made"
                    + (" while dry run was forced" if halted else ""),
                },
            )
            return await self._finish(tenant_id, action, connector, result)
        else:
            rerun = await self._repos.actions.count_attempt(tenant_id, action.id)
            if rerun is None:
                return (await self._repos.actions.get(tenant_id, action.id)).status
            executing = rerun
            held_result = self._rerun_held(executing, connector)
            if held_result is not None:
                return await self._finish(tenant_id, executing, connector, held_result)
        return await self._run_connector(tenant_id, executing, connector, timeout_s=deadline_s)

    @staticmethod
    def _rerun_held(action: ResponseAction, connector: Connector) -> Optional[ConnectorResult]:
        """What a re-run of a started stateful row gets instead of a dry run or a plain misconfiguration.

        The row's checkpoints show that an earlier attempt got as far as a
        write, so recording ``dry_run`` ("nothing was executed") would hide
        it and block its rollback. While a kill switch forces the dry-run
        connector it is held (``deferred``, ``halted``; each wait counts one
        attempt, then it fails with ``halted``); a misconfigured integration
        (disabled or deleted) fails it retryably. ``_finish`` keeps what the
        checkpoints show was done. ``None``: run it normally.
        """
        if action.connector not in STATEFUL_CONNECTORS or not started(action.external_ref):
            return None
        if isinstance(connector, DryRunConnector):
            return ConnectorResult(
                "deferred",
                {"connector": action.connector, "deferred": "halted", "changed": False, "attempts": action.attempts,
                 "summary": "held: dry run is forced (a kill switch is on); it runs again when the switch is off"},
                retry_after_s=HALTED_RETRY_S,
            )
        if isinstance(connector, MisconfiguredConnector):
            return ConnectorResult(
                "failed",
                {"connector": action.connector, "error": "connector_misconfigured", "reason": connector.reason,
                 "retryable": True, "changed": False,
                 "summary": "not run again: the Microsoft integration this action is pinned to is not available"},
            )
        return None

    async def fail_orphaned_executing(self, tenant_id: Optional[str] = None, *, limit: int = 100) -> int:
        """Settle workflow actions left ``executing`` whose run will never finish them.

        An action stays ``executing`` when its worker died mid-call; the run
        normally resumes and re-runs it, but a run that was dead-lettered (or
        completed on another path) never will. After a grace period (the
        execution budget plus 60 s, so a call still in flight is not
        touched), actions of stateful connectors (Microsoft) are handed to
        the scheduler, which re-runs and reconciles them; the others are
        failed with ``error="orphaned_execution"``: the external outcome is
        unknown, and the receiver can be asked by the action id (its
        idempotency key). ``tenant_id=None`` sweeps every tenant (scheduler;
        system transaction). Returns how many actions were settled.
        """
        grace = self._execution_budget_s + ORPHAN_GRACE_S
        if tenant_id is None:
            rows = await self._repos.actions.find_orphaned_executing_all_tenants(limit=limit, grace_s=grace)
        else:
            rows = await self._repos.actions.find_orphaned_executing(tenant_id, limit=limit, grace_s=grace)
        settled = 0
        for owner, action_id, connector in rows:
            if connector in STATEFUL_CONNECTORS:
                handed = await self.hand_off(owner, [action_id], reason="orphaned_execution")
                settled += len(handed)
                continue
            try:
                await self._transition_audited(
                    owner,
                    action_id,
                    "failed",
                    details={"reason": "orphaned_execution"},
                    expected_from="executing",
                    result={
                        "error": "orphaned_execution",
                        "note": "the workflow run ended while this action was executing; its outcome is unknown",
                    },
                )
            except (AlreadyInState, InvalidTransition):
                continue
            settled += 1
        if settled:
            log.warning("response.orphaned_actions_settled", count=settled)
        return settled

    async def hand_off(
        self, tenant_id: str, action_ids: Sequence[UUID], *, reason: str, conn: Optional[Connection] = None
    ) -> List[UUID]:
        """Give workflow rows to the scheduler (audited ``response_action.handed_off``); returns the ids handed off."""
        if conn is None:
            async with self._repos.db.tenant_tx(tenant_id) as tx:
                handed = await self.hand_off(tenant_id, action_ids, reason=reason, conn=tx)
            for action in await self._repos.actions.get_many(tenant_id, handed):
                await self.publish_action(tenant_id, action)
            return handed
        handed = await self._repos.actions.hand_off(tenant_id, action_ids, reason=reason, conn=conn)
        for action in await self._repos.actions.get_many(tenant_id, handed, conn=conn):
            await self._audit_only(
                tenant_id, action, "response_action.handed_off", {"reason": reason}, actor_type="system",
                actor_id=SCHEDULER_ACTOR, conn=conn,
            )
        if handed:
            log.info("response.handed_off", count=len(handed), reason=reason)
        return handed

    async def block_approved(
        self, tenant_id: str, action_id: UUID, code: str, detail: Mapping[str, Any]
    ) -> Optional[ResponseAction]:
        """``approved -> blocked`` with a guardrail-style reason (expiry, superseded), audited; ``None`` if it moved on."""
        try:
            return await self._transition_audited(
                tenant_id, action_id, "blocked", details={"reason": code}, actor_type="system", actor_id=SCHEDULER_ACTOR,
                expected_from="approved", blocked_reason=code, result=guardrail_result(code, **detail),
            )
        except (AlreadyInState, InvalidTransition):
            return None

    async def _block_approved(
        self, tenant_id: str, action: ResponseAction, code: str, detail: Mapping[str, Any], conn: Optional[Connection] = None
    ) -> ResponseAction:
        return await self._repos.actions.transition(
            tenant_id,
            action.id,
            "blocked",
            expected_from="approved",
            blocked_reason=code,
            result=guardrail_result(code, **detail),
            conn=conn,
        )

    async def _claim(
        self,
        tenant_id: str,
        action: ResponseAction,
        connector: Connector,
        policy: ResponsePolicy,
        now: Optional[datetime],
    ) -> Optional[ResponseAction]:
        """Move an approved action to ``executing``; ``None`` when it was blocked or taken by someone else.

        For real connectors the hourly cap, the blast-radius check and the
        claim run in one transaction under a per-tenant advisory lock, so
        concurrent workers cannot overshoot either limit. The claim records
        the connector, the integration it uses and one more attempt. A
        rollback of a restorative type is checked with the restorative
        exemptions (:func:`check_guardrails`).
        """
        blocked: Optional[ResponseAction] = None
        executing: Optional[ResponseAction] = None
        spec = ACTION_CATALOG.get(action.action_type)
        restorative = bool(spec is not None and spec.restorative and action.rollback_of is not None)
        integration_id: Optional[UUID] = getattr(connector, "integration_id", None)
        try:
            guard = check_guardrails(action.action_type, action.target, policy, restorative=restorative)
            if guard is not None or isinstance(connector, DryRunConnector):
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    if guard is not None:
                        blocked = await self._block_approved(
                            tenant_id, action, guard.code, {"detail": guard.detail, "stage": "execution"}, conn
                        )
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            integration_id=integration_id, bump_attempts=True, conn=conn,
                        )
                    await self._audit_claim(tenant_id, blocked, executing, connector, conn)
            else:
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    await locks.tenant_xact_lock(conn, locks.ACTION_CAP, tenant_id)
                    window_start = now - timedelta(hours=1) if now is not None else None
                    used, by_type = await self._repos.actions.executed_counts(tenant_id, window_start, conn=conn)
                    cap_block = self._cap_block(policy, action.action_type, used, by_type)
                    if cap_block is not None:
                        blocked = await self._block_approved(tenant_id, action, cap_block[0], cap_block[1], conn)
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            integration_id=integration_id, bump_attempts=True, conn=conn,
                        )
                    await self._audit_claim(tenant_id, blocked, executing, connector, conn)
        except (AlreadyInState, InvalidTransition):
            return None
        if blocked is not None:
            log.warning("response.execution_blocked", action_type=action.action_type, reason=blocked.blocked_reason)
            await self.publish_action(tenant_id, blocked)
            return None
        assert executing is not None
        await self.publish_action(tenant_id, executing)
        return executing

    @staticmethod
    def _cap_block(
        policy: ResponsePolicy, action_type: str, used: int, by_type: Mapping[str, int]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """(reason, detail) when the hourly cap or the type's blast radius is reached, else ``None``."""
        type_limit = policy.blast_radius.get(action_type)
        if used >= policy.max_actions_per_hour:
            return HOURLY_CAP_REASON, {"cap": policy.max_actions_per_hour, "used": used}
        if type_limit is not None and by_type.get(action_type, 0) >= type_limit:
            return BLAST_RADIUS_REASON, {"limit": type_limit, "used": by_type.get(action_type, 0)}
        return None

    async def _audit_claim(
        self,
        tenant_id: str,
        blocked: Optional[ResponseAction],
        executing: Optional[ResponseAction],
        connector: Connector,
        conn: Connection,
    ) -> None:
        """Audit a claim inside its transaction (published by the caller after commit)."""
        if blocked is not None:
            await self._record_transition(tenant_id, blocked, "response_action.blocked", {"stage": "execution"}, conn=conn)
        elif executing is not None:
            await self._record_transition(
                tenant_id, executing, "response_action.executing", {"connector": connector.name}, conn=conn
            )

    async def _run_connector(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, *, timeout_s: Optional[float] = None
    ) -> str:
        scope = asyncio.timeout(timeout_s)
        loop = asyncio.get_running_loop()
        token = call_deadline.set(loop.time() + timeout_s if timeout_s is not None else None)
        try:
            async with scope:
                result = await connector.execute(executing)
        except TimeoutError as exc:
            if not scope.expired():
                log.warning("response.connector_failed", connector=connector.name, error_type=type(exc).__name__)
                result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
            elif connector.name in STATEFUL_CONNECTORS:
                # A write may be in flight: the scheduler re-runs the action, and the handler reconciles.
                log.warning("response.connector_deadline", connector=connector.name, action_type=executing.action_type,
                            deferred=True)
                result = ConnectorResult(
                    "deferred",
                    {"connector": connector.name, "deferred": "deadline", "changed": False,
                     "summary": "the call ran out of time; the scheduler runs it again and reconciles what was done"},
                    retry_after_s=30.0,
                )
            else:
                log.warning("response.connector_deadline", connector=connector.name, action_type=executing.action_type)
                result = ConnectorResult(
                    "failed",
                    {
                        "error": "deadline",
                        "note": "abandoned when the execution budget ran out; the receiver may have acted (same action id)",
                    },
                )
        except (AssertionError, LedgerUnavailable):
            # A ledger error mid-call is not the action's outcome: the row stays executing and is run again.
            raise
        except Exception as exc:  # noqa: BLE001 - any connector failure is recorded on the ledger as 'failed'
            log.warning("response.connector_failed", connector=connector.name, error_type=type(exc).__name__)
            result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
        finally:
            call_deadline.reset(token)
        return await self._finish(tenant_id, executing, connector, result)

    def _verification_write(self, executing: ResponseAction, plan: VerifyPlan) -> VerificationWrite:
        """The verification written with ``succeeded``: proven, or pending for the plan's window.

        The window starts now, when the change was accepted, not at the
        row's first claim (``executed_at``): a change made after deferrals
        (throttling, a long purge) still gets its whole window, capped by
        ``response.verify_max_s``.
        """
        detail = bounded_detail(plan.detail, MAX_VERIFICATION_DETAIL_BYTES)
        if plan.state == "verified":
            return VerificationWrite("verified", detail)
        now = datetime.now(UTC)
        ceiling = float(self._settings.response.verify_max_s)
        deadline = now + timedelta(seconds=min(max(plan.max_duration_s, 1.0), ceiling))
        after = min(now + timedelta(seconds=max(plan.first_check_s, 0.0)), deadline)
        return VerificationWrite(
            "pending", {**detail, "first_check_s": float(plan.first_check_s)}, verify_after=after,
            verify_deadline=deadline,
        )

    async def _finish(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, result: ConnectorResult
    ) -> str:
        """Write the connector's outcome (and verification schedule) with its audit entry; returns the new status.

        ``deferred`` keeps the row ``executing``, hands it to the scheduler
        and returns ``executing``.
        """
        if executing.connector in STATEFUL_CONNECTORS:
            # A failure the connector did not describe keeps what the row's checkpoints show was done.
            result = with_progress(executing.action_type, result, executing.external_ref)
        detail = bounded_detail(result.detail)
        if result.status == "deferred":
            return await self._defer(tenant_id, executing, connector, result, detail)
        status = result.status if result.status in ("succeeded", "failed", "dry_run") else "failed"
        changes: Dict[str, Any] = {}
        if result.external_ref is not None:
            changes["external_ref"] = result.external_ref
        if status == "succeeded" and result.verify is not None:
            changes["verification"] = self._verification_write(executing, result.verify)
        try:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                final = await self._repos.actions.transition(
                    tenant_id, executing.id, status, expected_from="executing", result=detail, conn=conn, **changes
                )
                await self._record_transition(
                    tenant_id, final, f"response_action.{status}", {"connector": connector.name}, conn=conn
                )
                if final.verification == "verified":
                    await self.record_verification_outcome(tenant_id, final, conn=conn)
        except (AlreadyInState, InvalidTransition):
            # Settled elsewhere meanwhile (a lost lease): the ledger keeps the other outcome.
            log.warning("response.finish_lost", action_type=executing.action_type)
            return (await self._repos.actions.get(tenant_id, executing.id)).status
        await self.publish_action(tenant_id, final)
        return final.status

    async def _defer(
        self,
        tenant_id: str,
        executing: ResponseAction,
        connector: Connector,
        result: ConnectorResult,
        detail: Mapping[str, Any],
    ) -> str:
        retry_after = float(result.retry_after_s or 30.0)
        try:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                deferred = await self._repos.actions.defer(
                    tenant_id,
                    executing.id,
                    retry_after_s=retry_after,
                    detail=detail,
                    external_ref=result.external_ref if result.external_ref is not None else UNSET,
                    conn=conn,
                )
                await self._audit_only(
                    tenant_id, deferred, "response_action.deferred",
                    {"connector": connector.name, "retry_after_s": round(retry_after, 1),
                     "reason": detail.get("deferred")},
                    actor_type="system", actor_id=SCHEDULER_ACTOR, conn=conn,
                )
        except (AlreadyInState, InvalidTransition):
            return (await self._repos.actions.get(tenant_id, executing.id)).status
        log.info("response.deferred", action_type=executing.action_type, retry_after_s=round(retry_after, 1))
        await self.publish_action(tenant_id, deferred)
        return deferred.status

    async def record_verification_outcome(
        self, tenant_id: str, action: ResponseAction, *, conn: Connection, notify: bool = True
    ) -> None:
        """Audit, timeline entry and (failed or inconclusive) outbox event of a final verification, in ``conn``'s tx.

        ``notify=False`` (an outcome that is not news, e.g. a verification
        ended by the action's rollback) writes the audit entry only.
        """
        state = action.verification
        detail = dict(action.verification_detail or {})
        reason = detail.get("reason") if isinstance(detail.get("reason"), str) else None
        audit_action = {
            "verified": "response_action.verified",
            "failed": "response_action.verification_failed",
            "inconclusive": "response_action.verification_inconclusive",
        }.get(str(state))
        if audit_action is None:
            return
        await self._audit_only(
            tenant_id, action, audit_action, {"outcome": state, "detail": detail}, actor_type="system",
            actor_id=SCHEDULER_ACTOR, conn=conn,
        )
        if not notify:
            return
        await self._repos.alert_events.append(
            tenant_id,
            action.alert_id,
            "action.verified" if state == "verified" else "action.verification_failed",
            actor_type="system",
            actor_id=SCHEDULER_ACTOR,
            data={"action_id": str(action.id), "action_type": action.action_type, "outcome": state, "reason": reason},
            conn=conn,
        )
        if state in ("failed", "inconclusive"):
            await enqueue_event(
                conn,
                tenant_id,
                ACTION_VERIFICATION_FAILED,
                alert_id=action.alert_id,
                dedupe_key=f"{ACTION_VERIFICATION_FAILED}:{action.id}:{action.verify_attempts}",
                action=action,
            )

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
            cap_block = self._cap_block(policy, action.action_type, used, by_type)
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
            await self._audit_only(
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

    # --------------------------------------------------------------- audit

    async def _transition_audited(
        self,
        tenant_id: str,
        action_id: Any,
        to_status: str,
        *,
        audit_action: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        **changes: Any,
    ) -> ResponseAction:
        """A ledger transition and its audit entry in one transaction; the event is published after commit.

        If the audit append fails the transition rolls back too, so a retry
        repeats both: the audit trail never misses a transition that happened.
        """
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            updated = await self._repos.actions.transition(tenant_id, action_id, to_status, conn=conn, **changes)
            await self._record_transition(
                tenant_id, updated, audit_action or f"response_action.{to_status}", details or {},
                actor_type=actor_type, actor_id=actor_id, conn=conn,
            )
        await self.publish_action(tenant_id, updated)
        return updated

    async def _audit_only(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str,
        actor_id: Optional[str],
        conn: Connection,
    ) -> None:
        """An audit entry about an action without a status event (hand-offs, deferrals, verification, requests)."""
        await self._audit.record(
            tenant_id,
            audit_action,
            "response_action",
            str(action.id),
            actor_type=actor_type,
            actor_id=actor_id,
            details={
                "alert_id": action.alert_id,
                "action_type": action.action_type,
                "risk_level": action.risk_level,
                "status": action.status,
                **dict(details),
            },
            conn=conn,
        )

    async def audit_action(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str,
        actor_id: Optional[str],
        conn: Connection,
    ) -> None:
        """Audit a request about an action made by another service (rollback, verification), in ``conn``'s tx."""
        await self._audit_only(
            tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=conn
        )

    async def _record_transition(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        event_type = ACTION_EVENTS.get(action.status)
        if conn is None and event_type is not None:
            # The integration event must commit with the audit entry: give both one transaction.
            async with self._repos.db.tenant_tx(tenant_id) as scoped:
                await self._record_transition(
                    tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=scoped
                )
            await self.publish_action(tenant_id, action)
            return
        assert conn is not None  # every caller passes its transaction (AuditLogger.record refuses None)
        await self._audit.record(
            tenant_id,
            audit_action,
            "response_action",
            str(action.id),
            actor_type=actor_type,
            actor_id=(actor_id or ("workflow" if actor_type == "agent" else None)),
            details={
                "alert_id": action.alert_id,
                "action_type": action.action_type,
                "risk_level": action.risk_level,
                "status": action.status,
                "blocked_reason": action.blocked_reason,
                **dict(details),
            },
            conn=conn,
        )
        if event_type is not None:
            await enqueue_event(
                conn,
                tenant_id,
                event_type,
                alert_id=action.alert_id,
                dedupe_key=f"{event_type}:{action.id}",
                action=action,
            )
        # Inside a caller's transaction the caller publishes after commit (publish_action).
        record_action(action.action_type, action.status)

    async def record_transition(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        """Audit a ledger transition made by another service (the review service); see ``publish_action``."""
        await self._record_transition(
            tenant_id, action, audit_action, details, actor_type=actor_type, actor_id=actor_id, conn=conn
        )

    async def publish_action(self, tenant_id: str, action: ResponseAction) -> None:
        await publish_event(
            self._events,
            "action.updated",
            tenant_id,
            action.alert_id,
            {"action_id": str(action.id), "action_type": action.action_type, "status": action.status},
        )
