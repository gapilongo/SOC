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

Malformed policy fails closed. When the guardrail keys of ``response`` (or
the top-level ``autonomy``) do not match the schema, every action is blocked
with ``response_policy_invalid``; when ``protected_assets`` /
``protected_cidrs`` are malformed or hold more than
:data:`MAX_PROTECTED_ENTRIES` entries per list, every action on a host, user,
address, domain, URL, hash or process is blocked with
``protected_assets_invalid``. Both are logged with the problems found.

Guardrails, in order (the first that fails blocks the action, and blocked
actions can never be approved later):

0. the tenant's response policy and protected assets are well formed;
1. the action type is known and allowed by the tenant's allowlist;
2. the target kind is one the action accepts (:data:`ACTION_TARGET_KINDS`);
3. the target is syntactically valid for its kind;
4. IP blocks never target loopback, link-local, multicast, unspecified or
   reserved addresses (also when embedded in IPv4-mapped, 6to4, NAT64,
   Teredo or IPv4-compatible IPv6 addresses), and target private/CGNAT/ULA
   addresses only when the tenant sets ``allow_internal_ip_blocks``;
5. protected hosts, users, domains (and their subdomains) and CIDRs are never
   acted on, whatever the target's spelling (sender addresses are checked by
   their domain and as a whole address; senders of the tenant's own
   ``tools.internal_domains`` are never blocked: disable or reset the account
   instead): IP literals in host, domain and
   URL targets (including the decimal/hex/octal IPv4 forms browsers accept
   and IPv6 forms embedding an IPv4 address) are checked against protected
   CIDRs; domain and URL hosts are checked against protected host names;
   user names are compared as written, as the CN/UID of a DN and as the bare
   account (``DOMAIN\\user``, ``domain/user``, ``user@domain``); names are
   compared case-insensitively after Unicode NFKC normalisation with
   invisible format characters removed;
6. the tenant's autonomy policy is not ``disabled`` for the action's risk.

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
import fnmatch
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from urllib.parse import unquote, urlsplit
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.core.phishing import email_block_targets, plan_email_entities
from lg_sotf.db import locks
from lg_sotf.db.errors import AlreadyInState, InvalidTransition
from lg_sotf.db.repos._base import UNSET
from lg_sotf.db.repos.actions import EXECUTED_STATUSES, VerificationWrite
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.integrations.events import (
    ACTION_AWAITING_APPROVAL,
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_VERIFICATION_FAILED,
)
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import record_action
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.services.connectors import (
    CONNECTOR_NAMES,
    ROUTE_NAMES,
    STATEFUL_CONNECTORS,
    Connector,
    ConnectorRegistry,
    ConnectorResult,
    DryRunConnector,
    LedgerUnavailable,
    MisconfiguredConnector,
    VerifyPlan,
    tenant_response_settings,
)
from lg_sotf.services.connectors.base import call_deadline
from lg_sotf.services.connectors.microsoft import (
    DEADLINE_MARGIN_S,
    MIN_HANDLER_S,
    MicrosoftClients,
    microsoft_connector_for,
    started,
    with_progress,
)
from lg_sotf.services.connectors.routing import ConnectorRouter, RoutingSnapshot
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Integration, Repositories, ResponseAction

__all__ = [
    "ACTION_CATALOG",
    "ACTION_TARGET_KINDS",
    "ActionRequestError",
    "Connector",
    "ConnectorResult",
    "DryRunConnector",
    "GUARDRAIL_REASONS",
    "GuardrailBlock",
    "PlanContext",
    "PlanResult",
    "ProtectedAssets",
    "ProtectedAssetsSettings",
    "ResponsePolicy",
    "ResponsePolicyError",
    "ResponsePolicySettings",
    "ResponseService",
    "approval_allowed",
    "bounded_detail",
    "candidate_targets",
    "check_guardrails",
    "plan_entities",
    "preapproval_allowed",
    "protected_lookup",
    "resolve_autonomy",
    "validate_response_settings",
    "validate_target",
]

log = get_logger(__name__)

Autonomy = Literal["auto", "approval", "disabled"]
Evidence = Literal["rules", "llm_only", "analyst"]
TargetKind = Literal["ip", "domain", "url", "hash", "user", "host", "process", "alert", "email", "message"]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
RISK_LEVELS = ("low", "medium", "high", "critical")
AUTONOMY_MODES = ("auto", "approval", "disabled")
MAX_TARGETS_PER_TYPE = 3
MAX_ACTIONS = 15
REQUESTED_BY = "agent:workflow"
POLICY_APPROVER = "policy:auto"
PENDING_WORK_STATUSES = frozenset({"awaiting_approval", "approved"})
ANALYST_APPROVAL_RISKS = frozenset({"low", "medium"})
ANALYST_PREAPPROVAL_RISKS = ANALYST_APPROVAL_RISKS
HOURLY_CAP_REASON = "hourly_cap_reached"
BLAST_RADIUS_REASON = "blast_radius_exceeded"
POLICY_INVALID_REASON = "response_policy_invalid"
APPROVAL_EXPIRED_REASON = "approval_expired"
APPROVAL_SUPERSEDED_REASON = "approval_superseded"
PROTECTED_INVALID_REASON = "protected_assets_invalid"
# Per list (hosts, users, domains, cidrs). Larger inventories belong in the SOAR, not in tenant settings.
MAX_PROTECTED_ENTRIES = 10_000
MAX_PROTECTED_ENTRY_CHARS = 256
MAX_BLAST_RADIUS = 10_000
MAX_TENANT_HOURLY_CAP = 100_000
MAX_POLICY_PROBLEMS = 5
# create_ticket runs through the tenant's ticketing integration when one is enabled (lg_sotf.integrations).
TICKET_ACTION = "create_ticket"
TICKET_CONNECTOR_NAME = "ticketing"
MICROSOFT_CONNECTOR_NAME = "microsoft"
MAX_ROUTES = 64
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
_EXECUTED_COUNTS_SQL = """
    SELECT action_type, count(*)::int AS n FROM response_actions
    WHERE tenant_id = $1 AND status = ANY($3::text[])
      -- The window is measured on the database clock that stamps executed_at, unless given.
      AND executed_at >= COALESCE($2::timestamptz, now() - interval '1 hour')
    GROUP BY action_type
"""
# Workflow actions left 'executing' whose run will never come back to them ($3: grace period in seconds,
# so a call still in flight is left alone).
_ORPHANED_EXECUTING_SQL = """
    SELECT a.tenant_id, a.id, a.connector FROM response_actions a
    JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.alert_id
    WHERE a.status = 'executing' AND a.execution_owner = 'workflow' AND r.status IN ('dead_lettered', 'completed')
      AND ($1::text IS NULL OR a.tenant_id = $1)
      AND (a.executed_at IS NULL OR a.executed_at < now() - make_interval(secs => $3))
    ORDER BY a.executed_at NULLS FIRST
    LIMIT $2
"""
ORPHAN_GRACE_S = 60.0
WORKFLOW_OWNER = "workflow"
SCHEDULER_OWNER = "scheduler"
SCHEDULER_ACTOR = "scheduler"
# Connector results are stored in response_actions.result; larger details keep their essential keys.
MAX_RESULT_BYTES = 8 * 1024
MAX_VERIFICATION_DETAIL_BYTES = 12 * 1024
RESULT_ESSENTIAL_KEYS = (
    "connector", "capability", "integration_id", "live", "summary", "changed", "already", "error", "http_status",
    "ms_code", "request_id", "retryable", "hint", "deferred", "rehearsal", "would_execute", "attempts",
)


@dataclass(frozen=True)
class ActionSpec:
    target_kind: TargetKind
    risk: str
    containment: bool
    description: str
    # An entity kind the plan must have for the action to be proposed (its values go into the params).
    requires: Optional[str] = None
    # The type that undoes this one (a rollback is a new ledger row of that type).
    inverse: Optional[str] = None
    # False: never proposed by playbooks or recommendations (only rollbacks create it).
    plannable: bool = True
    # Undoes one of our own changes: rollbacks of it skip the non-public-IP, protected-asset and
    # internal-sender guardrails, so an asset protected after the change can still be released.
    restorative: bool = False
    # What a rollback cannot undo, or what stays in effect after the action (shown in the UI).
    irreversible_note: str = ""


ACTION_CATALOG: Dict[str, ActionSpec] = {
    "block_ip": ActionSpec("ip", "medium", True, "Block an IP address at the perimeter", inverse="unblock_ip"),
    "block_domain": ActionSpec("domain", "medium", True, "Block a domain in DNS/proxy", inverse="unblock_domain"),
    "block_url": ActionSpec("url", "medium", True, "Block a URL in the web proxy", inverse="unblock_url"),
    "isolate_host": ActionSpec("host", "high", True, "Network-isolate a host through EDR", inverse="release_host"),
    "terminate_process": ActionSpec(
        "process", "medium", True, "Terminate a process through EDR",
        irreversible_note="a terminated process is not restarted by a rollback",
    ),
    "quarantine_file": ActionSpec(
        "hash", "low", True, "Quarantine a file by hash through EDR", inverse="unblock_file"
    ),
    "disable_user": ActionSpec("user", "critical", True, "Disable a user account", inverse="enable_user"),
    "reset_password": ActionSpec(
        "user", "critical", True, "Force a password reset",
        irreversible_note="the previous password cannot be restored",
    ),
    "revoke_sessions": ActionSpec(
        "user", "high", True, "Revoke a user's active sessions",
        irreversible_note="existing access tokens stay valid until they expire, about 1 h",
    ),
    "collect_forensics": ActionSpec(
        "host", "low", False, "Collect forensic evidence from a host",
        irreversible_note="a collected investigation package cannot be un-collected",
    ),
    "create_ticket": ActionSpec("alert", "low", False, "Open an incident ticket"),
    "send_alert": ActionSpec("alert", "low", False, "Notify the SOC channel"),
    "block_sender": ActionSpec(
        "email", "medium", True, "Block a sender address in the mail gateway", inverse="unblock_sender"
    ),
    "purge_message": ActionSpec(
        "message", "high", True, "Remove a message (by Message-ID, sender and subject) from every mailbox",
        inverse="restore_message",
    ),
    "notify_reporter": ActionSpec(
        "alert", "low", False, "Tell the user who reported the email what was found", requires="reporter",
        irreversible_note="a sent notification cannot be recalled",
    ),
    "confirm_compromised": ActionSpec(
        "user", "high", True, "Confirm a user as compromised in Entra ID Protection", inverse="dismiss_user_risk"
    ),
    # Inverse types: created only by rollbacks, never planned.
    "release_host": ActionSpec(
        "host", "high", False, "Release a host from network isolation", plannable=False, restorative=True
    ),
    "unblock_ip": ActionSpec(
        "ip", "medium", False, "Remove an IP address block", plannable=False, restorative=True
    ),
    "unblock_domain": ActionSpec(
        "domain", "medium", False, "Remove a domain block", plannable=False, restorative=True
    ),
    "unblock_url": ActionSpec("url", "medium", False, "Remove a URL block", plannable=False, restorative=True),
    "unblock_file": ActionSpec(
        "hash", "medium", False, "Remove a file hash block", plannable=False, restorative=True
    ),
    "unblock_sender": ActionSpec(
        "email", "medium", False, "Remove a sender block", plannable=False, restorative=True
    ),
    "enable_user": ActionSpec(
        "user", "critical", False, "Re-enable a disabled user account", plannable=False, restorative=True
    ),
    "restore_message": ActionSpec(
        "message", "high", False, "Restore a removed message to the mailboxes it was removed from",
        plannable=False, restorative=True,
    ),
    "dismiss_user_risk": ActionSpec(
        "user", "high", False, "Dismiss a user's risk in Entra ID Protection", plannable=False, restorative=True
    ),
}

# Forward type of each inverse type (``release_host`` -> ``isolate_host``).
FORWARD_OF: Dict[str, str] = {spec.inverse: name for name, spec in ACTION_CATALOG.items() if spec.inverse}

ACTION_TARGET_KINDS: Dict[str, FrozenSet[str]] = {name: frozenset({spec.target_kind}) for name, spec in ACTION_CATALOG.items()}

# Per action type, how many may start executing per tenant per hour (tenants may override).
DEFAULT_BLAST_RADIUS: Dict[str, int] = {
    "isolate_host": 5,
    "disable_user": 3,
    "reset_password": 5,
    "revoke_sessions": 10,
    "terminate_process": 20,
    "quarantine_file": 20,
    "purge_message": 10,
    "block_sender": 20,
    "release_host": 5,
    "enable_user": 3,
    "restore_message": 10,
    "confirm_compromised": 10,
    "dismiss_user_risk": 5,
}

GUARDRAIL_REASONS: Dict[str, str] = {
    "unknown_action": "the action type is not in the action catalog",
    "action_not_allowed": "the tenant's allowed_actions list does not include this action type",
    "target_type_not_allowed": "the action does not accept this kind of target",
    "invalid_target": "the target is empty, too long or malformed",
    "invalid_ip": "the target is not an IP address",
    "invalid_domain": "the target is not a valid domain name",
    "invalid_url": "the target is not an http(s) URL with a host",
    "invalid_hash": "the target is not an MD5/SHA-1/SHA-256/SHA-512 hex digest",
    "invalid_host": "the target is not a valid host name",
    "invalid_user": "the target is not a valid user name",
    "invalid_process": "the target is not a valid process name",
    "invalid_email": "the target is not an email address",
    "invalid_message": "the target is not an Internet Message-ID",
    "internal_sender": "senders of the tenant's own domains are never blocked (disable or reset the account instead)",
    "unroutable_ip": "loopback, link-local, multicast, unspecified and reserved addresses are never blocked",
    "non_public_ip": "private/internal addresses are blocked only when the tenant allows internal IP blocks",
    "protected_asset": "the target is on the tenant's protected assets list",
    PROTECTED_INVALID_REASON: (
        "the tenant's protected assets setting is malformed or too large, so no action on hosts, users, "
        "addresses, domains, URLs, files or processes is allowed until it is fixed"
    ),
    POLICY_INVALID_REASON: "the tenant's response policy is malformed, so no action is allowed until it is fixed",
    "autonomy_disabled": "the tenant's autonomy policy disables actions of this risk level",
    HOURLY_CAP_REASON: "the tenant's hourly action cap was reached",
    BLAST_RADIUS_REASON: "the hourly limit for this action type (blast radius) was reached",
    APPROVAL_EXPIRED_REASON: "the approval was not executed within response.approval_ttl_s and expired",
    APPROVAL_SUPERSEDED_REASON: (
        "the approval arrived while the alert's workflow run was still active, and the run ended without "
        "executing it"
    ),
}

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

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")
_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?=.{1,253}$)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")
_MESSAGE_ID_RE = re.compile(r"^<?[\x21-\x3b\x3d\x3f-\x7e]{1,995}>?$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

# Operating-system and security-agent processes no response ever terminates, whatever the
# tenant configured: killing them crashes or blinds the host, and malware routinely borrows
# their names (an implant called lsass.exe in a Temp folder is still named lsass.exe).
# Compared by base name, NFKC-normalised and case-folded, with and without ".exe".
CRITICAL_PROCESSES: FrozenSet[str] = frozenset(
    {
        "system", "system idle process", "registry", "memory compression", "secure system",
        "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso", "svchost", "explorer",
        "dwm", "fontdrvhost", "spoolsv", "taskhostw", "sihost", "ctfmon", "conhost", "userinit",
        "msmpeng", "mssense", "sensecncproxy", "nissrv", "securityhealthservice", "senseir",
        "csfalconservice", "csfalconcontainer", "sentinelagent", "sentinelservicehost", "cbdefense", "repmgr",
        "cylancesvc", "xagt", "elastic-agent", "elastic-endpoint", "osqueryd", "sysmon", "sysmon64",
        "init", "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "kthreadd", "sshd", "dbus-daemon",
        "launchd", "kernel_task", "windowserver", "loginwindow", "falcon-sensor", "auditd",
    }
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


def target_key(kind: str, value: str) -> Tuple[str, ...]:
    """Comparison forms of a target, so evidence and plan targets match whatever their spelling."""
    if kind == "process":
        return (_process_base(value),)
    if kind == "host":
        return _host_forms(value)
    if kind == "user":
        return _user_forms(value)
    if kind == "domain":
        return (_domain_key(value),)
    if kind == "ip":
        address = parse_address(value)
        return (str(address),) if address is not None else (_clean(value),)
    if kind == "message":
        return (value.strip(),)
    return (_clean(value),)


def target_corroborated(kind: str, value: str, corroborated: FrozenSet[Tuple[str, str]]) -> bool:
    keys = {(k, form) for k, v in corroborated for form in target_key(k, v)}
    return any((kind, form) in keys for form in target_key(kind, value))


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
    # Imported here: the agents package pulls in the LLM stack, which API processes need not load.
    from lg_sotf.agents.correlation.indicators import extract_indicators

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
    return frozenset({_process_base(value) if kind == "process" else _clean(value)})


def lineage_only_values(raw: Any) -> FrozenSet[str]:
    """Normalised process base names and hashes that occur *only* under parent/grandparent keys of the raw event."""
    lineage: set[str] = set()
    primary: set[str] = set()
    budget = [_MAX_LINEAGE_SCAN]

    def add(bucket: set[str], value: str) -> None:
        text = value.strip()
        if not text or len(text) > 1_024:
            return
        bucket.add(_clean(text))
        bucket.add(_process_base(text))

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


def validate_target(kind: str, target: str) -> Optional[str]:
    """Syntax only: ``None`` when the target is well formed for its kind, otherwise the reason code."""
    if not target or len(target) > 2_048:
        return "invalid_target"
    if kind == "ip":
        try:
            ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            return "invalid_ip"
        return None
    if kind == "domain":
        return None if _DOMAIN_RE.match(target.lower().rstrip(".")) else "invalid_domain"
    if kind == "url":
        try:
            parts = urlsplit(target)
            host = parts.hostname
        except ValueError:
            return "invalid_url"
        return None if parts.scheme in ("http", "https") and host else "invalid_url"
    if kind == "hash":
        return None if _HASH_RE.match(target.lower()) else "invalid_hash"
    if kind == "host":
        return None if _HOST_RE.match(target) else "invalid_host"
    if kind in ("user", "process"):
        return None if _NAME_RE.match(target) else f"invalid_{kind}"
    if kind == "email":
        return None if _EMAIL_RE.match(target.lower()) else "invalid_email"
    if kind == "message":
        return None if _MESSAGE_ID_RE.match(target) else "invalid_message"
    if kind == "alert":
        return None if target.startswith("alert:") else "invalid_target"
    return "invalid_target"


_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_PREFIX = ipaddress.IPv6Network("64:ff9b:1::/48")
# Characters URL parsers (WHATWG/UTS 46) treat as a label separator in host names.
_DOT_EQUIVALENTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_CLASS_RANK = {"public": 0, "internal": 1, "unroutable": 2}
_WILDCARDS = frozenset("*?[")
_DN_VALUE_RE = re.compile(r"^(?:cn|uid)\s*=\s*((?:\\.|[^,+\\])+)")
_DN_ESCAPE_RE = re.compile(r"\\(.)")


def _embedded_ipv4(address: IPAddress) -> List[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address carries (6to4, Teredo client, NAT64 well-known prefix, IPv4-compatible)."""
    if not isinstance(address, ipaddress.IPv6Address):
        return []
    out: List[ipaddress.IPv4Address] = []
    if address.sixtofour is not None:
        out.append(address.sixtofour)
    if address.teredo is not None:
        out.append(address.teredo[1])
    value = int(address)
    if address in _NAT64_PREFIX:
        out.append(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    if address in _NAT64_LOCAL_PREFIX:
        # RFC 8215 local-use prefix 64:ff9b:1::/48 with the RFC 6052 /48 layout: the IPv4
        # address sits in bits 48-63 and 72-87 (bits 64-71 are the reserved "u" octet).
        # Some translators put it in the low 32 bits instead; both readings are checked.
        packed = address.packed
        out.append(ipaddress.IPv4Address(packed[6:8] + packed[9:11]))
        out.append(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    if value >> 32 == 0 and value > 1:
        out.append(ipaddress.IPv4Address(value))
    return out


def _single_class(address: IPAddress) -> str:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return "unroutable"
    return "public" if address.is_global else "internal"


def ip_block_class(address: IPAddress) -> str:
    """``public``, ``internal`` (private/CGNAT/ULA) or ``unroutable`` (never a sensible block target).

    An IPv4-mapped address is classified as its IPv4 address; any other IPv6
    address that embeds an IPv4 address takes the stricter of the two classes.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _single_class(address.ipv4_mapped)
    classes = [_single_class(a) for a in (address, *_embedded_ipv4(address))]
    return max(classes, key=_CLASS_RANK.__getitem__)


def _ipv4_part(part: str) -> Optional[int]:
    if part[:2] in ("0x", "0X"):
        digits, base, allowed = part[2:], 16, "0123456789abcdefABCDEF"
        if not digits:
            return 0
    elif len(part) > 1 and part.startswith("0"):
        digits, base, allowed = part[1:], 8, "01234567"
    else:
        digits, base, allowed = part, 10, "0123456789"
    if not digits or len(digits) > 32 or any(ch not in allowed for ch in digits):
        return None
    return int(digits, base)


def loose_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address a browser or curl connects to for a numeric host, else ``None``.

    Follows the WHATWG URL IPv4 parser: one to four dot-separated parts, each
    decimal, ``0x`` hex or ``0``-prefixed octal, the last part filling the
    remaining bytes (``3405803781``, ``0xcb.0.113.5`` and ``203.28933``
    are all ``203.0.113.5``).
    """
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    numbers = [_ipv4_part(p) for p in parts]
    if any(n is None for n in numbers):
        return None
    values = [int(n) for n in numbers if n is not None]
    *head, last = values
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(values)):
        return None
    address = last
    for index, number in enumerate(head):
        address += number << (8 * (3 - index))
    return ipaddress.IPv4Address(address)


def parse_address(text: str) -> Optional[IPAddress]:
    """An IP literal in any spelling a network stack accepts (brackets, zone ids, numeric IPv4 forms)."""
    candidate = text.strip().strip("[]").split("%", 1)[0]
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return loose_ipv4(candidate)


def _clean(text: str) -> str:
    """Compare form of a name: NFKC, invisible format characters removed, trimmed, lowercased."""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf").strip().lower()


def _short_host(name: str) -> str:
    return name.split(".", 1)[0]


def _host_forms(name: str) -> Tuple[str, ...]:
    cleaned = _clean(name).rstrip(".")
    return tuple(dict.fromkeys((cleaned, _short_host(cleaned))))


def _domain_key(name: str) -> str:
    cleaned = _clean(name).strip(".")
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return cleaned


def _user_forms(name: str) -> Tuple[str, ...]:
    """An account as written, as the CN/UID of a DN, and as the bare account name.

    ``DOMAIN\\user``, ``domain/user``, ``user@domain`` and
    ``CN=user,OU=...,DC=...`` all also compare as ``user``.
    """
    cleaned = _clean(name)
    match = _DN_VALUE_RE.match(cleaned)
    base = _DN_ESCAPE_RE.sub(r"\1", match.group(1)).strip() if match else cleaned
    bare = base.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].split("@", 1)[0].strip()
    return tuple(dict.fromkeys(f for f in (cleaned, base, bare) if f))


def _process_base(name: str) -> str:
    """Compare form of a process's base name (``C:\\x\\LSASS.EXE`` -> ``lsass.exe``)."""
    return re.split(r"[\\/]", _clean(name).strip("\"'"))[-1].strip()


def _process_forms(name: str) -> Tuple[str, ...]:
    """A process as written, its base name and the base name without ``.exe``."""
    cleaned = _clean(name).strip("\"'")
    base = _process_base(name)
    stem = base[:-4] if base.endswith(".exe") else base
    return tuple(dict.fromkeys(f for f in (cleaned, base, stem) if f))


def critical_process(name: str) -> bool:
    """Whether ``name`` (any path, case or Unicode spelling) is a built-in never-terminate process."""
    return any(form in CRITICAL_PROCESSES for form in _process_forms(name))


class _Names:
    """Exact names in a set (constant-time lookup), wildcard patterns matched with fnmatch."""

    __slots__ = ("exact", "patterns")

    def __init__(self, entries: Iterable[str]) -> None:
        exact: set[str] = set()
        patterns: List[str] = []
        for entry in entries:
            if not entry or set(entry) <= {"*", "?"}:
                continue  # a bare wildcard (e.g. the short form of "*.corp.local") would match everything
            if _WILDCARDS & set(entry):
                patterns.append(entry)
            else:
                exact.add(entry)
        self.exact = frozenset(exact)
        self.patterns = tuple(dict.fromkeys(patterns))

    def matches(self, forms: Iterable[str]) -> bool:
        for form in forms:
            if form in self.exact or any(fnmatch.fnmatchcase(form, p) for p in self.patterns):
                return True
        return False


def _problem_list(prefix: str, exc: ValidationError) -> List[str]:
    out: List[str] = []
    for error in exc.errors()[:MAX_POLICY_PROBLEMS]:
        loc = ".".join(str(p) for p in error["loc"])
        out.append(f"{prefix}{'.' + loc if loc else ''}: {error['msg']}"[:200])
    return out


def _check_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("not an IP network in CIDR notation") from exc
    return value


ProtectedName = Annotated[
    StrictStr, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_PROTECTED_ENTRY_CHARS)
]
ProtectedCidr = Annotated[
    StrictStr, StringConstraints(strip_whitespace=True, min_length=1, max_length=64), AfterValidator(_check_cidr)
]


class ProtectedAssetsSettings(BaseModel):
    """Schema of ``tenants.settings["protected_assets"]``. Host and user entries may use ``*``/``?`` wildcards."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    users: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    domains: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    cidrs: List[ProtectedCidr] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    # Process names (or wildcards) never terminated, and file hashes never quarantined, on top of
    # the built-in CRITICAL_PROCESSES (e.g. line-of-business agents, known-good binaries).
    processes: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    hashes: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)


_LEGACY_ASSETS: TypeAdapter[List[str]] = TypeAdapter(
    Annotated[List[ProtectedName], Field(max_length=MAX_PROTECTED_ENTRIES)]
)
_LEGACY_CIDRS: TypeAdapter[List[str]] = TypeAdapter(
    Annotated[List[ProtectedCidr], Field(max_length=MAX_PROTECTED_ENTRIES)]
)


@dataclass(frozen=True)
class ProtectedAssets:
    """Tenant assets no action may touch. ``problems`` non-empty means the setting is malformed (fail closed)."""

    hosts: Tuple[str, ...] = ()
    users: Tuple[str, ...] = ()
    domains: Tuple[str, ...] = ()
    networks: Tuple[IPNetwork, ...] = ()
    problems: Tuple[str, ...] = ()
    processes: Tuple[str, ...] = ()
    hashes: Tuple[str, ...] = ()
    _hosts: _Names = field(init=False, repr=False, compare=False)
    _users: _Names = field(init=False, repr=False, compare=False)
    _domains: FrozenSet[str] = field(init=False, repr=False, compare=False)
    _processes: _Names = field(init=False, repr=False, compare=False)
    _hashes: FrozenSet[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        host_entries: List[str] = []
        for host in self.hosts:
            host_entries.extend(_host_forms(host))
        user_entries: List[str] = []
        for user in self.users:
            user_entries.extend(_user_forms(user))
        object.__setattr__(self, "_hosts", _Names(host_entries))
        object.__setattr__(self, "_users", _Names(user_entries))
        # "*.example.com" means example.com and its subdomains, which is what every domain entry covers.
        domains = (_domain_key(d[2:] if d.startswith("*.") else d) for d in self.domains)
        object.__setattr__(self, "_domains", frozenset(d for d in domains if d))
        process_entries: List[str] = []
        for process in self.processes:
            process_entries.extend(_process_forms(process))
        object.__setattr__(self, "_processes", _Names(process_entries))
        object.__setattr__(self, "_hashes", frozenset(_clean(h) for h in self.hashes if _clean(h)))

    @property
    def invalid(self) -> bool:
        return bool(self.problems)

    @classmethod
    def from_tenant_settings(cls, tenant_settings: Mapping[str, Any]) -> ProtectedAssets:
        raw = tenant_settings.get("protected_assets")
        hosts: List[str] = []
        users: List[str] = []
        domains: List[str] = []
        cidrs: List[str] = []
        processes: List[str] = []
        hashes: List[str] = []
        problems: List[str] = []
        if isinstance(raw, Mapping):
            try:
                parsed = ProtectedAssetsSettings.model_validate(dict(raw))
            except ValidationError as exc:
                problems += _problem_list("protected_assets", exc)
            else:
                hosts, users, domains, cidrs = list(parsed.hosts), list(parsed.users), list(parsed.domains), list(parsed.cidrs)
                processes, hashes = list(parsed.processes), list(parsed.hashes)
        elif raw is not None:
            # Legacy flat list: networks become CIDRs, anything else protects that exact name everywhere.
            try:
                entries = _LEGACY_ASSETS.validate_python(raw)
            except ValidationError as exc:
                problems += _problem_list("protected_assets", exc)
            else:
                for entry in entries:
                    if any(ch.isdigit() for ch in entry) and ("." in entry or ":" in entry) and _is_network(entry):
                        cidrs.append(entry)
                    else:
                        hosts.append(entry)
                        users.append(entry)
                        domains.append(entry)
        legacy_cidrs = tenant_settings.get("protected_cidrs")
        if legacy_cidrs is not None:
            try:
                cidrs += _LEGACY_CIDRS.validate_python(legacy_cidrs)
            except ValidationError as exc:
                problems += _problem_list("protected_cidrs", exc)
        if problems:
            log.warning("response.protected_assets_invalid", problems=problems[:MAX_POLICY_PROBLEMS])
        return cls(
            hosts=tuple(hosts),
            users=tuple(users),
            domains=tuple(domains),
            networks=tuple(ipaddress.ip_network(c, strict=False) for c in cidrs),
            problems=tuple(problems[:MAX_POLICY_PROBLEMS]),
            processes=tuple(processes),
            hashes=tuple(hashes),
        )

    def _host_protected(self, host: str) -> bool:
        return self._hosts.matches(_host_forms(host))

    def _user_protected(self, user: str) -> bool:
        return self._users.matches(_user_forms(user))

    def _domain_protected(self, domain: str) -> bool:
        labels = _domain_key(domain).split(".")
        return any(".".join(labels[i:]) in self._domains for i in range(len(labels)))

    def _ip_protected(self, address: IPAddress) -> bool:
        forms: List[IPAddress] = [address]
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            forms.append(address.ipv4_mapped)
        forms += _embedded_ipv4(address)
        return any(form.version == net.version and form in net for form in forms for net in self.networks)

    def _address_match(self, value: str, *, as_domain: bool) -> Optional[str]:
        address = parse_address(value)
        if address is not None and self._ip_protected(address):
            return "cidr"
        if self._host_protected(value):
            return "host"
        if as_domain and self._domain_protected(value):
            return "domain"
        return None

    def match(self, kind: str, target: str) -> Optional[str]:
        """Which protected category the target falls in, else ``None``.

        Categories: ``host``/``user``/``domain``/``cidr``/``process``/``hash``
        and ``critical_process`` (the built-in never-terminate list). IP and
        host targets are checked against CIDRs and host names; domain targets
        and URL hosts (canonicalised) also against protected domains; sender
        addresses by their domain (and subdomains) and as a whole address
        against protected users (a bare account name such as ``admin`` does
        not protect ``admin@`` every domain).
        """
        if kind == "process":
            if critical_process(target):
                return "critical_process"
            return "process" if self._processes.matches(_process_forms(target)) else None
        if kind == "hash":
            return "hash" if _clean(target) in self._hashes else None
        if kind == "user":
            return "user" if self._user_protected(target) else None
        if kind in ("ip", "host"):
            return self._address_match(target, as_domain=False)
        if kind == "domain":
            return self._address_match(target, as_domain=True)
        if kind == "url":
            for host in url_hosts(target):
                category = self._address_match(host, as_domain=True)
                if category is not None:
                    return category
            return None
        if kind == "email":
            address = _clean(target)
            if address in self._users.exact or any(fnmatch.fnmatchcase(address, p) for p in self._users.patterns):
                return "user"
            domain = address.rsplit("@", 1)[-1]
            return self._address_match(domain, as_domain=True)
        return None


def canonical_host(host: str) -> str:
    """A URL host the way browsers and proxies resolve it: percent-decoded, NFKC (full-width
    digits and letters to ASCII), ideographic/full-width dots to ``.``, invisible format
    characters removed, lowercased."""
    decoded = unquote(host).translate(_DOT_EQUIVALENTS)
    return _clean(decoded).translate(_DOT_EQUIVALENTS).rstrip(".")


def url_hosts(target: str) -> List[str]:
    """Every host a client could connect to for ``target``: Python's reading of the URL and the
    WHATWG one (``\\`` is a path separator in http(s) URLs, so ``http://1.2.3.4\\@evil.com/``
    goes to 1.2.3.4), each in its literal and canonical form."""
    text = target.strip()
    hosts: List[str] = []
    candidates = [text]
    if "\\" in text and text.lower().startswith(("http:", "https:")):
        candidates.append(text.replace("\\", "/"))
    for candidate in candidates:
        try:
            host = urlsplit(candidate).hostname or ""
        except ValueError:
            continue
        if host:
            hosts += [unquote(host), canonical_host(host)]
    return list(dict.fromkeys(h for h in hosts if h))


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- policy


def _catalog_actions(values: Optional[List[str]]) -> Optional[List[str]]:
    unknown = [v for v in values or [] if v not in ACTION_CATALOG]
    if unknown:
        raise ValueError(f"unknown action types: {', '.join(sorted(unknown)[:5])[:120]}")
    return values


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
AutonomyMap = Dict[Literal["low", "medium", "high", "critical"], Literal["auto", "approval", "disabled"]]


class ResponsePolicySettings(BaseModel):
    """Schema of ``tenants.settings["response"]`` (connector keys: :mod:`lg_sotf.services.connectors.registry`)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector: Optional[StrictStr] = None
    dry_run: Optional[StrictBool] = None
    webhook_url: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=2_048)]] = None
    webhook_secret_ciphertext: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=8_192)]] = None
    ca_cert_pem: Optional[Annotated[StrictStr, StringConstraints(min_length=1, max_length=65_536)]] = None
    tls_verify: Optional[StrictBool] = None
    allow_internal_ip_blocks: Optional[StrictBool] = None
    allowed_actions: Optional[List[StrictStr]] = Field(default=None, max_length=64)
    max_actions_per_hour: Optional[Annotated[StrictInt, Field(ge=0, le=MAX_TENANT_HOURLY_CAP)]] = None
    blast_radius: Optional[Dict[StrictStr, Annotated[StrictInt, Field(ge=0, le=MAX_BLAST_RADIUS)]]] = None
    autonomy: Optional[AutonomyMap] = None
    # Per action type, which connector executes it (lg_sotf.services.connectors.routing).
    routes: Optional[Dict[StrictStr, StrictStr]] = Field(default=None, max_length=MAX_ROUTES)

    @field_validator("connector")
    @classmethod
    def _connector(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in CONNECTOR_NAMES:
            raise ValueError(f"connector must be one of {', '.join(CONNECTOR_NAMES)}")
        return value

    @field_validator("webhook_url")
    @classmethod
    def _url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        try:
            parts = urlsplit(value)
        except ValueError as exc:
            raise ValueError("webhook_url is not a URL") from exc
        if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
            raise ValueError("webhook_url must be an http(s) URL with a host and no credentials")
        return value

    @field_validator("tls_verify")
    @classmethod
    def _tls(cls, value: Optional[bool]) -> Optional[bool]:
        if value is False:
            raise ValueError("TLS verification cannot be disabled for response webhooks (use ca_cert_pem)")
        return value

    @field_validator("allowed_actions")
    @classmethod
    def _allowed(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        return _catalog_actions(value)

    @field_validator("blast_radius")
    @classmethod
    def _blast(cls, value: Optional[Dict[str, int]]) -> Optional[Dict[str, int]]:
        _catalog_actions(list(value or {}))
        return value

    @field_validator("routes")
    @classmethod
    def _routes(cls, value: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        for action_type, route in (value or {}).items():
            problem = route_problem(action_type, route)
            if problem:
                raise ValueError(problem)
        return value


def route_problem(action_type: str, route: Any) -> Optional[str]:
    """Why ``response.routes[action_type] = route`` is not allowed, or ``None``."""
    if action_type not in ACTION_CATALOG:
        return f"routes: unknown action type {str(action_type)[:64]!r}"
    if route not in ROUTE_NAMES:
        return f"routes.{action_type}: must be one of {', '.join(ROUTE_NAMES)}"
    if route == TICKET_CONNECTOR_NAME and action_type != TICKET_ACTION:
        return f"routes.{action_type}: ticketing executes create_ticket only"
    if route == MICROSOFT_CONNECTOR_NAME:
        from lg_sotf.integrations.microsoft.catalog import executes

        if not executes(action_type):
            return f"routes.{action_type}: no Microsoft capability executes {action_type}"
    return None


# The response keys the guardrails read; malformed values fail closed when a policy is resolved.
GUARDRAIL_KEYS = ("allow_internal_ip_blocks", "allowed_actions", "max_actions_per_hour", "blast_radius", "autonomy")
_AUTONOMY: TypeAdapter[Dict[str, str]] = TypeAdapter(AutonomyMap)


class ResponsePolicyError(ValueError):
    """Tenant response settings do not match the schema (message lists the problems; safe to return)."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = list(problems)


def validate_response_settings(tenant_settings: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the response sections of a tenant settings document (for the settings API).

    Checks ``response``, ``protected_assets`` (object form, or the legacy flat
    list), ``protected_cidrs``, ``autonomy`` and the legacy top-level
    ``connector``/``dry_run`` when present, and returns them normalised
    (whitespace stripped, unset keys dropped). Raises
    :class:`ResponsePolicyError` listing every problem found.
    """
    problems: List[str] = []
    out: Dict[str, Any] = {}
    if "response" in tenant_settings:
        try:
            out["response"] = ResponsePolicySettings.model_validate(tenant_settings["response"]).model_dump(
                exclude_none=True
            )
        except ValidationError as exc:
            problems += _problem_list("response", exc)
    if "protected_assets" in tenant_settings:
        raw = tenant_settings["protected_assets"]
        try:
            if isinstance(raw, Mapping):
                out["protected_assets"] = ProtectedAssetsSettings.model_validate(dict(raw)).model_dump()
            else:
                out["protected_assets"] = _LEGACY_ASSETS.validate_python(raw)
        except ValidationError as exc:
            problems += _problem_list("protected_assets", exc)
    if "protected_cidrs" in tenant_settings:
        try:
            out["protected_cidrs"] = _LEGACY_CIDRS.validate_python(tenant_settings["protected_cidrs"])
        except ValidationError as exc:
            problems += _problem_list("protected_cidrs", exc)
    if "autonomy" in tenant_settings:
        try:
            out["autonomy"] = _AUTONOMY.validate_python(tenant_settings["autonomy"])
        except ValidationError as exc:
            problems += _problem_list("autonomy", exc)
    if "connector" in tenant_settings or "dry_run" in tenant_settings:
        legacy = {k: tenant_settings[k] for k in ("connector", "dry_run") if k in tenant_settings}
        try:
            out.update(ResponsePolicySettings.model_validate(legacy).model_dump(exclude_none=True))
        except ValidationError as exc:
            problems += _problem_list("settings", exc)
    if problems:
        raise ResponsePolicyError(problems)
    return out


def resolve_autonomy(risk: str, tenant_settings: Mapping[str, Any], settings: Settings) -> Autonomy:
    """Tenant autonomy (``response.autonomy`` over top-level ``autonomy``) over the install default.

    A value outside ``auto``/``approval``/``disabled`` means ``disabled``: a
    typo never loosens the policy.
    """
    policy: Dict[str, Any] = dict(settings.response.default_autonomy)
    for override in (tenant_settings.get("autonomy"), tenant_response_settings(tenant_settings).get("autonomy")):
        if isinstance(override, Mapping):
            policy.update({k: v for k, v in override.items() if k in RISK_LEVELS})
    mode = policy.get(risk, "approval")
    return mode if mode in AUTONOMY_MODES else "disabled"


@dataclass(frozen=True)
class ResponsePolicy:
    """The effective response policy for one tenant (tenant settings over install settings).

    ``problems`` non-empty means the tenant's guardrail settings are
    malformed: every action is blocked (``response_policy_invalid``).
    """

    autonomy: Mapping[str, Autonomy]
    protected: ProtectedAssets
    allow_internal_ip_blocks: bool = False
    allowed_actions: Optional[FrozenSet[str]] = None
    max_actions_per_hour: int = 50
    blast_radius: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_BLAST_RADIUS))
    problems: Tuple[str, ...] = ()
    # The tenant's own mail domains (tools.internal_domains, tenant and install): never blocked as senders.
    internal_domains: Tuple[str, ...] = ()

    @classmethod
    def resolve(cls, tenant_settings: Mapping[str, Any], settings: Settings) -> ResponsePolicy:
        rs = tenant_response_settings(tenant_settings)
        install_cap = int(settings.response.max_actions_per_hour_per_tenant)
        problems: List[str] = []
        parsed = ResponsePolicySettings()
        try:
            parsed = ResponsePolicySettings.model_validate({k: rs[k] for k in GUARDRAIL_KEYS if k in rs})
        except ValidationError as exc:
            problems += _problem_list("response", exc)
        if tenant_settings.get("autonomy") is not None:
            try:
                _AUTONOMY.validate_python(tenant_settings["autonomy"])
            except ValidationError as exc:
                problems += _problem_list("autonomy", exc)
        if problems:
            log.warning("response.policy_invalid", problems=problems[:MAX_POLICY_PROBLEMS])
        blast = dict(DEFAULT_BLAST_RADIUS)
        blast.update(parsed.blast_radius or {})
        tenant_cap = parsed.max_actions_per_hour
        return cls(
            autonomy={risk: resolve_autonomy(risk, tenant_settings, settings) for risk in RISK_LEVELS},
            protected=ProtectedAssets.from_tenant_settings(tenant_settings),
            allow_internal_ip_blocks=parsed.allow_internal_ip_blocks is True,
            allowed_actions=frozenset(parsed.allowed_actions) if parsed.allowed_actions is not None else None,
            max_actions_per_hour=install_cap if tenant_cap is None else min(tenant_cap, install_cap),
            blast_radius=blast,
            problems=tuple(problems[:MAX_POLICY_PROBLEMS]),
            internal_domains=_internal_domains(tenant_settings, settings),
        )

    def internal_sender(self, address: str) -> bool:
        domain = _domain_key(address.rsplit("@", 1)[-1])
        return any(domain == d or domain.endswith("." + d) for d in self.internal_domains)


def _internal_domains(tenant_settings: Mapping[str, Any], settings: Settings) -> Tuple[str, ...]:
    tools = tenant_settings.get("tools")
    values: List[Any] = []
    for source in (tools if isinstance(tools, Mapping) else {}, settings.tools or {}):
        entries = source.get("internal_domains")
        if isinstance(entries, list):
            values.extend(entries)
    domains = (_domain_key(v.strip().lstrip("*.")) for v in values if isinstance(v, str) and v.strip())
    return tuple(dict.fromkeys(d for d in domains if d))


@dataclass(frozen=True)
class GuardrailBlock:
    code: str
    detail: str

    @property
    def explanation(self) -> str:
        return f"{GUARDRAIL_REASONS.get(self.code, self.code)}: {self.detail}" if self.detail else GUARDRAIL_REASONS.get(
            self.code, self.code
        )


def check_guardrails(
    action_type: str,
    target: str,
    policy: ResponsePolicy,
    *,
    target_kind: Optional[str] = None,
    restorative: bool = False,
) -> Optional[GuardrailBlock]:
    """The first guardrail the action fails (module docstring, rules 0-6), or ``None``.

    ``restorative`` (a rollback that undoes one of our own changes) skips the
    non-public-IP, protected-asset and internal-sender rules: releasing a host
    that became protected after it was isolated must stay possible. An
    inverse type passes the ``allowed_actions`` allowlist when it or its
    forward type is listed; autonomy is checked against its own risk.
    """
    spec = ACTION_CATALOG.get(action_type)
    if spec is None:
        return GuardrailBlock("unknown_action", action_type[:64])
    if policy.problems:
        return GuardrailBlock(POLICY_INVALID_REASON, "; ".join(policy.problems)[:300])
    if policy.allowed_actions is not None and not (
        action_type in policy.allowed_actions or FORWARD_OF.get(action_type) in policy.allowed_actions
    ):
        return GuardrailBlock("action_not_allowed", action_type)
    kind = target_kind or spec.target_kind
    if kind not in ACTION_TARGET_KINDS[action_type]:
        return GuardrailBlock("target_type_not_allowed", f"{action_type} accepts {sorted(ACTION_TARGET_KINDS[action_type])}, got {kind[:32]}")
    invalid = validate_target(kind, target)
    if invalid is not None:
        return GuardrailBlock(invalid, "")
    if kind != "alert" and policy.protected.invalid:
        return GuardrailBlock(PROTECTED_INVALID_REASON, "; ".join(policy.protected.problems)[:300])
    if kind == "ip":
        cls = ip_block_class(ipaddress.ip_address(target.strip("[]")))
        if cls == "unroutable":
            return GuardrailBlock("unroutable_ip", "")
        if cls == "internal" and not policy.allow_internal_ip_blocks and not restorative:
            return GuardrailBlock("non_public_ip", "tenant setting response.allow_internal_ip_blocks is off")
    if not restorative:
        category = policy.protected.match(kind, target)
        if category is not None:
            return GuardrailBlock("protected_asset", f"matches a protected {category} entry")
        if kind == "email" and policy.internal_sender(target):
            return GuardrailBlock("internal_sender", "")
    if policy.autonomy.get(spec.risk) == "disabled":
        return GuardrailBlock("autonomy_disabled", f"{spec.risk} risk")
    return None


def protected_lookup(tenant_settings: Mapping[str, Any]) -> Callable[[str, str], Optional[str]]:
    """The tenant's protected assets as a connector lookup: ``lookup(kind, value)`` -> the category matched.

    A direct connector checks the identity it resolved a target to (an alias
    or object id resolved to a user) with it, because the guardrails only
    saw the literal target. A malformed list matches everything (fail closed).
    """
    assets = ProtectedAssets.from_tenant_settings(tenant_settings)

    def lookup(kind: str, value: str) -> Optional[str]:
        if assets.invalid:
            return PROTECTED_INVALID_REASON
        return assets.match(kind, value)

    return lookup


def approval_allowed(risk: str, role: Optional[str], autonomy: Optional[str] = None) -> bool:
    """Role vs risk: analysts approve low/medium, admins also high and critical; nothing whose autonomy is disabled."""
    if autonomy == "disabled":
        return False
    if role == "admin":
        return risk in RISK_LEVELS
    if role == "analyst":
        return risk in ANALYST_APPROVAL_RISKS
    return False


def preapproval_allowed(risk: str, approver_role: Optional[str]) -> bool:
    """Analysts may pre-approve low/medium actions; high and critical need an admin."""
    return risk in ANALYST_PREAPPROVAL_RISKS or approver_role == "admin"


def _is_preapproved(candidate: Candidate, approved: Sequence[str]) -> bool:
    """``action_type:target`` names exactly this action; a bare ``action_type`` covers every target of this alert."""
    return candidate.action_type in approved or f"{candidate.action_type}:{candidate.target}" in approved


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
            overrides=connectors,
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
            self._ticketing = TicketService(self._repos, self._settings, retries=1)
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

    async def executed_counts(
        self, tenant_id: str, since: Optional[datetime] = None, *, conn: Any = None
    ) -> Tuple[int, Dict[str, int]]:
        """(total, per action type) of actions that started real execution since ``since``.

        ``since=None`` (what the guardrails use) means the last hour on the
        database clock, the clock that stamps ``executed_at``: a worker whose
        clock runs fast cannot shrink the window and exceed the caps.
        """

        async def _fetch(c: Any) -> List[Any]:
            return list(await c.fetch(_EXECUTED_COUNTS_SQL, tenant_id, since, list(EXECUTED_STATUSES)))

        if conn is not None:
            rows = await _fetch(conn)
        else:
            async with self._repos.db.tenant_tx(tenant_id, readonly=True) as c:
                rows = await _fetch(c)
        by_type = {str(r["action_type"]): int(r["n"]) for r in rows}
        return sum(by_type.values()), by_type

    # ------------------------------------------------------------------ plan

    async def plan(
        self, tenant_id: str, alert_id: str, ctx: PlanContext, *, now: Optional[datetime] = None
    ) -> PlanResult:
        window_start = now - timedelta(hours=1) if now is not None else None
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        threat_type, candidates = build_candidates(ctx, alert_id)
        result = PlanResult(threat_type=threat_type)
        used_total, used_by_type = await self.executed_counts(tenant_id, window_start)
        auto_budget = max(0, policy.max_actions_per_hour - used_total)
        type_budget = {t: max(0, limit - used_by_type.get(t, 0)) for t, limit in policy.blast_radius.items()}

        for cand in candidates:
            spec = ACTION_CATALOG[cand.action_type]
            params: Dict[str, Any] = {
                **cand.params,
                "alert": {"severity": ctx.severity, "title": ctx.title[:200]},
                "evidence": ctx.evidence,
            }
            if cand.action_type in HOST_SCOPED_ACTIONS:
                params["scope"] = {"hosts": list(dict.fromkeys(str(h) for h in ctx.hosts))[:MAX_SCOPE_HOSTS]}
            uncorroborated = (
                spec.containment
                and ctx.evidence == "rules"
                and ctx.corroborated_targets is not None
                and not target_corroborated(spec.target_kind, cand.target, ctx.corroborated_targets)
            )
            autonomy = policy.autonomy[spec.risk]
            block = check_guardrails(cand.action_type, cand.target, policy)
            reason = block.code if block else None

            approved_by: Optional[str] = None
            preapproved = _is_preapproved(cand, ctx.approved_actions) and bool(ctx.approved_by)
            if block is not None:
                status = "blocked"
                params["explanation"] = f"blocked: {block.explanation}"
            elif preapproved and preapproval_allowed(spec.risk, ctx.approver_role):
                status, approved_by = "approved", ctx.approved_by
                params["explanation"] = f"approved: pre-approved by the analyst decision ({spec.risk} risk)"
            elif preapproved:
                status, params["approval_reason"] = "awaiting_approval", "admin_approval_required"
                params["explanation"] = f"awaiting approval: {spec.risk} risk needs an admin approval"
            elif autonomy == "auto":
                if spec.containment and ctx.evidence == "llm_only":
                    status, params["approval_reason"] = "awaiting_approval", "llm_only_evidence"
                    params["explanation"] = "awaiting approval: containment on LLM-only evidence is never automatic"
                elif uncorroborated:
                    status, params["approval_reason"] = "awaiting_approval", "target_not_corroborated"
                    params["explanation"] = (
                        "awaiting approval: the rule evidence does not concern this target, so containing it "
                        "is not automatic"
                    )
                elif auto_budget <= 0:
                    status, params["approval_reason"] = "awaiting_approval", HOURLY_CAP_REASON
                    params["explanation"] = f"awaiting approval: hourly cap of {policy.max_actions_per_hour} reached"
                elif cand.action_type in type_budget and type_budget[cand.action_type] <= 0:
                    status, params["approval_reason"] = "awaiting_approval", BLAST_RADIUS_REASON
                    params["explanation"] = (
                        f"awaiting approval: at most {policy.blast_radius[cand.action_type]} "
                        f"{cand.action_type} per hour"
                    )
                else:
                    status, approved_by = "approved", POLICY_APPROVER
                    params["explanation"] = f"approved: tenant autonomy for {spec.risk} risk is 'auto'"
                    auto_budget -= 1
                    if cand.action_type in type_budget:
                        type_budget[cand.action_type] -= 1
            else:
                status = "awaiting_approval"
                params["explanation"] = f"awaiting approval: tenant autonomy for {spec.risk} risk is 'approval'"

            # Approved rows are written as 'proposed' first so approved_by lands in the
            # ledger column; a re-run finds the row still 'proposed' and finishes it.
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                action, created = await self._repos.actions.propose(
                    tenant_id,
                    alert_id,
                    cand.action_type,
                    cand.target,
                    spec.risk,
                    params=params,
                    requested_by=REQUESTED_BY,
                    status="proposed" if status == "approved" else status,
                    blocked_reason=reason,
                    conn=conn,
                )
                if created:
                    await self._record_transition(
                        tenant_id,
                        action,
                        "response_action.proposed",
                        {"approved_by": approved_by, "autonomy": autonomy},
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
                tenant_id,
                action.id,
                "approved",
                details={"approved_by": approved_by[:128], "preapproved": not policy},
                actor_type="agent" if policy else "user",
                actor_id=approved_by,
                expected_from="proposed",
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
                    tenant_id,
                    action.id,
                    target,
                    details={
                        "decided_by": decided_by[:128],
                        "reject_remaining": reject_remaining and action_id not in rejected,
                    },
                    actor_type="user",
                    actor_id=decided_by,
                    expected_from="awaiting_approval",
                    **extra,
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
            async with self._repos.db.system_tx() as conn:
                rows = list(await conn.fetch(_ORPHANED_EXECUTING_SQL, None, limit, grace))
        else:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                rows = list(await conn.fetch(_ORPHANED_EXECUTING_SQL, tenant_id, limit, grace))
        settled = 0
        for row in rows:
            owner, action_id, connector = str(row["tenant_id"]), row["id"], row["connector"]
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
        self, tenant_id: str, action_ids: Sequence[UUID], *, reason: str, conn: Any = None
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
                tenant_id,
                action_id,
                "blocked",
                details={"reason": code},
                actor_type="system",
                actor_id=SCHEDULER_ACTOR,
                expected_from="approved",
                blocked_reason=code,
                result={"guardrail": code, "explanation": GUARDRAIL_REASONS.get(code, code), **dict(detail)},
            )
        except (AlreadyInState, InvalidTransition):
            return None

    async def _block_approved(
        self, tenant_id: str, action: ResponseAction, code: str, detail: Mapping[str, Any], conn: Any = None
    ) -> ResponseAction:
        return await self._repos.actions.transition(
            tenant_id,
            action.id,
            "blocked",
            expected_from="approved",
            blocked_reason=code,
            result={"guardrail": code, "explanation": GUARDRAIL_REASONS.get(code, code), **detail},
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
                    used, by_type = await self.executed_counts(tenant_id, window_start, conn=conn)
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
        conn: Any,
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
        self, tenant_id: str, action: ResponseAction, *, conn: Any, notify: bool = True
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
            used, by_type = await self.executed_counts(tenant_id, conn=conn)
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
                tenant_id,
                updated,
                audit_action or f"response_action.{to_status}",
                details or {},
                actor_type=actor_type,
                actor_id=actor_id,
                conn=conn,
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
        conn: Any,
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
        conn: Any,
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
        conn: Any = None,
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
        record_action(action.action_type, action.status)
        if conn is None:
            # Inside a caller's transaction the caller publishes after commit (publish_action).
            await self.publish_action(tenant_id, action)

    async def record_transition(
        self,
        tenant_id: str,
        action: ResponseAction,
        audit_action: str,
        details: Mapping[str, Any],
        *,
        actor_type: str = "agent",
        actor_id: Optional[str] = None,
        conn: Any = None,
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
