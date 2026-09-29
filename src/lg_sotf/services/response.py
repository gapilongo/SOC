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
   acted on, whatever the target's spelling: IP literals in host, domain and
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

Execution runs up to :data:`EXECUTION_CONCURRENCY` actions at a time within
an execution budget of :data:`EXECUTION_BUDGET_FRACTION` of
``worker.node_timeout_s``, so the ``execute_actions`` node is never cancelled
half-way through a connector call. An action still running when the budget
ends is recorded ``failed`` (``error="deadline"``, outcome unknown: the
receiver deduplicates a later retry by action id); one the budget leaves no
time to start is recorded ``failed`` with ``error="execution_budget_exhausted"``
without being sent. :meth:`ResponseService.fail_orphaned_executing` settles
actions left ``executing`` by a run that will never finish them.

Approval rules: containment on LLM-only evidence is never automatic; an
analyst's pre-approval covers only low and medium risk; high and critical
need ``approver_role="admin"`` (:func:`approval_allowed`).
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Annotated,
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
from lg_sotf.db.errors import AlreadyInState, InvalidTransition
from lg_sotf.db.repos.actions import EXECUTED_STATUSES
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import record_action
from lg_sotf.services.connectors import (
    CONNECTOR_NAMES,
    Connector,
    ConnectorRegistry,
    ConnectorResult,
    DryRunConnector,
    tenant_response_settings,
)
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories, ResponseAction

__all__ = [
    "ACTION_CATALOG",
    "ACTION_TARGET_KINDS",
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
    "candidate_targets",
    "check_guardrails",
    "plan_entities",
    "preapproval_allowed",
    "resolve_autonomy",
    "validate_response_settings",
    "validate_target",
]

log = get_logger(__name__)

Autonomy = Literal["auto", "approval", "disabled"]
Evidence = Literal["rules", "llm_only", "analyst"]
TargetKind = Literal["ip", "domain", "url", "hash", "user", "host", "process", "alert"]
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
PROTECTED_INVALID_REASON = "protected_assets_invalid"
# Per list (hosts, users, domains, cidrs). Larger inventories belong in the SOAR, not in tenant settings.
MAX_PROTECTED_ENTRIES = 10_000
MAX_PROTECTED_ENTRY_CHARS = 256
MAX_BLAST_RADIUS = 10_000
MAX_TENANT_HOURLY_CAP = 100_000
MAX_POLICY_PROBLEMS = 5
# Execution: parallel connector calls per node run, and the share of the node timeout they may use.
EXECUTION_CONCURRENCY = 4
EXECUTION_BUDGET_FRACTION = 0.75
MIN_EXECUTION_S = 1.0
# Advisory lock class for the per-tenant hourly cap (next to lg_sotf.db.locks' namespaces).
ACTION_CAP_LOCK = 710_020
_CAP_LOCK_SQL = "SELECT pg_advisory_xact_lock($1, hashtext($2))"
_EXECUTED_COUNTS_SQL = """
    SELECT action_type, count(*)::int AS n FROM response_actions
    WHERE tenant_id = $1 AND executed_at >= $2 AND status = ANY($3::text[])
    GROUP BY action_type
"""
# Actions left 'executing' whose run will never come back to them.
_ORPHANED_EXECUTING_SQL = """
    SELECT a.tenant_id, a.id FROM response_actions a
    JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.alert_id
    WHERE a.status = 'executing' AND r.status IN ('dead_lettered', 'completed')
      AND ($1::text IS NULL OR a.tenant_id = $1)
    ORDER BY a.executed_at NULLS FIRST
    LIMIT $2
"""


@dataclass(frozen=True)
class ActionSpec:
    target_kind: TargetKind
    risk: str
    containment: bool
    description: str


ACTION_CATALOG: Dict[str, ActionSpec] = {
    "block_ip": ActionSpec("ip", "medium", True, "Block an IP address at the perimeter"),
    "block_domain": ActionSpec("domain", "medium", True, "Block a domain in DNS/proxy"),
    "block_url": ActionSpec("url", "medium", True, "Block a URL in the web proxy"),
    "isolate_host": ActionSpec("host", "high", True, "Network-isolate a host through EDR"),
    "terminate_process": ActionSpec("process", "medium", True, "Terminate a process through EDR"),
    "quarantine_file": ActionSpec("hash", "low", True, "Quarantine a file by hash through EDR"),
    "disable_user": ActionSpec("user", "critical", True, "Disable a user account"),
    "reset_password": ActionSpec("user", "critical", True, "Force a password reset"),
    "revoke_sessions": ActionSpec("user", "high", True, "Revoke a user's active sessions"),
    "collect_forensics": ActionSpec("host", "low", False, "Collect forensic evidence from a host"),
    "create_ticket": ActionSpec("alert", "low", False, "Open an incident ticket"),
    "send_alert": ActionSpec("alert", "low", False, "Notify the SOC channel"),
}

ACTION_TARGET_KINDS: Dict[str, FrozenSet[str]] = {name: frozenset({spec.target_kind}) for name, spec in ACTION_CATALOG.items()}

# Per action type, how many may start executing per tenant per hour (tenants may override).
DEFAULT_BLAST_RADIUS: Dict[str, int] = {
    "isolate_host": 5,
    "disable_user": 3,
    "reset_password": 5,
    "revoke_sessions": 10,
    "terminate_process": 20,
    "quarantine_file": 20,
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
}

PLAYBOOKS: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...] = (
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
    )
)

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


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
    return by_kind


def candidate_targets(action_type: str, entities: Mapping[str, Sequence[str]], alert_id: str) -> List[str]:
    """The targets the planner proposes ``action_type`` for (at most :data:`MAX_TARGETS_PER_TYPE`)."""
    spec = ACTION_CATALOG[action_type]
    targets = [f"alert:{alert_id}"] if spec.target_kind == "alert" else list(entities.get(spec.target_kind, ()))
    return list(dict.fromkeys(str(t) for t in targets))[:MAX_TARGETS_PER_TYPE]


def build_candidates(ctx: PlanContext, alert_id: str) -> Tuple[str, List[Candidate]]:
    threat_type, playbook = detect_threat_type(
        [ctx.title, ctx.category or "", *ctx.threat_texts, *ctx.recommended_actions]
    )
    wanted = list(playbook) + [a for a in actions_from_recommendations(ctx.recommended_actions) if a not in playbook]
    candidates: List[Candidate] = []
    for action_type in wanted:
        for target in candidate_targets(action_type, ctx.entities, alert_id):
            candidates.append(Candidate(action_type, target, {"playbook": threat_type}))
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
    if kind == "alert":
        return None if target.startswith("alert:") else "invalid_target"
    return "invalid_target"


_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
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
    _hosts: _Names = field(init=False, repr=False, compare=False)
    _users: _Names = field(init=False, repr=False, compare=False)
    _domains: FrozenSet[str] = field(init=False, repr=False, compare=False)

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
        problems: List[str] = []
        if isinstance(raw, Mapping):
            try:
                parsed = ProtectedAssetsSettings.model_validate(dict(raw))
            except ValidationError as exc:
                problems += _problem_list("protected_assets", exc)
            else:
                hosts, users, domains, cidrs = list(parsed.hosts), list(parsed.users), list(parsed.domains), list(parsed.cidrs)
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
        """Which protected category the target falls in (``host``/``user``/``domain``/``cidr``), else ``None``.

        IP and host targets are checked against CIDRs and host names; domain
        targets and URL hosts (percent-decoded) also against protected domains.
        """
        if kind == "user":
            return "user" if self._user_protected(target) else None
        if kind in ("ip", "host"):
            return self._address_match(target, as_domain=False)
        if kind == "domain":
            return self._address_match(target, as_domain=True)
        if kind == "url":
            try:
                host = urlsplit(target.strip()).hostname or ""
            except ValueError:
                return None
            return self._address_match(unquote(host), as_domain=True) if host else None
        return None


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
        )


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
) -> Optional[GuardrailBlock]:
    """The first guardrail the action fails (module docstring, rules 0-6), or ``None``."""
    spec = ACTION_CATALOG.get(action_type)
    if spec is None:
        return GuardrailBlock("unknown_action", action_type[:64])
    if policy.problems:
        return GuardrailBlock(POLICY_INVALID_REASON, "; ".join(policy.problems)[:300])
    if policy.allowed_actions is not None and action_type not in policy.allowed_actions:
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
        if cls == "internal" and not policy.allow_internal_ip_blocks:
            return GuardrailBlock("non_public_ip", "tenant setting response.allow_internal_ip_blocks is off")
    category = policy.protected.match(kind, target)
    if category is not None:
        return GuardrailBlock("protected_asset", f"matches a protected {category} entry")
    if policy.autonomy.get(spec.risk) == "disabled":
        return GuardrailBlock("autonomy_disabled", f"{spec.risk} risk")
    return None


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


class ResponseService:
    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        events: Optional[EventPublisher] = None,
        *,
        connectors: Optional[Mapping[str, Connector]] = None,
        registry: Optional[ConnectorRegistry] = None,
    ) -> None:
        """``connectors`` override built-in connectors by name (see :class:`ConnectorRegistry`)."""
        self._repos = repos
        self._settings = settings
        self._events = events
        self._audit = AuditLogger(repos)
        self._registry = registry or ConnectorRegistry(
            settings,
            overrides=connectors,
            target_kinds={name: spec.target_kind for name, spec in ACTION_CATALOG.items()},
        )
        self._execution_budget_s = float(settings.worker.node_timeout_s) * EXECUTION_BUDGET_FRACTION

    @property
    def registry(self) -> ConnectorRegistry:
        return self._registry

    @property
    def execution_budget_s(self) -> float:
        """Wall time one :meth:`execute` call may spend in connectors (a share of the node timeout)."""
        return self._execution_budget_s

    def policy(self, tenant_settings: Mapping[str, Any]) -> ResponsePolicy:
        return ResponsePolicy.resolve(tenant_settings, self._settings)

    def connector_for(self, tenant_id: str, tenant_settings: Mapping[str, Any]) -> Connector:
        return self._registry.for_tenant(tenant_id, tenant_settings)

    async def executed_counts(
        self, tenant_id: str, since: datetime, *, conn: Any = None
    ) -> Tuple[int, Dict[str, int]]:
        """(total, per action type) of actions that started real execution since ``since``."""

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
        now = now or datetime.now(UTC)
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        threat_type, candidates = build_candidates(ctx, alert_id)
        result = PlanResult(threat_type=threat_type)
        used_total, used_by_type = await self.executed_counts(tenant_id, now - timedelta(hours=1))
        auto_budget = max(0, policy.max_actions_per_hour - used_total)
        type_budget = {t: max(0, limit - used_by_type.get(t, 0)) for t, limit in policy.blast_radius.items()}

        for cand in candidates:
            spec = ACTION_CATALOG[cand.action_type]
            params: Dict[str, Any] = {
                **cand.params,
                "alert": {"severity": ctx.severity, "title": ctx.title[:200]},
                "evidence": ctx.evidence,
            }
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
            )
            if created:
                await self._record_transition(
                    tenant_id, action, "response_action.proposed", {"approved_by": approved_by, "autonomy": autonomy}
                )
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
            settled = await self._repos.actions.transition(
                tenant_id, action.id, status, expected_from="proposed", blocked_reason=reason
            )
        except (AlreadyInState, InvalidTransition):
            return await self._repos.actions.get(tenant_id, action.id)
        await self._record_transition(tenant_id, settled, f"response_action.{status}", {"replanned": True})
        return settled

    async def _approve_proposed(self, tenant_id: str, action: ResponseAction, approved_by: str) -> ResponseAction:
        try:
            approved = await self._repos.actions.transition(
                tenant_id, action.id, "approved", expected_from="proposed", approved_by=approved_by[:128]
            )
        except (AlreadyInState, InvalidTransition):
            return await self._repos.actions.get(tenant_id, action.id)
        policy = approved_by == POLICY_APPROVER
        await self._record_transition(
            tenant_id,
            approved,
            "response_action.approved",
            {"approved_by": approved_by[:128], "preapproved": not policy},
            actor_type="agent" if policy else "user",
            actor_id=approved_by,
        )
        return approved

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
        other alerts and actions no longer pending are ignored. Actions the
        API already approved or rejected through
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
            if action.alert_id != alert_id:
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
                updated = await self._repos.actions.transition(
                    tenant_id, action.id, target, expected_from="awaiting_approval", **extra  # type: ignore[arg-type]
                )
            except (AlreadyInState, InvalidTransition):
                current = await self._repos.actions.get(tenant_id, action.id)
                outcome[action_id] = current.status
                continue
            await self._record_transition(
                tenant_id,
                updated,
                f"response_action.{target}",
                {"decided_by": decided_by[:128], "reject_remaining": reject_remaining and action_id not in rejected},
                actor_type="user",
                actor_id=decided_by,
            )
            outcome[action_id] = updated.status
        return outcome

    async def awaiting(self, tenant_id: str, alert_id: str, action_ids: Sequence[str]) -> List[str]:
        """Which of ``action_ids`` (this alert's) are still pending work, in ledger order.

        Pending work is an action awaiting approval or one approved but not
        yet executed: an approval can commit at any moment (the API does not
        wait for the run), so an ``approved`` row is work the run still owes.
        """
        if not action_ids:
            return []
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        return [str(a.id) for a in actions if a.alert_id == alert_id and a.status in PENDING_WORK_STATUSES]

    # ------------------------------------------------------------- execution

    async def execute(
        self,
        tenant_id: str,
        alert_id: str,
        action_ids: Sequence[str],
        *,
        now: Optional[datetime] = None,
        budget_s: Optional[float] = None,
    ) -> Dict[str, str]:
        """Run this alert's approved actions. Returns ``{action_id: status}`` for the actions considered.

        Guardrails are evaluated again before each claim. Actions left
        ``executing`` by an interrupted earlier attempt are run again with the
        connector recorded on the row: connectors are idempotent per action
        id, and the alert's run lease guarantees no other worker is executing
        them. Terminal actions are never executed twice.

        Up to :data:`EXECUTION_CONCURRENCY` actions run at once, and all of
        them within ``budget_s`` (default :attr:`execution_budget_s`): a
        connector call still running when the budget ends is abandoned and
        recorded ``failed`` (``error="deadline"``), and an action there is no
        time left to start is recorded ``failed`` without being sent
        (``error="execution_budget_exhausted"``).
        """
        now = now or datetime.now(UTC)
        if not action_ids:
            return {}
        tenant = await self._repos.tenants.get(tenant_id)
        policy = self.policy(tenant.settings)
        connector = self.connector_for(tenant_id, tenant.settings)
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        loop = asyncio.get_running_loop()
        ends_at = loop.time() + (self._execution_budget_s if budget_s is None else budget_s)
        slots = asyncio.Semaphore(EXECUTION_CONCURRENCY)

        async def run(action: ResponseAction) -> str:
            async with slots:
                return await self._execute_one(tenant_id, tenant.settings, action, connector, policy, now, ends_at)

        mine = [a for a in actions if a.alert_id == alert_id]
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
        tenant_settings: Mapping[str, Any],
        action: ResponseAction,
        connector: Connector,
        policy: ResponsePolicy,
        now: datetime,
        ends_at: float,
    ) -> str:
        if action.status == "executing":
            log.warning("response.resuming_interrupted_action", action_type=action.action_type)
            executing: Optional[ResponseAction] = action
            runner = self._registry.named(tenant_id, tenant_settings, action.connector) if action.connector else connector
        elif action.status == "approved":
            executing = await self._claim(tenant_id, action, connector, policy, now)
            runner = connector
        else:
            return action.status
        if executing is None:
            return (await self._repos.actions.get(tenant_id, action.id)).status
        remaining = ends_at - asyncio.get_running_loop().time()
        if remaining < MIN_EXECUTION_S and not isinstance(runner, DryRunConnector):
            log.warning("response.execution_budget_exhausted", action_type=action.action_type)
            result = ConnectorResult(
                "failed",
                {
                    "error": "execution_budget_exhausted",
                    "note": "not sent: the execution budget of this workflow step ran out before it could start",
                },
            )
            return await self._finish(tenant_id, executing, runner, result)
        return await self._run_connector(tenant_id, executing, runner, timeout_s=max(remaining, MIN_EXECUTION_S))

    async def fail_orphaned_executing(self, tenant_id: Optional[str] = None, *, limit: int = 100) -> int:
        """Record ``failed`` for actions left ``executing`` whose run will never finish them.

        An action stays ``executing`` when its worker died mid-call; the run
        normally resumes and re-runs it, but a run that was dead-lettered (or
        completed on another path) never will. Such actions are failed with
        ``error="orphaned_execution"``: the external outcome is unknown, and
        the receiver can be asked by the action id (its idempotency key).
        ``tenant_id=None`` sweeps every tenant (scheduler; system transaction).
        Returns how many actions were settled.
        """
        if tenant_id is None:
            async with self._repos.db.system_tx() as conn:
                rows = list(await conn.fetch(_ORPHANED_EXECUTING_SQL, None, limit))
        else:
            async with self._repos.db.tenant_tx(tenant_id) as conn:
                rows = list(await conn.fetch(_ORPHANED_EXECUTING_SQL, tenant_id, limit))
        settled = 0
        for row in rows:
            owner, action_id = str(row["tenant_id"]), row["id"]
            try:
                failed = await self._repos.actions.transition(
                    owner,
                    action_id,
                    "failed",
                    expected_from="executing",
                    result={
                        "error": "orphaned_execution",
                        "note": "the workflow run ended while this action was executing; its outcome is unknown",
                    },
                )
            except (AlreadyInState, InvalidTransition):
                continue
            await self._record_transition(owner, failed, "response_action.failed", {"reason": "orphaned_execution"})
            settled += 1
        if settled:
            log.warning("response.orphaned_actions_failed", count=settled)
        return settled

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
        now: datetime,
    ) -> Optional[ResponseAction]:
        """Move an approved action to ``executing``; ``None`` when it was blocked or taken by someone else.

        For real connectors the hourly cap, the blast-radius check and the
        claim run in one transaction under a per-tenant advisory lock, so
        concurrent workers cannot overshoot either limit.
        """
        blocked: Optional[ResponseAction] = None
        executing: Optional[ResponseAction] = None
        try:
            guard = check_guardrails(action.action_type, action.target, policy)
            if guard is not None:
                blocked = await self._block_approved(tenant_id, action, guard.code, {"detail": guard.detail, "stage": "execution"})
            elif isinstance(connector, DryRunConnector):
                executing = await self._repos.actions.transition(
                    tenant_id, action.id, "executing", expected_from="approved", connector=connector.name
                )
            else:
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    await conn.execute(_CAP_LOCK_SQL, ACTION_CAP_LOCK, tenant_id)
                    used, by_type = await self.executed_counts(tenant_id, now - timedelta(hours=1), conn=conn)
                    type_limit = policy.blast_radius.get(action.action_type)
                    if used >= policy.max_actions_per_hour:
                        blocked = await self._block_approved(
                            tenant_id, action, HOURLY_CAP_REASON, {"cap": policy.max_actions_per_hour, "used": used}, conn
                        )
                    elif type_limit is not None and by_type.get(action.action_type, 0) >= type_limit:
                        blocked = await self._block_approved(
                            tenant_id,
                            action,
                            BLAST_RADIUS_REASON,
                            {"limit": type_limit, "used": by_type.get(action.action_type, 0)},
                            conn,
                        )
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            conn=conn,
                        )
        except (AlreadyInState, InvalidTransition):
            return None
        if blocked is not None:
            log.warning("response.execution_blocked", action_type=action.action_type, reason=blocked.blocked_reason)
            await self._record_transition(tenant_id, blocked, "response_action.blocked", {"stage": "execution"})
            return None
        assert executing is not None
        await self._record_transition(tenant_id, executing, "response_action.executing", {"connector": connector.name})
        return executing

    async def _run_connector(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, *, timeout_s: Optional[float] = None
    ) -> str:
        scope = asyncio.timeout(timeout_s)
        try:
            async with scope:
                result = await connector.execute(executing)
        except TimeoutError as exc:
            if not scope.expired():
                log.warning("response.connector_failed", connector=connector.name, error_type=type(exc).__name__)
                result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
            else:
                log.warning("response.connector_deadline", connector=connector.name, action_type=executing.action_type)
                result = ConnectorResult(
                    "failed",
                    {
                        "error": "deadline",
                        "note": "abandoned when the execution budget ran out; the receiver may have acted (same action id)",
                    },
                )
        except Exception as exc:  # noqa: BLE001 - any connector failure is recorded on the ledger as 'failed'
            log.warning("response.connector_failed", connector=connector.name, error_type=type(exc).__name__)
            result = ConnectorResult("failed", {"error": "connector_exception", "error_type": type(exc).__name__})
        return await self._finish(tenant_id, executing, connector, result)

    async def _finish(
        self, tenant_id: str, executing: ResponseAction, connector: Connector, result: ConnectorResult
    ) -> str:
        final = await self._repos.actions.transition(
            tenant_id, executing.id, result.status, expected_from="executing", result=result.detail
        )
        await self._record_transition(tenant_id, final, f"response_action.{result.status}", {"connector": connector.name})
        return final.status

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
