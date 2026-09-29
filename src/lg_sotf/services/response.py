"""Response planning, guardrails, approval and execution over the action ledger (contract section 11).

``plan`` turns the investigation outcome into typed actions, resolves each
action's risk level against the tenant's autonomy policy, applies the
guardrails and writes every action to the ledger (idempotent per tenant,
alert, action type and target). ``execute`` runs approved actions through a
:class:`Connector`; this wave ships only :class:`DryRunConnector`, which
records what would have been done. Every ledger transition is audited.

Safety rules:

* guardrail failures (bad target syntax, non-public IPs, protected assets)
  block the action; blocked actions can never be approved later;
* containment on LLM-only evidence is never automatic: it needs approval;
* an analyst's pre-approval in the escalation decision covers only low and
  medium risk actions; high and critical ones need ``approver_role="admin"``
  (set by the API from the authenticated principal) or a separate approval;
* the per-tenant hourly cap turns would-be automatic actions into approvals
  at planning time and, for real connectors, is enforced atomically at
  execution time: an approved action over the cap is blocked
  (``hourly_cap_reached``), never left silently pending.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Literal, Mapping, Optional, Protocol, Sequence, Tuple
from urllib.parse import urlsplit
from uuid import UUID

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.db.errors import AlreadyInState, InvalidTransition
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import record_action
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories, ResponseAction

log = get_logger(__name__)

Autonomy = Literal["auto", "approval", "disabled"]
Evidence = Literal["rules", "llm_only", "analyst"]
TargetKind = Literal["ip", "domain", "url", "hash", "user", "host", "process", "alert"]
RISK_LEVELS = ("low", "medium", "high", "critical")
MAX_TARGETS_PER_TYPE = 3
MAX_ACTIONS = 15
REQUESTED_BY = "agent:workflow"
POLICY_APPROVER = "policy:auto"
ANALYST_PREAPPROVAL_RISKS = frozenset({"low", "medium"})
HOURLY_CAP_REASON = "hourly_cap_reached"
# Advisory lock class for the per-tenant hourly cap (next to lg_sotf.db.locks' namespaces).
ACTION_CAP_LOCK = 710_020
_CAP_LOCK_SQL = "SELECT pg_advisory_xact_lock($1, hashtext($2))"


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


@dataclass(frozen=True)
class ConnectorResult:
    status: Literal["succeeded", "failed", "dry_run"]
    detail: Dict[str, Any] = field(default_factory=dict)


class Connector(Protocol):
    """Executes one approved ledger action. Implementations must be idempotent per action id."""

    name: str

    async def execute(self, action: ResponseAction) -> ConnectorResult: ...


class DryRunConnector:
    """Records what would have been executed; changes nothing outside the ledger."""

    name = "dry_run"

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        return ConnectorResult(
            "dry_run",
            {
                "would_execute": action.action_type,
                "target": action.target,
                "params": dict(action.params),
                "note": "dry-run connector: no external system was called",
            },
        )


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


def build_candidates(ctx: PlanContext, alert_id: str) -> Tuple[str, List[Candidate]]:
    threat_type, playbook = detect_threat_type(
        [ctx.title, ctx.category or "", *ctx.threat_texts, *ctx.recommended_actions]
    )
    wanted = list(playbook) + [a for a in actions_from_recommendations(ctx.recommended_actions) if a not in playbook]
    candidates: List[Candidate] = []
    for action_type in wanted:
        spec = ACTION_CATALOG[action_type]
        targets = [f"alert:{alert_id}"] if spec.target_kind == "alert" else list(ctx.entities.get(spec.target_kind, ()))
        for target in list(dict.fromkeys(str(t) for t in targets))[:MAX_TARGETS_PER_TYPE]:
            candidates.append(Candidate(action_type, target, {"playbook": threat_type}))
    return threat_type, candidates[:MAX_ACTIONS]


def validate_target(kind: str, target: str) -> Optional[str]:
    """``None`` when the target is acceptable, otherwise the reason it is blocked."""
    if not target or len(target) > 2_048:
        return "invalid_target"
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            return "invalid_ip"
        if not ip.is_global:
            return "non_public_ip"
        return None
    if kind == "domain":
        return None if _DOMAIN_RE.match(target.lower().rstrip(".")) else "invalid_domain"
    if kind == "url":
        try:
            parts = urlsplit(target)
        except ValueError:
            return "invalid_url"
        return None if parts.scheme in ("http", "https") and parts.hostname else "invalid_url"
    if kind == "hash":
        return None if _HASH_RE.match(target.lower()) else "invalid_hash"
    if kind == "host":
        return None if _HOST_RE.match(target) else "invalid_host"
    if kind in ("user", "process"):
        return None if _NAME_RE.match(target) else f"invalid_{kind}"
    if kind == "alert":
        return None if target.startswith("alert:") else "invalid_target"
    return "unknown_target_kind"


def _protected(kind: str, target: str, tenant_settings: Mapping[str, Any]) -> bool:
    assets = {str(a).lower() for a in tenant_settings.get("protected_assets") or [] if isinstance(a, str)}
    if target.lower() in assets:
        return True
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            return False
        for cidr in tenant_settings.get("protected_cidrs") or []:
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                log.warning("response.protected_cidr_invalid")
                continue
            if ip.version == net.version and ip in net:
                return True
    return False


def resolve_autonomy(risk: str, tenant_settings: Mapping[str, Any], settings: Settings) -> Autonomy:
    policy: Dict[str, Any] = dict(settings.response.default_autonomy)
    override = tenant_settings.get("autonomy")
    if isinstance(override, Mapping):
        policy.update({k: v for k, v in override.items() if k in RISK_LEVELS})
    mode = policy.get(risk, "approval")
    return mode if mode in ("auto", "approval", "disabled") else "approval"


def _is_preapproved(candidate: Candidate, approved: Sequence[str]) -> bool:
    return candidate.action_type in approved or f"{candidate.action_type}:{candidate.target}" in approved


def preapproval_allowed(risk: str, approver_role: Optional[str]) -> bool:
    """Analysts may pre-approve low/medium actions; high and critical need an admin."""
    return risk in ANALYST_PREAPPROVAL_RISKS or approver_role == "admin"


class ResponseService:
    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        events: Optional[EventPublisher] = None,
        *,
        connectors: Optional[Mapping[str, Connector]] = None,
    ) -> None:
        self._repos = repos
        self._settings = settings
        self._events = events
        self._audit = AuditLogger(repos)
        self._dry_run = DryRunConnector()
        self._connectors: Dict[str, Connector] = dict(connectors or {})

    def connector_for(self, tenant_settings: Mapping[str, Any]) -> Connector:
        if self._settings.response.dry_run or tenant_settings.get("dry_run") is True:
            return self._dry_run
        name = tenant_settings.get("connector")
        if isinstance(name, str) and name in self._connectors:
            return self._connectors[name]
        return self._dry_run

    async def plan(
        self, tenant_id: str, alert_id: str, ctx: PlanContext, *, now: Optional[datetime] = None
    ) -> PlanResult:
        now = now or datetime.now(UTC)
        tenant = await self._repos.tenants.get(tenant_id)
        tenant_settings = tenant.settings
        threat_type, candidates = build_candidates(ctx, alert_id)
        result = PlanResult(threat_type=threat_type)
        cap = self._settings.response.max_actions_per_hour_per_tenant
        executed_last_hour = await self._repos.actions.count_executed_since(tenant_id, now - timedelta(hours=1))
        auto_budget = max(0, cap - executed_last_hour)

        for cand in candidates:
            spec = ACTION_CATALOG[cand.action_type]
            params = dict(cand.params)
            autonomy = resolve_autonomy(spec.risk, tenant_settings, self._settings)
            reason = validate_target(spec.target_kind, cand.target)
            if reason is None and _protected(spec.target_kind, cand.target, tenant_settings):
                reason = "protected_asset"
            if reason is None and autonomy == "disabled":
                reason = "autonomy_disabled"

            approved_by: Optional[str] = None
            preapproved = _is_preapproved(cand, ctx.approved_actions) and bool(ctx.approved_by)
            if reason is not None:
                status = "blocked"
            elif preapproved and preapproval_allowed(spec.risk, ctx.approver_role):
                status, approved_by = "approved", ctx.approved_by
            elif preapproved:
                status, params["approval_reason"] = "awaiting_approval", "admin_approval_required"
            elif autonomy == "auto":
                if spec.containment and ctx.evidence == "llm_only":
                    status, params["approval_reason"] = "awaiting_approval", "llm_only_evidence"
                elif auto_budget <= 0:
                    status, params["approval_reason"] = "awaiting_approval", "hourly_cap_reached"
                else:
                    status, approved_by = "approved", POLICY_APPROVER
                    auto_budget -= 1
            else:
                status = "awaiting_approval"

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
        """Apply an approval decision to this alert's pending actions.

        Only actions of this alert that are awaiting approval change; ids of
        other alerts are ignored. Pending actions the decision does not
        mention stay awaiting approval (per-action approve/reject), unless
        ``reject_remaining`` is set, which rejects them.
        Returns ``{action_id: status}`` for the actions this call looked at.
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
                target, extra = "rejected", {}
            elif reject_remaining:
                target, extra = "rejected", {"blocked_reason": "rejected with the remaining pending actions"}
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
                {"decided_by": decided_by[:128]},
                actor_type="user",
                actor_id=decided_by,
            )
            outcome[action_id] = updated.status
        return outcome

    async def awaiting(self, tenant_id: str, alert_id: str, action_ids: Sequence[str]) -> List[str]:
        """Which of ``action_ids`` (this alert's) are still awaiting approval, in ledger order."""
        if not action_ids:
            return []
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        return [str(a.id) for a in actions if a.alert_id == alert_id and a.status == "awaiting_approval"]

    async def execute(
        self, tenant_id: str, alert_id: str, action_ids: Sequence[str], *, now: Optional[datetime] = None
    ) -> Dict[str, str]:
        """Run this alert's approved actions. Returns ``{action_id: status}`` for the actions considered.

        Actions left ``executing`` by an interrupted earlier attempt are run
        again: connectors are idempotent per action id, and the alert's run
        lease guarantees no other worker is executing them.
        """
        now = now or datetime.now(UTC)
        if not action_ids:
            return {}
        tenant = await self._repos.tenants.get(tenant_id)
        connector = self.connector_for(tenant.settings)
        actions = await self._repos.actions.get_many(tenant_id, [UUID(str(i)) for i in action_ids])
        outcome: Dict[str, str] = {}
        for action in actions:
            action_id = str(action.id)
            if action.alert_id != alert_id:
                continue
            if action.status == "executing":
                log.warning("response.resuming_interrupted_action", action_type=action.action_type)
                executing: Optional[ResponseAction] = action
                runner = self._connector_named(action.connector) or connector
            elif action.status == "approved":
                executing = await self._claim(tenant_id, action, connector, now)
                runner = connector
            else:
                outcome[action_id] = action.status
                continue
            if executing is None:
                outcome[action_id] = (await self._repos.actions.get(tenant_id, action.id)).status
                continue
            outcome[action_id] = await self._run_connector(tenant_id, executing, runner)
        return outcome

    def _connector_named(self, name: Optional[str]) -> Optional[Connector]:
        if name == self._dry_run.name:
            return self._dry_run
        return self._connectors.get(name) if name else None

    async def _claim(
        self, tenant_id: str, action: ResponseAction, connector: Connector, now: datetime
    ) -> Optional[ResponseAction]:
        """Move an approved action to ``executing``; ``None`` when it was blocked or taken by someone else.

        For real connectors the hourly cap check and the claim run in one
        transaction under a per-tenant advisory lock, so concurrent workers
        cannot overshoot the cap.
        """
        blocked: Optional[ResponseAction] = None
        try:
            if isinstance(connector, DryRunConnector):
                executing = await self._repos.actions.transition(
                    tenant_id, action.id, "executing", expected_from="approved", connector=connector.name
                )
            else:
                cap = self._settings.response.max_actions_per_hour_per_tenant
                async with self._repos.db.tenant_tx(tenant_id) as conn:
                    await conn.execute(_CAP_LOCK_SQL, ACTION_CAP_LOCK, tenant_id)
                    used = await self._repos.actions.count_executed_since(
                        tenant_id, now - timedelta(hours=1), conn=conn
                    )
                    if used >= cap:
                        blocked = await self._repos.actions.transition(
                            tenant_id,
                            action.id,
                            "blocked",
                            expected_from="approved",
                            blocked_reason=HOURLY_CAP_REASON,
                            conn=conn,
                        )
                    else:
                        executing = await self._repos.actions.transition(
                            tenant_id, action.id, "executing", expected_from="approved", connector=connector.name,
                            conn=conn,
                        )
        except (AlreadyInState, InvalidTransition):
            return None
        if blocked is not None:
            log.warning("response.hourly_cap_blocked", action_type=action.action_type)
            await self._record_transition(
                tenant_id, blocked, "response_action.blocked", {"cap": self._settings.response.max_actions_per_hour_per_tenant}
            )
            return None
        await self._record_transition(tenant_id, executing, "response_action.executing", {"connector": connector.name})
        return executing

    async def _run_connector(self, tenant_id: str, executing: ResponseAction, connector: Connector) -> str:
        try:
            result = await connector.execute(executing)
        except Exception as exc:  # noqa: BLE001 - any connector failure is recorded on the ledger as 'failed'
            log.warning("response.connector_failed", connector=connector.name, error_type=type(exc).__name__)
            result = ConnectorResult("failed", {"error_type": type(exc).__name__})
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
        )
        record_action(action.action_type, action.status)
        await publish_event(
            self._events,
            "action.updated",
            tenant_id,
            action.alert_id,
            {"action_id": str(action.id), "action_type": action.action_type, "status": action.status},
        )
