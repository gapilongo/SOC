"""Response planning: playbooks, candidate actions and the approval disposition (no I/O).

:func:`build_candidates` turns what the investigation found
(:class:`PlanContext`) into typed candidate actions: the playbook of the
detected threat type plus the actions the analysis recommends, at most
:data:`MAX_TARGETS_PER_TYPE` targets each. :func:`dispose` decides each
candidate's ledger status: blocked by a guardrail, approved (by the analyst's
pre-approval or by the tenant's ``auto`` autonomy, within the hourly
:class:`AutoBudget`) or awaiting an approval.

Approval rules: containment on LLM-only evidence is never automatic; an
analyst's pre-approval covers only low and medium risk; high and critical
need ``approver_role="admin"`` (:func:`approval_allowed`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.actions import ACTION_CATALOG, BLAST_RADIUS_REASON, HOURLY_CAP_REASON, ActionSpec
from lg_sotf.domain.indicators import extract_indicators
from lg_sotf.domain.phishing import email_block_targets, plan_email_entities
from lg_sotf.models.vocabulary import POLICY_APPROVER
from lg_sotf.services.response.guardrails import GuardrailBlock
from lg_sotf.services.response.policy import ResponsePolicy, preapproval_allowed
from lg_sotf.services.response.targets import clean, process_base, target_corroborated, target_key

Evidence = Literal["rules", "llm_only", "analyst"]
MAX_TARGETS_PER_TYPE = 3
MAX_ACTIONS = 15

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


def _is_preapproved(candidate: Candidate, approved: Sequence[str]) -> bool:
    """``action_type:target`` names exactly this action; a bare ``action_type`` covers every target of this alert."""
    return candidate.action_type in approved or f"{candidate.action_type}:{candidate.target}" in approved


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
