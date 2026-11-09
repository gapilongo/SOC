"""Model-led closure (decision policy v2, FIX-1): the tenant's autonomy tier and when a model may close.

Without approved benign evidence (:func:`lg_sotf.domain.routing.decide`), a
low or medium alert is closed on the models' word only when the tenant chose
the autonomy tier ``auto_full_audit`` (tenant setting ``ai_closure.tier``,
default ``off``) and every condition below holds. Each one fails closed: a
missing or unreadable value blocks the close.

* severity ``info``, ``low`` or ``medium`` (high and critical never close on a
  model's word, at any tier);
* not a never-close class (:func:`never_close_class`), by the ATT&CK tactic
  or technique the detection rule declares: credential access, log clearing
  and other indicator removal, security-tool tampering, ransomware
  behaviour, and persistence through an object the attacker creates and
  names (scheduled tasks, services, autostart entries, WMI subscriptions,
  accounts), whose alert text is the attacker's. An alert the rule maps to
  no tactic or technique is ``unmapped`` and counts as a never-close class:
  nothing shows it is outside them;
* no steering text: triage did not flag ``prompt_injection_suspected``;
* no recent true positive on the alert's entities: no analyst-confirmed
  malicious history (``prior_malicious_history``), no related alert of the
  correlation window closed as malicious, and no rule evidence that
  corroborates a threat (``rule_corroborated``);
* no campaign in progress: no burst of related alerts, no related alert a
  model judged malicious or suspicious, none still open for an analyst or an
  approval (counted over every related alert, not only those shown to the
  correlation model), so an attack is never closed alert by alert;
* both model tiers say benign: the fast tier's assessment is ``benign`` with
  a threat likelihood at most ``routing.model_close_max_likelihood``
  (default 8), and the deep tier's verdict is ``benign`` with a certainty of
  at least ``routing.model_close_min_certainty`` (default 85). A verdict the
  rules produced because a model was not consulted never counts.

A model-led close carries the decision code ``model_closed`` and the close
reason ``ai_closed:audit_required``: an analyst is expected to audit it.
Correlation shows such an alert to later models as ``ai_closed_unaudited``,
never as ``benign``, so one persuaded close cannot vouch for the next.

Approved benign evidence closes without the tier, but never past steering
text or a recent true positive, and context evidence (a declared scanner, a
test source) never past a mapped never-close class
(:func:`evidence_close_blockers`).
The thresholds are install settings (``routing``), so a tenant can turn
model-led closure on or off but never loosen what it needs.
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, Optional, Tuple, get_args

from pydantic import BaseModel, ConfigDict, ValidationError

from lg_sotf.domain.benign_evidence import INJECTION_SIGNAL

__all__ = [
    "AUTONOMY_TIERS",
    "AiClosureSettings",
    "AutonomyTier",
    "CLOSABLE_SEVERITIES",
    "CONTEXT_EVIDENCE",
    "MODEL_CLOSED",
    "MODEL_CLOSE_REASON",
    "MODEL_CLOSE_TIER",
    "NEVER_CLOSE_TACTICS",
    "NEVER_CLOSE_TECHNIQUES",
    "SETTING",
    "UNMAPPED",
    "autonomy_tier",
    "evidence_close_blockers",
    "model_close_blockers",
    "never_close_class",
    "validate_ai_closure_settings",
]

#: ``off``: a model never closes an alert alone. ``auto_full_audit``: it may, under the conditions above.
AutonomyTier = Literal["off", "auto_full_audit"]
AUTONOMY_TIERS: Tuple[AutonomyTier, ...] = get_args(AutonomyTier)
MODEL_CLOSE_TIER: AutonomyTier = "auto_full_audit"
#: The tenant settings section (``{"tier": "off" | "auto_full_audit"}``).
SETTING = "ai_closure"
#: The decision code and the close reason of a model-led close.
MODEL_CLOSED = "model_closed"
MODEL_CLOSE_REASON = "ai_closed:audit_required"
CLOSABLE_SEVERITIES: FrozenSet[str] = frozenset({"info", "low", "medium"})
#: Triage's rule false-positive signals that say where the activity came from (a scanner the tenant declared, a
#: test-environment source), as opposed to what was detected (the rule's own test intent, the EICAR file).
CONTEXT_EVIDENCE: FrozenSet[str] = frozenset({"known_scanner", "test_environment"})

#: ATT&CK tactics whose alerts a model never closes, keyed by name or id in lower case without separators, so
#: Wazuh's "Credential Access", Sentinel's "CredentialAccess", "credential_access" and "TA0006" all match.
NEVER_CLOSE_TACTICS: Mapping[str, str] = {"credentialaccess": "credential_access", "ta0006": "credential_access"}
#: ATT&CK techniques (sub-techniques included) whose alerts a model never closes.
NEVER_CLOSE_TECHNIQUES: Mapping[str, str] = {
    "T1003": "credential_access",  # OS credential dumping
    "T1110": "credential_access",  # brute force, password spraying
    "T1552": "credential_access",  # unsecured credentials
    "T1555": "credential_access",  # credentials from password stores
    "T1556": "credential_access",  # modify authentication process
    "T1558": "credential_access",  # Kerberos tickets (Kerberoasting)
    "T1070": "log_clearing",  # indicator removal: clearing event logs and shell history
    "T1562": "tampering",  # impair defenses: disabling security tools and logging
    "T1485": "ransomware",  # data destruction
    "T1486": "ransomware",  # data encrypted for impact
    "T1489": "ransomware",  # service stop
    "T1490": "ransomware",  # inhibit system recovery
    # Persistence through an object the attacker creates and names: its alert text (task, service, run-key,
    # subscription or account name and description) is the attacker's, the title camouflage of AI-E6.3.
    "T1053": "named_persistence",  # scheduled task or job
    "T1136": "named_persistence",  # create account
    "T1543": "named_persistence",  # create or modify system process (services)
    "T1546": "named_persistence",  # event triggered execution (WMI subscriptions)
    "T1547": "named_persistence",  # boot or logon autostart execution (run keys)
}
#: The class of an alert without any ATT&CK mapping: whether it is a never-close class is unknown, so it is one.
UNMAPPED = "unmapped"
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
MAX_MITRE_VALUES = 50


class AiClosureSettings(BaseModel):
    """Schema of ``tenants.settings["ai_closure"]``: the tenant's autonomy tier for model-led closure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: AutonomyTier = "off"


def validate_ai_closure_settings(value: Any) -> Dict[str, Any]:
    """Normalised settings for the tenant settings API; raises ``ValueError`` listing the problems."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{SETTING}: must be an object")
    try:
        return AiClosureSettings.model_validate(dict(value)).model_dump()
    except ValidationError as exc:
        problems = [f"{SETTING}.{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"[:200] for e in exc.errors()[:5]]
        raise ValueError("; ".join(problems)) from exc


def autonomy_tier(tenant_settings: Optional[Mapping[str, Any]]) -> AutonomyTier:
    """The tenant's tier; ``off`` for anything missing or unreadable (fail closed)."""
    section = tenant_settings.get(SETTING) if isinstance(tenant_settings, Mapping) else None
    tier = section.get("tier") if isinstance(section, Mapping) else None
    return MODEL_CLOSE_TIER if tier == MODEL_CLOSE_TIER else "off"


def _mitre(alert: Mapping[str, Any], key: str) -> List[str]:
    mitre = alert.get("mitre")
    values = mitre.get(key) if isinstance(mitre, Mapping) else None
    items = values if isinstance(values, list) else [values]
    return [v.strip() for v in items[:MAX_MITRE_VALUES] if isinstance(v, str) and v.strip()]


def never_close_class(alert: Any) -> Optional[str]:
    """The never-close class the detection rule's ATT&CK mapping puts the alert in, or ``None``.

    An alert the rule maps to no tactic and no technique is :data:`UNMAPPED`:
    nothing shows it is outside the never-close classes, so it is treated as
    inside one (fail closed).
    """
    if not isinstance(alert, Mapping):
        return UNMAPPED
    tactics, techniques = _mitre(alert, "tactics"), _mitre(alert, "techniques")
    for tactic in tactics:
        found = NEVER_CLOSE_TACTICS.get(_NOT_ALNUM.sub("", tactic.lower()))
        if found is not None:
            return found
    for technique in techniques:
        found = NEVER_CLOSE_TECHNIQUES.get(technique.upper().split(".", 1)[0])
        if found is not None:
            return found
    return None if tactics or techniques else UNMAPPED


def _number(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _fast_tier_benign(triage: Mapping[str, Any], max_likelihood: int) -> bool:
    likelihood = _number(triage.get("threat_likelihood"))
    return (
        triage.get("llm_used") is True
        and triage.get("threat_assessment") == "benign"
        and likelihood is not None
        and likelihood <= max_likelihood
    )


def _deep_tier_benign(analysis: Mapping[str, Any], min_certainty: int) -> bool:
    certainty = _number(analysis.get("certainty"))
    return (
        analysis.get("llm_used") is True
        and analysis.get("verdict") == "benign"
        and certainty is not None
        and certainty >= min_certainty
    )


def _recent_true_positive(analysis: Mapping[str, Any], correlation: Mapping[str, Any]) -> bool:
    evidence = analysis.get("rule_evidence")
    dispositions = correlation.get("related_dispositions")
    related_malicious = dispositions.get("malicious") if isinstance(dispositions, Mapping) else None
    return (
        (isinstance(evidence, list) and "prior_malicious_history" in evidence)
        or analysis.get("rule_corroborated") is True
        or (_number(related_malicious) or 0) > 0
    )


def _campaign_in_progress(correlation: Mapping[str, Any]) -> bool:
    """Related alerts that may be one attack: a burst, one a model judged malicious or suspicious, or one still
    open for review. Unknown counts (a digest without them) fail closed."""
    related = _number(correlation.get("related_count"))
    if related is None:
        return True
    if related == 0:
        return False
    if correlation.get("burst") is not False:
        return True
    counts = [_number(correlation.get(key)) for key in ("related_threats", "related_open_reviews")]
    return any(count is None or count > 0 for count in counts)


def _steering_text(triage: Mapping[str, Any]) -> bool:
    rule_tp = triage.get("rule_tp")
    return not isinstance(rule_tp, list) or INJECTION_SIGNAL in rule_tp


def _digest(state: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = state.get(key)
    return value if isinstance(value, Mapping) else {}


def evidence_close_blockers(state: Mapping[str, Any]) -> List[str]:
    """Why approved benign evidence may not close this alert; empty when it may.

    Whatever the evidence: steering text, or a recent true positive on the
    alert's entities. For context evidence (:data:`CONTEXT_EVIDENCE`: a
    declared scanner or a test source, which say where the activity came
    from and which an attacker borrows by acting from that host), also a
    never-close class the detection rule maps the alert to. Evidence about
    what was detected (the rule's own test intent, the EICAR file) is exempt
    from the class test, and so is an unmapped alert: the class is unknown,
    but the benign fact is declared, not a model's judgement.
    """
    triage = _digest(state, "triage")
    fp = triage.get("rule_fp")
    context = isinstance(fp, list) and any(signal in CONTEXT_EVIDENCE for signal in fp)
    found = never_close_class(state.get("alert"))
    checks = (
        ("steering_text", _steering_text(triage)),
        ("recent_true_positive", _recent_true_positive(_digest(state, "analysis"), _digest(state, "correlation"))),
        ("never_close_class", context and found not in (None, UNMAPPED)),
    )
    return [name for name, blocked in checks if blocked]


def model_close_blockers(
    state: Mapping[str, Any], *, tier: str, max_likelihood: int, min_certainty: int
) -> List[str]:
    """Why the models may not close this alert on their own; empty when they may (see the module docs)."""
    triage, analysis, correlation = _digest(state, "triage"), _digest(state, "analysis"), _digest(state, "correlation")
    checks = (
        ("tier_off", tier != MODEL_CLOSE_TIER),
        ("severity", state.get("severity") not in CLOSABLE_SEVERITIES),
        ("never_close_class", never_close_class(state.get("alert")) is not None),
        ("steering_text", _steering_text(triage)),
        ("recent_true_positive", _recent_true_positive(analysis, correlation)),
        ("campaign_in_progress", _campaign_in_progress(correlation)),
        ("fast_tier_not_benign", not _fast_tier_benign(triage, max_likelihood)),
        ("deep_tier_not_benign", not _deep_tier_benign(analysis, min_certainty)),
    )
    return [name for name, blocked in checks if blocked]
