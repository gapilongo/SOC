"""Model-led closure (decision policy v3, FIX-3): the tenant's autonomy tier and when the models close an alert.

Founder decision 2026-11-09: every alert the AI judges benign closes, and a
backward safety net replaces the forward gates of FIX-1 and FIX-2. Without
approved benign evidence (:func:`lg_sotf.domain.routing.decide`), an alert
closes on the models' word only when the tenant chose the autonomy tier
``auto_full_audit`` (tenant setting ``ai_closure.tier``, default ``off``)
and every condition below holds. Each one fails closed: a missing or
unreadable value blocks the close.

* the deep tier (analysis) says ``benign``, at any certainty; a verdict the
  rules produced because a model was not consulted never counts;
* the fast tier (triage) did not call it a threat (``likely_threat`` or
  ``confirmed_threat``);
* severity ``info``, ``low``, ``medium`` or ``high`` (critical never closes
  on a model's word, at any tier);
* not a never-close class (:func:`model_close_class`): credential access by
  ATT&CK tactic or technique (T1531 included) or by the vendor's own
  authentication-failure rule groups and ids
  (:func:`lg_sotf.domain.noise_families.vendor_never_close_class`), a Wazuh
  alert whose rule cannot be read (``vendor_unknown``), log clearing and
  other indicator removal, security-tool tampering, ransomware behaviour,
  and persistence through an object the attacker creates and names. An alert
  without an ATT&CK mapping (``unmapped``) is no longer blocked;
* no steering text: triage did not flag ``prompt_injection_suspected``;
* no recent true positive on the alert's entities: no analyst-confirmed
  malicious history (``prior_malicious_history``), no related alert of the
  correlation window closed as malicious, and no rule evidence that
  corroborates a threat (``rule_corroborated``);
* not normalised by a model (the LLM-fallback normalizer chose its fields),
  and not reopened by the safety net (``reopened``): a reopened alert goes
  to an analyst;
* no related open threat (AI-E3.16, #435). When the decision is made the
  workflow reads the tenant's stored alerts of the previous 24 hours that
  share a host or user with this one
  (:func:`lg_sotf.core.retro_reopen.related_open`, the digest
  :data:`RELATED_OPEN`). The close is held back and the alert goes to an
  analyst, in the threat's case, when one of them is not closed and is a
  strong enough signal (code ``related_open_threat``): it waits for a
  response approval; or it is high or critical and a model judged it a
  threat (the deep tier's ``malicious``, the fast tier's ``likely_threat``
  or ``confirmed_threat``); or a person confirmed it (an analyst's
  ``true_positive``, a blind-audit ``malicious`` label). It is also held
  back when a high or critical alert on the same host is being processed
  at that moment: nothing is decided about it yet (code
  ``related_in_progress``). A low or medium threat only a model stands
  behind holds nothing: the alert closes and is linked to that threat's
  case at once, as the safety net links it when the threat comes later.
  The facts come from the database, never from a model's text or from the
  correlation digest. A digest that is missing or unreadable blocks the
  close (``related_unchecked``).

Removed in v3: the install thresholds on the model tiers (likelihood 8,
certainty 85), the campaign check and the ``unmapped`` block. The related
open threat check is narrower than that campaign check: it reads stored
state, only alerts on the same host or user, and it holds a close back
only for a serious threat, one a person or a pending response stands
behind, or a serious alert still in progress (never for a model's
``suspicious``, and never for a model's own low or medium false alarms,
which cost 13 of 53 benign closes on a realistic mix).

The safety net (:mod:`lg_sotf.core.retro_reopen`) covers the other order of
arrival, a threat that appears after the close: when an alert becomes a
threat, every model-closed alert of the tenant that shares a host, user or
IP with it and closed in the previous 24 hours is looked at. A threat only a
model stands behind (an escalation a model judged a threat, a response plan
or a malicious close with no analyst decision) links it to the threat's case
and leaves it closed, audited ``alert.linked``. A threat a person confirmed
(an analyst true positive, an approved response action, a blind-audit
malicious label) reopens it, attached to that escalation and audited
``alert.reopened``.

A model-led close carries the decision code ``model_closed`` and the close
reason ``ai_closed:audit_required``: an analyst is expected to audit it.
When the noise catalogue knows the detection rule, the decision reason names
the family and the catalogue version. Correlation shows such an alert to
later models as ``ai_closed_unaudited``, never as ``benign``, so one
persuaded close cannot vouch for the next.

Approved benign evidence closes without the tier, but never past steering
text or a recent true positive, and context evidence (a declared scanner, a
test source) never past a mapped never-close class
(:func:`evidence_close_blockers`).
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, Optional, Tuple, get_args

from pydantic import BaseModel, ConfigDict, ValidationError

from lg_sotf.domain.benign_evidence import INJECTION_SIGNAL
from lg_sotf.domain.noise_families import NoiseFamily, noise_family, vendor_never_close_class

__all__ = [
    "AUTONOMY_TIERS",
    "AiClosureSettings",
    "AutonomyTier",
    "CLOSABLE_SEVERITIES",
    "CONTEXT_EVIDENCE",
    "FAST_TIER_THREATS",
    "MODEL_CLOSED",
    "MODEL_CLOSE_REASON",
    "MODEL_CLOSE_TIER",
    "NEVER_CLOSE_TACTICS",
    "NEVER_CLOSE_TECHNIQUES",
    "RELATED_HOLDS",
    "RELATED_OPEN",
    "REOPENED",
    "SETTING",
    "UNMAPPED",
    "autonomy_tier",
    "catalogued_noise",
    "evidence_close_blockers",
    "linked_only_cases",
    "model_close_blockers",
    "model_close_class",
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
CLOSABLE_SEVERITIES: FrozenSet[str] = frozenset({"info", "low", "medium", "high"})
#: Fast-tier assessments that block a model-led close.
FAST_TIER_THREATS: FrozenSet[str] = frozenset({"likely_threat", "confirmed_threat"})
#: The alert key the safety net sets on a reopened alert (lg_sotf.core.retro_reopen); it never model-closes.
REOPENED = "reopened"
LLM_NORMALIZED_FLAG = "llm_normalized"
#: The state and alert-summary key of the related-alert check: ``{"threats": [alert ids], "in_progress": [alert
#: ids], "model_only": [alert ids]}`` as the database held them when the decision was made
#: (lg_sotf.core.retro_reopen.related_open). ``threats`` and ``in_progress`` hold the close back; ``model_only``
#: (threats only a model stands behind) holds nothing: the closed alert is linked to their case.
RELATED_OPEN = "related_open"
#: The blockers that hold a close back because of a related alert's stored state. When nothing else blocks the
#: close, the alert goes to an analyst under the blocker's own name as the decision code (lg_sotf.domain.routing).
RELATED_HOLDS: FrozenSet[str] = frozenset({"related_open_threat", "related_in_progress"})


def linked_only_cases(summary: Mapping[str, Any]) -> FrozenSet[str]:
    """The cases the safety net only linked this alert into (its summary's ``linked`` entries): the alert stayed
    closed by the models, so nobody's claim or decision on such a case is a human step of this alert. A case the
    alert was later reopened through is not one of them."""
    links = summary.get("linked")
    cases = {link.get("escalation_id") for link in links if isinstance(link, Mapping)} if isinstance(links, list) else set()
    reopened = summary.get(REOPENED)
    through = reopened.get("escalation_id") if isinstance(reopened, Mapping) else None
    return frozenset(case for case in cases if isinstance(case, str) and case != through)
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
    # Account access removal: Wazuh maps its Windows logon-failure rules (60122-60130) and others to it (FIX-2 review).
    "T1531": "credential_access",
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
    """The never-close class the detection rule's ATT&CK mapping (or the vendor rule itself) puts the alert in, or
    ``None``.

    A Wazuh rule in an authentication-failure group, or one of a few listed
    rule ids, is credential access whatever its ATT&CK id
    (:func:`lg_sotf.domain.noise_families.vendor_never_close_class`).

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
    vendor = vendor_never_close_class(alert)
    if vendor is not None:
        return vendor
    return None if tactics or techniques else UNMAPPED


def catalogued_noise(alert: Any) -> Optional[NoiseFamily]:
    """The catalogued noise family that lifts the alert's ``unmapped`` class, or ``None`` (FIX-2).

    ``None`` unless the alert is :data:`UNMAPPED` and its vendor detection rule
    id is in the catalogue: a mapped alert never needs the lift, and a mapped
    never-close class is never lifted.
    """
    return noise_family(alert) if never_close_class(alert) == UNMAPPED else None


def model_close_class(alert: Any) -> Optional[str]:
    """The never-close class that blocks a model-led close: :func:`never_close_class`, except that ``unmapped``
    does not block it (policy v3). ``vendor_unknown`` and every mapped class do."""
    found = never_close_class(alert)
    return None if found == UNMAPPED else found


def _number(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _fast_tier_threat(triage: Mapping[str, Any]) -> bool:
    return triage.get("threat_assessment") in FAST_TIER_THREATS


def _deep_tier_benign(analysis: Mapping[str, Any]) -> bool:
    return analysis.get("llm_used") is True and analysis.get("verdict") == "benign"


def _recent_true_positive(analysis: Mapping[str, Any], correlation: Mapping[str, Any]) -> bool:
    evidence = analysis.get("rule_evidence")
    dispositions = correlation.get("related_dispositions")
    related_malicious = dispositions.get("malicious") if isinstance(dispositions, Mapping) else None
    return (
        (isinstance(evidence, list) and "prior_malicious_history" in evidence)
        or analysis.get("rule_corroborated") is True
        or (_number(related_malicious) or 0) > 0
    )


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


def _flagged(alert: Any, flag: str) -> bool:
    flags = alert.get("flags") if isinstance(alert, Mapping) else None
    return isinstance(flags, list) and flag in flags


def model_close_blockers(state: Mapping[str, Any], *, tier: str) -> List[str]:
    """Why the models may not close this alert on their own; empty when they may (see the module docs)."""
    triage, analysis, correlation = _digest(state, "triage"), _digest(state, "analysis"), _digest(state, "correlation")
    alert = state.get("alert")
    related = _digest(state, RELATED_OPEN)
    threats, in_progress = related.get("threats"), related.get("in_progress")
    checked = isinstance(threats, list) and isinstance(in_progress, list)
    checks = (
        ("tier_off", tier != MODEL_CLOSE_TIER),
        ("severity", state.get("severity") not in CLOSABLE_SEVERITIES),
        ("never_close_class", model_close_class(alert) is not None),
        ("llm_normalized", _flagged(alert, LLM_NORMALIZED_FLAG)),
        ("reopened", not isinstance(alert, Mapping) or alert.get(REOPENED) is not None),
        ("steering_text", _steering_text(triage)),
        ("recent_true_positive", _recent_true_positive(analysis, correlation)),
        ("fast_tier_threat", _fast_tier_threat(triage)),
        ("deep_tier_not_benign", not _deep_tier_benign(analysis)),
        # The stored state of the related alerts; only read at the tier, so it is only missing there.
        ("related_unchecked", tier == MODEL_CLOSE_TIER and not checked),
        ("related_open_threat", bool(threats)),
        ("related_in_progress", bool(in_progress)),
    )
    return [name for name, blocked in checks if blocked]
