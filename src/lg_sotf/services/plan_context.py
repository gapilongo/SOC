"""The planner's view of a case (:class:`~lg_sotf.services.response.PlanContext`), from an alert and its digests.

Shared by the workflow's ``plan_response`` node (which reads the run's
state) and the response preview (which reads the stored alert and its
summary), so the preview shows the plan the workflow would compute.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.db.repos import Alert
from lg_sotf.domain.phishing import message_context
from lg_sotf.services.response import Evidence, PlanContext, plan_entities


def canonical_alert(alert: Alert) -> Dict[str, Any]:
    """The workflow's view of a stored alert: the normalized form with the row's own columns and ``raw``
    (without the size caps the workflow applies to its state)."""
    canonical: Dict[str, Any] = dict(alert.normalized)
    canonical.update(
        {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "category": alert.category if alert.category is not None else canonical.get("category"),
            "source_id": alert.source_id,
            "fingerprint": alert.fingerprint,
        }
    )
    canonical.setdefault("raw", alert.raw)
    return canonical


def threat_texts(alert: Mapping[str, Any], analysis: Mapping[str, Any], triage: Mapping[str, Any]) -> List[str]:
    """What the playbook choice reads: the analysis conclusion, triage's threat categories, MITRE tactics."""
    mitre = alert.get("mitre") if isinstance(alert.get("mitre"), Mapping) else {}
    texts = [str(analysis.get("conclusion") or ""), *[str(c) for c in triage.get("threat_categories") or []]]
    for key in ("tactics", "techniques"):
        texts.extend(str(v) for v in (mitre or {}).get(key) or [] if isinstance(v, (str, int)))
    return texts


def corroborated_targets(analysis: Mapping[str, Any]) -> Optional[FrozenSet[Tuple[str, str]]]:
    """The (kind, value) targets the rule evidence is about; ``None`` when the digest predates them."""
    targets = analysis.get("corroborated_targets")
    if not isinstance(targets, list):
        return None
    return frozenset((str(t[0]), str(t[1])) for t in targets if isinstance(t, (list, tuple)) and len(t) == 2)


def plan_context(
    alert: Mapping[str, Any],
    *,
    severity: str,
    evidence: Evidence,
    analysis: Mapping[str, Any],
    triage: Mapping[str, Any],
    approved_actions: Sequence[str] = (),
    approved_by: Optional[str] = None,
    approver_role: Optional[str] = None,
) -> PlanContext:
    entities = alert.get("entities") if isinstance(alert.get("entities"), Mapping) else {}
    return PlanContext(
        severity=severity,
        evidence=evidence,
        title=str(alert.get("title", "")),
        category=alert.get("category"),
        entities=plan_entities(alert),
        recommended_actions=list(analysis.get("recommended_actions") or []),
        threat_texts=threat_texts(alert, analysis, triage),
        approved_actions=list(approved_actions),
        approved_by=approved_by,
        approver_role=approver_role,
        corroborated_targets=corroborated_targets(analysis),
        hosts=[str(h) for h in (entities or {}).get("hosts") or [] if isinstance(h, str)],
        message=message_context(alert),
    )
