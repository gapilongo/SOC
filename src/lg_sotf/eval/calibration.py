"""What ``decide`` read, recorded per evaluation item (``decision_inputs``).

An evaluation report records, per item, the confidence, the triage,
correlation and analysis digests' scores and the verdict ``decide`` saw, so a
later reader can tell why an item was routed the way it was. AI-E1.9's offline
policy simulator over these inputs was removed with decision policy v2
(FIX-1): the policy switches it compared no longer exist.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from lg_sotf.domain.routing import llm_normalized, refused_by


def _number(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def decision_inputs(state: Mapping[str, Any]) -> Dict[str, Any]:
    """What ``decide`` reads from a finished run's state, small enough for every report item."""
    triage = state.get("triage") or {}
    correlation = state.get("correlation") or {}
    analysis = state.get("analysis") or {}
    return {
        "severity": state.get("severity"),
        "confidence": _number(state.get("confidence")),
        "more_info_loops": int(state.get("more_info_loops", 0) or 0),
        "refused_by": refused_by(state),
        "llm_normalized": llm_normalized(state),
        "triage": {
            "confidence": _number(triage.get("confidence")),
            "rule_confidence": _number(triage.get("rule_confidence")),
            "rule_fp": [str(s)[:64] for s in (triage.get("rule_fp") or [])][:20],
            "rule_tp": [str(s)[:64] for s in (triage.get("rule_tp") or [])][:20],
        },
        "correlation": {
            "score": _number(correlation.get("score")),
            "related_count": correlation.get("related_count"),
            "burst": correlation.get("burst"),
        },
        "analysis": {
            "verdict": analysis.get("verdict"),
            "threat_score": _number(analysis.get("threat_score")),
            "rule_threat_score": _number(analysis.get("rule_threat_score")),
        }
        if analysis
        else None,
    }


