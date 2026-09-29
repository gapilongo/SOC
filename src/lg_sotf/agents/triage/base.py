"""Triage: rule scoring plus one fast-tier LLM assessment.

Rule evidence and LLM evidence are kept apart in :class:`TriageResult` so the
routing policy can require rule corroboration before closing an alert.

False-positive rule signals can close low/medium alerts, so they come only
from fields the attacker does not write: whole words of the detection title
and rule name, and environment tags in the configured source id. Raw event
fields, dict keys and command lines never produce them. True-positive
signals may use the whole alert, since they only push towards review.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, Field

from lg_sotf.agents.base import AgentContext, BaseAgent

SEVERITY_WEIGHTS: Dict[str, int] = {"critical": 30, "high": 20, "medium": 10, "low": -10, "info": -20}
TP_KEYWORD_WEIGHTS: Dict[str, int] = {
    "malware": 25,
    "trojan": 25,
    "backdoor": 30,
    "exploit": 20,
    "suspicious": 15,
    "anomaly": 10,
}
FP_KEYWORD_WEIGHTS: Dict[str, int] = {"test": -30, "scheduled": -20, "maintenance": -25}
FP_KEYWORDS = ("test", "testing", "scheduled", "maintenance", "update", "backup", "scan", "health_check", "monitoring")
# Tokens keep path and extension characters so "maintenance.exe" or "C:\\test\\x" never read as a word.
_WORD_RE = re.compile(r"[a-z0-9_.\\/:-]+")
_SOURCE_TOKEN_RE = re.compile(r"[^a-z0-9]+")
TP_KEYWORDS = (
    "malware",
    "trojan",
    "backdoor",
    "exploit",
    "suspicious",
    "anomaly",
    "breach",
    "intrusion",
    "attack",
    "threat",
    "mimikatz",
    "ransomware",
    "persistence",
    "credential",
    "lateral",
)
TEST_ENVIRONMENTS = ("test", "dev", "staging", "qa")
SUSPICIOUS_PORTS = frozenset({4444, 6666, 31337})
PRIORITY_BY_SEVERITY = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}
MAX_INDICATORS = 20

SYSTEM_PROMPT = (
    "You are a senior SOC analyst performing first-pass triage of a security alert. "
    "Assess how likely the alert represents real malicious activity, list the concrete evidence "
    "for and against, and keep the reasoning short and factual."
)
TASK_PROMPT = (
    "Return threat_likelihood (0-100, how likely this is a true positive), a threat assessment, "
    "short false-positive and true-positive indicators observed in the data, threat categories, "
    "an urgency level, recommended next steps and a one-paragraph reasoning."
)


class TriageAssessment(BaseModel):
    threat_likelihood: int = Field(ge=0, le=100)
    threat_assessment: Literal["benign", "suspicious", "likely_threat", "confirmed_threat"]
    false_positive_indicators: List[str] = Field(default_factory=list, max_length=MAX_INDICATORS)
    true_positive_indicators: List[str] = Field(default_factory=list, max_length=MAX_INDICATORS)
    threat_categories: List[str] = Field(default_factory=list, max_length=10)
    urgency_level: Literal["low", "medium", "high", "critical"]
    recommended_actions: List[str] = Field(default_factory=list, max_length=10)
    reasoning: str = Field(max_length=4_000)


@dataclass
class TriageResult:
    confidence: int
    rule_confidence: int
    priority: int
    rule_fp: List[str]
    rule_tp: List[str]
    llm_fp: List[str] = field(default_factory=list)
    llm_tp: List[str] = field(default_factory=list)
    llm_used: bool = False
    threat_assessment: Optional[str] = None
    threat_categories: List[str] = field(default_factory=list)
    reasoning: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def digest(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("notes")
        if data["reasoning"]:
            data["reasoning"] = data["reasoning"][:1_000]
        return data


def _raw(alert: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = alert.get("raw")
    if isinstance(raw, Mapping):
        nested = raw.get("raw_data")
        return nested if isinstance(nested, Mapping) else raw
    return {}


def _lower_text(alert: Mapping[str, Any]) -> str:
    return str(alert).lower()


def trusted_words(alert: Mapping[str, Any]) -> FrozenSet[str]:
    """Whole words of the detection title and rule name (the fields FP signals may come from)."""
    text = " ".join(str(alert.get(k) or "") for k in ("title", "rule_name")).lower()
    return frozenset(t.strip(".:-") for t in _WORD_RE.findall(text))


def source_environment(alert: Mapping[str, Any]) -> Optional[str]:
    """Test-like environment tag in the configured source id (``splunk-staging`` -> ``staging``)."""
    tokens = set(_SOURCE_TOKEN_RE.split(_source(alert)))
    return next((env for env in TEST_ENVIRONMENTS if env in tokens), None)


def _source(alert: Mapping[str, Any]) -> str:
    return str(alert.get("source_id") or alert.get("source") or "").lower()


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def rule_confidence(alert: Mapping[str, Any]) -> int:
    score = 50 + SEVERITY_WEIGHTS.get(str(alert.get("severity", "")).lower(), 0)
    text = _lower_text(alert)
    words = trusted_words(alert)
    score += sum(weight for keyword, weight in TP_KEYWORD_WEIGHTS.items() if keyword in text)
    score += sum(weight for keyword, weight in FP_KEYWORD_WEIGHTS.items() if keyword in words)
    if source_environment(alert) is not None:
        score -= 25
    occurred = _parse_time(alert.get("occurred_at"))
    if occurred is not None and (occurred.hour < 6 or occurred.hour >= 18):
        score += 5
    return max(0, min(100, score))


def rule_indicators(alert: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    text = _lower_text(alert)
    raw = _raw(alert)
    words = trusted_words(alert)
    fp = [f"{k}_detected" for k in FP_KEYWORDS if k in words]
    if source_environment(alert) is not None:
        fp.append("test_environment")

    tp = [f"{k}_detected" for k in TP_KEYWORDS if k in text]
    entities = alert.get("entities") if isinstance(alert.get("entities"), Mapping) else {}
    if raw.get("file_hash") or (entities or {}).get("hashes"):
        tp.append("file_hash_present")
    if raw.get("destination_ip"):
        tp.append("network_connection")
    if raw.get("destination_port") in SUSPICIOUS_PORTS:
        tp.append("suspicious_port")
    if raw.get("event_type") == "file_creation" and str(raw.get("file_path", "")).endswith(".exe"):
        tp.append("executable_creation")
    if "privilege" in text and "escalation" in text:
        tp.append("privilege_escalation")
    return list(dict.fromkeys(fp))[:MAX_INDICATORS], list(dict.fromkeys(tp))[:MAX_INDICATORS]


def priority_for(severity: str, confidence: int) -> int:
    """1-10, higher is more urgent (same scale as escalations)."""
    base = PRIORITY_BY_SEVERITY.get(severity, 5)
    if confidence >= 90:
        adjust = 1
    elif confidence >= 70:
        adjust = 0
    elif confidence >= 50:
        adjust = -1
    else:
        adjust = -2
    return max(1, min(10, base + adjust))


class TriageAgent(BaseAgent):
    name = "triage"

    def __init__(self, config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        self.enable_llm = bool(self.get_config("enable_llm_scoring", True))
        self.llm_weight = float(self.get_config("llm_weight", 0.4))
        if not 0.0 <= self.llm_weight <= 1.0:
            raise ValueError("agents.triage.llm_weight must be between 0 and 1")

    async def run(self, ctx: AgentContext, alert: Mapping[str, Any]) -> TriageResult:
        base = rule_confidence(alert)
        rule_fp, rule_tp = rule_indicators(alert)
        llm = await self.call_llm(
            ctx,
            tier="fast",
            schema=TriageAssessment,
            system=SYSTEM_PROMPT,
            task=TASK_PROMPT,
            untrusted={"alert": dict(alert)},
            enabled=self.enable_llm,
        )
        severity = str(alert.get("severity", "medium")).lower()
        if llm.value is None:
            return TriageResult(
                confidence=base,
                rule_confidence=base,
                priority=priority_for(severity, base),
                rule_fp=rule_fp,
                rule_tp=rule_tp,
                notes=llm.notes,
            )
        a = llm.value
        confidence = max(0, min(100, round(base * (1 - self.llm_weight) + a.threat_likelihood * self.llm_weight)))
        llm_fp = [i[:120] for i in a.false_positive_indicators if i not in rule_fp][:MAX_INDICATORS]
        llm_tp = [i[:120] for i in a.true_positive_indicators if i not in rule_tp][:MAX_INDICATORS]
        return TriageResult(
            confidence=confidence,
            rule_confidence=base,
            priority=priority_for(severity, confidence),
            rule_fp=rule_fp,
            rule_tp=rule_tp,
            llm_fp=llm_fp,
            llm_tp=llm_tp,
            llm_used=True,
            threat_assessment=a.threat_assessment,
            threat_categories=[c[:64] for c in a.threat_categories],
            reasoning=a.reasoning,
            notes=llm.notes,
        )
