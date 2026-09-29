"""Analysis: rule-based assessment plus a bounded deep-tier ReAct investigation.

The rule assessment always runs and is reported separately
(``rule_threat_score``/``rule_verdict``) so routing can tell corroborated
verdicts from LLM-only ones. Tool evidence is simulated today and is
labelled as such in every digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional

from pydantic import BaseModel, Field

from lg_sotf.agents.analysis.react import TOOL_NAMES, AnalysisRunContext, ReActReasoner
from lg_sotf.agents.analysis.tools import default_tools
from lg_sotf.agents.base import AgentContext, BaseAgent
from lg_sotf.agents.correlation.indicators import extract_indicators
from lg_sotf.tools.cache import TTLCache
from lg_sotf.tools.orchestrator import ToolOrchestrator

SEVERITY_BOOST = {"critical": 25, "high": 20, "medium": 10, "low": 0, "info": -10}
SUSPICIOUS_PORTS = frozenset({4444, 6666, 31337, 8080})
PRIVILEGED_USERS = frozenset({"administrator", "admin", "root", "system"})
BEHAVIOURAL_KEYWORDS = ("persistence", "lateral", "escalation", "exfiltration")
MAX_ACTIONS = 10

SYSTEM_PROMPT = (
    "You are a senior SOC analyst concluding an investigation of one security alert. Weigh the alert, "
    "the triage and correlation results and the tool observations. Observations marked simulated come "
    "from built-in heuristics rather than live intelligence and must not be treated as confirmation."
)
TASK_PROMPT = (
    "Return threat_score (0-100), your certainty (0-100) in that assessment, a verdict (malicious, benign "
    "or inconclusive), a short conclusion and concrete recommended response actions."
)


class AnalysisVerdict(BaseModel):
    threat_score: int = Field(ge=0, le=100)
    certainty: int = Field(ge=0, le=100)
    verdict: Literal["malicious", "benign", "inconclusive"]
    conclusion: str = Field(max_length=2_000)
    recommended_actions: List[str] = Field(default_factory=list, max_length=MAX_ACTIONS)


@dataclass
class AnalysisResult:
    threat_score: int
    certainty: int
    verdict: str
    rule_threat_score: int
    rule_verdict: str
    conclusion: str
    recommended_actions: List[str]
    threat_indicators: List[str]
    llm_used: bool
    tool_steps: int
    observations: List[Dict[str, Any]] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def simulated_evidence(self) -> bool:
        return any(o.get("simulated") for o in self.observations)

    def digest(self) -> Dict[str, Any]:
        """Small enough for graph state."""
        return {
            "threat_score": self.threat_score,
            "certainty": self.certainty,
            "verdict": self.verdict,
            "rule_threat_score": self.rule_threat_score,
            "rule_verdict": self.rule_verdict,
            "conclusion": self.conclusion[:1_000],
            "recommended_actions": self.recommended_actions,
            "llm_used": self.llm_used,
            "tool_steps": self.tool_steps,
            "simulated_evidence": self.simulated_evidence,
        }

    def summary(self) -> Dict[str, Any]:
        """For ``alerts.summary.analysis``: includes the (simulated-labelled) tool evidence."""
        return {
            **self.digest(),
            "threat_indicators": self.threat_indicators,
            "tools": self.observations,
            "reasoning": self.reasoning,
        }


def _raw(alert: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = alert.get("raw")
    if isinstance(raw, Mapping):
        nested = raw.get("raw_data")
        return nested if isinstance(nested, Mapping) else raw
    return {}


def rule_threat_indicators(alert: Mapping[str, Any], correlation: Mapping[str, Any]) -> List[str]:
    raw = _raw(alert)
    entities = alert.get("entities") if isinstance(alert.get("entities"), Mapping) else {}
    entities = entities or {}
    out: List[str] = []
    if raw.get("file_hash") or entities.get("hashes"):
        out.append("file_hash_present")
    if raw.get("process_name") or entities.get("processes"):
        out.append("process_execution")
    if "temp" in str(raw.get("file_path", "")).lower():
        out.append("temp_directory_execution")
    if raw.get("destination_ip"):
        out.append("network_communication")
    if raw.get("destination_port") in SUSPICIOUS_PORTS:
        out.append("suspicious_port_usage")
    users = [str(u).lower() for u in (entities.get("users") or []) if isinstance(u, str)]
    if str(raw.get("user", "")).lower() in PRIVILEGED_USERS or PRIVILEGED_USERS.intersection(users):
        out.append("privileged_account_usage")
    if correlation.get("related_count", 0) and correlation.get("score", 0) > 80:
        out.append("high_confidence_correlations")
    if correlation.get("frequency_level") in ("high", "critical") or correlation.get("burst"):
        out.append("high_threat_correlations")
    description = str(alert.get("description", "")).lower()
    out.extend(f"behavioral_{k}" for k in BEHAVIOURAL_KEYWORDS if k in description)
    return out


def rule_threat_score(
    alert: Mapping[str, Any], triage: Mapping[str, Any], correlation: Mapping[str, Any], indicators: List[str]
) -> int:
    score = 50 + SEVERITY_BOOST.get(str(alert.get("severity", "")).lower(), 0)
    score += min(30, 3 * len(indicators))
    related = int(correlation.get("related_count", 0))
    if related:
        score += min(20, 2 * related + (5 if correlation.get("score", 0) > 80 else 0))
    score -= min(40, 10 * len(triage.get("rule_fp") or []))
    source = str(alert.get("source_id", "")).lower()
    if "test" in source or "dev" in source:
        score -= 15
    score += 8 * sum(1 for i in indicators if i in ("suspicious_port_usage", "temp_directory_execution", "privileged_account_usage"))
    return max(0, min(100, score))


def rule_verdict(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score < 30:
        return "benign"
    return "inconclusive"


def rule_conclusion(score: int) -> str:
    if score >= 85:
        return "Critical threat: multiple rule indicators suggest active malicious activity."
    if score >= 70:
        return "High threat: strong rule evidence of a potential security incident."
    if score >= 55:
        return "Moderate threat: several suspicious indicators, investigation advised."
    if score >= 40:
        return "Low threat: some concerning indicators, routine review recommended."
    return "Minimal threat: limited indicators, likely benign or a false positive."


def rule_actions(score: int) -> List[str]:
    if score >= 85:
        return ["Isolate affected host", "Block malicious network indicators", "Collect forensic evidence", "Create incident ticket"]
    if score >= 70:
        return ["Block suspicious indicators", "Create incident ticket", "Collect forensic evidence"]
    if score >= 55:
        return ["Review related alerts for patterns", "Create investigation ticket"]
    if score >= 40:
        return ["Add to watchlist", "Review for false-positive patterns"]
    return ["Close as likely false positive", "Tune detection rule if recurring"]


def tool_candidates(alert: Mapping[str, Any]) -> Dict[str, List[str]]:
    indicators = extract_indicators(alert)
    by_type: Dict[str, List[str]] = {}
    for ind in indicators:
        by_type.setdefault(ind.type, []).append(ind.value)
    raw = _raw(alert)
    candidates: Dict[str, List[str]] = {
        "ip_analysis": by_type.get("ip", [])[:5],
        "hash_analysis": by_type.get("hash", [])[:5],
        "process_analysis": by_type.get("process", [])[:5],
        "network_analysis": ["alert"] if raw.get("destination_port") is not None else [],
        "temporal_analysis": [str(alert["occurred_at"])] if alert.get("occurred_at") else [],
    }
    return {k: v for k, v in candidates.items() if k in TOOL_NAMES}


class AnalysisAgent(BaseAgent):
    name = "analysis"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        orchestrator: Optional[ToolOrchestrator] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(config, **kwargs)
        self.orchestrator = orchestrator or ToolOrchestrator(
            default_tools(),
            timeout_s=float(self.get_config("tool_timeout", 30)),
            cache=TTLCache(maxsize=int(self.get_config("tool_cache_size", 1_024)), ttl_s=300.0),
        )
        self.reasoner = ReActReasoner(self.orchestrator, max_steps=int(self.get_config("max_iterations", 5)))
        self.enable_llm = bool(self.get_config("enable_llm_reasoning", True))

    async def run(
        self,
        ctx: AgentContext,
        alert: Mapping[str, Any],
        *,
        triage: Mapping[str, Any],
        correlation: Mapping[str, Any],
        analyst_notes: Optional[str] = None,
    ) -> AnalysisResult:
        indicators = rule_threat_indicators(alert, correlation)
        rule_score = rule_threat_score(alert, triage, correlation, indicators)
        background: Dict[str, Any] = {
            "triage": {k: triage.get(k) for k in ("confidence", "rule_fp", "rule_tp", "threat_assessment")},
            "correlation": {k: correlation.get(k) for k in ("score", "related_count", "burst", "frequency_level")},
            "rule_threat_indicators": indicators,
        }
        if analyst_notes:
            background["analyst_request"] = analyst_notes[:1_000]
        run = AnalysisRunContext(agent_ctx=ctx, alert=alert, candidates=tool_candidates(alert), background=background)
        if self.enable_llm and ctx.settings.llm.enabled:
            await self.reasoner.reason(self, run)

        llm = await self.call_llm(
            ctx,
            tier="deep",
            schema=AnalysisVerdict,
            system=SYSTEM_PROMPT,
            task=TASK_PROMPT,
            untrusted={
                "alert": dict(alert),
                "background": background,
                "observations": [o.digest() for o in run.observations],
            },
            enabled=self.enable_llm,
        )
        notes = run.notes + llm.notes
        observations = [o.digest() for o in run.observations]
        if llm.value is None:
            return AnalysisResult(
                threat_score=rule_score,
                certainty=50,
                verdict=rule_verdict(rule_score),
                rule_threat_score=rule_score,
                rule_verdict=rule_verdict(rule_score),
                conclusion=rule_conclusion(rule_score),
                recommended_actions=rule_actions(rule_score),
                threat_indicators=indicators,
                llm_used=False,
                tool_steps=run.steps,
                observations=observations,
                reasoning=run.thoughts,
                notes=notes,
            )
        v = llm.value
        actions = list(dict.fromkeys([a[:200] for a in v.recommended_actions] + rule_actions(max(rule_score, v.threat_score))))
        return AnalysisResult(
            threat_score=v.threat_score,
            certainty=v.certainty,
            verdict=v.verdict,
            rule_threat_score=rule_score,
            rule_verdict=rule_verdict(rule_score),
            conclusion=v.conclusion,
            recommended_actions=actions[:MAX_ACTIONS],
            threat_indicators=indicators,
            llm_used=True,
            tool_steps=run.steps,
            observations=observations,
            reasoning=run.thoughts,
            notes=notes,
        )

    async def cleanup(self) -> None:
        await self.orchestrator.cleanup()
