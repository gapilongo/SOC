"""Bounded ReAct loop for the analysis agent.

All per-alert data lives in :class:`AnalysisRunContext`; the reasoner itself
is a stateless singleton. The model chooses the next tool, but targets are
restricted to indicators extracted from the alert, so injected text in the
alert cannot make the agent look up (or send) arbitrary values. The loop
stops when the model says ``finish``, when it repeats an observation, or
after ``max_steps``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Mapping, Optional

from pydantic import BaseModel, Field

from lg_sotf.agents.analysis.tools import network_facts
from lg_sotf.agents.base import AgentContext
from lg_sotf.core.exceptions import ToolError
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact_text
from lg_sotf.tools.orchestrator import ToolOrchestrator

if TYPE_CHECKING:
    from lg_sotf.agents.base import BaseAgent

log = get_logger(__name__)

TOOL_NAMES = ("ip_analysis", "hash_analysis", "process_analysis", "network_analysis", "temporal_analysis")
MAX_TARGETS_PER_TOOL = 5
MAX_OBSERVATION_KEYS = 12

SYSTEM_PROMPT = (
    "You are a SOC investigator running a short, bounded investigation of one security alert. "
    "At each step either call one of the available tools on one of the listed candidate targets, "
    "or finish when the evidence is sufficient. Tool results marked simulated come from built-in "
    "heuristics, not live threat intelligence; weigh them accordingly."
)
TASK_PROMPT = (
    "Return a short thought, the next action (a tool name or 'finish') and the target, which must be "
    "copied exactly from the candidates for that tool."
)


class ReActStep(BaseModel):
    thought: str = Field(max_length=1_000)
    action: Literal["finish", "ip_analysis", "hash_analysis", "process_analysis", "network_analysis", "temporal_analysis"]
    target: str = Field(default="", max_length=512)


@dataclass
class Observation:
    tool: str
    target: str
    result: Dict[str, Any]
    error: Optional[str] = None

    def digest(self) -> Dict[str, Any]:
        display, _ = redact_text(self.target)
        small = {k: v for k, v in list(self.result.items())[:MAX_OBSERVATION_KEYS] if not isinstance(v, (dict, list))}
        out: Dict[str, Any] = {"tool": self.tool, "target": display[:128], "simulated": bool(self.result.get("simulated"))}
        if self.error:
            out["error"] = self.error
        else:
            out["result"] = small
        return out


@dataclass
class AnalysisRunContext:
    agent_ctx: AgentContext
    alert: Mapping[str, Any]
    candidates: Dict[str, List[str]]
    background: Dict[str, Any] = field(default_factory=dict)
    observations: List[Observation] = field(default_factory=list)
    thoughts: List[str] = field(default_factory=list)
    steps: int = 0
    llm_steps: int = 0
    notes: List[str] = field(default_factory=list)

    def observed(self, tool: str, target: str) -> bool:
        return any(o.tool == tool and o.target == target for o in self.observations)


class ReActReasoner:
    def __init__(self, orchestrator: ToolOrchestrator, *, max_steps: int = 5) -> None:
        if max_steps < 0:
            raise ValueError("max_steps must be >= 0")
        self.orchestrator = orchestrator
        self.max_steps = max_steps

    def _resolve_target(self, run: AnalysisRunContext, tool: str, requested: str) -> Optional[str]:
        allowed = run.candidates.get(tool) or []
        if requested in allowed and not run.observed(tool, requested):
            return requested
        return next((t for t in allowed if not run.observed(tool, t)), None)

    async def reason(self, agent: BaseAgent, run: AnalysisRunContext) -> None:
        available = {tool: targets for tool, targets in run.candidates.items() if targets}
        if not available:
            return
        for _ in range(self.max_steps):
            llm = await agent.call_llm(
                run.agent_ctx,
                tier="deep",
                schema=ReActStep,
                system=SYSTEM_PROMPT,
                task=TASK_PROMPT,
                untrusted={
                    "alert": dict(run.alert),
                    "background": run.background,
                    "candidates": available,
                    "observations": [o.digest() for o in run.observations],
                },
            )
            run.notes.extend(llm.notes)
            if llm.value is None:
                return
            step = llm.value
            run.llm_steps += 1
            run.thoughts.append(step.thought[:500])
            if step.action == "finish":
                return
            target = self._resolve_target(run, step.action, step.target)
            if target is None:
                return
            run.steps += 1
            await self._observe(run, step.action, target)

    async def _observe(self, run: AnalysisRunContext, tool: str, target: str) -> None:
        args: Dict[str, Any] = {"target": target}
        if tool == "network_analysis":
            args.update(network_facts(run.alert))
        try:
            result = await self.orchestrator.execute_tool(tool, args, tenant_id=run.agent_ctx.tenant_id)
        except ToolError as exc:
            log.warning("analysis.tool_failed", tool=tool, error=str(exc))
            run.observations.append(Observation(tool, target, {}, error="tool_failed"))
            return
        run.observations.append(Observation(tool, target, result))
