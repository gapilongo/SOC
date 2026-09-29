"""Agent singletons for a process.

:class:`AgentSet` bundles the stateless workflow agents built from one
``Settings``. :class:`AgentRegistry` is a small name -> instance registry
kept for callers that list agents (metrics endpoints).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.base import BaseAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.exceptions import AgentError
from lg_sotf.settings import Settings


@dataclass(frozen=True)
class AgentSet:
    triage: TriageAgent
    correlation: CorrelationAgent
    analysis: AnalysisAgent

    @classmethod
    def build(cls, settings: Settings) -> AgentSet:
        return cls(
            triage=TriageAgent(settings=settings),
            correlation=CorrelationAgent(settings=settings),
            analysis=AnalysisAgent(settings=settings),
        )

    def all(self) -> List[BaseAgent]:
        return [self.triage, self.correlation, self.analysis]

    async def initialize(self) -> None:
        for agent in self.all():
            await agent.initialize()

    async def cleanup(self) -> None:
        for agent in self.all():
            await agent.cleanup()


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: Dict[str, BaseAgent] = {}

    def register(self, name: str, agent: BaseAgent) -> None:
        if not isinstance(agent, BaseAgent):
            raise AgentError(f"agent {name!r} must be a BaseAgent")
        self._agents[name] = agent

    def register_set(self, agents: AgentSet) -> None:
        for agent in agents.all():
            self.register(agent.name, agent)

    def get_agent(self, name: str) -> BaseAgent:
        agent = self._agents.get(name)
        if agent is None:
            raise AgentError(f"agent {name!r} is not registered")
        return agent

    def agent_exists(self, name: str) -> bool:
        return name in self._agents

    def list_agent_instances(self) -> Dict[str, BaseAgent]:
        return dict(self._agents)

    def get_registry_stats(self) -> Dict[str, Any]:
        return {
            "agent_instances_count": len(self._agents),
            "agent_instances": sorted(self._agents),
            "initialized_agents": sorted(n for n, a in self._agents.items() if a.initialized),
        }

    async def cleanup_all_agents(self) -> None:
        for agent in self._agents.values():
            await agent.cleanup()
        self._agents.clear()

    def clear(self) -> None:
        self._agents.clear()


agent_registry = AgentRegistry()


def build_agents(settings: Settings, *, register: Optional[AgentRegistry] = None) -> AgentSet:
    agents = AgentSet.build(settings)
    if register is not None:
        register.register_set(agents)
    return agents
