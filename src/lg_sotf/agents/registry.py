"""Agent singletons for a process.

:class:`AgentSet` bundles the stateless workflow agents built from one
``Settings``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.base import BaseAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.triage.base import TriageAgent
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

