"""Agent singletons for a process.

:class:`AgentSet` bundles the stateless workflow agents built from one
``Settings``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.base import BaseAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService


@dataclass(frozen=True)
class AgentSet:
    triage: TriageAgent
    correlation: CorrelationAgent
    analysis: AnalysisAgent

    @classmethod
    def build(cls, settings: Settings, *, secret_box: Optional[SecretBox] = None) -> AgentSet:
        """``secret_box`` (the process's) decrypts the tenant tool keys analysis enrichment uses."""
        enrichment = EnrichmentService.from_settings(settings, secret_box=secret_box)
        return cls(
            triage=TriageAgent(settings=settings),
            correlation=CorrelationAgent(settings=settings),
            analysis=AnalysisAgent(settings=settings, enrichment=enrichment),
        )

    def all(self) -> List[BaseAgent]:
        return [self.triage, self.correlation, self.analysis]

    async def initialize(self) -> None:
        for agent in self.all():
            await agent.initialize()

    async def cleanup(self) -> None:
        for agent in self.all():
            await agent.cleanup()

