"""Agent singletons for a process.

:class:`AgentSet` bundles the stateless workflow agents built from one
``Settings``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.base import BaseAgent, ModelFactory
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from lg_sotf.tools.wazuh.tools import Backends


@dataclass(frozen=True)
class AgentSet:
    triage: TriageAgent
    correlation: CorrelationAgent
    analysis: AnalysisAgent

    @classmethod
    def build(
        cls,
        settings: Settings,
        *,
        secret_box: Optional[SecretBox] = None,
        model_factory: Optional[ModelFactory] = None,
        enrichment: Optional[EnrichmentService] = None,
        evidence: Optional[Backends] = None,
    ) -> AgentSet:
        """``secret_box`` (the process's) decrypts the tenant tool keys analysis enrichment uses.

        ``model_factory`` replaces :func:`~lg_sotf.llm.get_chat_model` for every agent (evaluation cassettes).
        ``evidence`` is where the Wazuh evidence tools read for a run; without it the analysis agent has no
        investigation harness. The workflow engine always gives one (``lg_sotf.core.workflow.build_node_deps``);
        the history backtest (``lg_sotf.eval.history``) does not yet, so it replays without the lookups.
        """
        enrichment = enrichment or EnrichmentService.from_settings(settings, secret_box=secret_box)
        return cls(
            triage=TriageAgent(settings=settings, model_factory=model_factory),
            correlation=CorrelationAgent(settings=settings, model_factory=model_factory),
            analysis=AnalysisAgent(
                settings=settings, enrichment=enrichment, evidence=evidence, model_factory=model_factory
            ),
        )

    def all(self) -> List[BaseAgent]:
        return [self.triage, self.correlation, self.analysis]

    async def initialize(self) -> None:
        for agent in self.all():
            await agent.initialize()

    async def cleanup(self) -> None:
        for agent in self.all():
            await agent.cleanup()

