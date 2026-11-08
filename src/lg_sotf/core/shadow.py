"""Shadow runs (AI-E1.5a): a candidate pipeline on a real alert, beside production, with no side effects.

:class:`ShadowRunner` runs the workflow graph on one alert inside
:func:`~lg_sotf.security.shadow.shadow_scope`, with the candidate's agents
and the production services. Every egress boundary then records what it
would have done instead of doing it, and every database transaction is read
only (see :mod:`lg_sotf.security.shadow`). The run:

* starts from the alert row, like a fresh production run, under its own run
  id (``shadow/<hex>``), which the agents' contexts carry;
* keeps its checkpoints in memory (production checkpoints are untouched) and
  stops at the first interrupt: no analyst or approver answers a shadow run;
* never reserves or charges the tenant's LLM token budget, and its LLM use
  is never a billing row (``llm_usage_daily``, which also seeds the budget):
  the tokens and cost stay on the run (:class:`ShadowOutcome`);
* reads Redis through a client that refuses every write
  (:class:`~lg_sotf.queue.redis.ShadowSafeRedis`, on the same connection pool);
* answers threat-intelligence lookups from the cache only: a miss is
  ``skipped``, so a shadow verdict can see fewer threat-intelligence answers
  than production's;
* moves only the ``mode="shadow"`` metric series;
* writes one thing, after it has left shadow mode: its would-be effects, to
  ``shadow_effects`` (append-only, read by no API endpoint).

Only system code starts a shadow run: nothing in an alert or in the graph
state can enter or leave shadow mode.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver

from lg_sotf.agents.registry import AgentSet
from lg_sotf.core.graph import GraphBuilder, build_graph, initial_state
from lg_sotf.core.nodes import NodeDeps, WorkflowNodes
from lg_sotf.core.workflow import RECURSION_LIMIT
from lg_sotf.models.tenant_settings import token_budget
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.queue.redis import ShadowSafeRedis
from lg_sotf.security.shadow import SHADOW_RUN_PREFIX, ShadowEffect, ShadowRun, shadow_scope

log = get_logger(__name__)


@dataclass(frozen=True)
class ShadowOutcome:
    run_id: str
    state: Dict[str, Any]
    """The final graph state: the candidate's digests, confidence and routing decision."""
    interrupt: Optional[Dict[str, Any]]
    """The analyst decision or approval the run would have waited for (it stops there), if any."""
    effects: Tuple[ShadowEffect, ...]
    trace: Tuple[Any, ...]
    """The LLM and tool steps the agents recorded (not written to the trace store)."""
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_cost_usd: Decimal = Decimal(0)


def _interrupt(snapshot: Any) -> Optional[Dict[str, Any]]:
    for pending in getattr(snapshot, "interrupts", ()) or ():
        if isinstance(getattr(pending, "value", None), dict):
            return dict(pending.value)
    return None


class ShadowRunner:
    """Runs a candidate (``agents``, or the ones in ``deps``) on alerts in shadow mode."""

    def __init__(
        self, deps: NodeDeps, *, agents: Optional[AgentSet] = None, graph_builder: GraphBuilder = build_graph
    ) -> None:
        verdicts = deps.verdicts.with_redis(ShadowSafeRedis(connection_pool=deps.verdicts.redis.connection_pool))
        self._deps = dataclasses.replace(deps, agents=agents or deps.agents, budget=None, verdicts=verdicts)
        self._checkpoints = InMemorySaver()
        graph = graph_builder(WorkflowNodes(self._deps), self._deps.thresholds)
        self._graph = graph.compile(checkpointer=self._checkpoints)

    async def run(self, tenant_id: str, alert_id: str) -> ShadowOutcome:
        repos = self._deps.repos
        alert = await repos.alerts.get(tenant_id, alert_id)
        tenant = await repos.tenants.get(tenant_id)
        run = ShadowRun(SHADOW_RUN_PREFIX + uuid4().hex)
        config: RunnableConfig = {"configurable": {"thread_id": run.run_id}, "recursion_limit": RECURSION_LIMIT}
        state = initial_state(tenant_id, alert, llm_budget_limit=token_budget(tenant.settings))
        with bound_context(tenant_id=tenant_id, alert_id=alert_id, shadow_run_id=run.run_id):
            try:
                with shadow_scope(run):
                    await self._graph.ainvoke(state, config)
                    snapshot = await self._graph.aget_state(config)
            finally:
                await self._checkpoints.adelete_thread(run.run_id)
                # Live again: the record of what the run would have done is its only write.
                await repos.shadow_effects.append(tenant_id, alert_id, run.run_id, run.sink.effects)
            log.info("shadow.completed", effects=len(run.sink.effects), dropped=run.sink.dropped)
        return ShadowOutcome(
            run_id=run.run_id,
            state=dict(snapshot.values),
            interrupt=_interrupt(snapshot),
            effects=run.sink.effects,
            trace=tuple(run.trace),
            llm_calls=run.llm_calls,
            llm_tokens=run.llm_tokens,
            llm_cost_usd=run.llm_cost_usd,
        )
