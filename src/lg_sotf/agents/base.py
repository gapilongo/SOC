"""Agent base class, the per-run context and the shared LLM call helper.

Agents are stateless singletons: configuration and collaborators live on the
instance, everything about the alert being processed is passed in an
:class:`AgentContext` (or a per-run object derived from it).

Every LLM call goes through :meth:`BaseAgent.call_llm`, which builds the
prompt with :func:`~lg_sotf.llm.build_prompt` (fixed instructions in the
system message, alert data in a delimited untrusted block) and validates the
answer with :func:`~lg_sotf.llm.ainvoke_structured` (``json_schema``
structured output). LLM-layer failures never fail the node:

* a refusal is recorded (metric by category, ``ctx.refusals``) and the agent
  falls back to its rules, marking its digest with ``llm_refusal`` so routing
  and analysts see that the model declined;
* invalid or truncated output falls back to rules;
* an exhausted tenant budget sets ``ctx.llm_budget_exceeded`` (no further
  calls for this alert) and is written to ``summary.llm_budget_exceeded``.

Transport errors (rate limits, timeouts, 5xx) propagate so the node's retry
policy handles them. Token and cost totals of every call are accumulated in
``ctx.usage`` and added to ``alerts.summary.llm_usage`` by
:func:`persist_llm_accounting`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, Generic, List, Mapping, Optional, Type, TypeVar

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import BaseModel

from lg_sotf.llm import (
    USE_DEFAULT,
    BudgetLimit,
    LLMBudgetExceeded,
    LLMError,
    LLMRefusal,
    TokenBudget,
    UsageTally,
    ainvoke_structured,
    build_prompt,
    get_chat_model,
    merge_usage_summary,
)
from lg_sotf.llm.client import Tier
from lg_sotf.llm.provenance import merge_model_provenance, model_provenance
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import record_llm_refusal, record_llm_skipped
from lg_sotf.settings import Settings, get_settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)
ModelFactory = Callable[[Tier, Settings], BaseChatModel]

MAX_REFUSALS_KEPT = 10
REFUSAL_NOTE = "model declined to analyse this alert; rule-based assessment used, analyst review advised"


@dataclass
class AgentContext:
    """Everything an agent needs about one alert run. Created per node invocation."""

    tenant_id: str
    alert_id: str
    settings: Settings
    repos: Optional[Repositories] = None
    budget: Optional[TokenBudget] = None
    budget_limit: BudgetLimit = USE_DEFAULT
    llm_budget_exceeded: bool = False
    usage: UsageTally = field(default_factory=UsageTally)
    refusals: List[Dict[str, Optional[str]]] = field(default_factory=list)
    models: Dict[str, Dict[str, str]] = field(default_factory=dict)
    """Provider and model each agent called (``summary.llm_models``, evidence packs)."""
    # False for a replay (the history backtest): agents read through ``repos`` but write nothing,
    # neither LLM accounting on the alert nor indicator sightings.
    persist: bool = True


@dataclass
class LLMResult(Generic[T]):
    """Outcome of an optional LLM call: ``value`` or the reason it is missing."""

    value: Optional[T] = None
    skipped: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    refusal_category: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.value is not None

    @property
    def refused(self) -> bool:
        return self.skipped == "refusal"


class BaseAgent:
    """Common configuration access for agents.

    ``config`` is the agent's section of ``settings.agents`` unless given
    explicitly (tests pass a plain dict).
    ``model_factory`` replaces :func:`~lg_sotf.llm.get_chat_model` (tests,
    evaluation harness).
    """

    name: str = "agent"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        settings: Optional[Settings] = None,
        name: Optional[str] = None,
        model_factory: Optional[ModelFactory] = None,
    ) -> None:
        self.settings = settings or get_settings()
        if name is not None:
            self.name = name
        elif type(self).name == BaseAgent.name:
            self.name = type(self).__name__
        section = self.settings.agents.get(self.name, {}) if config is None else config
        self.config: Dict[str, Any] = dict(section or {})
        self.model_factory: ModelFactory = model_factory or get_chat_model
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True

    async def cleanup(self) -> None:
        return None

    def get_config(self, key: str, default: Any = None) -> Any:
        node: Any = self.config
        for part in key.split("."):
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                return default
        return node

    def skip_llm(self, reason: str, note: Optional[str] = None) -> LLMResult[Any]:
        """An LLM call deliberately not made (counted in ``lgsotf_llm_skipped_total``)."""
        record_llm_skipped(self.name, reason)
        return LLMResult(skipped=reason, notes=[note] if note else [])

    async def call_llm(
        self,
        ctx: AgentContext,
        *,
        tier: Tier,
        schema: Type[T],
        system: str,
        task: str,
        untrusted: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
        cache_untrusted: bool = False,
        enabled: bool = True,
    ) -> LLMResult[T]:
        """Structured LLM call that degrades to "no LLM result" for LLM-layer failures (see module docs)."""
        if not enabled or not ctx.settings.llm.enabled:
            return self.skip_llm("disabled")
        if ctx.llm_budget_exceeded:
            return self.skip_llm("budget_exceeded", f"{self.name}: LLM budget exceeded, rules only")
        agent = self.name
        try:
            model = self.model_factory(tier, ctx.settings)
            ctx.models[agent] = model_provenance(model, tier)
            prompt = build_prompt(
                system, task, untrusted, context=context, cache_untrusted=cache_untrusted, settings=ctx.settings
            )
            value = await ainvoke_structured(
                model,
                schema,
                prompt.messages,
                agent=agent,
                tier=tier,
                tenant_id=ctx.tenant_id,
                settings=ctx.settings,
                budget=ctx.budget,
                budget_limit=ctx.budget_limit,
                tally=ctx.usage,
            )
        except LLMBudgetExceeded:
            ctx.llm_budget_exceeded = True
            record_llm_skipped(agent, "budget_exceeded")
            return LLMResult(skipped="budget_exceeded", notes=[f"{agent}: LLM budget exceeded, rules only"])
        except LLMRefusal as exc:
            record_llm_refusal(agent, exc.category)
            category = str(exc.category)[:32] if exc.category is not None else None
            if len(ctx.refusals) < MAX_REFUSALS_KEPT:
                ctx.refusals.append({"agent": agent, "category": category})
            log.warning("agent.llm_refused", agent=agent, category=category)
            return LLMResult(skipped="refusal", notes=[f"{agent}: {REFUSAL_NOTE}"], refusal_category=category)
        except LLMError as exc:
            log_failure(log, "agent.llm_unusable", exc, level="warning", agent=agent, error_type=type(exc).__name__)
            return LLMResult(skipped=type(exc).__name__, notes=[f"{agent}: LLM output unusable, rules only"])
        return LLMResult(value=value)


def refusal_digest(result: LLMResult[Any]) -> Optional[Dict[str, Optional[str]]]:
    """The ``llm_refusal`` entry agents put in their digest when the model declined."""
    if not result.refused:
        return None
    return {"reason": "model_refused", "category": result.refusal_category}


async def persist_llm_accounting(ctx: AgentContext, *, budget_was_exceeded: bool) -> None:
    """Add this run's LLM usage to ``alerts.summary.llm_usage`` (and budget/refusal flags, models used).

    Writes nothing for a context with ``persist=False``, or when the run made
    no LLM call, hit no budget limit and saw no refusal. Nodes of one alert run one at a time, so the read-add-write
    in one transaction cannot interleave with another agent's update.
    """
    newly_exceeded = ctx.llm_budget_exceeded and not budget_was_exceeded
    if not ctx.persist or ctx.repos is None or (
        ctx.usage.is_empty() and not newly_exceeded and not ctx.refusals and not ctx.models
    ):
        return
    repos = ctx.repos
    async with repos.db.tenant_tx(ctx.tenant_id) as conn:
        alert = await repos.alerts.get(ctx.tenant_id, ctx.alert_id, conn=conn)
        summary = alert.summary if isinstance(alert.summary, Mapping) else {}
        patch: Dict[str, Any] = {}
        if not ctx.usage.is_empty():
            patch["llm_usage"] = merge_usage_summary(summary.get("llm_usage"), ctx.usage)
        if ctx.llm_budget_exceeded:
            patch["llm_budget_exceeded"] = True
        if ctx.refusals:
            previous = summary.get("llm_refusals")
            kept = [r for r in previous if isinstance(r, Mapping)] if isinstance(previous, list) else []
            patch["llm_refusals"] = [*kept, *ctx.refusals][-MAX_REFUSALS_KEPT:]
        if ctx.models:
            patch["llm_models"] = merge_model_provenance(summary.get("llm_models"), ctx.models)
        await repos.alerts.update(ctx.tenant_id, ctx.alert_id, summary=patch, conn=conn)


class AccountedRun:
    """``async with AccountedRun(ctx):`` persists LLM accounting when the block ends.

    On an exception the accounting is written best-effort (a failure to
    write it never replaces the original error); cancellation writes nothing.
    """

    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx
        self._budget_was_exceeded = ctx.llm_budget_exceeded

    async def __aenter__(self) -> AgentContext:
        return self.ctx

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is None:
            await persist_llm_accounting(self.ctx, budget_was_exceeded=self._budget_was_exceeded)
            return
        if isinstance(exc, Exception):
            try:
                await persist_llm_accounting(self.ctx, budget_was_exceeded=self._budget_was_exceeded)
            except Exception as persist_exc:  # noqa: BLE001 - never mask the run's own error
                log_failure(
                    log, "agent.llm_accounting_failed", persist_exc, level="warning",
                    error_type=type(persist_exc).__name__,
                )
