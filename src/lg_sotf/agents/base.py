"""Agent base class, the per-run context and the shared LLM call helper.

Agents are stateless singletons: configuration and collaborators live on the
instance, everything about the alert being processed is passed in an
:class:`AgentContext` (or a per-run object derived from it).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Generic, List, Mapping, Optional, Type, TypeVar

from pydantic import BaseModel

from lg_sotf.core.exceptions import AgentError
from lg_sotf.llm import (
    USE_DEFAULT,
    BudgetLimit,
    LLMBudgetExceeded,
    LLMError,
    LLMRefusal,
    TokenBudget,
    ainvoke_structured,
    build_messages,
    get_chat_model,
)
from lg_sotf.llm.client import Tier
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings, get_settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


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


@dataclass
class LLMResult(Generic[T]):
    """Outcome of an optional LLM call: ``value`` or the reason it is missing."""

    value: Optional[T] = None
    skipped: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.value is not None


class BaseAgent:
    """Common configuration access for agents.

    ``config`` is the agent's section of ``settings.agents``. Legacy agents
    pass a plain dict; new agents pass ``settings`` and a ``name``.
    """

    name: str = "agent"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        settings: Optional[Settings] = None,
        name: Optional[str] = None,
    ) -> None:
        self.settings = settings or get_settings()
        if name is not None:
            self.name = name
        elif type(self).name == BaseAgent.name:
            self.name = type(self).__name__
        section = self.settings.agents.get(self.name, {}) if config is None else config
        self.config: Dict[str, Any] = dict(section or {})
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True

    async def cleanup(self) -> None:
        return None

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError(f"{type(self).__name__} does not implement execute()")

    async def health_check(self) -> bool:
        return self.initialized

    def get_config(self, key: str, default: Any = None) -> Any:
        node: Any = self.config
        for part in key.split("."):
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                return default
        return node

    def get_required_config_keys(self) -> List[str]:
        return []

    def validate_config(self) -> bool:
        missing = [k for k in self.get_required_config_keys() if k not in self.config]
        if missing:
            raise AgentError(f"agent {self.name} is missing configuration keys: {', '.join(missing)}")
        return True

    def get_metrics(self) -> Dict[str, Any]:
        return {"name": self.name, "initialized": self.initialized, "config_keys": sorted(self.config)}

    async def call_llm(
        self,
        ctx: AgentContext,
        *,
        tier: Tier,
        schema: Type[T],
        system: str,
        task: str,
        untrusted: Mapping[str, Any],
        enabled: bool = True,
    ) -> LLMResult[T]:
        """Structured LLM call that degrades to "no LLM result" for LLM-layer failures.

        Refusals, invalid output, disabled LLMs and an exhausted tenant budget
        return an empty :class:`LLMResult` so the agent falls back to its
        rules; transport errors (rate limits, timeouts, 5xx) propagate so the
        node's retry policy handles them.
        """
        if not enabled or not ctx.settings.llm.enabled:
            return LLMResult(skipped="disabled")
        if ctx.llm_budget_exceeded:
            return LLMResult(skipped="budget_exceeded")
        agent = self.name
        try:
            model = get_chat_model(tier, ctx.settings)
            messages = build_messages(system, task, untrusted, settings=ctx.settings)
            value = await ainvoke_structured(
                model,
                schema,
                messages,
                agent=agent,
                tier=tier,
                tenant_id=ctx.tenant_id,
                settings=ctx.settings,
                budget=ctx.budget,
                budget_limit=ctx.budget_limit,
            )
        except LLMBudgetExceeded:
            ctx.llm_budget_exceeded = True
            return LLMResult(skipped="budget_exceeded", notes=[f"{agent}: LLM budget exceeded, rules only"])
        except LLMRefusal as exc:
            log.warning("agent.llm_refused", agent=agent, category=exc.category)
            return LLMResult(skipped="refusal", notes=[f"{agent}: LLM declined, rules only"])
        except LLMError as exc:
            log.warning("agent.llm_unusable", agent=agent, error_type=type(exc).__name__)
            return LLMResult(skipped=type(exc).__name__, notes=[f"{agent}: LLM output unusable, rules only"])
        return LLMResult(value=value)
