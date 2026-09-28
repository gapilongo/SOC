"""LLM layer: model factory, prompt builder, structured output, usage metering, fake model."""

from lg_sotf.llm.budget import USE_DEFAULT, BudgetLimit, Reservation, TokenBudget
from lg_sotf.llm.client import Tier, get_chat_model, llm_slot, reset_llm_state
from lg_sotf.llm.errors import LLMBudgetExceeded, LLMError, LLMOutputError, LLMRefusal, LLMUnavailable
from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.llm.prompting import PromptBundle, build_messages, build_prompt
from lg_sotf.llm.structured import ainvoke_structured
from lg_sotf.llm.usage import LLMUsageRow, UsageRecorder, get_usage_recorder

__all__ = [
    "USE_DEFAULT",
    "BudgetLimit",
    "FakeChatModel",
    "LLMBudgetExceeded",
    "LLMError",
    "LLMOutputError",
    "LLMRefusal",
    "LLMUnavailable",
    "LLMUsageRow",
    "PromptBundle",
    "Reservation",
    "Tier",
    "TokenBudget",
    "UsageRecorder",
    "ainvoke_structured",
    "build_messages",
    "build_prompt",
    "get_chat_model",
    "get_usage_recorder",
    "llm_slot",
    "reset_llm_state",
]
