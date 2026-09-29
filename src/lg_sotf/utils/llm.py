"""Compatibility shim for agents that predate :mod:`lg_sotf.llm`.

New code should call :func:`lg_sotf.llm.get_chat_model` with an explicit tier
and :func:`lg_sotf.llm.ainvoke_structured` for validated output.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from langchain_core.language_models.chat_models import BaseChatModel

from lg_sotf.llm.client import get_chat_model

if TYPE_CHECKING:
    from lg_sotf.core.config.manager import ConfigManager


def get_llm_client(config_manager: Optional[ConfigManager] = None) -> BaseChatModel:
    """Fast-tier chat model. Raises :class:`lg_sotf.llm.LLMUnavailable` when disabled or misconfigured."""
    settings = config_manager.settings if config_manager is not None else None
    return get_chat_model("fast", settings=settings)
