"""Which provider and model produced each agent's output (``alerts.summary.llm_models``).

Agents record the chat model they called for an alert; evidence packs show
it per workflow step, so a reviewer can reconstruct which model (for
example a local model or a hosted one) informed each verdict. The summary
keeps the latest model per agent: ``{agent: {"provider", "model", "tier"}}``.
``model`` is the same id LLM usage is metered under (``local/<model>`` for
self-hosted providers), so provenance and usage reports agree.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from langchain_core.language_models.chat_models import BaseChatModel

from lg_sotf.llm.client import provider_of
from lg_sotf.llm.structured import usage_model_id

MAX_AGENTS = 16
_MAX_CHARS = 128


def model_provenance(model: BaseChatModel, tier: str) -> Dict[str, str]:
    """``{"provider", "model", "tier"}`` of a chat model instance (no secrets, bounded length)."""
    return {
        "provider": provider_of(model)[:_MAX_CHARS],
        "model": usage_model_id(model)[:_MAX_CHARS],
        "tier": str(tier)[:_MAX_CHARS],
    }


def merge_model_provenance(
    stored: Optional[Any], latest: Mapping[str, Mapping[str, str]]
) -> Dict[str, Dict[str, str]]:
    """Stored ``summary.llm_models`` updated with ``latest``; malformed stored values are dropped."""
    merged: Dict[str, Dict[str, str]] = {}
    if isinstance(stored, Mapping):
        for agent, entry in list(stored.items())[:MAX_AGENTS]:
            if isinstance(agent, str) and isinstance(entry, Mapping):
                merged[agent[:64]] = {str(k)[:32]: str(v)[:_MAX_CHARS] for k, v in entry.items() if isinstance(v, str)}
    for agent, entry in latest.items():
        if agent in merged or len(merged) < MAX_AGENTS:
            merged[agent[:64]] = dict(entry)
    return merged


__all__ = ["merge_model_provenance", "model_provenance"]
