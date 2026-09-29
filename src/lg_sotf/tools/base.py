"""Tool adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping, Optional


class BaseToolAdapter(ABC):
    """A tool the analysis agent can call.

    ``cacheable`` tools are pure lookups of ``args`` whose results may be
    reused for a short time. Tools with side effects must leave it
    ``False``; response actions never go through tools (they use the ledger
    and connectors). Tools that read ``context`` must set ``reads_context``,
    which disables caching for them.
    ``simulated`` tools return synthetic data and every result they produce
    carries ``"simulated": True``.
    """

    name: str = "tool"
    description: str = ""
    cacheable: bool = False
    reads_context: bool = False
    simulated: bool = False

    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = dict(config or {})

    @abstractmethod
    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Run the tool. ``args["target"]`` is the indicator being examined."""

    async def cleanup(self) -> None:
        return None
