"""Tool execution with timeouts and a bounded cache for read-only tools.

A cached result is reused only for the same tenant, tool and arguments, and
only for tools that are ``cacheable`` and do not read the per-call
``context`` (their output must depend on ``args`` alone).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from lg_sotf.core.exceptions import ToolError
from lg_sotf.tools.base import BaseToolAdapter
from lg_sotf.tools.cache import TTLCache


class ToolOrchestrator:
    """Registry plus executor. One instance per process; holds no per-alert state."""

    def __init__(
        self,
        tools: Iterable[BaseToolAdapter] = (),
        *,
        timeout_s: float = 30.0,
        cache: Optional[TTLCache[Dict[str, Any]]] = None,
    ) -> None:
        self._tools: Dict[str, BaseToolAdapter] = {}
        self.timeout_s = timeout_s
        self._cache = cache
        for tool in tools:
            self.register(tool)

    def register(self, tool: BaseToolAdapter) -> None:
        if tool.name in self._tools:
            raise ToolError(f"tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> BaseToolAdapter:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool {name!r}")
        return tool

    def list_tools(self) -> List[str]:
        return list(self._tools)

    @staticmethod
    def _cache_key(tenant_id: Optional[str], name: str, args: Mapping[str, Any]) -> str:
        payload = json.dumps([tenant_id, name, args], sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def execute_tool(
        self,
        name: str,
        args: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
        *,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run ``name``. Raises :class:`ToolError` for tool failures and ``TimeoutError`` on timeout."""
        tool = self.get_tool(name)
        cacheable = tool.cacheable and not tool.reads_context and self._cache is not None
        key = self._cache_key(tenant_id, name, args) if cacheable else None
        if key is not None:
            cached = self._cache.get(key)  # type: ignore[union-attr]
            if cached is not None:
                return {**cached, "cached": True}
        try:
            async with asyncio.timeout(self.timeout_s):
                result = await tool.execute(args, context)
        except (ToolError, TimeoutError):
            raise
        except (ValueError, TypeError, KeyError) as exc:
            raise ToolError(f"tool {name!r} failed: {type(exc).__name__}") from exc
        if tool.simulated:
            result = {**result, "simulated": True}
        if key is not None:
            self._cache.set(key, result)  # type: ignore[union-attr]
        return result

    async def cleanup(self) -> None:
        for tool in self._tools.values():
            await tool.cleanup()
