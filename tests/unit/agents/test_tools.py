"""Tool orchestrator: bounded TTL cache for read-only tools only, timeouts, error wrapping."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Mapping, Optional

import pytest

from lg_sotf.core.exceptions import ToolError
from lg_sotf.tools import BaseToolAdapter, ToolOrchestrator, TTLCache


class Counting(BaseToolAdapter):
    def __init__(self, name: str, cacheable: bool) -> None:
        super().__init__()
        self.name = name
        self.cacheable = cacheable
        self.calls: List[Mapping[str, Any]] = []

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        self.calls.append(args)
        return {"n": len(self.calls)}


class Slow(BaseToolAdapter):
    name = "slow"

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        await asyncio.sleep(1)
        return {}


class Broken(BaseToolAdapter):
    name = "broken"

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        raise KeyError("x")


def test_ttl_cache_is_bounded_and_expires() -> None:
    now = [0.0]
    cache: TTLCache[int] = TTLCache(maxsize=2, ttl_s=10, clock=lambda: now[0])
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")
    cache.set("c", 3)
    assert len(cache) == 2 and cache.get("b") is None and cache.get("a") == 1
    now[0] = 11
    assert cache.get("a") is None


async def test_only_cacheable_tools_are_cached() -> None:
    lookup, action = Counting("lookup", True), Counting("action", False)
    orch = ToolOrchestrator([lookup, action], cache=TTLCache(maxsize=8, ttl_s=60))
    await orch.execute_tool("lookup", {"target": "x"})
    assert (await orch.execute_tool("lookup", {"target": "x"}))["cached"] is True
    await orch.execute_tool("action", {"target": "x"})
    await orch.execute_tool("action", {"target": "x"})
    assert len(lookup.calls) == 1 and len(action.calls) == 2


class ContextReader(Counting):
    reads_context = True


async def test_cache_is_per_tenant_and_skips_tools_that_read_context() -> None:
    lookup, reader = Counting("lookup", True), ContextReader("reader", True)
    orch = ToolOrchestrator([lookup, reader], cache=TTLCache(maxsize=8, ttl_s=60))
    await orch.execute_tool("lookup", {"target": "x"}, tenant_id="t1")
    other = await orch.execute_tool("lookup", {"target": "x"}, tenant_id="t2")
    same = await orch.execute_tool("lookup", {"target": "x"}, tenant_id="t1")
    assert "cached" not in other and same["cached"] is True and len(lookup.calls) == 2
    await orch.execute_tool("reader", {"target": "x"}, {"raw": {"p": 1}}, tenant_id="t1")
    second = await orch.execute_tool("reader", {"target": "x"}, {"raw": {"p": 2}}, tenant_id="t1")
    assert "cached" not in second and len(reader.calls) == 2


async def test_errors() -> None:
    orch = ToolOrchestrator([Slow(), Broken()], timeout_s=0.05)
    with pytest.raises(TimeoutError):
        await orch.execute_tool("slow", {})
    with pytest.raises(ToolError):
        await orch.execute_tool("broken", {})
    with pytest.raises(ToolError):
        await orch.execute_tool("missing", {})
    with pytest.raises(ToolError):
        orch.register(Broken())
