"""Shared by the tool registry tests: a parameter model, a run context, tool and settings stand-ins."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Mapping, Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.llm.trace import TraceRecorder
from lg_sotf.tools.enrichment import EnrichmentService
from lg_sotf.tools.enrichment.tools import enrichment_tools
from lg_sotf.tools.registry import Tool, ToolError, ToolRegistry, ToolSpec

P = {"kind": "ip", "value": "198.51.100.7"}
HASH = {"kind": "hash", "value": "44d88612fea8a8f36de82e1278abb02f"}
VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
KEY = "test-only-" + "k" * 12


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: str = Field(max_length=8)
    value: str = Field(min_length=1, max_length=64)


class WindowParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    since: datetime
    until: datetime


@dataclass
class Ctx:
    tenant_id: str = "t1"
    alert_id: str = "a1"
    repos: Any = None
    trace: TraceRecorder = field(default_factory=TraceRecorder)


def spec(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "name": "reputation.example",
        "version": 1,
        "risk": "read_external",
        "params": Params,
        "produces": frozenset({"reputation"}),
        "row_cap": 5,
        "time_cap_s": 1.0,
        "window_cap": None,
        "egress": "third_party",
        "shadow": "cache_only",
        "tenant_setting": "example",
        "egress_boundary": "enrichment_lookup",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not ...}


PLATFORM = {
    "name": "platform.example", "risk": "read_internal", "egress": "platform", "shadow": "live",
    "tenant_setting": None, "egress_boundary": None,
}


class Handler:
    def __init__(self, answer: Any = "ok", delay_s: float = 0.0) -> None:
        self.answer = answer
        self.delay_s = delay_s
        self.calls: List[Any] = []

    async def __call__(self, ctx: Any, params: Any) -> Any:
        self.calls.append(params)
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        return self.answer


class Boom(Handler):
    async def __call__(self, ctx: Any, params: Any) -> Any:
        self.calls.append(params)
        raise RuntimeError("provider exploded at 198.51.100.7")


def rows(result: Any) -> int:
    return len(result) if isinstance(result, list) else 1


def failed(result: Any) -> bool:
    return isinstance(result, dict) and "refused" in result


def refused(params: Any, error: ToolError) -> Dict[str, Any]:
    return {"refused": type(error).__name__}


def tool(handler: Handler, **overrides: Any) -> Tool[Any, Any]:
    return Tool(ToolSpec(**spec(**overrides)), handler, rows, failed, lambda r: r, lambda params, rec: rec, refused)


def bare(declared: ToolSpec) -> Tool[Any, Any]:
    return Tool(declared, Handler(), rows, failed, str, lambda params, rec: rec, refused)


class Settings:
    """The tenant's ``tools`` section (``None``: it cannot be read), counting reads."""

    def __init__(self, tools: Optional[Mapping[str, Any]] = None, *, readable: bool = True) -> None:
        self.tools = dict(tools or {})
        self.readable = readable
        self.reads = 0

    async def __call__(self, tenant_id: str, repos: Any) -> Optional[Mapping[str, Any]]:
        self.reads += 1
        return self.tools if self.readable else None


def registry(*tools: Tool[Any, Any], settings: Optional[Settings] = None) -> ToolRegistry:
    out = ToolRegistry(settings or Settings())
    for t in tools:
        out.register(t)
    return out


def repos_with(stored: Mapping[str, Any]) -> Any:
    """Repositories whose tenants have the ``settings`` in ``stored`` (by tenant id; others have none)."""

    class Tenants:
        async def get(self, tenant_id: str, *, conn: Any = None) -> Any:
            return SimpleNamespace(id=tenant_id, settings=stored.get(tenant_id, {}))

    return SimpleNamespace(tenants=Tenants())


def lookup_service(make_settings: Any, server: Callable[[httpx.Request], httpx.Response]) -> EnrichmentService:
    """The enrichment service against a fake VirusTotal and AbuseIPDB."""
    cfg = {"api_key": KEY, "share_with_tenants": True, "requests_per_minute": 100}
    settings = make_settings(tools={"virustotal": cfg, "abuseipdb": dict(cfg)})
    return EnrichmentService.from_settings(settings, transport=httpx.MockTransport(server))


def lookups(make_settings: Any, server: Callable[[httpx.Request], httpx.Response]) -> ToolRegistry:
    """Today's lookups against a fake VirusTotal and AbuseIPDB."""
    return enrichment_tools(lookup_service(make_settings, server))
