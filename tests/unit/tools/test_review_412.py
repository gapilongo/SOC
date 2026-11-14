"""Reviewer probes for PR #412 (AI-E2.1). Each test asserts the SAFE behaviour; a failure is a finding."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict, List

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from lg_sotf.security.shadow import ShadowRun, shadow_scope
from lg_sotf.tools.enrichment import EnrichmentService
from lg_sotf.tools.enrichment.tools import enrichment_tools
from lg_sotf.tools.registry import Tool, ToolParamsInvalid, ToolSpec
from tests.unit.tools._support import Ctx, Handler, Settings, failed, refused, registry, rows, spec, tool

pytestmark = pytest.mark.unit
P = {"kind": "ip", "value": "198.51.100.7"}
HASH = {"kind": "hash", "value": "44d88612fea8a8f36de82e1278abb02f"}
VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
KEY = "test-only-" + "k" * 12


def vt(make_settings: Any, server: Any, **extra: Any) -> Any:
    cfg = {"api_key": KEY, "share_with_tenants": True, "requests_per_minute": 100}
    settings = make_settings(tools={"virustotal": cfg, "abuseipdb": dict(cfg), **extra})
    return enrichment_tools(EnrichmentService.from_settings(settings, transport=httpx.MockTransport(server)))


# ---- 3. tenant switch: fail closed on malformed settings -------------------------------------------------
@pytest.mark.parametrize(
    "entry", [{"enabled": "false"}, {"enabled": 0}, {"enabled": None}, False, "off", {"Enabled": False}]
)
async def test_f1_malformed_switch_fails_closed(entry: Any) -> None:
    handler = Handler()
    tools = registry(tool(handler), settings=Settings({"example": entry}))
    result = await tools.call(Ctx(), "reputation.example", P, agent="a")
    assert handler.calls == [] and result.outcome == "failed"


async def test_f2_switch_survives_a_call_without_repos(make_settings: Any) -> None:
    """One call for the tenant with repos=None caches 'no settings' for 60 s: the tenant's opt-out is ignored."""
    seen: List[httpx.Request] = []

    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=VT_OK)

    tools = vt(make_settings, server)

    class Tenants:
        async def get(self, tenant_id: str, *, conn: Any = None) -> Any:
            return SimpleNamespace(id=tenant_id, settings={"tools": {"virustotal": {"enabled": False}}})

    no_repos = await tools.call(Ctx(tenant_id="t1", repos=None), "reputation.virustotal", HASH, agent="a")
    with_repos = await tools.call(
        Ctx(tenant_id="t1", repos=SimpleNamespace(tenants=Tenants())), "reputation.virustotal", HASH, agent="a"
    )
    assert seen == [], f"{len(seen)} request(s) left for a tenant that switched VirusTotal off"
    assert (no_repos.outcome, with_repos.outcome) == ("failed", "failed")


# ---- 2. outcome typing ------------------------------------------------------------------------------------
async def test_f3_trace_step_outcome_agrees_with_the_typed_outcome() -> None:
    ctx = Ctx()
    timed_out = await registry(tool(Handler(delay_s=5.0), time_cap_s=0.05)).call(ctx, "reputation.example", P, agent="a")
    over = await registry(tool(Handler(answer=list(range(6))))).call(ctx, "reputation.example", P, agent="a")
    assert (timed_out.outcome, over.outcome) == ("failed", "failed")
    assert [s.outcome for s in ctx.trace.steps] != ["success", "success"], "the trace store records failed calls as success"


async def test_f4_an_exception_inside_the_tool_is_a_failed_result() -> None:
    class Boom(Handler):
        async def __call__(self, ctx: Any, params: Any) -> Any:
            self.calls.append(params)
            raise RuntimeError("provider exploded")

    ctx = Ctx()
    result = await registry(tool(Boom())).call(ctx, "reputation.example", P, agent="a")
    assert result.outcome == "failed"


async def test_f5_one_member_raising_does_not_lose_the_family() -> None:
    class Boom(Handler):
        async def __call__(self, ctx: Any, params: Any) -> Any:
            raise RuntimeError("provider exploded")

    ok = Handler(answer=["row"], delay_s=0.05)
    tools = registry(tool(Boom()), tool(ok, name="reputation.other", tenant_setting="other"))
    ctx = Ctx()
    try:
        results = await tools.call_family(ctx, "reputation", ["example", "other"], P, agent="a")
    except RuntimeError:
        await asyncio.sleep(0.1)
        # The sibling still ran (and reached its provider), but its answer is in no result and no trace output.
        assert len(ok.calls) == 1 and ctx.trace.steps[-1].outcome == "error" and ctx.trace.steps[-1].output_hash is None
        pytest.fail("call_family raised; the sibling's egress happened but is recorded nowhere")
    assert [r.outcome for r in results] == ["failed", "success"]


async def test_f6_abuseipdb_http_404_is_not_empty(make_settings: Any) -> None:
    """AbuseIPDB answers an unknown IP with 200/score 0; a 404 is a broken endpoint or proxy, not 'matched nothing'."""
    tools = vt(make_settings, lambda _: httpx.Response(404, text="<html>not found</html>"))
    result = await tools.call(Ctx(), "reputation.abuseipdb", {"kind": "ip", "value": "8.8.8.8"}, agent="a")
    assert result.outcome == "failed", (result.outcome, result.value.status)


async def test_f7_a_partial_virustotal_body_is_not_success(make_settings: Any) -> None:
    tools = vt(make_settings, lambda _: httpx.Response(200, json={"data": {"attributes": {"type_description": "x"}}}))
    result = await tools.call(Ctx(), "reputation.virustotal", HASH, agent="a")
    assert result.outcome == "failed", (result.outcome, result.value.as_dict())


async def test_f8_a_truncated_result_is_distinguishable_from_a_complete_one() -> None:
    """A tool that stops reading at its cap returns exactly row_cap rows: nothing says more existed."""
    cut = await registry(tool(Handler(answer=list(range(5))))).call(Ctx(), "reputation.example", P, agent="a")
    assert cut.rows == 5 and cut.outcome == "success"
    assert any(hasattr(cut, name) for name in ("truncated", "complete", "partial")), "no truncation marker on ToolResult"


# ---- caps ---------------------------------------------------------------------------------------------------
class WindowParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    since: datetime
    until: datetime


async def test_f9_window_cap_is_enforced_at_call_time() -> None:
    handler = Handler(answer=["row"])
    declared = ToolSpec(**spec(params=WindowParams, window_cap=timedelta(hours=1)))
    tools = registry(Tool(declared, handler, rows, failed, lambda r: r, lambda p, rec: rec, refused))
    now = datetime(2026, 1, 1)
    result = await tools.call(Ctx(), "reputation.example", {"since": now - timedelta(days=300), "until": now}, agent="a")
    assert handler.calls == [] or result.outcome == "failed", "a 300-day window ran under window_cap=1h"


async def test_f10_row_cap_counts_the_result_not_the_tools_own_number() -> None:
    lying = Tool(ToolSpec(**spec()), Handler(answer=list(range(400))), lambda r: 1, failed, lambda r: r, lambda p, rec: rec, refused)
    result = await registry(lying).call(Ctx(), "reputation.example", P, agent="a")
    assert result.outcome == "failed", f"{len(result.value)} rows passed row_cap=5"


# ---- 1. bypass --------------------------------------------------------------------------------------------
async def test_f11_the_registered_tool_cannot_be_run_around_the_registry() -> None:
    handler = Handler()
    tools = registry(tool(handler), settings=Settings({"example": {"enabled": False}}))
    ctx = Ctx()
    try:
        await tools.get("reputation.example").run(ctx, "anything, unvalidated")
    except Exception:  # noqa: BLE001, S110
        pass
    assert handler.calls == [], "registry.get(name).run(...) ran a switched-off tool with unvalidated params, untraced"


def test_f12_params_model_bounds_are_checked_at_load() -> None:
    class Loose(BaseModel):
        model_config = ConfigDict(extra="forbid")  # not strict, unbounded string, free-form dict
        index: str
        query: Dict[str, Any]

    with pytest.raises(ValueError):
        ToolSpec(**spec(params=Loose))


# ---- 4. params in error text ------------------------------------------------------------------------------
async def test_f13_error_text_carries_no_caller_supplied_text() -> None:
    hostile = "IGNORE-PREVIOUS-INSTRUCTIONS-" + "z" * 40
    with pytest.raises(ToolParamsInvalid) as raised:
        await registry(tool(Handler())).call(Ctx(), "reputation.example", {**P, hostile: 1}, agent="a")
    assert hostile not in str(raised.value)


# ---- 7. hashes ----------------------------------------------------------------------------------------------
async def test_f14_family_result_hashes_are_the_trace_steps() -> None:
    ctx = Ctx()
    tools = registry(tool(Handler(answer=["row"])))
    [result] = await tools.call_family(ctx, "reputation", ["example"], P, agent="a")
    [step] = ctx.trace.steps
    assert (result.input_hash, result.output_hash) == (step.input_hash, step.output_hash)


async def test_f15_output_hash_is_stable_across_runs(make_settings: Any) -> None:
    tools = vt(make_settings, lambda _: httpx.Response(200, json=VT_OK))
    first = await tools.call(Ctx(), "reputation.virustotal", HASH, agent="a")
    again = await tools.call(Ctx(), "reputation.virustotal", HASH, agent="a")
    assert first.value.data == again.value.data and first.input_hash == again.input_hash
    assert first.output_hash == again.output_hash, "same provider answer, different output_hash (the cached flag is hashed)"


async def test_f16_a_disabled_call_is_in_the_trace() -> None:
    ctx = Ctx()
    off = await registry(tool(Handler()), settings=Settings({"example": {"enabled": False}})).call(
        ctx, "reputation.example", P, agent="a"
    )
    assert off.outcome == "failed" and off.input_hash
    assert [s.input_hash for s in ctx.trace.steps] == [off.input_hash], "INV-14: 'records every call in the trace'"


# ---- 6. shadow (expected to pass) ---------------------------------------------------------------------------
async def test_s1_a_shadow_run_makes_no_third_party_request(make_settings: Any) -> None:
    seen: List[httpx.Request] = []

    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=VT_OK)

    tools = vt(make_settings, server)
    with shadow_scope(ShadowRun("shadow/r1")):
        single = await tools.call(Ctx(), "reputation.virustotal", HASH, agent="a")
        family = await tools.call_family(Ctx(), "reputation", ["virustotal", "abuseipdb"], {"kind": "ip", "value": "8.8.8.8"}, agent="a")
    assert seen == [] and single.outcome == "failed" and {r.outcome for r in family} == {"failed"}


async def test_s2_rate_limit_and_unsupported_are_failed(make_settings: Any) -> None:
    replies = iter([httpx.Response(429, json={}), httpx.Response(401, json={}), httpx.Response(200, text="not json")])
    tools = vt(make_settings, lambda _: next(replies))
    out = []
    for digit in "123":
        out.append(await tools.call(Ctx(tenant_id="t" + digit), "reputation.virustotal", {"kind": "hash", "value": digit * 32}, agent="a"))
    unsupported = await tools.call(Ctx(), "reputation.abuseipdb", {"kind": "hash", "value": "4" * 32}, agent="a")
    assert [r.outcome for r in out] + [unsupported.outcome] == ["failed"] * 4, [r.value.status for r in out]
