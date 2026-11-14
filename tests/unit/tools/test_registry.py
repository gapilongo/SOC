"""The tool registry (AI-E2.1): declaration rules at load, and the order of the checks on every call."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

import lg_sotf.tools.enrichment.service  # noqa: F401  (registers the enrichment_lookup egress boundary)
from lg_sotf.llm.trace import TraceRecorder, tool_input_hash
from lg_sotf.llm.trace import content_hash as tool_output_hash
from lg_sotf.security.shadow import EGRESS_POINTS
from lg_sotf.tools.registry import (
    Tool,
    ToolDisabled,
    ToolError,
    ToolNotFound,
    ToolParamsInvalid,
    ToolRegistry,
    ToolRowCapExceeded,
    ToolSpec,
    ToolTimedOut,
)

pytestmark = pytest.mark.unit


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: str = Field(max_length=8)
    value: str = Field(min_length=1, max_length=64)


class LaxParams(BaseModel):
    kind: str


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
    """The tenant's ``tools`` section, counting reads."""

    def __init__(self, tools: Optional[Mapping[str, Any]] = None) -> None:
        self.tools = dict(tools or {})
        self.reads = 0

    async def __call__(self, tenant_id: str, repos: Any) -> Mapping[str, Any]:
        self.reads += 1
        return self.tools


def registry(*tools: Tool[Any, Any], settings: Optional[Settings] = None) -> ToolRegistry:
    out = ToolRegistry(settings or Settings())
    for t in tools:
        out.register(t)
    return out


@pytest.mark.parametrize("missing", ["row_cap", "time_cap_s", "window_cap", "params", "produces", "tenant_setting"])
def test_a_tool_missing_caps_or_schema_fails_to_load(missing: str) -> None:
    with pytest.raises(ValidationError):
        ToolSpec(**spec(**{missing: ...}))
    # A hand-built declaration does not skip the rules: the registry validates it again.
    fields = {k: v for k, v in spec().items() if k != missing}
    with pytest.raises(ValueError, match="does not load"):
        registry(bare(ToolSpec.model_construct(**fields)))


@pytest.mark.parametrize(
    "overrides",
    [
        {"params": LaxParams},  # unknown keys would be ignored, not refused
        {"params": dict},
        {"row_cap": 0},
        {"row_cap": 100_000},
        {"time_cap_s": 0},
        {"time_cap_s": 3_600.0},
        {"window_cap": timedelta(days=4_000)},
        {"produces": frozenset({"raw_rows"})},
        {"name": "no_namespace"},
    ],
)
def test_an_uncapped_or_unschemaed_declaration_fails_to_load(overrides: Dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ToolSpec(**spec(**overrides))


@pytest.mark.parametrize("risk", ["write", "read_write", "execute", "delete"])
def test_no_tool_can_register_a_write_risk_class(risk: str) -> None:
    with pytest.raises(ValidationError):
        ToolSpec(**spec(risk=risk))
    with pytest.raises(ValueError, match="does not load"):
        registry(bare(ToolSpec.model_construct(**spec(risk=risk))))


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"shadow": "live"}, "cache_only in shadow runs"),
        ({"tenant_setting": None}, "has a tenant_setting"),
        ({"risk": "read_internal"}, "goes with egress third_party"),
        ({"egress": "platform", "egress_boundary": None}, "goes with egress third_party"),
        ({"egress_boundary": None}, "names its egress boundary"),
        ({"egress": "tenant_source", "risk": "read_internal", "egress_boundary": None}, "names its egress boundary"),
    ],
)
def test_egress_is_declared_and_coherent(overrides: Dict[str, Any], problem: str) -> None:
    with pytest.raises(ValidationError, match=problem):
        ToolSpec(**spec(**overrides))


def test_the_egress_boundary_exists_and_diverts_for_a_cache_only_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="no @egress boundary"):
        registry(tool(Handler(), egress_boundary="nowhere"))
    allowing = [k for k, p in EGRESS_POINTS.items() if p.policy.action == "allow"]
    if allowing:
        with pytest.raises(ValueError, match="must divert"):
            registry(tool(Handler(), egress_boundary=EGRESS_POINTS[allowing[0]].boundary))
    with pytest.raises(ValueError, match="registered twice"):
        registry(tool(Handler()), tool(Handler()))


async def test_parameters_are_validated_before_the_call() -> None:
    handler = Handler()
    settings = Settings()
    ctx = Ctx()
    tools = registry(tool(handler), settings=settings)
    secret = "test-only-" + "x" * 80
    for params in (
        {"kind": "ip", "value": "198.51.100.7", "extra": 1},  # unknown key
        {"kind": "ip", "value": 7},  # wrong type, no coercion
        {"kind": "ip", "value": secret},  # too long
        {"kind": "ip"},  # missing
    ):
        with pytest.raises(ToolParamsInvalid) as raised:
            await tools.call(ctx, "reputation.example", params, agent="analysis")
        assert secret not in str(raised.value)
        with pytest.raises(ToolParamsInvalid):
            await tools.call_family(ctx, "reputation", ["example"], params, agent="analysis")
    # Nothing ran: no handler call, no tenant-settings read, no trace step.
    assert handler.calls == [] and settings.reads == 0 and ctx.trace.steps == []
    with pytest.raises(ToolNotFound):
        await tools.call(ctx, "reputation.other", {"kind": "ip", "value": "x"}, agent="analysis")

    done = await tools.call(ctx, "reputation.example", {"kind": "ip", "value": "198.51.100.7"}, agent="analysis")
    assert done.value == "ok" and done.outcome == "success"
    assert [p.model_dump() for p in handler.calls] == [{"kind": "ip", "value": "198.51.100.7"}]
    [step] = ctx.trace.steps
    assert step.tool == "reputation.example" and step.agent == "analysis" and step.outcome == "success"
    assert step.input_hash == tool_input_hash("reputation.example", {"kind": "ip", "value": "198.51.100.7"})


async def test_a_tool_disabled_for_the_tenant_is_not_called() -> None:
    off, on = Handler(), Handler()
    settings = Settings({"example": {"enabled": False}, "other": {"enabled": True}})
    ctx = Ctx()
    tools = registry(tool(off), tool(on, name="reputation.other", tenant_setting="other"), settings=settings)
    params = {"kind": "ip", "value": "198.51.100.7"}

    refusal = await tools.call(ctx, "reputation.example", params, agent="analysis")
    assert refusal.value == {"refused": "ToolDisabled"} and refusal.outcome == "failed"
    assert off.calls == [] and ctx.trace.steps == []

    results = await tools.call_family(ctx, "reputation", ["example", "other"], params, agent="analysis")
    assert [(r.value, r.outcome) for r in results] == [({"refused": "ToolDisabled"}, "failed"), ("ok", "success")]
    assert off.calls == [] and len(on.calls) == 1
    [step] = ctx.trace.steps
    assert step.tool == "reputation"
    assert step.input_hash == tool_input_hash("reputation", {**params, "providers": ["example", "other"]})

    # A tool without a tenant switch reads no tenant setting.
    always = Handler()
    platform = tool(always, name="platform.example", risk="read_internal", egress="platform", shadow="live",
                    tenant_setting=None, egress_boundary=None, trace_name="example")
    reads = settings.reads
    assert (await registry(platform, settings=settings).call(ctx, "platform.example", params, agent="a")).value == "ok"
    assert settings.reads == reads and ctx.trace.steps[-1].tool == "example"
    assert isinstance(ToolDisabled("x"), ToolError)


async def test_a_tenant_switch_applies_to_that_tenant_only(make_settings: Any) -> None:
    """The switch is read from the calling tenant's own settings: t1 turning VirusTotal off stops t1 only."""
    from lg_sotf.tools.enrichment import EnrichmentService
    from lg_sotf.tools.enrichment.tools import enrichment_tools

    seen: List[httpx.Request] = []

    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}})

    key = "test-only-" + "k" * 12
    settings = make_settings(tools={"virustotal": {"api_key": key, "share_with_tenants": True, "requests_per_minute": 100}})
    tools = enrichment_tools(EnrichmentService.from_settings(settings, transport=httpx.MockTransport(server)))
    stored = {"t1": {"tools": {"virustotal": {"enabled": False}}}, "t2": {"tools": {"virustotal": {"enabled": True}}}}

    class Tenants:
        async def get(self, tenant_id: str, *, conn: Any = None) -> Any:
            return SimpleNamespace(id=tenant_id, settings=stored.get(tenant_id, {}))

    repos = SimpleNamespace(tenants=Tenants())
    t1, t2 = Ctx(tenant_id="t1", repos=repos), Ctx(tenant_id="t2", repos=repos)
    params = {"kind": "hash", "value": "44d88612fea8a8f36de82e1278abb02f"}

    assert (await tools.call(t1, "reputation.virustotal", params, agent="analysis")).value.status == "not_configured"
    assert (await tools.call(t2, "reputation.virustotal", params, agent="analysis")).value.status == "ok"
    # t2 having it on did not turn it on for t1: the registry refused t1 before the tool, the trace or the network.
    assert (await tools.call(t1, "reputation.virustotal", params, agent="analysis")).outcome == "failed"
    assert len(seen) == 1 and t1.trace.steps == [] and [s.tool for s in t2.trace.steps] == ["reputation.virustotal"]


async def test_time_and_row_caps_answer_with_the_refusal() -> None:
    ctx = Ctx()
    slow = registry(tool(Handler(delay_s=5.0), time_cap_s=0.05))
    params = {"kind": "ip", "value": "198.51.100.7"}
    timed_out = await slow.call(ctx, "reputation.example", params, agent="a")
    assert timed_out.value == {"refused": ToolTimedOut.__name__}
    big = registry(tool(Handler(answer=list(range(6)))))
    over = await big.call(ctx, "reputation.example", params, agent="a")
    assert over.value == {"refused": ToolRowCapExceeded.__name__}
    fits = registry(tool(Handler(answer=list(range(5)))))
    assert (await fits.call(ctx, "reputation.example", params, agent="a")).value == list(range(5))
    # Every call that ran is in the trace.
    assert [s.tool for s in ctx.trace.steps] == ["reputation.example"] * 3


async def test_an_empty_result_and_a_failed_call_are_distinguishable(make_settings: Any) -> None:
    """The caller always gets a typed outcome: "no rows" (empty) never looks like "did not run" (failed)."""
    ctx = Ctx()
    params = {"kind": "ip", "value": "198.51.100.7"}

    async def outcome(*tools: Tool[Any, Any], settings: Optional[Settings] = None) -> Any:
        return await registry(*tools, settings=settings).call(ctx, "reputation.example", params, agent="a")

    found = await outcome(tool(Handler(answer=["row-1", "row-2"])))
    empty = await outcome(tool(Handler(answer=[])))
    assert (found.outcome, found.rows, found.value) == ("success", 2, ["row-1", "row-2"])
    assert (empty.outcome, empty.rows, empty.value) == ("empty", 0, [])
    # Every way a query does not run to an answer is ``failed``, with the tool's refusal answer and no rows.
    timed_out = await outcome(tool(Handler(delay_s=5.0), time_cap_s=0.05))
    over_cap = await outcome(tool(Handler(answer=list(range(6)))))
    switched_off = await outcome(tool(Handler(answer=[])), settings=Settings({"example": {"enabled": False}}))
    own_failure = await outcome(tool(Handler(answer={"refused": "unreachable"})))
    for result in (timed_out, over_cap, switched_off, own_failure):
        assert (result.outcome, result.rows) == ("failed", 0) and result.value != empty.value
    assert {r.outcome for r in (found, empty, timed_out)} == {"success", "empty", "failed"}

    # A tool whose refusal answer would read as "no rows" is stopped, not believed.
    silent = Tool(ToolSpec(**spec()), Handler(delay_s=5.0), rows, failed, lambda r: r, lambda p, rec: rec, lambda p, e: [])
    with pytest.raises(ToolError, match="does not read as failed"):
        await registry(replace(silent, spec=ToolSpec(**spec(time_cap_s=0.05)))).call(ctx, "reputation.example", params, agent="a")

    # Today's lookups: an indicator the provider does not know is empty, a provider error is failed.
    from lg_sotf.tools.enrichment import EnrichmentService
    from lg_sotf.tools.enrichment.tools import enrichment_tools

    replies = iter([httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}),
                    httpx.Response(404, json={}), httpx.Response(500, json={})])
    key = "test-only-" + "k" * 12
    settings = make_settings(tools={"virustotal": {"api_key": key, "share_with_tenants": True, "requests_per_minute": 100}})
    lookups = enrichment_tools(EnrichmentService.from_settings(settings, transport=httpx.MockTransport(lambda _: next(replies))))
    seen = []
    for digit in "123":
        hashed = {"kind": "hash", "value": digit * 32}
        seen.append(await lookups.call(ctx, "reputation.virustotal", hashed, agent="analysis"))
    assert [(r.outcome, r.value.status) for r in seen] == [("success", "ok"), ("empty", "not_found"), ("failed", "error")]
    private = await lookups.call(ctx, "reputation.virustotal", {"kind": "ip", "value": "10.0.0.5"}, agent="analysis")
    assert (private.outcome, private.value.status) == ("failed", "skipped")  # never sent, so it proves nothing


async def test_input_and_output_hashes_are_stable_and_follow_the_output() -> None:
    """SHA-256 of the canonical JSON of the input and of the output, the same values the trace store keeps."""
    ctx = Ctx()
    params = {"kind": "ip", "value": "198.51.100.7"}
    answer = {"verdict": "harmless", "seen": 3}

    first = await registry(tool(Handler(answer=answer))).call(ctx, "reputation.example", params, agent="a")
    again = await registry(tool(Handler(answer=dict(reversed(answer.items()))))).call(
        ctx, "reputation.example", dict(reversed(params.items())), agent="a"
    )
    assert (first.input_hash, first.output_hash) == (again.input_hash, again.output_hash)  # key order does not matter
    assert first.input_hash == hashlib.sha256(
        json.dumps({"tool": "reputation.example", **params}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert first.output_hash == hashlib.sha256(json.dumps(answer, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    # They are the hashes of the call's trace step.
    assert (ctx.trace.steps[0].input_hash, ctx.trace.steps[0].output_hash) == (first.input_hash, first.output_hash)

    other_output = await registry(tool(Handler(answer={**answer, "seen": 4}))).call(ctx, "reputation.example", params, agent="a")
    assert other_output.input_hash == first.input_hash and other_output.output_hash != first.output_hash
    other_input = await registry(tool(Handler(answer=answer))).call(
        ctx, "reputation.example", {**params, "value": "198.51.100.8"}, agent="a"
    )
    assert other_input.input_hash != first.input_hash and other_input.output_hash == first.output_hash
    # A refused call is hashed too: the refusal answer is what the caller observed.
    off = await registry(tool(Handler(answer=answer)), settings=Settings({"example": {"enabled": False}})).call(
        ctx, "reputation.example", params, agent="a"
    )
    assert off.input_hash == first.input_hash and off.output_hash == tool_output_hash({"refused": "ToolDisabled"})


def test_todays_lookups_are_registered_with_their_caps(make_settings: Any) -> None:
    from lg_sotf.tools.enrichment import EnrichmentResult, EnrichmentService, HistoryProvider
    from lg_sotf.tools.enrichment.history import MAX_HISTORY_ALERTS
    from lg_sotf.tools.enrichment.tools import enrichment_tools

    service = EnrichmentService.from_settings(make_settings())
    tools = enrichment_tools(service)
    assert tools.names == ["platform.history", "reputation.abuseipdb", "reputation.virustotal"]
    for name in ("reputation.abuseipdb", "reputation.virustotal"):
        declared = tools.get(name).spec
        assert (declared.risk, declared.egress, declared.shadow) == ("read_external", "third_party", "cache_only")
        assert declared.tenant_setting == name.split(".")[1] and declared.traced_as == "reputation." + declared.tenant_setting
    history = tools.get("platform.history").spec
    assert (history.risk, history.egress, history.traced_as, history.tenant_setting) == (
        "read_internal", "platform", "history", None
    )
    provider = service.provider(HistoryProvider.name)
    assert isinstance(provider, HistoryProvider) and provider.max_alerts <= MAX_HISTORY_ALERTS == history.row_cap
    assert history.time_cap_s > service.lookup_timeout_s  # the service's own deadline answers first
    # The row cap counts the earlier alerts a history answer read; a reputation answer is one row.
    counted = tools.get("platform.history").rows(EnrichmentResult.ok("history", "ip", "unknown", {"prior_alerts": 7}))
    assert counted == 7 and tools.get("reputation.virustotal").rows(EnrichmentResult.ok("virustotal", "ip", "unknown", {})) == 1
