"""The tool registry: every investigation tool is declared here and called through here (AI-E2.1).

A tool is a :class:`ToolSpec` (what it is, what it may touch and how much it may read) plus the code that
runs it. :meth:`ToolRegistry.register` refuses a tool whose declaration is incomplete or unsafe, and every
call takes the same steps, in this order:

1. the parameters are validated against the tool's strict model before anything else: an unknown key, a
   wrong type or an over-long value raises :class:`ToolParamsInvalid` and nothing runs;
2. a tool the tenant switched off (``tenants.settings.tools.<tenant_setting>.enabled: false``) is not
   called: the caller gets the tool's refusal answer;
3. the tool runs under its time cap, inside ``ctx.trace.tool(...)``, so the trace store, the cassettes and
   shadow runs see every call (a replaying cassette answers instead of the tool);
4. a result with more rows than the tool's row cap (counted by the tool's ``rows``) is dropped for the
   refusal answer;
5. the caller gets a :class:`ToolResult`: the tool's result with a typed outcome and the hashes of what
   went in and what came out.

A refusal, a timeout or an over-long result is an answer (the tool's ``refused``), never an exception
that fails the workflow node, as the enrichment service already does for provider failures. What a tool
returns is data: the registry hands it back as it is, and the caller shows it to a model only as untrusted
tool data, never as instructions.

The outcome is ``success`` (rows came back), ``empty`` (the query ran and matched nothing) or ``failed``
(switched off, unreachable, refused, timed out or over the row cap). "No rows" must never read as
"nothing happened" when the query did not run, so a caller can always tell ``empty`` from ``failed``.
The hashes are the trace store's own (``investigation_steps.input_hash`` and ``output_hash``): SHA-256 of
the canonical JSON of the input (the tool's name and its validated parameters) and of the recorded output,
computed by the run's trace (``ctx.trace.tool_hashes``), never by a model.

The tenant switch is read with the calling run's own tenant id (``ctx.tenant_id``, under that tenant's
row-level security), so one tenant's settings never turn a tool on or off for another.

There is no write risk class: ``risk`` is ``read_internal`` or ``read_external``. Egress is declared and
checked when the tool loads: a tool that leaves the platform names the ``@egress`` boundary
(:mod:`lg_sotf.security.shadow`) its requests pass through, a third-party tool is ``cache_only`` in a
shadow run and its boundary must divert there, and a third-party tool can always be switched off per
tenant. INV-14 (pending) states the rule.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    List,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
)

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from lg_sotf.models.evidence_fact import FACT_KINDS
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.shadow import EGRESS_POINTS

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

__all__ = [
    "MAX_ROW_CAP",
    "MAX_TIME_CAP_S",
    "MAX_WINDOW_CAP",
    "Tool",
    "ToolContext",
    "ToolDisabled",
    "ToolError",
    "ToolNotFound",
    "ToolParamsInvalid",
    "ToolRegistry",
    "ToolResult",
    "ToolRowCapExceeded",
    "ToolSpec",
    "ToolTimedOut",
]

log = get_logger(__name__)

T = TypeVar("T")
P = TypeVar("P", bound=BaseModel)
R = TypeVar("R")
MAX_ROW_CAP = 500
MAX_TIME_CAP_S = 60.0
MAX_WINDOW_CAP = timedelta(days=366)
_NAME = r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$"
_SETTING = r"^[a-z][a-z0-9_]{0,63}$"

Risk = Literal["read_internal", "read_external"]
Egress = Literal["tenant_source", "third_party", "platform"]
ShadowMode = Literal["live", "cache_only"]
Outcome = Literal["success", "empty", "failed"]


class ToolError(Exception):
    """A call the registry did not let through."""


class ToolNotFound(ToolError):
    pass


class ToolParamsInvalid(ToolError):
    pass


class ToolDisabled(ToolError):
    pass


class ToolTimedOut(ToolError):
    pass


class ToolRowCapExceeded(ToolError):
    pass


class ToolSpec(BaseModel):
    """A tool's declaration. Every field without a default must be given; ``None`` is a declared absence."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, arbitrary_types_allowed=True)

    name: str = Field(pattern=_NAME)
    version: int = Field(ge=1)
    risk: Risk
    params: type[BaseModel]
    """The parameter model: it must forbid unknown keys."""
    produces: FrozenSet[str] = Field(min_length=1)
    """The evidence-fact kinds the tool's results map to."""
    row_cap: int = Field(ge=1, le=MAX_ROW_CAP)
    time_cap_s: float = Field(gt=0, le=MAX_TIME_CAP_S)
    window_cap: Optional[timedelta]
    """The longest time window one call may read; ``None``: the tool reads no window."""
    egress: Egress
    shadow: ShadowMode
    tenant_setting: Optional[str] = Field(pattern=_SETTING)
    """The key under ``tenants.settings.tools`` that switches the tool off; ``None``: always on."""
    egress_boundary: Optional[str] = None
    """The ``@egress`` boundary the tool's requests pass through (required unless ``egress`` is ``platform``)."""
    trace_name: Optional[str] = Field(default=None, max_length=64)
    """The name traces and cassettes record (default ``name``): kept by tools older than the registry."""

    @model_validator(mode="after")
    def _coherent(self) -> ToolSpec:
        problems: List[str] = []
        if self.params.model_config.get("extra") != "forbid":
            problems.append("params must be a model that forbids unknown keys")
        unknown = sorted(self.produces - set(FACT_KINDS))
        if unknown:
            problems.append(f"produces unknown fact kinds: {', '.join(unknown)}")
        if self.window_cap is not None and not timedelta(0) < self.window_cap <= MAX_WINDOW_CAP:
            problems.append(f"window_cap must be positive and at most {MAX_WINDOW_CAP.days} days")
        third_party = self.egress == "third_party"
        if third_party != (self.risk == "read_external"):
            problems.append("risk read_external goes with egress third_party, and only with it")
        if third_party and (self.shadow != "cache_only" or self.tenant_setting is None):
            problems.append("a third-party tool is cache_only in shadow runs and has a tenant_setting")
        if self.egress != "platform" and not self.egress_boundary:
            problems.append("a tool that leaves the platform names its egress boundary")
        if problems:
            raise ValueError(f"tool {self.name}: " + "; ".join(problems))
        return self

    @property
    def traced_as(self) -> str:
        return self.trace_name or self.name


def _check_boundary(spec: ToolSpec) -> None:
    """The declared boundary exists, and diverts in a shadow run when the tool must not go live there."""
    if spec.egress_boundary is None:
        return
    points = [p for p in EGRESS_POINTS.values() if p.boundary == spec.egress_boundary]
    if not points:
        raise ValueError(f"tool {spec.name}: no @egress boundary named {spec.egress_boundary!r}")
    if spec.shadow == "cache_only" and any(p.policy.action == "allow" for p in points):
        raise ValueError(f"tool {spec.name}: a cache_only tool's boundary must divert in shadow runs")


class ToolTrace(Protocol):
    async def tool(
        self,
        agent: str,
        tool: str,
        request: Mapping[str, Any],
        call: Awaitable[T],
        output: Callable[[T], Any],
        restore: Optional[Callable[[Any], T]] = None,
    ) -> T: ...

    def tool_hashes(self, tool: str, request: Mapping[str, Any], recorded: Any) -> Tuple[str, str]: ...


class ToolContext(Protocol):
    """What a call needs from the run (``lg_sotf.agents.base.AgentContext`` is one)."""

    @property
    def tenant_id(self) -> str: ...

    @property
    def alert_id(self) -> str: ...

    @property
    def repos(self) -> Optional[Repositories]: ...

    @property
    def trace(self) -> ToolTrace: ...


@dataclass(frozen=True)
class Tool(Generic[P, R]):
    """A declared tool and the code behind it: ``P`` is its validated parameter model, ``R`` its result."""

    spec: ToolSpec
    run: Callable[[ToolContext, P], Awaitable[R]]
    rows: Callable[[R], int]
    """How many rows a result holds, checked against ``spec.row_cap``; none is the ``empty`` outcome."""
    failed: Callable[[R], bool]
    """Whether a result says the query did not run to an answer (the ``failed`` outcome)."""
    record: Callable[[R], Any]
    """A result as the trace and cassettes store it."""
    restore: Callable[[P, Any], R]
    """``(params, recorded)``: the result a recorded output stands for."""
    refused: Callable[[P, ToolError], R]
    """``(params, error)``: what a call answers when the tool is off, times out or returns too many rows.

    ``failed`` must be true of it."""


AnyTool = Tool[Any, Any]


@dataclass(frozen=True)
class ToolResult(Generic[R]):
    """What a call hands back: the tool's result, its typed outcome and the hashes of its input and output."""

    outcome: Outcome
    value: R
    rows: int
    input_hash: str
    """SHA-256 of the canonical JSON of the tool's traced name and validated parameters."""
    output_hash: str
    """SHA-256 of the canonical JSON of the result as the trace records it."""


TenantTools = Callable[[str, Optional["Repositories"]], Awaitable[Mapping[str, Any]]]
"""``(tenant_id, repos)``: the tenant's ``tenants.settings.tools`` section."""


class ToolRegistry:
    def __init__(self, tenant_tools: TenantTools) -> None:
        self._tools: Dict[str, AnyTool] = {}
        self._tenant_tools = tenant_tools

    def register(self, tool: AnyTool) -> None:
        """Load ``tool``; its declaration is validated again here, so a hand-built spec cannot skip a rule."""
        try:
            declared = {name: getattr(tool.spec, name) for name in ToolSpec.model_fields if hasattr(tool.spec, name)}
            spec = ToolSpec.model_validate(declared)
        except ValidationError as exc:
            raise ValueError(f"tool {getattr(tool.spec, 'name', '?')!r} does not load: {exc}") from None
        _check_boundary(spec)
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} registered twice")
        self._tools[spec.name] = replace(tool, spec=spec)

    def get(self, name: str) -> AnyTool:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFound(f"no tool {name!r}")
        return tool

    @property
    def names(self) -> List[str]:
        return sorted(self._tools)

    async def call(self, ctx: ToolContext, name: str, params: Mapping[str, Any], *, agent: str) -> ToolResult[Any]:
        """Run one tool (see the module docs for the steps)."""
        tool = self.get(name)
        valid = _validated(tool, params)
        if not await self._enabled(ctx, tool):
            return _result(ctx, tool, valid, _refuse(tool, valid, ToolDisabled(name)))
        value = await ctx.trace.tool(
            agent,
            tool.spec.traced_as,
            valid.model_dump(mode="json"),
            self._capped(ctx, tool, valid),
            tool.record,
            lambda recorded: tool.restore(valid, recorded),
        )
        return _result(ctx, tool, valid, value)

    async def call_family(
        self, ctx: ToolContext, family: str, members: Sequence[str], params: Mapping[str, Any], *, agent: str
    ) -> List[ToolResult[Any]]:
        """Run the tools ``<family>.<member>`` concurrently with the same parameters, as one trace step.

        The step is named ``family`` and its request is the parameters plus the sorted ``providers``: the
        shape the threat-intelligence lookup had before the registry, so recorded cassettes still replay.
        Results come back in ``members`` order.
        """
        tools = [self.get(f"{family}.{member}") for member in members]
        if not tools:
            raise ToolNotFound(f"no members given for {family!r}")
        valid = [_validated(tool, params) for tool in tools]
        enabled = [await self._enabled(ctx, tool) for tool in tools]

        async def run_all() -> List[Any]:
            return list(
                await asyncio.gather(
                    *(
                        self._capped(ctx, tool, v) if on else _switched_off(tool, v)
                        for tool, v, on in zip(tools, valid, enabled, strict=True)
                    )
                )
            )

        request = {**valid[0].model_dump(mode="json"), "providers": sorted(members)}
        values = await ctx.trace.tool(
            agent,
            family,
            request,
            run_all(),
            lambda results: [tool.record(r) for tool, r in zip(tools, results, strict=True)],
            lambda rows: [tool.restore(v, row) for tool, v, row in zip(tools, valid, rows, strict=True)],
        )
        return [_result(ctx, tool, v, value) for tool, v, value in zip(tools, valid, values, strict=True)]

    async def _enabled(self, ctx: ToolContext, tool: AnyTool) -> bool:
        setting = tool.spec.tenant_setting
        if setting is None:
            return True
        entry = (await self._tenant_tools(ctx.tenant_id, ctx.repos)).get(setting)
        if isinstance(entry, Mapping) and entry.get("enabled") is False:
            log.info("tool.refused", tool=tool.spec.name, reason="disabled_for_tenant")
            return False
        return True

    async def _capped(self, ctx: ToolContext, tool: AnyTool, params: BaseModel) -> Any:
        spec = tool.spec
        try:
            async with asyncio.timeout(spec.time_cap_s):
                result = await tool.run(ctx, params)
        except TimeoutError:
            log.warning("tool.refused", tool=spec.name, reason="time_cap", time_cap_s=spec.time_cap_s)
            return _refuse(tool, params, ToolTimedOut(f"{spec.name} took longer than {spec.time_cap_s:g}s"))
        rows = tool.rows(result)
        if rows > spec.row_cap:
            log.warning("tool.refused", tool=spec.name, reason="row_cap", rows=rows, row_cap=spec.row_cap)
            return _refuse(tool, params, ToolRowCapExceeded(f"{spec.name} returned more than {spec.row_cap} rows"))
        return result


def _refuse(tool: AnyTool, params: BaseModel, error: ToolError) -> Any:
    """The tool's refusal answer; it must read as ``failed``, so a refusal is never taken for "no rows"."""
    answer = tool.refused(params, error)
    if not tool.failed(answer):
        raise ToolError(f"{tool.spec.name}: its refusal answer does not read as failed")
    return answer


async def _switched_off(tool: AnyTool, params: BaseModel) -> Any:
    return _refuse(tool, params, ToolDisabled(tool.spec.name))


def _result(ctx: ToolContext, tool: AnyTool, params: BaseModel, value: Any) -> ToolResult[Any]:
    failed = tool.failed(value)
    rows = 0 if failed else tool.rows(value)
    outcome: Outcome = "failed" if failed else "success" if rows > 0 else "empty"
    hashes = ctx.trace.tool_hashes(tool.spec.traced_as, params.model_dump(mode="json"), tool.record(value))
    return ToolResult(outcome, value, rows, *hashes)


def _validated(tool: AnyTool, params: Mapping[str, Any]) -> BaseModel:
    try:
        return tool.spec.params.model_validate(dict(params))
    except ValidationError as exc:
        # The locations and messages only: the values may be hostile or sensitive.
        where: Tuple[str, ...] = tuple(
            ".".join(str(p) for p in err["loc"]) + f": {err['msg']}" for err in exc.errors(include_input=False)
        )
        raise ToolParamsInvalid(f"{tool.spec.name}: invalid parameters ({'; '.join(where)[:300]})") from None

