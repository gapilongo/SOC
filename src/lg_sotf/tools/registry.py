"""The tool registry: every investigation tool is declared here and called through here (AI-E2.1).

A tool is a :class:`ToolSpec` (what it is, what it may touch and how much it may read) plus the code that
runs it. :meth:`ToolRegistry.register` refuses a tool whose declaration is incomplete or unsafe. The
registry never hands a tool's code out (:meth:`ToolRegistry.get` returns the declaration), so the only way
to run a tool is :meth:`ToolRegistry.call`, which takes these steps in this order:

1. The parameters are validated against the tool's strict model: an unknown key, a wrong type or an
   over-long value raises :class:`ToolParamsInvalid` and nothing runs. The error names allowed fields only.
2. The call is refused without running the tool when
   * the tenant switched the tool off, its setting is malformed, or its settings cannot be read
     (``tenants.settings.tools.<tenant_setting>``: the tool runs only when the entry is absent or its
     ``enabled`` is absent or exactly ``true``);
   * the time window the parameters ask for is longer than the tool's ``window_cap``.
3. The tool runs under its time cap and inside its egress scope (below). Any exception it raises is a
   refusal, named by the exception's type only.
4. A result with more rows than the row cap is dropped for a refusal. A collection is counted by the
   registry (``len``); for any other result the tool's ``rows`` says how many rows it stands for.
5. Every call that passed step 1, refused or not, is one step in the run's trace (``ctx.trace``), with the
   same outcome as the result. A replaying cassette answers a call that ran instead of the tool; a call
   refused in step 2 never touches the cassette.

The caller gets a :class:`ToolResult`, never an exception that fails the workflow node:

* ``outcome``: ``success`` (rows came back), ``empty`` (the query ran and matched nothing) or ``failed``
  (refused, unreachable, timed out, over a cap, or the tool's own result says it did not get an answer).
  "No rows" never reads as "nothing happened" when the query did not run.
* ``complete``: false when the result is ``failed`` or holds as many rows as the row cap, so more may
  exist. A tool whose cap is one row is a point lookup and its one record is the whole answer. A tool
  that knows more (``Tool.whole``: its source cut the answer, the time window has not closed, the
  source's retention does not reach back far enough) can say an answer is incomplete, never the reverse.
* ``input_hash`` and ``output_hash``: the hashes of the stored trace step
  (``investigation_steps.input_hash`` and ``output_hash``), SHA-256 of the canonical JSON of the request
  and of the recorded output without transport flags (the tool's ``evidence``). The run's trace computes
  them, never a model. The members of one family call share the hashes of their one step.

What a tool returns is data: the registry hands it back as it is, and the caller shows it to a model only
as untrusted tool data, never as instructions.

The tenant switch is read with the calling run's own tenant id (``ctx.tenant_id``, under that tenant's
row-level security), so one tenant's settings never turn a tool on or off for another.

There is no write risk class: ``risk`` is ``read_internal`` or ``read_external``. Egress is declared,
checked when the tool loads and enforced while it runs (:func:`lg_sotf.security.shadow.tool_egress_scope`):
a tool crosses only the ``@egress`` boundary it declared, a tool with ``platform`` egress crosses none (it
cannot open an outside connection or reach a registered write path), and a ``cache_only`` tool crosses
none live in a shadow run, whatever the boundary's own shadow policy says. INV-14 (pending) states the rule.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from enum import Enum
from types import UnionType
from typing import (
    TYPE_CHECKING,
    Annotated,
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
    Union,
    get_args,
    get_origin,
)

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from lg_sotf.models.evidence_fact import FACT_KINDS
from lg_sotf.models.trace import NewTraceStep, StepOutcome
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.shadow import EGRESS_POINTS, ToolEgress, in_shadow, tool_egress_scope

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
    "ToolFailed",
    "ToolNotFound",
    "ToolParamsInvalid",
    "ToolRegistry",
    "ToolResult",
    "ToolRowCapExceeded",
    "ToolSettingsUnavailable",
    "ToolSpec",
    "ToolTimedOut",
    "ToolWindowExceeded",
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
_WINDOW_FIELDS = frozenset({"since", "until"})
_SCALARS = (bool, int, float, datetime, date, timedelta)
_COLLECTIONS = (list, tuple, set, frozenset)

Risk = Literal["read_internal", "read_external"]
Egress = Literal["tenant_source", "third_party", "platform"]
ShadowMode = Literal["live", "cache_only"]
Outcome = Literal["success", "empty", "failed"]
_WORST_FIRST: Tuple[Outcome, ...] = ("failed", "empty", "success")


class ToolError(Exception):
    """A call the registry did not let through; ``reason`` is what the result and the trace step say."""

    reason = "refused"


class ToolNotFound(ToolError):
    pass


class ToolParamsInvalid(ToolError):
    pass


class ToolDisabled(ToolError):
    reason = "disabled"


class ToolSettingsUnavailable(ToolDisabled):
    """The tenant's tool settings could not be read (no repositories, or not a mapping): the tool stays off."""

    reason = "settings_unavailable"


class ToolWindowExceeded(ToolError):
    reason = "window_cap"


class ToolTimedOut(ToolError):
    reason = "time_cap"


class ToolRowCapExceeded(ToolError):
    reason = "row_cap"


class ToolFailed(ToolError):
    """The tool raised; the message is the exception's type name, never its text."""

    reason = "error"


def _bounded(metadata: Sequence[Any]) -> bool:
    flat = [m for item in metadata for m in (getattr(item, "metadata", None) or [item])]
    return any(getattr(m, "max_length", None) is not None for m in flat)


def _open_type(annotation: Any, metadata: Sequence[Any]) -> Optional[str]:
    """Why a parameter of this type could carry unbounded or free-form input (``None``: it cannot)."""
    origin = get_origin(annotation)
    if origin is Annotated:
        base, *extra = get_args(annotation)
        return _open_type(base, [*metadata, *extra])
    if origin is Literal or annotation in _SCALARS:
        return None
    if origin in (Union, UnionType):
        members = [a for a in get_args(annotation) if a is not type(None)]
        return next((p for p in (_open_type(a, metadata) for a in members) if p), None)
    if origin in _COLLECTIONS:
        if not _bounded(metadata):
            return "an unbounded collection"
        return next((p for p in (_open_type(a, ()) for a in get_args(annotation) if a is not Ellipsis) if p), None)
    if annotation is str:
        return None if _bounded(metadata) else "an unbounded string"
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return None
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return next(iter(_params_problems(annotation)), None)
    return f"a free-form type ({getattr(annotation, '__name__', annotation)})"


def _params_problems(model: type[BaseModel]) -> List[str]:
    problems: List[str] = []
    if model.model_config.get("extra") != "forbid" or model.model_config.get("strict") is not True:
        problems.append("params must be a strict model that forbids unknown keys")
    for name, field in model.model_fields.items():
        problem = _open_type(field.annotation, field.metadata)
        if problem:
            problems.append(f"parameter {name} is {problem}")
    return problems


class ToolSpec(BaseModel):
    """A tool's declaration. Every field without a default must be given; ``None`` is a declared absence."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, arbitrary_types_allowed=True)

    name: str = Field(pattern=_NAME)
    version: int = Field(ge=1)
    risk: Risk
    params: type[BaseModel]
    """The parameter model: strict, no unknown keys, every string and collection bounded, no free-form type."""
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
    """The only ``@egress`` boundary the tool may cross (required unless ``egress`` is ``platform``)."""
    trace_name: Optional[str] = Field(default=None, max_length=64)
    """The name traces and cassettes record (default ``name``): kept by tools older than the registry."""
    price_usd: float = Field(default=0.0, ge=0.0, le=10.0)
    """What one call costs in US dollars (a metered third-party lookup); 0: free. The registry charges
    nothing itself: an investigation counts this against its money budget before it calls the tool."""

    @model_validator(mode="after")
    def _coherent(self) -> ToolSpec:
        problems = _params_problems(self.params)
        unknown = sorted(self.produces - set(FACT_KINDS))
        if unknown:
            problems.append(f"produces unknown fact kinds: {', '.join(unknown)}")
        if self.window_cap is not None and not timedelta(0) < self.window_cap <= MAX_WINDOW_CAP:
            problems.append(f"window_cap must be positive and at most {MAX_WINDOW_CAP.days} days")
        if self.window_cap is None and _WINDOW_FIELDS <= set(self.params.model_fields):
            problems.append("a tool whose parameters take a window (since, until) declares a window_cap")
        third_party = self.egress == "third_party"
        if third_party != (self.risk == "read_external"):
            problems.append("risk read_external goes with egress third_party, and only with it")
        if third_party and (self.shadow != "cache_only" or self.tenant_setting is None):
            problems.append("a third-party tool is cache_only in shadow runs and has a tenant_setting")
        if (self.egress == "platform") != (self.egress_boundary is None):
            problems.append("a tool that leaves the platform names its egress boundary, and only such a tool")
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
    async def tool_step(
        self,
        agent: str,
        tool: str,
        request: Mapping[str, Any],
        call: Awaitable[T],
        output: Callable[[T], Any],
        restore: Optional[Callable[[Any], T]] = None,
        *,
        outcome: Optional[Callable[[T], Tuple[StepOutcome, Optional[str]]]] = None,
        evidence: Optional[Callable[[Any], Any]] = None,
        taped: bool = True,
    ) -> Tuple[T, NewTraceStep]: ...


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


def _whole(recorded: Any) -> Any:
    return recorded


@dataclass(frozen=True)
class Tool(Generic[P, R]):
    """A declared tool and the code behind it: ``P`` is its validated parameter model, ``R`` its result."""

    spec: ToolSpec
    run: Callable[[ToolContext, P], Awaitable[R]]
    rows: Callable[[R], int]
    """How many rows a result that is not a collection stands for; none is the ``empty`` outcome."""
    failed: Callable[[R], bool]
    """Whether a result says the query did not run to an answer (the ``failed`` outcome)."""
    record: Callable[[R], Any]
    """A result as the trace and cassettes store it."""
    restore: Callable[[P, Any], R]
    """``(params, recorded)``: the result a recorded output stands for."""
    refused: Callable[[P, ToolError], R]
    """``(params, error)``: what a refused call answers. ``failed`` must be true of it."""
    window: Optional[Callable[[P], timedelta]] = None
    """The time window a call reads, for a tool whose parameters are not ``since`` and ``until``."""
    evidence: Callable[[Any], Any] = _whole
    """``(recorded)``: the recorded output without transport flags (cached, retry hints); this is hashed."""
    whole: Optional[Callable[[R], bool]] = None
    """Whether an answer is all there is: false when the tool knows a cap, an open time window or its source's
    retention cut it. It can only take ``complete`` away: an answer at the row cap is incomplete whatever it says."""


AnyTool = Tool[Any, Any]


@dataclass(frozen=True)
class ToolResult(Generic[R]):
    """What a call hands back: the tool's result, its typed outcome and the hashes of its trace step."""

    outcome: Outcome
    value: R
    rows: int
    input_hash: str
    """The stored step's input hash: SHA-256 of the canonical JSON of the traced name and the request."""
    output_hash: str
    """The stored step's output hash: SHA-256 of the canonical JSON of the recorded evidence."""
    complete: bool
    """False when the call failed, returned as many rows as the row cap allows (more may exist), or the tool
    says its answer was cut."""
    reason: Optional[str] = None
    """Why the call failed: the registry's refusal reason, or ``reported`` for the tool's own failure answer."""


@dataclass(frozen=True)
class _Ran:
    """A tool's answer inside the trace step: the value, and the registry's reason when it is a refusal."""

    value: Any
    reason: Optional[str] = None


TenantTools = Callable[[str, Optional["Repositories"]], Awaitable[Optional[Mapping[str, Any]]]]
"""``(tenant_id, repos)``: the tenant's ``tenants.settings.tools`` section, or ``None`` when it cannot be read."""


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
        measured = tool.window is not None or _WINDOW_FIELDS <= set(spec.params.model_fields)
        if spec.window_cap is not None and not measured:
            raise ValueError(f"tool {spec.name!r} does not load: it declares a window_cap and no way to measure the window")
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} registered twice")
        self._tools[spec.name] = replace(tool, spec=spec)

    def get(self, name: str) -> ToolSpec:
        """The tool's declaration. Its code stays inside the registry: :meth:`call` is the only way to run it."""
        return self._tool(name).spec

    def _tool(self, name: str) -> AnyTool:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFound(f"no tool {name!r}")
        return tool

    @property
    def names(self) -> List[str]:
        return sorted(self._tools)

    async def call(self, ctx: ToolContext, name: str, params: Mapping[str, Any], *, agent: str) -> ToolResult[Any]:
        """Run one tool (see the module docs for the steps)."""
        tool = self._tool(name)
        valid = _validated(tool, params)
        refusal = await self._refusal(ctx, tool, valid)
        ran, step = await ctx.trace.tool_step(
            agent,
            tool.spec.traced_as,
            valid.model_dump(mode="json"),
            self._run(ctx, tool, valid, refusal),
            lambda done: tool.record(done.value),
            lambda recorded: _Ran(tool.restore(valid, recorded)),
            outcome=lambda done: _step_outcome([_judged(tool, done)]),
            evidence=tool.evidence,
            taped=refusal is None,
        )
        return _result(tool, ran, step)

    async def call_family(
        self, ctx: ToolContext, family: str, members: Sequence[str], params: Mapping[str, Any], *, agent: str
    ) -> List[ToolResult[Any]]:
        """Run the tools ``<family>.<member>`` concurrently with the same parameters, as one trace step.

        The step is named ``family`` and its request is the parameters plus the sorted ``providers``: the
        shape the threat-intelligence lookup had before the registry, so recorded cassettes still replay.
        Results come back in ``members`` order, each with its own outcome and with the hashes of the one
        step. The step's outcome is the worst of its members' (``failed``, then ``empty``, then ``success``),
        so a stored ``success`` means every member succeeded. One member failing never loses another's answer.
        """
        tools = [self._tool(f"{family}.{member}") for member in members]
        if not tools:
            raise ToolNotFound(f"no members given for {family!r}")
        valid = [_validated(tool, params) for tool in tools]
        refusals = [await self._refusal(ctx, tool, v) for tool, v in zip(tools, valid, strict=True)]

        async def run_all() -> List[_Ran]:
            runs = (self._run(ctx, tool, v, no) for tool, v, no in zip(tools, valid, refusals, strict=True))
            done = await asyncio.gather(*runs, return_exceptions=True)
            for item in done:  # only a tool that breaks the protocol raises; every member has finished by now
                if isinstance(item, BaseException):
                    raise item
            return [item for item in done if isinstance(item, _Ran)]

        def judged(done: Sequence[_Ran]) -> List[Tuple[Outcome, int, Optional[str]]]:
            return [_judged(tool, ran) for tool, ran in zip(tools, done, strict=True)]

        request = {**valid[0].model_dump(mode="json"), "providers": sorted(members)}
        ran, step = await ctx.trace.tool_step(
            agent,
            family,
            request,
            run_all(),
            lambda done: [tool.record(r.value) for tool, r in zip(tools, done, strict=True)],
            lambda rows: [_Ran(tool.restore(v, row)) for tool, v, row in zip(tools, valid, rows, strict=True)],
            outcome=lambda done: _step_outcome(judged(done)),
            evidence=lambda rows: [tool.evidence(row) for tool, row in zip(tools, rows, strict=True)],
            taped=any(refusal is None for refusal in refusals),
        )
        return [_result(tool, r, step) for tool, r in zip(tools, ran, strict=True)]

    async def _refusal(self, ctx: ToolContext, tool: AnyTool, params: BaseModel) -> Optional[ToolError]:
        """Why this call must not run the tool, decided before anything leaves: the tenant switch, then the window."""
        spec = tool.spec
        if spec.tenant_setting is not None:
            settings = await self._tenant_tools(ctx.tenant_id, ctx.repos)
            if settings is None:
                return ToolSettingsUnavailable(spec.name)
            if not _switched_on(settings, spec.tenant_setting):
                return ToolDisabled(spec.name)
        if spec.window_cap is not None:
            window = _window(tool, params)
            if window is None or not timedelta(0) <= window <= spec.window_cap:
                return ToolWindowExceeded(spec.name)
        return None

    async def _run(self, ctx: ToolContext, tool: AnyTool, params: BaseModel, refusal: Optional[ToolError]) -> _Ran:
        """The tool's answer under its caps and its egress scope, or its refusal answer. Never raises for the tool."""
        spec = tool.spec
        if refusal is not None:
            return _refuse(tool, params, refusal)
        scope = ToolEgress(spec.name, spec.egress_boundary, live=not (in_shadow() and spec.shadow == "cache_only"))
        try:
            with tool_egress_scope(scope):
                async with asyncio.timeout(spec.time_cap_s):
                    value = await tool.run(ctx, params)
        except TimeoutError:
            return _refuse(tool, params, ToolTimedOut(f"{spec.name} took longer than {spec.time_cap_s:g}s"))
        except Exception as exc:  # noqa: BLE001 - whatever a tool raises is a failed call, never a failed node
            return _refuse(tool, params, ToolFailed(type(exc).__name__))
        if not tool.failed(value) and _rows(tool, value) > spec.row_cap:
            return _refuse(tool, params, ToolRowCapExceeded(f"{spec.name} returned more than {spec.row_cap} rows"))
        return _Ran(value)


def _switched_on(settings: Mapping[str, Any], setting: str) -> bool:
    """On when the entry is absent, or a mapping whose ``enabled`` is absent or exactly ``True``; else off."""
    if setting not in settings:
        return True
    entry = settings[setting]
    if not isinstance(entry, Mapping):
        return False
    flags = [key for key in entry if str(key).strip().lower() == "enabled"]
    return not flags or (flags == ["enabled"] and entry["enabled"] is True)


def _window(tool: AnyTool, params: BaseModel) -> Optional[timedelta]:
    """The window the call would read; ``None`` when it cannot be measured (the call is then refused)."""
    try:
        if tool.window is not None:
            return tool.window(params)
        given = vars(params)
        window = given["until"] - given["since"]
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    return window if isinstance(window, timedelta) else None


def _refuse(tool: AnyTool, params: BaseModel, error: ToolError) -> _Ran:
    """The tool's refusal answer; it must read as ``failed``, so a refusal is never taken for "no rows"."""
    reason = f"error:{error}"[:64] if isinstance(error, ToolFailed) else error.reason
    log.warning("tool.refused", tool=tool.spec.name, reason=reason)
    answer = tool.refused(params, error)
    if not tool.failed(answer):
        raise ToolError(f"{tool.spec.name}: its refusal answer does not read as failed")
    return _Ran(answer, reason)


def _rows(tool: AnyTool, value: Any) -> int:
    """A collection is counted here, whatever the tool says; any other result by the tool's ``rows``."""
    if isinstance(value, _COLLECTIONS):
        return max(len(value), tool.rows(value))
    return tool.rows(value)


def _judged(tool: AnyTool, ran: _Ran) -> Tuple[Outcome, int, Optional[str]]:
    """``(outcome, rows, reason)`` of one answer; it reads only the value, so a replayed answer judges the same."""
    if tool.failed(ran.value):
        return "failed", 0, ran.reason or "reported"
    rows = _rows(tool, ran.value)
    return ("success" if rows > 0 else "empty"), rows, None


def _step_outcome(judged: Sequence[Tuple[Outcome, int, Optional[str]]]) -> Tuple[StepOutcome, Optional[str]]:
    """The stored step's outcome and error type: the worst of the answers it holds."""
    outcome = next(o for o in _WORST_FIRST if any(j[0] == o for j in judged))
    return outcome, next((j[2] for j in judged if j[0] == "failed"), None)


def _result(tool: AnyTool, ran: _Ran, step: NewTraceStep) -> ToolResult[Any]:
    outcome, rows, reason = _judged(tool, ran)
    complete = outcome != "failed" and (rows < tool.spec.row_cap or tool.spec.row_cap == 1)
    complete = complete and (tool.whole is None or tool.whole(ran.value))
    return ToolResult(outcome, ran.value, rows, step.input_hash, step.output_hash or "", complete, reason)


def _validated(tool: AnyTool, params: Mapping[str, Any]) -> BaseModel:
    try:
        return tool.spec.params.model_validate(dict(params))
    except ValidationError as exc:
        # Allowed field names and error types only: a caller's key names and values may be hostile or sensitive.
        allowed = sorted(tool.spec.params.model_fields)
        errors = exc.errors(include_input=False, include_url=False, include_context=False)
        named = sorted({f"{err['loc'][0]}: {err['type']}" for err in errors if err["loc"] and err["loc"][0] in allowed})
        unknown = sum(1 for err in errors if not err["loc"] or err["loc"][0] not in allowed)
        problems = named + ([f"{unknown} field(s) not allowed"] if unknown else [])
        raise ToolParamsInvalid(
            f"{tool.spec.name}: invalid parameters ({'; '.join(problems)[:300]}); allowed fields: {', '.join(allowed)}"
        ) from None
