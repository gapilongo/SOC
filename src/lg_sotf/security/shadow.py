"""Shadow mode: a run whose effects never leave the system (AI-E1.5a).

A shadow run executes a candidate (another model, prompt or graph) on a real
alert beside the production pipeline, so its verdicts can be compared with
production's. It must change nothing anyone outside the run can see: no
response action, notification, outbox row, webhook, Slack message, mail,
ticket or WebSocket event, no alert or escalation change, no audit entry.

The mode is one context flag, enforced at the egress boundaries, never in the agents:

* :func:`shadow_scope` enters the mode for the current task and everything
  it starts (tasks and ``asyncio.to_thread`` calls copy the context). Only
  system code enters it (:class:`lg_sotf.core.shadow.ShadowRunner`); nothing
  in an alert or in the graph state can, scopes do not nest, and nothing
  switches a running scope back to live.
* every egress boundary is a function decorated with :func:`egress`. In
  shadow mode it either refuses (:class:`ShadowEgressRefused`), or records
  the call in the run's :class:`ShadowSink` and returns a stand-in value
  ("would have done X"), or, for a read-only lookup, lets it through.
* the database is the backstop: in shadow mode every transaction is read only
  (:class:`lg_sotf.db.pool.Database`), so a write no boundary caught fails
  instead of committing.

``tests/unit/architecture/test_shadow_egress.py`` finds the egress call sites
in the source and fails when one is not inside a registered boundary.
"""

from __future__ import annotations

import enum
import functools
import inspect
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Literal, Mapping, Optional, Tuple, TypeVar, cast, get_args

F = TypeVar("F", bound=Callable[..., Any])
Arguments = Mapping[str, Any]
"""The arguments a boundary was called with, by parameter name (only those the caller passed)."""

SHADOW_RUN_PREFIX = "shadow/"
"""Shadow run ids start with it; a workflow thread id (``tenant:alert``) never contains ``/``."""
MAX_EFFECTS = 500
MAX_DETAIL_ITEMS = 20
MAX_DETAIL_CHARS = 200
_NOT_DETAIL = frozenset({"self", "conn", "tenant_id"})

EffectOutcome = Literal["sunk", "refused"]
EFFECT_OUTCOMES: Tuple[str, ...] = get_args(EffectOutcome)


class RunMode(enum.StrEnum):
    LIVE = "live"
    SHADOW = "shadow"


class ShadowEgressRefused(RuntimeError):
    """A shadow run reached a boundary that never runs in shadow mode."""

    def __init__(self, boundary: str, operation: str) -> None:
        super().__init__(f"{operation} ({boundary}) is not allowed in a shadow run")
        self.boundary = boundary
        self.operation = operation


@dataclass(frozen=True)
class ShadowEffect:
    """One thing a shadow run would have done (``sunk``) or tried and was stopped (``refused``)."""

    seq: int
    boundary: str
    operation: str
    outcome: EffectOutcome
    detail: Dict[str, Any] = field(default_factory=dict)


def _small(value: Any) -> Any:
    if isinstance(value, str):
        return value[:MAX_DETAIL_CHARS]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_small(v) for v in list(value)[:MAX_DETAIL_ITEMS]]
    return str(value)[:MAX_DETAIL_CHARS]


class ShadowSink:
    """What one shadow run would have done, in call order. Append-only; the first :data:`MAX_EFFECTS` are kept."""

    def __init__(self) -> None:
        self._effects: List[ShadowEffect] = []
        self.dropped = 0

    def record(self, boundary: str, operation: str, outcome: EffectOutcome, detail: Arguments) -> None:
        if len(self._effects) >= MAX_EFFECTS:
            self.dropped += 1
            return
        small = {str(k)[:64]: _small(v) for k, v in list(detail.items())[:MAX_DETAIL_ITEMS]}
        self._effects.append(ShadowEffect(len(self._effects), boundary, operation, outcome, small))

    @property
    def effects(self) -> Tuple[ShadowEffect, ...]:
        return tuple(self._effects)


@dataclass
class ShadowRun:
    run_id: str
    sink: ShadowSink = field(default_factory=ShadowSink)
    trace: List[Any] = field(default_factory=list)
    """Trace steps the agents recorded (kept here: the trace store is not written in shadow mode)."""


_RUN: ContextVar[Optional[ShadowRun]] = ContextVar("lg_sotf_shadow_run", default=None)


def active_shadow_run() -> Optional[ShadowRun]:
    return _RUN.get()


def run_mode() -> RunMode:
    return RunMode.LIVE if _RUN.get() is None else RunMode.SHADOW


def in_shadow() -> bool:
    return _RUN.get() is not None


def shadow_run_id() -> Optional[str]:
    """The active shadow run's id, or ``None`` in a live run."""
    run = _RUN.get()
    return None if run is None else run.run_id


@contextmanager
def shadow_scope(run: ShadowRun) -> Iterator[ShadowRun]:
    """Run the block in shadow mode, recording into ``run``. Scopes do not nest; the mode ends with the block."""
    if not run.run_id.startswith(SHADOW_RUN_PREFIX):
        raise ValueError(f"a shadow run id starts with {SHADOW_RUN_PREFIX!r}")
    if _RUN.get() is not None:
        raise RuntimeError("a shadow run cannot start inside another shadow run")
    token = _RUN.set(run)
    try:
        yield run
    finally:
        _RUN.reset(token)


@dataclass(frozen=True)
class ShadowPolicy:
    """What a boundary does in shadow mode: ``refuse``, ``sink`` (record, return a stand-in) or ``allow``."""

    action: Literal["refuse", "sink", "allow"]
    stand_in: Optional[Callable[[Arguments], Any]] = None
    detail: Optional[Callable[[Arguments], Arguments]] = None
    reason: str = ""


REFUSE = ShadowPolicy("refuse")


def sink(
    stand_in: Optional[Callable[[Arguments], Any]] = None, *, detail: Optional[Callable[[Arguments], Arguments]] = None
) -> ShadowPolicy:
    """Record the call and return ``stand_in(arguments)`` (``None`` without one) instead of running it.

    ``detail`` says what is recorded; by default the names of the arguments passed, never their values.
    """
    return ShadowPolicy("sink", stand_in, detail)


def allow(reason: str) -> ShadowPolicy:
    """A read-only lookup that runs in shadow mode too; ``reason`` says why it changes nothing outside."""
    if not reason.strip():
        raise ValueError("an allowed egress needs its reason")
    return ShadowPolicy("allow", reason=reason)


def passed_arguments(args: Arguments) -> Dict[str, Any]:
    return {"arguments": sorted(k for k in args if k not in _NOT_DETAIL)}


@dataclass(frozen=True)
class EgressPoint:
    boundary: str
    policy: ShadowPolicy


EGRESS_POINTS: Dict[str, EgressPoint] = {}
"""Every registered boundary, by ``module:qualname``."""


def _divert(run: ShadowRun, boundary: str, operation: str, policy: ShadowPolicy, arguments: Arguments) -> Any:
    if policy.action == "refuse":
        run.sink.record(boundary, operation, "refused", {})
        raise ShadowEgressRefused(boundary, operation)
    run.sink.record(boundary, operation, "sunk", (policy.detail or passed_arguments)(arguments))
    return policy.stand_in(arguments) if policy.stand_in is not None else None


def egress(boundary: str, policy: ShadowPolicy) -> Callable[[F], F]:
    """Mark a function as an egress boundary: live it runs unchanged, in shadow mode ``policy`` applies."""

    def decorate(fn: F) -> F:
        operation = fn.__qualname__
        EGRESS_POINTS[f"{fn.__module__}:{operation}"] = EgressPoint(boundary, policy)
        signature = inspect.signature(fn)

        def diverted(run: ShadowRun, args: Any, kwargs: Any) -> Any:
            return _divert(run, boundary, operation, policy, signature.bind(*args, **kwargs).arguments)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_boundary(*args: Any, **kwargs: Any) -> Any:
                run = _RUN.get()
                if run is None or policy.action == "allow":
                    return await fn(*args, **kwargs)
                return diverted(run, args, kwargs)

            return cast(F, async_boundary)

        @functools.wraps(fn)
        def sync_boundary(*args: Any, **kwargs: Any) -> Any:
            run = _RUN.get()
            if run is None or policy.action == "allow":
                return fn(*args, **kwargs)
            return diverted(run, args, kwargs)

        return cast(F, sync_boundary)

    return decorate


__all__ = [
    "EFFECT_OUTCOMES",
    "EGRESS_POINTS",
    "MAX_EFFECTS",
    "REFUSE",
    "SHADOW_RUN_PREFIX",
    "EffectOutcome",
    "EgressPoint",
    "RunMode",
    "ShadowEffect",
    "ShadowEgressRefused",
    "ShadowPolicy",
    "ShadowRun",
    "ShadowSink",
    "active_shadow_run",
    "allow",
    "egress",
    "in_shadow",
    "passed_arguments",
    "run_mode",
    "shadow_run_id",
    "shadow_scope",
    "sink",
]
