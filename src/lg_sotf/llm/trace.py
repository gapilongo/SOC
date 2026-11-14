"""Investigation trace: every LLM call and tool call of a run, recorded for the trace store.

A :class:`TraceRecorder` lives on the per-node agent context. Structured LLM
calls (:func:`lg_sotf.llm.structured.ainvoke_structured`, one step per model
attempt, transient retries and repair attempts included) and the analysis
agent's tool calls (threat-intelligence and history lookups, through
:meth:`TraceRecorder.tool`) append a step each; the agent's run then writes
them to ``investigation_steps`` (:func:`lg_sotf.agents.base.persist_trace`),
best effort.

A step stores SHA-256 hashes of its input and output, never the input
itself. The input hash of an LLM step covers the messages as sent; that of a
tool step covers the tool name and its request (``kind``, ``value``,
``providers``), so a later replay can find a recorded observation again by
it. ``result_digest`` is the output redacted (:func:`lg_sotf.security.redaction.redact`),
with long strings and lists cut, and replaced by a note when it is still
larger than :data:`MAX_DIGEST_BYTES`.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable, Dict, Iterator, List, Mapping, Optional, Protocol, Sequence, Tuple, TypeVar

from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from lg_sotf.llm.registry import CallProvenance
from lg_sotf.llm.usage import UsageSample
from lg_sotf.models.trace import NewTraceStep, StepOutcome
from lg_sotf.security.redaction import redact

T = TypeVar("T")

MAX_STEPS = 200
"""Steps one agent context keeps (one node of one run); later ones are counted in ``dropped``."""
MAX_DIGEST_BYTES = 8_192
MAX_DIGEST_STRING = 1_000
MAX_DIGEST_ITEMS = 20
MAX_DIGEST_DEPTH = 6
_MAX_LABEL = 64


def content_hash(value: Any) -> str:
    """Lowercase hex SHA-256 of ``value`` as canonical JSON (sorted keys, compact, UTF-8)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def messages_hash(messages: Sequence[BaseMessage]) -> str:
    """The input hash of an LLM attempt: each message's type and content as sent."""
    return content_hash([[m.type, m.content] for m in messages])


def _cap(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DIGEST_DEPTH:
        return "[cut: nesting]"
    if isinstance(value, str):
        return value if len(value) <= MAX_DIGEST_STRING else value[: MAX_DIGEST_STRING - 3] + "..."
    if isinstance(value, Mapping):
        return {str(k)[:_MAX_LABEL]: _cap(v, depth + 1) for k, v in list(value.items())[:MAX_DIGEST_ITEMS * 2]}
    if isinstance(value, (list, tuple)):
        return [_cap(v, depth + 1) for v in list(value)[:MAX_DIGEST_ITEMS]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_DIGEST_STRING]


def result_digest(value: Any) -> Dict[str, Any]:
    """``{"value": ...}``: ``value`` redacted and size-capped (never a raw secret, at most ``MAX_DIGEST_BYTES``)."""
    redacted, _ = redact(value.model_dump(mode="json") if isinstance(value, BaseModel) else value)
    digest = {"value": _cap(redacted)}
    size = len(json.dumps(digest, ensure_ascii=False, default=str).encode("utf-8"))
    if size > MAX_DIGEST_BYTES:
        return {"omitted": "too large", "bytes": size}
    return digest


class Tape(Protocol):
    """Where the current run's observations are recorded or replayed from (a cassette)."""

    @property
    def replays_tools(self) -> bool: ...

    def replay_tool(self, tool: str, input_hash: str) -> Any:
        """The recorded observation; raises when there is none (never falls back to the live tool)."""
        ...

    def record_tool(self, tool: str, request: Mapping[str, Any], input_hash: str, observation: Any) -> None: ...

    def record_llm(
        self,
        step: NewTraceStep,
        messages: Sequence[BaseMessage],
        value: Optional[BaseModel],
        reply: str,
        error: Optional[BaseException],
    ) -> None: ...


_TAPE: ContextVar[Optional[Tape]] = ContextVar("lg_sotf_tape", default=None)


def active_tape() -> Optional[Tape]:
    """The tape of the current task (and the tasks it started), if any."""
    return _TAPE.get()


@contextmanager
def use_tape(tape: Optional[Tape]) -> Iterator[None]:
    """Make ``tape`` the active tape while the block runs (``None``: none)."""
    token = _TAPE.set(tape)
    try:
        yield
    finally:
        _TAPE.reset(token)


def tool_input_hash(tool: str, request: Mapping[str, Any]) -> str:
    """The input hash of a tool call: the tool's name and its request, as canonical JSON."""
    return content_hash({"tool": tool, **request})


async def observe(
    tool: str,
    request: Mapping[str, Any],
    call: Awaitable[T],
    output: Callable[[T], Any],
    restore: Callable[[Any], T],
) -> T:
    """Await ``call`` through the active tape, without a trace step (an observation of configuration).

    ``output`` turns the result into what is recorded and ``restore`` turns that back into a result.
    """
    input_hash = tool_input_hash(tool, request)
    tape = _TAPE.get()
    if tape is not None and tape.replays_tools:
        return restore(_replay(tape, tool, input_hash, call))
    result = await call
    if tape is not None:
        tape.record_tool(tool, request, input_hash, output(result))
    return result


def _replay(tape: Tape, tool: str, input_hash: str, call: Awaitable[Any]) -> Any:
    if inspect.iscoroutine(call):
        call.close()  # never awaited: the live lookup does not run
    return tape.replay_tool(tool, input_hash)


def _output_hash(value: Any) -> str:
    return content_hash(value.model_dump(mode="json") if isinstance(value, BaseModel) else value)


@dataclass
class TraceRecorder:
    """The steps of one agent context, in the order they happened."""

    steps: List[NewTraceStep] = field(default_factory=list)
    dropped: int = 0

    def add(self, step: NewTraceStep) -> None:
        if len(self.steps) >= MAX_STEPS:
            self.dropped += 1
            return
        self.steps.append(step)

    def llm_step(
        self,
        *,
        agent: str,
        provenance: CallProvenance,
        messages: Sequence[BaseMessage],
        started_at: datetime,
        latency_ms: int,
        outcome: StepOutcome,
        samples: Sequence[UsageSample] = (),
        value: Optional[BaseModel] = None,
        reply: str = "",
        error: Optional[BaseException] = None,
    ) -> None:
        """One model attempt: the validated ``value``, or the raw ``reply`` text and the ``error``."""
        output: Any = value if value is not None else (reply or None)
        step = NewTraceStep(
            agent=agent[:_MAX_LABEL],
            kind="llm",
            prompt_name=provenance.prompt_name,
            prompt_hash=provenance.prompt_hash,
            provider=provenance.provider[:128],
            model=(samples[-1].model if samples else provenance.model_id)[:128],
            input_hash=messages_hash(messages),
            output_hash=_output_hash(output) if output is not None else None,
            result_digest=result_digest(value) if value is not None else None,
            outcome=outcome,
            error_type=type(error).__name__[:128] if error is not None else None,
            input_tokens=sum(s.input_tokens for s in samples),
            output_tokens=sum(s.output_tokens for s in samples),
            cache_read_tokens=sum(s.cache_read_tokens for s in samples),
            cache_write_tokens=sum(s.cache_write_tokens for s in samples),
            latency_ms=max(0, latency_ms),
            started_at=started_at,
        )
        self.add(step)
        tape = _TAPE.get()
        if tape is not None:
            tape.record_llm(step, messages, value, reply, error)

    @staticmethod
    def tool_hashes(tool: str, request: Mapping[str, Any], recorded: Any) -> Tuple[str, str]:
        """The input and output hash a tool step stores, for a caller that keeps them with the result."""
        return tool_input_hash(tool, request), content_hash(recorded)

    async def tool(
        self,
        agent: str,
        tool: str,
        request: Mapping[str, Any],
        call: Awaitable[T],
        output: Callable[[T], Any],
        restore: Optional[Callable[[Any], T]] = None,
    ) -> T:
        """Await ``call`` (a tool lookup) and record it; ``output`` turns its result into the recorded output.

        ``restore`` turns a recorded output back into a result: with a tape that replays tools, the
        result comes from the tape and ``call`` is never awaited.
        """
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        input_hash = tool_input_hash(tool, request)
        tape = _TAPE.get()
        replaying = tape is not None and tape.replays_tools
        try:
            if tape is not None and replaying:
                recorded = _replay(tape, tool, input_hash, call)
                if restore is None:
                    raise LookupError(f"tool {tool!r} has no restore function and cannot be replayed")
                result = restore(recorded)
            else:
                result = await call
                recorded = output(result)
        except Exception as exc:
            self.add(
                NewTraceStep(
                    agent=agent[:_MAX_LABEL], kind="tool", tool=tool[:_MAX_LABEL], input_hash=input_hash,
                    outcome="error", error_type=type(exc).__name__[:128], started_at=started_at,
                    latency_ms=round((time.perf_counter() - start) * 1000),
                )
            )
            raise
        if tape is not None and not replaying:
            tape.record_tool(tool, request, input_hash, recorded)
        self.add(
            NewTraceStep(
                agent=agent[:_MAX_LABEL], kind="tool", tool=tool[:_MAX_LABEL], input_hash=input_hash,
                output_hash=content_hash(recorded), result_digest=result_digest(recorded), outcome="success",
                started_at=started_at, latency_ms=round((time.perf_counter() - start) * 1000),
            )
        )
        return result


__all__ = [
    "MAX_DIGEST_BYTES",
    "MAX_STEPS",
    "Tape",
    "TraceRecorder",
    "active_tape",
    "content_hash",
    "messages_hash",
    "observe",
    "result_digest",
    "tool_input_hash",
    "use_tape",
]
