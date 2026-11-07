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
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, TypeVar

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
        self.add(
            NewTraceStep(
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
        )

    async def tool(
        self,
        agent: str,
        tool: str,
        request: Mapping[str, Any],
        call: Awaitable[T],
        output: Callable[[T], Any],
    ) -> T:
        """Await ``call`` (a tool lookup) and record it; ``output`` turns its result into the recorded output."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        input_hash = content_hash({"tool": tool, **request})
        try:
            result = await call
        except Exception as exc:
            self.add(
                NewTraceStep(
                    agent=agent[:_MAX_LABEL], kind="tool", tool=tool[:_MAX_LABEL], input_hash=input_hash,
                    outcome="error", error_type=type(exc).__name__[:128], started_at=started_at,
                    latency_ms=round((time.perf_counter() - start) * 1000),
                )
            )
            raise
        recorded = output(result)
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
    "TraceRecorder",
    "content_hash",
    "messages_hash",
    "result_digest",
]
