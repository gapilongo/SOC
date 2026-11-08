"""Cassettes: a run's tool observations and model replies, recorded once and replayed offline.

A cassette is one JSON Lines file per alert (one evaluation item), plain or
gzip-compressed (``.jsonl.gz``, see :class:`CassetteSet`). Its first
line is the header::

    {"cassette": 2, "item_id": ..., "item_sha256": ..., "dataset_sha256": ...,
     "source": ..., "recorded_at": ..., "models": {"fast": {...}, "deep": {...}}}

Every other line is an entry, in the order the run made the calls:

* ``{"type": "tool", "tool", "lookup", "request", "observation"}``: a tool call.
  ``lookup`` is the trace's input hash (:func:`lg_sotf.llm.trace.tool_input_hash`:
  the tool's name and its request as canonical JSON), the same hash
  ``investigation_steps.input_hash`` holds; ``observation`` is the tool's
  output in full.
* ``{"type": "llm", "lookup", "agent", "prompt_name", "prompt_hash", "model",
  "outcome", "value" | "reply", ...tokens}``: one model attempt. ``lookup`` hashes
  the messages as sent with alert ids (UUIDs) and timestamps blanked, since
  those change on every run, and with secrets redacted.

Keys are sorted in every line, so a re-recording of an unchanged run differs
only in ``recorded_at``. Requests, observations, replies and values are
redacted with :func:`lg_sotf.security.redaction.redact`, the rules the trace
digest uses; unlike the digest nothing is cut, so a replay sees what the run saw.

Observations are the tools' own outputs, not evidence facts
(:mod:`lg_sotf.models.evidence_fact`): a reputation fact keeps the verdict,
score and categories but not the provider status, error or data the analysis
prompt shows, and a history lookup has no fact kind, so a replay from facts
would not be identical. Once tools return facts, the facts are the observation.

The trace store cannot stand in for a cassette: its digests are cut and
dropped beyond :data:`lg_sotf.llm.trace.MAX_DIGEST_BYTES`, it keeps no reply
of an invalid attempt, and its LLM input hash covers the alert id, which a
replay never reproduces. Cassettes are therefore recorded from a live run.

Modes (:data:`CassetteMode`):

* ``record``: the run is live; every observation and reply is written.
* ``replay``: tools and the model answer from the cassette; nothing else is
  called. A call the cassette does not hold raises :class:`CassetteMiss`,
  never a live call.
* ``replay-tools``: tools answer from the cassette, the model is live, so a
  new model or prompt is judged against the same observations.
"""

from __future__ import annotations

import gzip
import json
import re
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple, Type, Union, get_args

from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models import LanguageModelInput
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from pydantic import BaseModel, PrivateAttr, ValidationError

from lg_sotf.llm.client import (
    PROVIDER_KEY,
    STRUCTURED_KEY,
    Tier,
    model_name_of,
    model_structured_method,
    provider_of,
)
from lg_sotf.llm.errors import LLMOutputError, LLMRefusal
from lg_sotf.llm.trace import active_tape, content_hash
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.security.redaction import redact
from lg_sotf.settings import Settings

CASSETTE_SCHEMA_VERSION = 2
CASSETTE_SUFFIX = ".jsonl"
GZIP_SUFFIX = ".gz"
CASSETTE_PROVIDER = "cassette"
CassetteMode = Literal["record", "replay", "replay-tools"]
CASSETTE_MODES: Tuple[str, ...] = get_args(CassetteMode)
ModelFactory = Callable[[Tier, Settings], BaseChatModel]

_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class CassetteError(RuntimeError):
    """A cassette file cannot be read or written."""


class CassetteMiss(RuntimeError):
    """A replay asked for a call the cassette does not hold. Never answered by a live call."""


def _stable(value: Any) -> Any:
    if isinstance(value, str):
        return _TIMESTAMP.sub("<time>", _UUID.sub("<uuid>", value))
    if isinstance(value, Mapping):
        return {str(k): _stable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    return value


def llm_key(messages: Sequence[BaseMessage]) -> str:
    """The replay key of a model attempt: its messages, redacted, with ids and timestamps blanked."""
    redacted, _ = redact([[m.type, m.content] for m in messages])
    return content_hash(_stable(redacted))


def _redacted(value: Any) -> Any:
    out, _ = redact(value.model_dump(mode="json") if isinstance(value, BaseModel) else value)
    return out


def _line(data: Mapping[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def cassette_name(item_id: str) -> str:
    """The file name of an item's cassette (characters outside ``[A-Za-z0-9._-]`` become ``_``)."""
    return _UNSAFE_NAME.sub("_", item_id) + CASSETTE_SUFFIX


@dataclass
class Cassette:
    """One alert's recording; the active :class:`~lg_sotf.llm.trace.Tape` while that alert runs."""

    mode: CassetteMode
    header: Dict[str, Any]
    entries: List[Dict[str, Any]] = field(default_factory=list)
    problem: Optional[str] = None
    """Why nothing can be replayed (no file, another item, unreadable): raised on the first lookup."""
    _cursor: Dict[Tuple[str, str], int] = field(default_factory=dict, repr=False)

    @property
    def item_id(self) -> str:
        return str(self.header.get("item_id", ""))

    @property
    def replays_tools(self) -> bool:
        return self.mode != "record"

    @property
    def replays_llm(self) -> bool:
        return self.mode == "replay"

    @property
    def models(self) -> Dict[str, Dict[str, Any]]:
        models = self.header.setdefault("models", {})
        return models  # type: ignore[no-any-return]

    def _next(self, kind: str, key: str, what: str) -> Dict[str, Any]:
        if self.problem is not None:
            raise CassetteMiss(f"cassette {self.item_id!r}: {self.problem}")
        matches = [e for e in self.entries if e.get("type") == kind and e.get("lookup") == key]
        if not matches:
            raise CassetteMiss(
                f"cassette {self.item_id!r} holds no {what} with input hash {key[:16]}; the input changed since "
                "it was recorded: record it again"
            )
        index = self._cursor.get((kind, key), 0)
        self._cursor[(kind, key)] = index + 1
        # The same input asked again after the recording ran out gets the last answer again.
        return matches[min(index, len(matches) - 1)]

    def replay_tool(self, tool: str, input_hash: str) -> Any:
        return self._next("tool", input_hash, f"{tool} observation").get("observation")

    def replay_llm(self, key: str) -> Dict[str, Any]:
        return self._next("llm", key, "model reply")

    def record_tool(self, tool: str, request: Mapping[str, Any], input_hash: str, observation: Any) -> None:
        if self.mode == "record":
            self.entries.append(
                {"type": "tool", "tool": tool, "lookup": input_hash, "request": _redacted(dict(request)),
                 "observation": _redacted(observation)}
            )

    def record_llm(
        self,
        step: NewTraceStep,
        messages: Sequence[BaseMessage],
        value: Optional[BaseModel],
        reply: str,
        error: Optional[BaseException],
    ) -> None:
        # Transport errors are not answers: the retry that follows is recorded instead.
        if self.mode != "record" or step.outcome == "error":
            return
        entry: Dict[str, Any] = {
            "type": "llm", "lookup": llm_key(messages), "agent": step.agent, "prompt_name": step.prompt_name,
            "prompt_hash": step.prompt_hash, "model": step.model, "outcome": step.outcome,
            "input_tokens": step.input_tokens, "output_tokens": step.output_tokens,
        }
        if step.cache_read_tokens or step.cache_write_tokens:
            entry.update(cache_read_tokens=step.cache_read_tokens, cache_write_tokens=step.cache_write_tokens)
        if value is not None:
            entry["value"] = _redacted(value)
        else:
            entry["reply"] = _redacted(reply)
        if isinstance(error, LLMRefusal):
            entry["refusal_category"] = error.category
        elif isinstance(error, LLMOutputError) and error.stop_reason:
            entry["stop_reason"] = error.stop_reason
        self.entries.append(entry)

    def note_model(self, tier: str, model: BaseChatModel) -> None:
        """Remember the model a tier used, so a replay takes the same structured-output path."""
        if self.mode == "record":
            self.models[tier] = {
                "provider": provider_of(model), "model": model_name_of(model),
                "structured_output": model_structured_method(model),
            }

    def dumps(self) -> str:
        return "".join(_line(data) + "\n" for data in [self.header, *self.entries])

    @classmethod
    def loads(cls, text: str, mode: CassetteMode) -> Cassette:
        try:
            lines = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError as exc:
            raise CassetteError(f"not JSON Lines: {exc}") from exc
        if not lines or not isinstance(lines[0], dict) or lines[0].get("cassette") != CASSETTE_SCHEMA_VERSION:
            raise CassetteError(f"not a version {CASSETTE_SCHEMA_VERSION} cassette")
        if not all(isinstance(e, dict) and e.get("type") in ("tool", "llm") for e in lines[1:]):
            raise CassetteError("an entry is not a tool or llm entry")
        return cls(mode=mode, header=lines[0], entries=lines[1:])


@dataclass(frozen=True)
class CassetteSet:
    """A directory of cassettes, one per item, read or written in one mode.

    A cassette may be stored gzip-compressed (``<name>.jsonl.gz``); a replay reads
    either form, and ``compress=True`` makes a recording write the compressed one.
    """

    directory: Path
    mode: CassetteMode
    source: str = "lg-sotf eval"
    dataset_sha256: Optional[str] = None
    compress: bool = False

    def _read(self, item_id: str) -> Tuple[Path, str]:
        path = self.directory / cassette_name(item_id)
        packed = path.with_name(path.name + GZIP_SUFFIX)
        if not path.exists() and packed.exists():
            return packed, gzip.decompress(packed.read_bytes()).decode("utf-8")
        return path, path.read_text(encoding="utf-8")

    def open(self, item_id: str, item_sha256: str) -> Cassette:
        """The item's cassette: a new one to record, or the recorded one (problems surface on first lookup)."""
        header: Dict[str, Any] = {"cassette": CASSETTE_SCHEMA_VERSION, "item_id": item_id, "item_sha256": item_sha256}
        if self.mode == "record":
            header.update(
                source=self.source, dataset_sha256=self.dataset_sha256, models={},
                recorded_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
            )
            return Cassette(mode=self.mode, header=header)
        path = self.directory / cassette_name(item_id)
        try:
            path, text = self._read(item_id)
            cassette = Cassette.loads(text, self.mode)
        except FileNotFoundError:
            return Cassette(mode=self.mode, header=header, problem=f"no cassette file {path.name} in {self.directory}")
        except (OSError, EOFError, zlib.error, UnicodeDecodeError, CassetteError) as exc:
            return Cassette(mode=self.mode, header=header, problem=f"unreadable cassette {path.name}: {exc}")
        if cassette.item_id != item_id:
            cassette.problem = f"{path.name} records item {cassette.item_id!r}"
        elif cassette.header.get("item_sha256") != item_sha256:
            cassette.problem = "the dataset item changed since it was recorded: record it again"
        return cassette

    def save(self, cassette: Cassette) -> None:
        """Write a recorded cassette (other modes write nothing)."""
        if self.mode != "record":
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / cassette_name(cassette.item_id)
            if self.compress:
                # mtime=0 and no file name: re-recording an unchanged run gives the same bytes but recorded_at.
                packed = gzip.compress(cassette.dumps().encode("utf-8"), compresslevel=9, mtime=0)
                path.with_name(path.name + GZIP_SUFFIX).write_bytes(packed)
            else:
                path.write_text(cassette.dumps(), encoding="utf-8")
        except OSError as exc:
            raise CassetteError(f"cannot write cassette for {cassette.item_id!r}: {exc}") from exc


# --------------------------------------------------------------------------
# Model clients
# --------------------------------------------------------------------------


def _active_cassette() -> Optional[Cassette]:
    tape = active_tape()
    return tape if isinstance(tape, Cassette) else None


def recording_model_factory(inner: ModelFactory) -> ModelFactory:
    """``inner``, noting in the active cassette which model each tier used."""

    def factory(tier: Tier, settings: Settings) -> BaseChatModel:
        model = inner(tier, settings)
        cassette = _active_cassette()
        if cassette is not None:
            cassette.note_model(str(tier), model)
        return model

    return factory


def replay_model_factory(tier: Tier, settings: Settings) -> BaseChatModel:
    """A :class:`CassetteChatModel` for the active cassette, shaped like the model that was recorded."""
    cassette = _active_cassette()
    if cassette is None or not cassette.replays_llm:
        raise CassetteMiss("a replayed model was asked for outside a replaying cassette")
    spec = cassette.models.get(str(tier)) or {}
    metadata: Dict[str, Any] = {PROVIDER_KEY: CASSETTE_PROVIDER}
    if spec.get("structured_output"):
        metadata[STRUCTURED_KEY] = spec["structured_output"]
    model = CassetteChatModel(model_name=str(spec.get("model") or CASSETTE_PROVIDER), metadata=metadata)
    model.bind_cassette(cassette)
    return model


def _reply_message(entry: Mapping[str, Any]) -> AIMessage:
    """The recorded reply as the provider's message: text, stop reason and token usage."""
    if "reply" in entry:
        content = str(entry.get("reply") or "")
    else:
        content = json.dumps(entry.get("value"), sort_keys=True, ensure_ascii=False)
    meta: Dict[str, Any] = {"model_name": entry.get("model"), "stop_reason": entry.get("stop_reason") or "end_turn"}
    if entry.get("outcome") == "refusal":
        meta.update(stop_reason="refusal", stop_details={"category": entry.get("refusal_category")})
    n_in, n_out = int(entry.get("input_tokens") or 0), int(entry.get("output_tokens") or 0)
    usage: Dict[str, Any] = {"input_tokens": n_in, "output_tokens": n_out, "total_tokens": n_in + n_out}
    cache_read, cache_write = int(entry.get("cache_read_tokens") or 0), int(entry.get("cache_write_tokens") or 0)
    if cache_read or cache_write:
        usage["input_token_details"] = {"cache_read": cache_read, "cache_creation": cache_write}
    return AIMessage(content=content, usage_metadata=usage, response_metadata=meta)


class CassetteChatModel(BaseChatModel):
    """A chat model that answers every call from a cassette, by :func:`llm_key`; it has no network client."""

    model_name: str = CASSETTE_PROVIDER
    _cassette: Optional[Cassette] = PrivateAttr(default=None)

    @property
    def _llm_type(self) -> str:
        return "lg-sotf-cassette"

    def bind_cassette(self, cassette: Cassette) -> None:
        self._cassette = cassette

    def _entry(self, messages: Sequence[BaseMessage]) -> Dict[str, Any]:
        cassette = self._cassette or _active_cassette()
        if cassette is None:
            raise CassetteMiss("no cassette to replay the model call from")
        return cassette.replay_llm(llm_key(messages))

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=_reply_message(self._entry(messages)))])

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return self._generate(messages, stop=stop, **kwargs)

    def with_structured_output(
        self,
        schema: Union[Dict[str, Any], Type[BaseModel]],
        *,
        include_raw: bool = False,
        **kwargs: Any,
    ) -> Runnable[LanguageModelInput, Any]:
        if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
            raise NotImplementedError("CassetteChatModel.with_structured_output supports Pydantic models only")
        model_schema: Type[BaseModel] = schema

        def _run(input_: LanguageModelInput, config: Optional[RunnableConfig] = None) -> Any:
            entry = self._entry(self._convert_input(input_).to_messages())
            parsed: Optional[BaseModel] = None
            error: Optional[Exception] = None
            if "value" in entry:
                try:
                    parsed = model_schema.model_validate(entry["value"])
                except ValidationError as exc:
                    error = exc
            else:
                error = ValueError("the recorded reply had no structured output")
            if not include_raw:
                if error is not None:
                    raise error
                return parsed
            return {"raw": _reply_message(entry), "parsed": parsed, "parsing_error": error}

        async def _arun(input_: LanguageModelInput, config: Optional[RunnableConfig] = None) -> Any:
            return _run(input_, config)

        runner: Callable[..., Any] = _run
        return RunnableLambda(runner, afunc=_arun, name=f"CassetteStructured[{model_schema.__name__}]")


__all__ = [
    "CASSETTE_MODES",
    "CASSETTE_SCHEMA_VERSION",
    "Cassette",
    "CassetteChatModel",
    "CassetteError",
    "CassetteMiss",
    "CassetteMode",
    "CassetteSet",
    "cassette_name",
    "llm_key",
    "recording_model_factory",
    "replay_model_factory",
]
