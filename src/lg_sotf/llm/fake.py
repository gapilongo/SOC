"""Deterministic offline chat model for tests, local demos and eval plumbing.

``FakeChatModel`` is a real LangChain ``BaseChatModel``. It never calls a
network service: it scores the untrusted alert text with keyword heuristics
(malware, ransomware, mimikatz, c2, beacon, ... raise the threat score and
confidence; test, scheduled, known, benign, update, ... lower them) and turns
that score into schema-valid structured output. The same input always yields
the same output. It is *not* a detection model and must never run in
production (``settings.assert_safe`` enforces this).
"""

from __future__ import annotations

import enum
import json
import math
import re
import types
import typing
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Type, Union

import annotated_types
from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models import LanguageModelInput
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from pydantic import BaseModel, ValidationError
from pydantic.fields import FieldInfo

MALICIOUS_KEYWORDS: Tuple[str, ...] = (
    "malware", "ransomware", "mimikatz", "c2", "command and control", "beacon", "cobalt strike",
    "cobaltstrike", "trojan", "backdoor", "exfiltration", "exfil", "lateral movement", "credential dump",
    "credential dumping", "lsass", "privilege escalation", "reverse shell", "webshell", "brute force",
    "phishing", "encodedcommand", "powershell -enc", "psexec", "rootkit", "cryptominer", "keylogger",
    "botnet", "exploit", "shellcode", "ransom", "wiper", "kerberoasting", "dcsync",
)
BENIGN_KEYWORDS: Tuple[str, ...] = (
    "test", "testing", "scheduled", "known", "benign", "update", "updated", "updates", "backup",
    "maintenance", "authorized", "authorised", "allowlisted", "whitelisted", "false positive", "expected",
    "approved", "patch", "patching", "health check", "healthcheck", "vulnerability scan", "sanctioned",
)
SEVERITY_WEIGHTS: Dict[str, int] = {"critical": 10, "high": 5, "medium": 0, "low": -5, "info": -10, "informational": -10}

_HIGH_CHOICES = {
    "malicious", "true_positive", "escalate", "escalated", "high", "critical", "confirmed", "compromised",
    "threat", "block", "isolate", "contain", "respond", "response", "tp", "true positive", "human_loop",
}
_LOW_CHOICES = {
    "benign", "false_positive", "close", "closed", "low", "info", "informational", "safe", "clean", "fp",
    "ignore", "suppress", "benign_positive", "false positive", "none",
}
_MID_CHOICES = {
    "inconclusive", "needs_more_info", "medium", "suspicious", "investigate", "unknown", "review", "analysis",
    "correlation", "uncertain", "moderate",
}
_SEVERITY_RE = re.compile(r"severity\W{0,4}(critical|high|medium|low|informational|info)\b")
_DATA_RE = re.compile(r"<alert_data>(.*?)</alert_data>", re.DOTALL)
_EPOCH = datetime(2024, 1, 1, tzinfo=UTC)
_UUID_NS = uuid.UUID("5b0d7c1e-8a52-4a55-9a7c-2f3b8c0f4d11")


def _keyword_pattern(words: Sequence[str]) -> re.Pattern[str]:
    alternatives = "|".join(sorted((re.escape(w) for w in words), key=len, reverse=True))
    return re.compile(rf"(?<![a-z0-9])(?:{alternatives})(?![a-z0-9])")


_MAL_RE = _keyword_pattern(MALICIOUS_KEYWORDS)
_BEN_RE = _keyword_pattern(BENIGN_KEYWORDS)


@dataclass(frozen=True)
class Signals:
    """Heuristic reading of the alert text."""

    threat_score: int
    confidence: int
    malicious: Tuple[str, ...]
    benign: Tuple[str, ...]

    @property
    def band(self) -> str:
        if self.threat_score >= 65:
            return "high"
        if self.threat_score <= 35:
            return "low"
        return "mid"


def analyse_text(text: str) -> Signals:
    lowered = text.lower()
    malicious = tuple(sorted(set(_MAL_RE.findall(lowered))))
    benign = tuple(sorted(set(_BEN_RE.findall(lowered))))
    severity = _SEVERITY_RE.search(lowered)
    score = 50 + 12 * len(malicious) - 12 * len(benign)
    if severity:
        score += SEVERITY_WEIGHTS[severity.group(1)]
    score = max(2, min(98, score))
    hits = len(malicious) + len(benign)
    confidence = 45 if hits == 0 else max(40, min(95, 55 + 6 * hits + abs(score - 50) // 3))
    return Signals(threat_score=score, confidence=confidence, malicious=malicious, benign=benign)


def _message_text(message: BaseMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "\n".join(parts)


def untrusted_text(messages: Sequence[BaseMessage]) -> str:
    """Alert text only: ``<alert_data>`` blocks if present, else all human turns (never the system prompt)."""
    human = "\n".join(_message_text(m) for m in messages if isinstance(m, HumanMessage))
    blocks = _DATA_RE.findall(human)
    return "\n".join(blocks) if blocks else human


# --------------------------------------------------------------------------
# Schema-valid value synthesis
# --------------------------------------------------------------------------


@dataclass
class _Bounds:
    ge: Optional[float] = None
    le: Optional[float] = None
    gt: Optional[float] = None
    lt: Optional[float] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None


def _bounds(field: Optional[FieldInfo]) -> _Bounds:
    b = _Bounds()
    if field is None:
        return b
    for meta in field.metadata:
        if isinstance(meta, annotated_types.MinLen):
            b.min_len = meta.min_length
        elif isinstance(meta, annotated_types.MaxLen):
            b.max_len = meta.max_length
        else:
            for attr in ("ge", "le", "gt", "lt"):
                bound = getattr(meta, attr, None)
                if isinstance(bound, (int, float)) and not isinstance(bound, bool):
                    setattr(b, attr, float(bound))
    return b


def _is_confidence(name: str) -> bool:
    return "confidence" in name or "certainty" in name


def _number(name: str, is_int: bool, b: _Bounds, sig: Signals) -> Union[int, float]:
    base = float(sig.confidence if _is_confidence(name) else sig.threat_score)
    upper = b.le if b.le is not None else b.lt
    if upper is not None and upper <= 1.0:
        value = base / 100.0
    elif upper is not None and upper <= 10.0:
        value = base / 10.0
    else:
        value = base
    lo = b.ge if b.ge is not None else (b.gt if b.gt is not None else None)
    hi = b.le if b.le is not None else (b.lt if b.lt is not None else None)
    step = 1.0 if is_int else 1e-6
    if lo is not None:
        value = max(value, lo + (step if b.ge is None and b.gt is not None else 0.0))
    if hi is not None:
        value = min(value, hi - (step if b.le is None and b.lt is not None else 0.0))
    if is_int:
        rounded = int(round(value))
        if lo is not None and rounded < lo:
            rounded = int(math.ceil(lo))
        if hi is not None and rounded > hi:
            rounded = int(math.floor(hi))
        return rounded
    return round(value, 4)


_BENIGN_BOOL_HINTS = ("false_positive", "benign", "safe", "suppress", "close", "is_fp", "noise")
_MALICIOUS_BOOL_HINTS = (
    "malicious", "true_positive", "escalat", "threat", "compromis", "requires", "needs", "human", "contain",
    "block", "isolate", "respond", "suspicious", "attack",
)


def _boolean(name: str, sig: Signals) -> bool:
    if any(h in name for h in _BENIGN_BOOL_HINTS):
        return sig.threat_score <= 35
    if any(h in name for h in _MALICIOUS_BOOL_HINTS):
        return sig.threat_score >= 65
    return sig.threat_score >= 50


def _choose(values: Sequence[Any], sig: Signals) -> Any:
    band_set = {"high": _HIGH_CHOICES, "low": _LOW_CHOICES, "mid": _MID_CHOICES}[sig.band]
    for v in values:
        if str(v).lower() in band_set:
            return v
    idx = round((sig.threat_score / 100.0) * (len(values) - 1))
    return values[max(0, min(len(values) - 1, idx))]


def _text(name: str, b: _Bounds, sig: Signals) -> str:
    if any(k in name for k in ("reason", "rationale", "explanation", "summary", "analysis", "notes", "description", "justification")):
        text = (
            f"Deterministic heuristic assessment (fake model): threat score {sig.threat_score}, "
            f"confidence {sig.confidence}. Malicious signals: {', '.join(sig.malicious) or 'none'}. "
            f"Benign signals: {', '.join(sig.benign) or 'none'}."
        )
    elif "title" in name:
        text = "Heuristic alert assessment"
    elif any(k in name for k in ("recommend", "action", "next_step")):
        text = {"high": "escalate for analyst review", "low": "close as benign", "mid": "investigate further"}[sig.band]
    elif "category" in name:
        text = "malware" if sig.malicious else "unknown"
    else:
        text = f"fake {name}".strip()
    if b.max_len is not None:
        text = text[: b.max_len]
    if b.min_len is not None and len(text) < b.min_len:
        text = text + "." * (b.min_len - len(text))
    return text


def _strings(name: str, b: _Bounds, sig: Signals) -> List[str]:
    source = sig.benign if any(h in name for h in ("benign", "fp", "false")) else sig.malicious
    items = list(source)
    if b.min_len is not None and len(items) < b.min_len:
        items += [f"{name}-{i}" for i in range(len(items), b.min_len)]
    if b.max_len is not None:
        items = items[: b.max_len]
    return items


def _value(name: str, annotation: Any, field: Optional[FieldInfo], sig: Signals, depth: int) -> Any:
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    b = _bounds(field)

    if origin is typing.Annotated:
        return _value(name, args[0], field, sig, depth)
    if origin in (Union, types.UnionType):
        non_none = [a for a in args if a is not type(None)]
        return _value(name, non_none[0], field, sig, depth) if non_none else None
    if origin is typing.Literal:
        return _choose(list(args), sig)
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        members = list(annotation)
        chosen = _choose([m.value for m in members], sig)
        return next(m for m in members if m.value == chosen)
    if annotation is bool:
        return _boolean(name, sig)
    if annotation is int or annotation is float:
        return _number(name, annotation is int, b, sig)
    if annotation is str:
        return _text(name, b, sig)
    if annotation is datetime:
        return _EPOCH
    if annotation is date:
        return _EPOCH.date()
    if annotation is uuid.UUID:
        return uuid.uuid5(_UUID_NS, f"{name}:{sig.threat_score}")
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return _instance_data(annotation, sig, depth + 1)
    if origin in (list, set, frozenset, tuple) or annotation in (list, set, tuple):
        item_type = args[0] if args else str
        if item_type is str:
            items: List[Any] = _strings(name, b, sig)
        else:
            count = max(b.min_len or 0, 1 if (isinstance(item_type, type) and issubclass(item_type, BaseModel) and depth < 3 and sig.malicious) else 0)
            if b.max_len is not None:
                count = min(count, b.max_len)
            items = [_value(name, item_type, None, sig, depth + 1) for _ in range(count)]
        return items
    if origin is dict or annotation is dict:
        return {}
    if annotation is Any or annotation is object:
        return None
    raise TypeError(f"FakeChatModel cannot synthesise a value for {name!r} of type {annotation!r}")


def _instance_data(schema: Type[BaseModel], sig: Signals, depth: int = 0) -> Dict[str, Any]:
    if depth > 6:
        raise TypeError(f"schema {schema.__name__} nests too deeply for FakeChatModel")
    data: Dict[str, Any] = {}
    for name, field in schema.model_fields.items():
        key = field.alias or name
        try:
            data[key] = _value(name.lower(), field.annotation, field, sig, depth)
        except TypeError:
            if field.is_required():
                raise
    return data


def synthesize(schema: Type[BaseModel], sig: Signals) -> BaseModel:
    """Build a schema-valid instance from heuristic signals (raises ``ValidationError`` if impossible)."""
    return schema.model_validate(_instance_data(schema, sig))


# --------------------------------------------------------------------------
# Chat model
# --------------------------------------------------------------------------


def _approx_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


class FakeChatModel(BaseChatModel):
    """Deterministic, offline chat model with structured-output support."""

    model_name: str = "fake"
    max_tokens: int = 1024

    @property
    def _llm_type(self) -> str:
        return "lg-sotf-fake"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        return {"model_name": self.model_name}

    def _usage(self, messages: Sequence[BaseMessage], output: str) -> Dict[str, Any]:
        prompt = "\n".join(_message_text(m) for m in messages)
        n_in, n_out = _approx_tokens(prompt), _approx_tokens(output)
        return {"input_tokens": n_in, "output_tokens": n_out, "total_tokens": n_in + n_out}

    def _response(self, messages: Sequence[BaseMessage], content: str) -> AIMessage:
        return AIMessage(
            content=content,
            usage_metadata=self._usage(messages, content),
            response_metadata={"model_name": self.model_name, "stop_reason": "end_turn", "model_provider": "fake"},
        )

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        sig = analyse_text(untrusted_text(messages))
        payload = {
            "threat_score": sig.threat_score,
            "confidence": sig.confidence,
            "verdict": {"high": "malicious", "low": "benign", "mid": "inconclusive"}[sig.band],
            "is_false_positive": sig.band == "low",
            "is_true_positive": sig.band == "high",
            "malicious_signals": list(sig.malicious),
            "benign_signals": list(sig.benign),
            "reasoning": _text("reasoning", _Bounds(), sig),
        }
        content = json.dumps(payload, sort_keys=True)
        return ChatResult(generations=[ChatGeneration(message=self._response(messages, content))])

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return self._generate(messages, stop=stop, **kwargs)

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> Runnable[LanguageModelInput, AIMessage]:
        """Accepts tools for interface compatibility; the fake model never emits tool calls."""
        return self

    def with_structured_output(
        self,
        schema: Union[Dict[str, Any], Type[BaseModel]],
        *,
        include_raw: bool = False,
        method: str = "json_schema",
        **kwargs: Any,
    ) -> Runnable[LanguageModelInput, Any]:
        if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
            raise NotImplementedError("FakeChatModel.with_structured_output supports Pydantic models only")
        model_schema: Type[BaseModel] = schema

        def _run(input_: LanguageModelInput, config: Optional[RunnableConfig] = None) -> Any:
            messages = self._convert_input(input_).to_messages()
            sig = analyse_text(untrusted_text(messages))
            parsed: Optional[BaseModel] = None
            error: Optional[BaseException] = None
            try:
                parsed = synthesize(model_schema, sig)
                content = parsed.model_dump_json()
            except (ValidationError, TypeError) as exc:
                if not include_raw:
                    raise
                error, content = exc, ""
            raw = self._response(messages, content)
            if include_raw:
                return {"raw": raw, "parsed": parsed, "parsing_error": error}
            return parsed

        async def _arun(input_: LanguageModelInput, config: Optional[RunnableConfig] = None) -> Any:
            return _run(input_, config)

        runner: Callable[..., Any] = _run
        return RunnableLambda(runner, afunc=_arun, name=f"FakeStructured[{model_schema.__name__}]")
