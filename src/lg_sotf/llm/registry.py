"""Prompt registry: every prompt template has a stable name and a content hash.

Prompts stay git-versioned constants next to the code that uses them.
Registering one (:func:`register_prompt`) gives it a name such as
``triage.assess`` and a hash of everything fixed that the model is sent for
it: the system prompt as built (instructions, task and the shared data
guard), the preambles of the untrusted data blocks and the output schema.
Changing the wording, the schema or the shared guard changes the hash, so two
calls with the same hash sent the model the same instructions. Wrapping that
depends on the provider path (the schema instructions and repair turn of the
JSON-text path in :mod:`lg_sotf.llm.structured`) is versioned with the code,
not by this hash.

Every structured call records a :class:`CallProvenance`
(``{prompt_name, prompt_hash, model_id, provider}``): in the ``llm.call``
log event, in the per-agent usage totals (``summary.llm_usage``, evaluation
reports) and, for agents, in ``summary.llm_models`` (evidence packs).
A call made without a registered template is recorded as ``unregistered``
with a hash of the system message it sent; production code always passes
one (``tests/unit/llm/test_prompt_registry.py`` checks every call site).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Generic, Optional, Sequence, Type, TypeVar

from langchain_core.messages import BaseMessage, SystemMessage
from pydantic import BaseModel

from lg_sotf.llm.prompting import CONTEXT_PREAMBLE, TRUNCATION_NOTE, UNTRUSTED_PREAMBLE, system_text

T = TypeVar("T", bound=BaseModel)

PROMPT_HASH_CHARS = 16
UNREGISTERED = "unregistered"
_NAME_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
MAX_NAME_CHARS = 64


def _digest(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:PROMPT_HASH_CHARS]


def template_hash(system: str, task: str, schema: Type[BaseModel]) -> str:
    """The content hash of a template: system prompt as sent, data preambles and output schema."""
    return _digest(
        {
            "system": system_text(system, task),
            "data_preamble": UNTRUSTED_PREAMBLE,
            "context_preamble": CONTEXT_PREAMBLE,
            "truncation_note": TRUNCATION_NOTE,
            "schema": schema.model_json_schema(),
        }
    )


@dataclass(frozen=True)
class PromptTemplate(Generic[T]):
    """A named prompt: trusted instructions (``system`` + ``task``) and the schema of the answer."""

    name: str
    system: str
    task: str
    schema: Type[T]
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "hash", template_hash(self.system, self.task, self.schema))


@dataclass(frozen=True)
class CallProvenance:
    """What produced one LLM call's answer: the prompt version and the model (no secrets, bounded)."""

    prompt_name: str
    prompt_hash: str
    model_id: str
    provider: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "prompt_name": self.prompt_name,
            "prompt_hash": self.prompt_hash,
            "model_id": self.model_id,
            "provider": self.provider,
        }


_REGISTRY: Dict[str, PromptTemplate[Any]] = {}


def register_prompt(name: str, *, system: str, task: str, schema: Type[T]) -> PromptTemplate[T]:
    """Register (or re-register identically) the template ``name``; a different template under a taken name raises."""
    if len(name) > MAX_NAME_CHARS or not _NAME_RE.match(name):
        raise ValueError(f"invalid prompt name {name!r}: lowercase dotted words, at most {MAX_NAME_CHARS} characters")
    template = PromptTemplate(name=name, system=system, task=task, schema=schema)
    existing = _REGISTRY.get(name)
    if existing is not None and existing.hash != template.hash:
        raise ValueError(f"prompt {name!r} is already registered with a different content")
    _REGISTRY[name] = template
    return template


def prompt_manifest() -> Dict[str, str]:
    """``{name: hash}`` of every registered template, sorted by name."""
    return {name: _REGISTRY[name].hash for name in sorted(_REGISTRY)}


def unregistered_hash(messages: Sequence[BaseMessage]) -> str:
    """A fingerprint of the system message of a call made without a registered template."""
    system = [m.content for m in messages if isinstance(m, SystemMessage)]
    return _digest(system)


def call_provenance(
    prompt: Optional[PromptTemplate[Any]], messages: Sequence[BaseMessage], *, model_id: str, provider: str
) -> CallProvenance:
    """The provenance of one call of ``model_id`` with ``prompt`` (or the unregistered ``messages``)."""
    if prompt is None:
        return CallProvenance(UNREGISTERED, unregistered_hash(messages), model_id, provider)
    return CallProvenance(prompt.name, prompt.hash, model_id, provider)


__all__ = [
    "PROMPT_HASH_CHARS",
    "UNREGISTERED",
    "CallProvenance",
    "PromptTemplate",
    "call_provenance",
    "prompt_manifest",
    "register_prompt",
    "template_hash",
    "unregistered_hash",
]
