"""Optional LLM normalization for events no deterministic normalizer recognizes.

Off by default (``ingestion.llm_fallback``). The event has already been
redacted and is passed to the model only as labelled untrusted data. The
model's answer is treated as untrusted too:

* entity values are validated like any other and kept only if they equal a
  whole value of the event or a whole token of one (split on separators, so
  ``1.1.1.1`` is not grounded by ``11.1.1.10``), so the model cannot invent
  indicators;
* the alert id is never taken from the model (a hash of the event is used);
* severity is floored at ``medium`` so a model cannot demote an unknown
  event into something the workflow might close without review;
* the alert is flagged ``llm_normalized``.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Set

from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.ingestion.entities import normalize_hash, normalize_ip
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext
from lg_sotf.llm import TokenBudget, ainvoke_structured, build_messages, get_chat_model
from lg_sotf.models.alert import SEVERITIES, CanonicalAlert, Severity
from lg_sotf.settings import Settings

AGENT = "ingestion_normalizer"
FLAG_LLM = "llm_normalized"
MIN_LLM_SEVERITY: Severity = "medium"

SYSTEM = (
    "You map security alerts from products without a dedicated parser onto a fixed canonical schema. "
    "You extract; you never infer, enrich or judge maliciousness."
)
TASK = (
    "Map the single event inside <alert_data> onto the output schema.\n"
    "- title: the detection or rule name as the product states it.\n"
    "- severity: the product's own severity mapped to info/low/medium/high/critical; medium if none is stated.\n"
    "- occurred_at: the event time exactly as written in the data, or null.\n"
    "- Entity lists: copy values exactly as they appear in the data. Leave a list empty rather than guess.\n"
    "- mitre_techniques: ATT&CK technique ids (T1234 or T1234.001) present in the data only."
)


class LLMNormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = Field(min_length=1, max_length=300)
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=2_000)
    rule_name: Optional[str] = Field(default=None, max_length=300)
    occurred_at: Optional[str] = Field(default=None, max_length=64)
    hosts: List[str] = Field(default_factory=list, max_length=20)
    users: List[str] = Field(default_factory=list, max_length=20)
    ips: List[str] = Field(default_factory=list, max_length=20)
    domains: List[str] = Field(default_factory=list, max_length=20)
    urls: List[str] = Field(default_factory=list, max_length=20)
    hashes: List[str] = Field(default_factory=list, max_length=20)
    processes: List[str] = Field(default_factory=list, max_length=20)
    command_lines: List[str] = Field(default_factory=list, max_length=20)
    emails: List[str] = Field(default_factory=list, max_length=20)
    mitre_tactics: List[str] = Field(default_factory=list, max_length=20)
    mitre_techniques: List[str] = Field(default_factory=list, max_length=20)


def _scalar_text(value: Any, out: List[str], depth: int = 0) -> None:
    if depth > 32:
        return
    if isinstance(value, Mapping):
        for v in value.values():
            _scalar_text(v, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _scalar_text(v, out, depth + 1)
    elif value is not None and not isinstance(value, bool):
        out.append(str(value))


# Separators between indicator-like tokens in free text. "=" and ":" are split
# in a second pass so "SHA256=<hash>" and "user:alice" ground their values
# while URLs and host:port stay whole in the first.
_SPLIT = re.compile(r"[\s,;|\"'()<>\[\]{}]+")
_SPLIT_FINE = re.compile(r"[\s,;|\"'()<>\[\]{}=:]+")
_MAX_GROUNDING_VALUES = 20_000

_CANON: Dict[str, Callable[[str], Optional[str]]] = {"ips": normalize_ip, "hashes": normalize_hash}


class Grounding:
    """Whole values and tokens of an event, for checking model output against it."""

    def __init__(self, event: Mapping[str, Any]):
        scalars: List[str] = []
        _scalar_text(event, scalars)
        self.values: Set[str] = set()
        for text in scalars[:_MAX_GROUNDING_VALUES]:
            self._add(text)
            for pattern in (_SPLIT, _SPLIT_FINE):
                for token in pattern.split(text):
                    self._add(token)
                    self._add(token.rstrip("."))
        self._canonical: Dict[str, Set[str]] = {
            kind: {c for c in (fn(v) for v in self.values) if c is not None} for kind, fn in _CANON.items()
        }

    def _add(self, text: str) -> None:
        value = text.strip().lower()
        if value:
            self.values.add(value)

    def contains(self, value: str, kind: Optional[str] = None) -> bool:
        if not isinstance(value, str) or not value.strip():
            return False
        if value.strip().lower() in self.values:
            return True
        canon = _CANON.get(kind or "")
        if canon is None:
            return False
        normalized = canon(value)
        return normalized is not None and normalized in self._canonical[kind or ""]

    def filter(self, values: List[str], kind: Optional[str] = None) -> List[str]:
        return [v for v in values if self.contains(v, kind)]


async def llm_normalize(
    event: Mapping[str, Any],
    ctx: NormalizeContext,
    *,
    settings: Settings,
    tenant_id: str,
    budget: Optional[TokenBudget] = None,
) -> CanonicalAlert:
    """Raises :class:`lg_sotf.llm.LLMError` subclasses or :class:`NormalizationError`."""
    model = get_chat_model("fast", settings)
    messages = build_messages(SYSTEM, TASK, {"event": dict(event)}, settings=settings)
    out = await ainvoke_structured(
        model,
        LLMNormalizedAlert,
        messages,
        agent=AGENT,
        tier="fast",
        tenant_id=tenant_id,
        settings=settings,
        budget=budget,
    )
    grounding = Grounding(event)
    b = AlertBuilder(event, ctx)
    for kind in ("hosts", "users", "ips", "domains", "urls", "hashes", "processes", "command_lines", "emails"):
        b.entities.add_by_kind(kind, grounding.filter(getattr(out, kind), kind))
    b.mitre.add_tactic(grounding.filter(out.mitre_tactics))
    b.mitre.add_technique(grounding.filter(out.mitre_techniques))
    b.flags.append(FLAG_LLM)
    severity = out.severity
    if SEVERITIES.index(severity) < SEVERITIES.index(MIN_LLM_SEVERITY):
        severity = MIN_LLM_SEVERITY
    occurred = out.occurred_at if out.occurred_at and grounding.contains(out.occurred_at) else None
    return b.build(
        title=out.title,
        severity=severity,
        time_candidates=(occurred,),
        source_alert_id=None,
        description=out.description,
        category=out.category,
        rule_name=out.rule_name,
    )
