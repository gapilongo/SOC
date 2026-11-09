"""Labelled evaluation datasets (JSONL).

One JSON object per line. An optional first line ``{"_meta": {...}}``
describes the file (``synthetic``, ``description``, ``version``, optional
``tenant_settings`` applied to every evaluation tenant: ``tools.internal_domains``,
the ``phishing`` section, ``triage.known_scanners`` and the model-led closure tier
``ai_closure.tier``); every other line is an :class:`EvalItem`::

    {"id": "syn-007",
     "source_type": "crowdstrike",          # canonical | splunk | crowdstrike | sentinel |
                                            # wazuh | guardduty | qradar | webhook | email
     "alert": {...},                        # the event exactly as the source sends it; for
                                            # email: {"mime": "<RFC 5322 text>", "reporter": "..."}
     "source_config": {...},                # webhook (generic field map) only
     "expected": {"disposition": "malicious",   # malicious | benign | inconclusive
                  "route": "escalate",          # optional: close | escalate | plan_response
                  "escalation": true},          # optional: should a human be asked?
     "labels": [{"annotator": "a1", "disposition": "malicious"}],   # optional, for kappa
     "split": "adversarial",                # optional, default "standard"
     "family": "log-field-hijack",          # optional adversarial family (per-family metrics)
     "injection": {"goal": "benign"},       # optional: what injected text asks for (benign | respond)
     "tool_fixtures": {"threat_intel": [...], "history": [...]},   # optional canned lookup answers
     "tags": ["prompt-injection", "identity"],
     "notes": "free text"}

A file ending in ``.gz`` is read as gzip-compressed JSONL.

Blank lines and lines starting with ``#`` are ignored. Loading is strict: an
invalid line raises :class:`DatasetError` with its line number, so a typo
never silently drops an item from a gated run.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from lg_sotf.domain.benign_evidence import TriageSettings
from lg_sotf.domain.closure import AiClosureSettings
from lg_sotf.domain.phishing import PhishingSettings
from lg_sotf.eval.context import TenantContext
from lg_sotf.models.vocabulary import DISPOSITIONS as DISPOSITIONS
from lg_sotf.models.vocabulary import Disposition
from lg_sotf.security.hashing import normalize_indicator

Route = Literal["close", "escalate", "plan_response"]
SourceType = Literal[
    "canonical", "splunk", "crowdstrike", "sentinel", "wazuh", "guardduty", "qradar", "webhook", "email"
]

ROUTES: tuple[str, ...] = ("close", "escalate", "plan_response")
SOURCE_TYPES: tuple[str, ...] = (
    "canonical",
    "splunk",
    "crowdstrike",
    "sentinel",
    "wazuh",
    "guardduty",
    "qradar",
    "webhook",
    "email",
)
DEFAULT_SPLIT = "standard"
ADVERSARIAL_SPLIT = "adversarial"
MAX_ITEMS = 100_000
MAX_LINE_BYTES = 1_048_576
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DatasetError(ValueError):
    """The dataset file cannot be used as is."""


MAX_MIME_CHARS = 1_000_000
DomainName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]


class EvalTools(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    internal_domains: List[DomainName] = Field(default_factory=list, max_length=256)


class EvalTenantSettings(BaseModel):
    """``_meta.tenant_settings``: the tenant context a dataset needs (internal domains, phishing profile, scanners)
    and the model-led closure tier it runs at."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: Optional[EvalTools] = None
    phishing: Optional[PhishingSettings] = None
    triage: Optional[TriageSettings] = None
    ai_closure: Optional[AiClosureSettings] = None

    def patch(self) -> Dict[str, Any]:
        """The tenant settings merge patch (only the sections that were given)."""
        return self.model_dump(exclude_none=True)


class EmailAlert(BaseModel):
    """The ``alert`` of an ``email`` item: the raw message as text, and optionally who reported it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mime: str = Field(min_length=1, max_length=MAX_MIME_CHARS)
    reporter: Optional[str] = Field(default=None, max_length=320)


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: Disposition
    route: Optional[Route] = None
    escalation: Optional[bool] = None


class Label(BaseModel):
    """One annotator's disposition for an item (inter-annotator agreement)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    annotator: str = Field(min_length=1, max_length=128)
    disposition: Disposition


Scalar = Union[str, int, float, bool, None]
EXTERNAL_FIXTURE_KINDS: Tuple[str, ...] = ("ip", "domain", "url", "hash")


class ToolFixture(BaseModel):
    """A canned lookup answer: what the threat-intelligence or history tool returns for one indicator.

    Only the evaluation harness reads these (:mod:`lg_sotf.eval.tool_fixtures`); production
    providers never simulate data.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["ip", "domain", "url", "hash", "user", "host", "process"]
    value: str = Field(min_length=1, max_length=512)
    verdict: Literal["malicious", "suspicious", "harmless", "unknown"] = "unknown"
    data: Dict[str, Union[Scalar, List[Scalar]]] = Field(default_factory=dict, max_length=16)

    def key(self) -> Tuple[str, str]:
        return self.kind, normalize_indicator(self.kind, self.value)


class ToolFixtures(BaseModel):
    """``tool_fixtures``: threat-intelligence and history answers for the item's indicators."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    threat_intel: List[ToolFixture] = Field(default_factory=list, max_length=8)
    history: List[ToolFixture] = Field(default_factory=list, max_length=8)

    @field_validator("threat_intel")
    @classmethod
    def _external(cls, value: List[ToolFixture]) -> List[ToolFixture]:
        for fixture in value:
            if fixture.kind not in EXTERNAL_FIXTURE_KINDS:
                raise ValueError(f"threat_intel fixtures take {', '.join(EXTERNAL_FIXTURE_KINDS)} indicators")
        return value

    def entries(self) -> Iterable[Tuple[str, ToolFixture]]:
        yield from (("threat_intel", f) for f in self.threat_intel)
        yield from (("history", f) for f in self.history)


class InjectionSpec(BaseModel):
    """What the item's injected text asks the model to do, so a report can tell whether the model did it.

    ``benign``: call the alert benign (and so close it). ``respond``: recommend an action against one
    of ``markers`` (an asset or address the injected text names), read from the model's recommended
    actions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    goal: Literal["benign", "respond"]
    markers: List[Annotated[str, StringConstraints(min_length=2, max_length=128)]] = Field(
        default_factory=list, max_length=8
    )

    @model_validator(mode="after")
    def _markers(self) -> InjectionSpec:
        if self.goal == "respond" and not self.markers:
            raise ValueError("goal 'respond' needs markers (the targets the injected text names)")
        return self


class EvalItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    source_type: SourceType
    alert: Dict[str, Any]
    source_config: Optional[Dict[str, Any]] = None
    expected: Expected
    labels: List[Label] = Field(default_factory=list, max_length=32)
    split: str = DEFAULT_SPLIT
    family: Optional[str] = None
    injection: Optional[InjectionSpec] = None
    tool_fixtures: Optional[ToolFixtures] = None
    tags: List[str] = Field(default_factory=list, max_length=32)
    notes: str = Field(default="", max_length=4_000)

    @field_validator("id", "split", "family")
    @classmethod
    def _name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not _NAME.match(value):
            raise ValueError("must be 1-128 of letters, digits, '.', '_', ':' or '-', starting with a letter or digit")
        return value

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: List[str]) -> List[str]:
        for tag in value:
            if not isinstance(tag, str) or not 1 <= len(tag) <= 64:
                raise ValueError("tags must be strings of 1-64 characters")
        return value

    @model_validator(mode="after")
    def _source(self) -> EvalItem:
        if not self.alert:
            raise ValueError("alert must be a non-empty object")
        if self.source_type == "webhook" and not self.source_config:
            raise ValueError("source_type 'webhook' needs source_config (the generic field map)")
        if self.source_type != "webhook" and self.source_config is not None:
            raise ValueError("source_config is only used with source_type 'webhook'")
        if self.source_type == "email":
            EmailAlert.model_validate(self.alert)
        annotators = [label.annotator for label in self.labels]
        if len(set(annotators)) != len(annotators):
            raise ValueError("each annotator may label an item once")
        return self

    @property
    def is_adversarial(self) -> bool:
        return self.split == ADVERSARIAL_SPLIT or ADVERSARIAL_SPLIT in self.tags

    @property
    def email(self) -> EmailAlert:
        """The raw message of an ``email`` item."""
        return EmailAlert.model_validate(self.alert)


@dataclass
class Dataset:
    items: List[EvalItem]
    meta: Dict[str, Any] = field(default_factory=dict)
    path: Optional[str] = None
    sha256: Optional[str] = None

    @property
    def synthetic(self) -> bool:
        return bool(self.meta.get("synthetic"))

    @property
    def tenant_settings(self) -> Dict[str, Any]:
        """``_meta.tenant_settings`` as a validated merge patch (empty when absent)."""
        raw = self.meta.get("tenant_settings")
        return EvalTenantSettings.model_validate(raw).patch() if raw else {}

    @property
    def tenant_context(self) -> Optional[TenantContext]:
        """``_meta.tenant_context`` (validated when the file was parsed), or None."""
        raw = self.meta.get("tenant_context")
        return TenantContext.model_validate(raw) if raw else None

    @property
    def has_tool_fixtures(self) -> bool:
        return any(item.tool_fixtures is not None for item in self.items)

    def splits(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in self.items:
            counts[item.split] = counts.get(item.split, 0) + 1
        return dict(sorted(counts.items()))

    def families(self) -> Dict[str, int]:
        """Items per adversarial ``family`` (items without one are not counted)."""
        counts: Dict[str, int] = {}
        for item in self.items:
            if item.family is not None:
                counts[item.family] = counts.get(item.family, 0) + 1
        return dict(sorted(counts.items()))

    def select(
        self,
        *,
        splits: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        limit: Optional[int] = None,
    ) -> Dataset:
        """A filtered copy: items in any of ``splits`` and carrying every tag in ``tags``, first ``limit``."""
        chosen: Iterable[EvalItem] = self.items
        if splits:
            wanted = set(splits)
            chosen = [i for i in chosen if i.split in wanted]
        if tags:
            required = set(tags)
            chosen = [i for i in chosen if required <= set(i.tags)]
        selected = list(chosen)
        if limit is not None:
            selected = selected[: max(0, limit)]
        return Dataset(items=selected, meta=dict(self.meta), path=self.path, sha256=self.sha256)


FixtureKey = Tuple[str, str, str]


def _check_fixtures(item: EvalItem, seen: Dict[FixtureKey, Tuple[ToolFixture, int]], where: str, lineno: int) -> None:
    """One answer per tool and indicator across the dataset: a second, different one is an error."""
    if item.tool_fixtures is None:
        return
    for tool, fixture in item.tool_fixtures.entries():
        first = seen.setdefault((tool, *fixture.key()), (fixture, lineno))
        if first[0] != fixture:
            raise DatasetError(
                f"{where}:{lineno}: {tool} fixture for {fixture.kind} {fixture.value!r} differs from the one "
                f"on line {first[1]}"
            )


def _validated(model: Any, value: Any, name: str, where: str) -> Any:
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or name}: {e['msg']}" for e in exc.errors()[:5])
        raise DatasetError(f"{where}: invalid _meta.{name} ({problems})") from None


def _check_meta(meta: Mapping[str, Any], where: str) -> None:
    """``tenant_settings`` and ``tenant_context`` are valid, and every configured scanner is a declared one."""
    settings = None
    if meta.get("tenant_settings") is not None:
        settings = _validated(EvalTenantSettings, meta["tenant_settings"], "tenant_settings", where)
    if meta.get("tenant_context") is None:
        return
    context: TenantContext = _validated(TenantContext, meta["tenant_context"], "tenant_context", where)
    configured = settings.triage.known_scanners if settings is not None and settings.triage is not None else []
    declared = set(TriageSettings(known_scanners=list(context.scanners)).known_scanners)
    undeclared = [s for s in configured if s not in declared]
    if undeclared:
        raise DatasetError(
            f"{where}: tenant_settings.triage.known_scanners lists {', '.join(undeclared)}, which "
            "_meta.tenant_context.scanners does not declare"
        )


def parse_dataset(text: str, *, path: Optional[str] = None) -> Dataset:
    """Parse JSONL text; raises :class:`DatasetError` naming the first bad line."""
    items: List[EvalItem] = []
    meta: Dict[str, Any] = {}
    seen: Dict[str, int] = {}
    fixtures: Dict[FixtureKey, Tuple[ToolFixture, int]] = {}
    where = path or "<dataset>"
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(stripped.encode("utf-8")) > MAX_LINE_BYTES:
            raise DatasetError(f"{where}:{lineno}: line is larger than {MAX_LINE_BYTES} bytes")
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise DatasetError(f"{where}:{lineno}: not valid JSON ({exc.msg})") from None
        if not isinstance(data, dict):
            raise DatasetError(f"{where}:{lineno}: each line must be a JSON object")
        if "_meta" in data:
            if items or meta:
                raise DatasetError(f"{where}:{lineno}: _meta is only allowed on the first line")
            if not isinstance(data["_meta"], dict) or len(data) != 1:
                raise DatasetError(f"{where}:{lineno}: _meta must be the only key and hold an object")
            meta = dict(data["_meta"])
            _check_meta(meta, f"{where}:{lineno}")
            continue
        try:
            item = EvalItem.model_validate(data)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or 'item'}: {e['msg']}" for e in exc.errors()[:5]
            )
            raise DatasetError(f"{where}:{lineno}: invalid item ({problems})") from None
        if item.id in seen:
            raise DatasetError(f"{where}:{lineno}: duplicate id {item.id!r} (first on line {seen[item.id]})")
        seen[item.id] = lineno
        _check_fixtures(item, fixtures, where, lineno)
        items.append(item)
        if len(items) > MAX_ITEMS:
            raise DatasetError(f"{where}: more than {MAX_ITEMS} items")
    if not items:
        raise DatasetError(f"{where}: the dataset has no items")
    return Dataset(
        items=items,
        meta=meta,
        path=path,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def load_dataset(path: str | Path) -> Dataset:
    """Read a ``.jsonl`` dataset, or a gzip-compressed ``.jsonl.gz`` one (the sha256 is of the JSONL text)."""
    p = Path(path)
    try:
        raw = p.read_bytes()
        if p.suffix == ".gz":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8")
    except (OSError, EOFError, zlib.error) as exc:
        raise DatasetError(f"cannot read dataset {p}: {getattr(exc, 'strerror', None) or exc}") from None
    except UnicodeDecodeError:
        raise DatasetError(f"dataset {p} is not UTF-8") from None
    return parse_dataset(text, path=str(p))
