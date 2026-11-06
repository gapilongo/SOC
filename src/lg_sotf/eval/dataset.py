"""Labelled evaluation datasets (JSONL).

One JSON object per line. An optional first line ``{"_meta": {...}}``
describes the file (``synthetic``, ``description``, ``version`` and optional
``tenant_settings`` applied to every evaluation tenant: ``tools.internal_domains``
and the ``phishing`` section); every other line is an :class:`EvalItem`::

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
     "tags": ["prompt-injection", "identity"],
     "notes": "free text"}

Blank lines and lines starting with ``#`` are ignored. Loading is strict: an
invalid line raises :class:`DatasetError` with its line number, so a typo
never silently drops an item from a gated run.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Dict, Iterable, List, Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from lg_sotf.domain.phishing import PhishingSettings

Disposition = Literal["malicious", "benign", "inconclusive"]
Route = Literal["close", "escalate", "plan_response"]
SourceType = Literal[
    "canonical", "splunk", "crowdstrike", "sentinel", "wazuh", "guardduty", "qradar", "webhook", "email"
]

DISPOSITIONS: tuple[str, ...] = ("malicious", "benign", "inconclusive")
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
    """``_meta.tenant_settings``: the tenant context a dataset needs (internal domains, phishing profile)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: Optional[EvalTools] = None
    phishing: Optional[PhishingSettings] = None

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


class EvalItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    source_type: SourceType
    alert: Dict[str, Any]
    source_config: Optional[Dict[str, Any]] = None
    expected: Expected
    labels: List[Label] = Field(default_factory=list, max_length=32)
    split: str = DEFAULT_SPLIT
    tags: List[str] = Field(default_factory=list, max_length=32)
    notes: str = Field(default="", max_length=4_000)

    @field_validator("id", "split")
    @classmethod
    def _name(cls, value: str) -> str:
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

    def splits(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in self.items:
            counts[item.split] = counts.get(item.split, 0) + 1
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


def parse_dataset(text: str, *, path: Optional[str] = None) -> Dataset:
    """Parse JSONL text; raises :class:`DatasetError` naming the first bad line."""
    items: List[EvalItem] = []
    meta: Dict[str, Any] = {}
    seen: Dict[str, int] = {}
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
            if meta.get("tenant_settings") is not None:
                try:
                    EvalTenantSettings.model_validate(meta["tenant_settings"])
                except ValidationError as exc:
                    problems = "; ".join(
                        f"{'.'.join(str(p) for p in e['loc']) or 'tenant_settings'}: {e['msg']}" for e in exc.errors()[:5]
                    )
                    raise DatasetError(f"{where}:{lineno}: invalid _meta.tenant_settings ({problems})") from None
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
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetError(f"cannot read dataset {p}: {exc.strerror or exc}") from None
    except UnicodeDecodeError:
        raise DatasetError(f"dataset {p} is not UTF-8") from None
    return parse_dataset(text, path=str(p))
