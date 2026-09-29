"""Canonical alert model: a subset of the OCSF Detection Finding class (class_uid 2004).

Every source normalizer produces a :class:`CanonicalAlert`. Field sizes are
capped here so one oversized vendor event cannot bloat the database, the
workflow state or an LLM prompt. Text is stripped of NUL characters, which
PostgreSQL cannot store.

Severity helpers map vendor scales onto the five canonical levels. Numeric
scales are explicit (a bare number is ambiguous between vendors), and values
outside the scale map to ``None`` so callers decide how to flag them.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: Tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")
SeverityScale = Literal["0-10", "0-15", "0-100", "1-4", "1-5", "guardduty"]
SEVERITY_SCALES: Tuple[str, ...] = ("0-10", "0-15", "0-100", "1-4", "1-5", "guardduty")

# OCSF severity_id for each canonical level.
OCSF_SEVERITY_ID: Dict[str, int] = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
OCSF_DETECTION_FINDING = 2004

MAX_TITLE_CHARS = 512
MAX_DESCRIPTION_CHARS = 8_192
MAX_CATEGORY_CHARS = 128
MAX_RULE_NAME_CHARS = 512
MAX_SOURCE_ALERT_ID_CHARS = 512
MAX_ENTITY_ITEMS = 50
MAX_ENTITY_CHARS = 1_024
MAX_COMMAND_LINE_CHARS = 4_096
MAX_URL_CHARS = 2_048
MAX_MITRE_ITEMS = 32
MAX_MITRE_CHARS = 128
MAX_FLAGS = 32
MAX_UNMAPPED_BYTES = 32_768
TRUNCATION_SUFFIX = "...[truncated]"

# Placeholders such as "unknown", "none" or "n/a" are deliberately absent: they
# map to None so the caller applies its default (medium, flagged) instead of
# silently demoting a detection to info.
_SEVERITY_NAMES: Dict[str, Severity] = {
    "info": "info",
    "informational": "info",
    "information": "info",
    "debug": "info",
    "notice": "low",
    "low": "low",
    "minor": "low",
    "warning": "medium",
    "warn": "medium",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "high": "high",
    "major": "high",
    "error": "high",
    "err": "high",
    "important": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "very high": "critical",
    "urgent": "critical",
    "emergency": "critical",
    "emerg": "critical",
    "alert": "critical",
    "fatal": "critical",
}


def strip_nul(text: str) -> str:
    return text.replace("\x00", "") if "\x00" in text else text


def cap_text(text: str, limit: int) -> str:
    """Truncate to ``limit`` characters with a visible marker."""
    text = strip_nul(text)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(TRUNCATION_SUFFIX))] + TRUNCATION_SUFFIX


def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str, sort_keys=False)


def json_size(value: Any) -> int:
    # surrogatepass: a lone surrogate (from a JSON escape such as \ud800) must not make sizing fail.
    return len(compact_json(value).encode("utf-8", "surrogatepass"))


def severity_from_name(value: Any) -> Optional[Severity]:
    """Map a vendor severity/urgency name (``High``, ``informational``, syslog levels...) to a level."""
    if not isinstance(value, str):
        return None
    key = " ".join(value.strip().lower().replace("_", " ").split())
    return _SEVERITY_NAMES.get(key)


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            number = float(value)
        elif isinstance(value, str):
            number = float(value.strip())
        else:
            return None
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def severity_from_scale(value: Any, scale: str) -> Optional[Severity]:
    """Map a numeric vendor severity on ``scale`` to a level; out-of-range values give ``None``.

    * ``0-10``  (QRadar severity/magnitude): 0-1 info, 2-3 low, 4-6 medium, 7-8 high, 9-10 critical
    * ``0-15``  (Wazuh rule level): 0-2 info, 3-6 low, 7-10 medium, 11-13 high, 14-15 critical
    * ``0-100`` (CrowdStrike, Splunk risk): <20 info, <40 low, <70 medium, <90 high, else critical
    * ``1-4``:  1 low, 2 medium, 3 high, 4 critical
    * ``1-5``:  1 info, 2 low, 3 medium, 4 high, 5 critical
    * ``guardduty`` (1.0-10.0): <4 low, <7 medium, <9 high, else critical
    """
    n = _as_number(value)
    if n is None:
        return None
    if scale == "0-10":
        if not 0 <= n <= 10:
            return None
        return "info" if n < 2 else "low" if n < 4 else "medium" if n < 7 else "high" if n < 9 else "critical"
    if scale == "0-15":
        if not 0 <= n <= 15:
            return None
        return "info" if n < 3 else "low" if n < 7 else "medium" if n < 11 else "high" if n < 14 else "critical"
    if scale == "0-100":
        if not 0 <= n <= 100:
            return None
        return "info" if n < 20 else "low" if n < 40 else "medium" if n < 70 else "high" if n < 90 else "critical"
    if scale == "1-4":
        if not 1 <= n <= 4:
            return None
        return ("low", "medium", "high", "critical")[int(round(n)) - 1]
    if scale == "1-5":
        if not 1 <= n <= 5:
            return None
        return ("info", "low", "medium", "high", "critical")[int(round(n)) - 1]
    if scale == "guardduty":
        if not 0 < n <= 10:
            return None
        return "low" if n < 4 else "medium" if n < 7 else "high" if n < 9 else "critical"
    raise ValueError(f"unknown severity scale {scale!r} (expected one of {', '.join(SEVERITY_SCALES)})")


def map_severity(value: Any, scale: Optional[str] = None) -> Optional[Severity]:
    """Names are always accepted; numbers only with an explicit ``scale``."""
    by_name = severity_from_name(value)
    if by_name is not None:
        return by_name
    if scale is None:
        return None
    return severity_from_scale(value, scale)


def _dedup_capped(values: List[str], item_chars: int, max_items: int = MAX_ENTITY_ITEMS) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for raw in values:
        text = cap_text(str(raw).strip(), item_chars)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= max_items:
            break
    return out


class Entities(BaseModel):
    """Observables extracted from the event. Values are validated by the normalizers."""

    model_config = ConfigDict(extra="forbid")

    hosts: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    command_lines: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)

    @field_validator("hosts", "users", "ips", "domains", "hashes", "processes", "emails")
    @classmethod
    def _cap(cls, v: List[str]) -> List[str]:
        return _dedup_capped(v, MAX_ENTITY_CHARS)

    @field_validator("urls")
    @classmethod
    def _cap_urls(cls, v: List[str]) -> List[str]:
        return _dedup_capped(v, MAX_URL_CHARS)

    @field_validator("command_lines")
    @classmethod
    def _cap_commands(cls, v: List[str]) -> List[str]:
        return _dedup_capped(v, MAX_COMMAND_LINE_CHARS)

    def is_empty(self) -> bool:
        return not any(getattr(self, name) for name in type(self).model_fields)


class Mitre(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)

    @field_validator("tactics", "techniques")
    @classmethod
    def _cap(cls, v: List[str]) -> List[str]:
        return _dedup_capped(v, MAX_MITRE_CHARS, MAX_MITRE_ITEMS)


class CanonicalAlert(BaseModel):
    """A normalized alert. ``raw`` is the original (redacted, size-capped) event."""

    model_config = ConfigDict(extra="forbid")

    class_uid: Literal[2004] = 2004
    source_id: str = Field(min_length=1, max_length=128)
    source_type: str = Field(min_length=1, max_length=32)
    source_alert_id: str = Field(min_length=1, max_length=MAX_SOURCE_ALERT_ID_CHARS)
    title: str = Field(min_length=1)
    description: Optional[str] = None
    severity: Severity
    category: Optional[str] = None
    rule_name: Optional[str] = None
    occurred_at: datetime
    entities: Entities = Field(default_factory=Entities)
    mitre: Mitre = Field(default_factory=Mitre)
    raw: Dict[str, Any] = Field(default_factory=dict)
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    # Data-quality notes, e.g. "occurred_at_missing", "severity_defaulted", "raw_truncated".
    flags: List[str] = Field(default_factory=list)

    @property
    def severity_id(self) -> int:
        return OCSF_SEVERITY_ID[self.severity]

    @field_validator("source_id", "source_type", "source_alert_id")
    @classmethod
    def _ids(cls, v: str) -> str:
        v = strip_nul(v).strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        v = cap_text(" ".join(strip_nul(v).split()), MAX_TITLE_CHARS)
        if not v:
            raise ValueError("title must not be blank")
        return v

    @field_validator("description")
    @classmethod
    def _description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = cap_text(strip_nul(v).strip(), MAX_DESCRIPTION_CHARS)
        return v or None

    @field_validator("category")
    @classmethod
    def _category(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = cap_text(" ".join(strip_nul(v).split()), MAX_CATEGORY_CHARS)
        return v or None

    @field_validator("rule_name")
    @classmethod
    def _rule_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = cap_text(" ".join(strip_nul(v).split()), MAX_RULE_NAME_CHARS)
        return v or None

    @field_validator("occurred_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        return v.astimezone(UTC)

    @field_validator("unmapped")
    @classmethod
    def _cap_unmapped(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return cap_mapping(v, MAX_UNMAPPED_BYTES)

    @field_validator("flags")
    @classmethod
    def _flags(cls, v: List[str]) -> List[str]:
        return _dedup_capped(v, 64, MAX_FLAGS)

    def normalized_document(self) -> Dict[str, Any]:
        """JSON document stored in ``alerts.normalized`` (everything except ``raw``)."""
        doc = self.model_dump(mode="json", exclude={"raw"})
        doc["severity_id"] = self.severity_id
        return doc

    @classmethod
    def from_stored(cls, normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]] = None) -> CanonicalAlert:
        """Rebuild from ``alerts.normalized`` (and optionally ``alerts.raw``)."""
        data = {k: v for k, v in normalized.items() if k != "severity_id"}
        if raw is not None:
            data["raw"] = dict(raw)
        return cls.model_validate(data)


def _shrink(value: Any, str_chars: int, list_items: int, depth: int = 0) -> Any:
    if depth > 32:
        return "[truncated: nesting too deep]"
    if isinstance(value, str):
        return cap_text(value, str_chars)
    if isinstance(value, Mapping):
        return {str(k): _shrink(v, str_chars, list_items, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_shrink(v, str_chars, list_items, depth + 1) for v in list(value)[:list_items]]
        if len(value) > list_items:
            items.append(f"[truncated: {len(value) - list_items} more items]")
        return items
    return value


TRUNCATED_MARKER = "_lgsotf_truncated"


def cap_mapping(value: Mapping[str, Any], max_bytes: int) -> Dict[str, Any]:
    """Return ``value`` if its compact JSON fits ``max_bytes``, else a smaller copy with a marker.

    Long strings and lists are shortened first; if that is not enough the
    document is replaced by a marker plus a JSON text preview.
    """
    data = dict(value)
    size = json_size(data)
    if size <= max_bytes:
        return data
    for str_chars, list_items in ((4_096, 100), (1_024, 25), (256, 10)):
        shrunk = _shrink(data, str_chars, list_items)
        shrunk[TRUNCATED_MARKER] = {"original_bytes": size}
        if json_size(shrunk) <= max_bytes:
            return shrunk
    text = compact_json(data).encode("utf-8", "surrogatepass")
    budget = max(0, max_bytes // 2)
    while True:
        # JSON escaping can grow the preview, so shrink until the envelope fits.
        preview = text[:budget].decode("utf-8", "ignore")
        capped = {TRUNCATED_MARKER: {"original_bytes": size}, "preview": preview}
        if budget == 0 or json_size(capped) <= max_bytes:
            return capped
        budget //= 2


@dataclass(frozen=True)
class IngestedAlert:
    """A newly inserted alert, handed to dispatch."""

    alert_id: str
    severity: str

