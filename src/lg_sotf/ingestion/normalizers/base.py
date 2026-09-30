"""Normalizer protocol and the shared builder every normalizer finishes with."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, runtime_checkable

from pydantic import ValidationError

from lg_sotf.ingestion.entities import EntityCollector, MitreCollector
from lg_sotf.ingestion.errors import NormalizationError, UnrecognizedEvent
from lg_sotf.ingestion.timeparse import DEFAULT_MAX_FUTURE, FLAG_MISSING, first_timestamp
from lg_sotf.models.alert import MAX_SOURCE_ALERT_ID_CHARS, CanonicalAlert, Severity, strip_nul

FLAG_SEVERITY_DEFAULTED = "severity_defaulted"
FLAG_ENTITIES_DROPPED = "entities_invalid_dropped"
FLAG_ENTITIES_TRUNCATED = "entities_truncated"
FLAG_ID_FROM_HASH = "source_alert_id_from_hash"
DEFAULT_SEVERITY: Severity = "medium"

_MISSING = object()


@dataclass(frozen=True)
class NormalizeContext:
    source_id: str
    source_type: str
    config: Mapping[str, Any] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    max_future: timedelta = DEFAULT_MAX_FUTURE


@runtime_checkable
class Normalizer(Protocol):
    """Turns one vendor event (already NUL-stripped and redacted) into a canonical alert.

    Must be deterministic: the same event and context always give the same
    alert. Raises :class:`UnrecognizedEvent` when the event is not in this
    format and :class:`NormalizationError` when it is but cannot be used.
    """

    name: str

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert: ...


# Keys this platform adds while fetching (``lgsotf_indextime`` and the like);
# they can differ between two reads of the same event.
INTERNAL_KEY_PREFIXES = ("lgsotf_", "_lgsotf_")


def event_hash(event: Mapping[str, Any], exclude: Iterable[str] = ()) -> str:
    """Deterministic id for events without a vendor id: sha256 of the canonical JSON.

    Top-level keys in ``exclude`` and keys this platform adds are left out, so
    transport fields that change between two reads of the same event (a
    result's position in a search, the serving node) do not change the id.
    """
    excluded = set(exclude)
    stable = {
        k: v for k, v in event.items() if k not in excluded and not str(k).startswith(INTERNAL_KEY_PREFIXES)
    }
    payload = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()


def get_path(data: Any, path: str, default: Any = None) -> Any:
    """Dot-path lookup (``a.b.0.c``); a literal key containing dots wins over traversal.

    ``*`` fans out over a list and returns a flat list of the matches.
    """
    if isinstance(data, Mapping) and path in data:
        return data[path]
    result = _walk(data, path.split(".") if path else [])
    return default if result is _MISSING else result


def _walk(node: Any, parts: Sequence[str]) -> Any:
    for i, part in enumerate(parts):
        if part == "*":
            if not isinstance(node, list):
                return _MISSING
            rest = parts[i + 1 :]
            matches: List[Any] = []
            for item in node:
                found = _walk(item, rest) if rest else item
                if found is _MISSING:
                    continue
                if isinstance(found, list):
                    matches.extend(found)
                else:
                    matches.append(found)
            return matches
        if isinstance(node, Mapping):
            if part not in node:
                return _MISSING
            node = node[part]
        elif isinstance(node, list) and part.isdigit():
            idx = int(part)
            if idx >= len(node):
                return _MISSING
            node = node[idx]
        else:
            return _MISSING
    return node


def first(*values: Any) -> Any:
    """First value that is not ``None``/empty string/empty list."""
    for value in values:
        if value is None or value == "" or value == [] or value == {}:
            continue
        return value
    return None


def as_text(value: Any) -> Optional[str]:
    """Scalar or single-item list to stripped text; multivalue lists are joined by ``, ``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (list, tuple)):
        parts = [t for t in (as_text(v) for v in value) if t]
        return ", ".join(parts) if parts else None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        text = strip_nul(value).strip()
        return text or None
    return None


def parse_json_field(value: Any) -> Any:
    """Sentinel and others embed JSON documents in string columns."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in ("[", "{"):
            try:
                return json.loads(text)
            except ValueError:
                return value
    return value


def require_mapping(event: Any, fmt: str) -> Mapping[str, Any]:
    if not isinstance(event, Mapping):
        raise UnrecognizedEvent(f"{fmt} event must be a JSON object")
    return event


class AlertBuilder:
    """Collects mapped fields, then validates them into a :class:`CanonicalAlert`."""

    def __init__(self, event: Mapping[str, Any], ctx: NormalizeContext):
        self.event = event
        self.ctx = ctx
        self.entities = EntityCollector()
        self.mitre = MitreCollector()
        self.flags: List[str] = []
        self.consumed: Set[str] = set()

    def consume(self, *keys: str) -> None:
        """Mark top-level keys as mapped so they are left out of ``unmapped``."""
        self.consumed.update(keys)

    def build(
        self,
        *,
        title: Optional[str],
        severity: Optional[str],
        time_candidates: Iterable[Any],
        source_alert_id: Any = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
        rule_name: Optional[str] = None,
        default_severity: Optional[Severity] = DEFAULT_SEVERITY,
        extra_unmapped: Optional[Mapping[str, Any]] = None,
        hash_exclude: Iterable[str] = (),
        email: Optional[Dict[str, Any]] = None,
    ) -> CanonicalAlert:
        """``hash_exclude``: volatile top-level keys ignored when the id falls back to a hash.

        ``email`` is the email section (only the email normalizer sets it).
        """
        if not title:
            raise NormalizationError("event has no usable title")
        if severity is None:
            if default_severity is None:
                raise NormalizationError("event has no recognizable severity")
            severity = default_severity
            self.flags.append(FLAG_SEVERITY_DEFAULTED)
        occurred = first_timestamp(*time_candidates, now=self.ctx.now, max_future=self.ctx.max_future)
        self.flags.extend(occurred.flags)
        occurred_at = occurred.value or self.ctx.now
        if occurred.value is None and FLAG_MISSING not in occurred.flags:
            self.flags.append(FLAG_MISSING)
        vendor_id = as_text(source_alert_id)
        if vendor_id is None or len(vendor_id) > MAX_SOURCE_ALERT_ID_CHARS:
            vendor_id = event_hash(self.event, hash_exclude)
            self.flags.append(FLAG_ID_FROM_HASH)
        if self.entities.dropped:
            self.flags.append(FLAG_ENTITIES_DROPPED)
        if self.entities.truncated:
            self.flags.append(FLAG_ENTITIES_TRUNCATED)
        unmapped: Dict[str, Any] = {
            k: v
            for k, v in self.event.items()
            if k not in self.consumed and not str(k).startswith(INTERNAL_KEY_PREFIXES)
        }
        if extra_unmapped:
            unmapped.update(extra_unmapped)
        try:
            return CanonicalAlert(
                source_id=self.ctx.source_id,
                source_type=self.ctx.source_type,
                source_alert_id=vendor_id,
                title=title,
                description=description,
                severity=severity,
                category=category,
                rule_name=rule_name,
                occurred_at=occurred_at,
                entities=self.entities.build(),
                mitre=self.mitre.build(),
                unmapped=unmapped,
                flags=self.flags,
                email=email,
            )
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in err["loc"]) for err in exc.errors()})
            raise NormalizationError(f"invalid canonical alert fields: {', '.join(fields)}") from exc

