"""Generic webhook: fields mapped by dot-paths from the source configuration.

Source ``config``::

    {
      "format": "generic",
      "field_map": {
        "title": "alert.name",                     # required
        "severity": "alert.priority",
        "occurred_at": ["alert.ts", "received"],   # first path that parses wins
        "source_alert_id": "alert.id",
        "description": "alert.details",
        "category": "alert.type",
        "rule_name": "alert.rule",
        "entities.ips": ["src.ip", "dst.ip"],
        "entities.hosts": "asset.hostname",
        "entities.users": "actors.*.login",       # "*" fans out over a list
        "mitre.techniques": "tags"
      },
      "severity_map": {"P1": "critical", "P2": "high"},  # vendor value -> level (checked first)
      "severity_scale": "1-5",                           # for numeric severities
      "default_severity": "medium"                       # null rejects events without one
    }

Top-level keys of the event that no path starts from are kept in
``unmapped``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.ingestion.entities import ENTITY_KINDS
from lg_sotf.ingestion.errors import SourceConfigError, UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import (
    DEFAULT_SEVERITY,
    AlertBuilder,
    NormalizeContext,
    as_text,
    get_path,
    require_mapping,
)
from lg_sotf.models.alert import SEVERITIES, SEVERITY_SCALES, CanonicalAlert, Severity, map_severity

SCALAR_TARGETS = ("title", "severity", "occurred_at", "source_alert_id", "description", "category", "rule_name")
LIST_TARGETS = tuple(f"entities.{k}" for k in ENTITY_KINDS) + ("mitre.tactics", "mitre.techniques")
MAX_PATHS_PER_TARGET = 16
MAX_PATH_CHARS = 256


def _paths(value: Any, target: str) -> List[str]:
    paths = [value] if isinstance(value, str) else value
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        raise SourceConfigError(f"field_map.{target} must be a dot-path or a non-empty list of dot-paths")
    if len(paths) > MAX_PATHS_PER_TARGET or any(len(p) > MAX_PATH_CHARS for p in paths):
        raise SourceConfigError(f"field_map.{target} has too many or too long paths")
    return list(paths)


def parse_webhook_config(config: Mapping[str, Any]) -> Tuple[Dict[str, List[str]], Dict[str, Severity], Optional[str], Optional[Severity]]:
    """Validate a generic webhook config; raises :class:`SourceConfigError`."""
    field_map = config.get("field_map")
    if not isinstance(field_map, Mapping) or not field_map:
        raise SourceConfigError("generic webhook source requires a 'field_map' object")
    unknown = sorted(set(field_map) - set(SCALAR_TARGETS) - set(LIST_TARGETS))
    if unknown:
        raise SourceConfigError(f"unknown field_map targets: {', '.join(unknown[:5])}")
    if "title" not in field_map:
        raise SourceConfigError("field_map.title is required")
    mapping = {target: _paths(value, target) for target, value in field_map.items()}
    raw_map = config.get("severity_map") or {}
    if not isinstance(raw_map, Mapping):
        raise SourceConfigError("severity_map must be an object")
    severity_map: Dict[str, Severity] = {}
    for key, level in raw_map.items():
        if level not in SEVERITIES:
            raise SourceConfigError(f"severity_map values must be one of {', '.join(SEVERITIES)}")
        severity_map[str(key).strip().lower()] = level
    scale = config.get("severity_scale")
    if scale is not None and scale not in SEVERITY_SCALES:
        raise SourceConfigError(f"severity_scale must be one of {', '.join(SEVERITY_SCALES)}")
    default = config.get("default_severity", DEFAULT_SEVERITY)
    if default is not None and default not in SEVERITIES:
        raise SourceConfigError(f"default_severity must be one of {', '.join(SEVERITIES)} or null")
    return mapping, severity_map, scale, default


def _lookup(event: Mapping[str, Any], paths: Sequence[str]) -> Any:
    for path in paths:
        value = get_path(event, path)
        if value is not None and value != "" and value != []:
            return value
    return None


class WebhookNormalizer:
    name = "webhook"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        mapping, severity_map, scale, default = parse_webhook_config(ctx.config)
        title = as_text(_lookup(event, mapping["title"]))
        if title is None:
            raise UnrecognizedEvent("webhook event has no value at the configured title path")
        b = AlertBuilder(event, ctx)
        for paths in mapping.values():
            b.consume(*(p.split(".", 1)[0] for p in paths))
            b.consume(*(p for p in paths if p in event))
        for target in LIST_TARGETS:
            if target not in mapping:
                continue
            group, kind = target.split(".", 1)
            for path in mapping[target]:
                value = get_path(event, path)
                if group == "entities":
                    b.entities.add_by_kind(kind, value)
                elif kind == "tactics":
                    b.mitre.add_tactic(value)
                else:
                    b.mitre.add_technique(value)
        severity: Optional[Severity] = None
        raw_severity = _lookup(event, mapping["severity"]) if "severity" in mapping else None
        if raw_severity is not None:
            key = as_text(raw_severity)
            severity = severity_map.get(key.lower()) if key else None
            severity = severity or map_severity(raw_severity, scale)
        times: List[Any] = [get_path(event, p) for p in mapping.get("occurred_at", [])]

        def text(target: str) -> Optional[str]:
            return as_text(_lookup(event, mapping[target])) if target in mapping else None

        return b.build(
            title=title,
            severity=severity,
            time_candidates=times,
            source_alert_id=_lookup(event, mapping["source_alert_id"]) if "source_alert_id" in mapping else None,
            description=text("description"),
            category=text("category"),
            rule_name=text("rule_name"),
            default_severity=default,
        )
