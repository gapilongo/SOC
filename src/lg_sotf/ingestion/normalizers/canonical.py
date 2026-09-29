"""Our own schema: what ``POST /ingest/alerts`` accepts.

```json
{
  "source_alert_id": "optional vendor id (alias: id)",
  "title": "required",
  "severity": "info|low|medium|high|critical (also common names such as informational)",
  "description": "...", "category": "...", "rule_name": "...",
  "occurred_at": "ISO 8601 or epoch s/ms/us (default: ingestion time, flagged)",
  "entities": {"hosts": [], "users": [], "ips": [], "domains": [], "urls": [],
               "hashes": [], "processes": [], "command_lines": [], "emails": []},
  "mitre": {"tactics": [], "techniques": []},
  "...": "any other keys are kept in unmapped"
}
```

Unlike vendor formats, a missing or unknown severity is an error here: the
caller controls the payload and must state it.
"""

from __future__ import annotations

from typing import Any, Mapping

from lg_sotf.ingestion.entities import ENTITY_KINDS
from lg_sotf.ingestion.errors import NormalizationError, UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, require_mapping
from lg_sotf.models.alert import CanonicalAlert, severity_from_name


class CanonicalNormalizer:
    name = "canonical"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        title = as_text(event.get("title"))
        if title is None:
            raise UnrecognizedEvent("canonical alert requires a non-empty 'title'")
        raw_severity = event.get("severity")
        if raw_severity is None:
            raise NormalizationError("canonical alert requires 'severity'")
        severity = severity_from_name(raw_severity)
        if severity is None:
            raise NormalizationError("canonical alert 'severity' must be one of info, low, medium, high, critical")
        b = AlertBuilder(event, ctx)
        b.consume(
            "title", "severity", "description", "category", "rule_name", "occurred_at", "timestamp",
            "source_alert_id", "id", "entities", "mitre",
        )
        entities = event.get("entities")
        if entities is not None:
            if not isinstance(entities, Mapping):
                raise NormalizationError("'entities' must be an object")
            unknown = sorted(set(entities) - set(ENTITY_KINDS))
            if unknown:
                raise NormalizationError(f"unknown entity kinds: {', '.join(unknown[:5])}")
            for kind in ENTITY_KINDS:
                b.entities.add_by_kind(kind, entities.get(kind))
        mitre = event.get("mitre")
        if mitre is not None:
            if not isinstance(mitre, Mapping):
                raise NormalizationError("'mitre' must be an object")
            b.mitre.add_tactic(mitre.get("tactics"))
            b.mitre.add_technique(mitre.get("techniques"))
        return b.build(
            title=title,
            severity=severity,
            time_candidates=(event.get("occurred_at"), event.get("timestamp")),
            source_alert_id=event.get("source_alert_id", event.get("id")),
            description=as_text(event.get("description")),
            category=as_text(event.get("category")),
            rule_name=as_text(event.get("rule_name")),
        )
