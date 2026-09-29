"""IBM QRadar offenses (``GET /api/siem/offenses``).

``offense_source`` holds whatever the offense is indexed on; ``offense_type``
says what that is (0 source IP, 1 destination IP, 3 user name, 7 host name...).
Only the kinds that map to entities are extracted.
"""

from __future__ import annotations

from typing import Any, List, Mapping

from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, first, require_mapping
from lg_sotf.models.alert import CanonicalAlert, map_severity

_OFFENSE_SOURCE_KIND = {0: "ip", 1: "ip", 3: "user", 7: "host", 10: "ip", 11: "ip", 17: "host"}


class QRadarNormalizer:
    name = "qradar"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        if "id" not in event or not as_text(event.get("description")):
            raise UnrecognizedEvent("qradar offense requires 'id' and 'description'")
        b = AlertBuilder(event, ctx)
        b.consume("id", "description", "severity", "magnitude", "start_time", "offense_source", "offense_type",
                  "categories", "rules")
        offense_type = event.get("offense_type")
        kind = _OFFENSE_SOURCE_KIND.get(offense_type) if isinstance(offense_type, int) else None
        source = event.get("offense_source")
        if kind == "ip":
            b.entities.add_ip(source)
        elif kind == "user":
            b.entities.add_user(source)
        elif kind == "host":
            b.entities.add_host(source)
        description = as_text(event.get("description")) or ""
        title = " ".join(description.split())
        raw_categories, raw_rules = event.get("categories"), event.get("rules")
        categories: List[Any] = raw_categories if isinstance(raw_categories, list) else []
        rules: List[Any] = raw_rules if isinstance(raw_rules, list) else []
        rule_ids = [str(r.get("id")) for r in rules if isinstance(r, Mapping) and r.get("id") is not None]
        return b.build(
            title=title,
            severity=map_severity(first(event.get("severity"), event.get("magnitude")), "0-10"),
            time_candidates=(event.get("start_time"),),
            source_alert_id=event.get("id"),
            description=description,
            category=as_text(categories[0]) if categories else None,
            rule_name=f"qradar-rules:{','.join(sorted(rule_ids))}" if rule_ids else title,
            extra_unmapped={"categories": categories, "rule_ids": rule_ids} if categories or rule_ids else None,
        )
