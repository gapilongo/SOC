"""Microsoft Sentinel: ``SecurityAlert`` and ``SecurityIncident`` rows from Log Analytics,
and incidents from the Sentinel REST API (``{"name", "properties": {...}}``).

Log Analytics returns ``Entities``, ``ExtendedProperties``, ``Techniques`` and
``AdditionalData`` as JSON text; they are parsed here.
"""

from __future__ import annotations

from typing import Any, Mapping

from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import (
    AlertBuilder,
    NormalizeContext,
    as_text,
    first,
    parse_json_field,
    require_mapping,
)
from lg_sotf.models.alert import CanonicalAlert, map_severity


def _add_entity(b: AlertBuilder, entity: Mapping[str, Any]) -> None:
    kind = str(entity.get("Type") or entity.get("type") or "").lower()
    if kind == "host":
        name = as_text(entity.get("HostName"))
        domain = as_text(entity.get("DnsDomain"))
        b.entities.add_host(f"{name}.{domain}" if name and domain else name)
        b.entities.add_host(entity.get("NetBiosName"))
        b.entities.add_ip(entity.get("Address"))
    elif kind == "account":
        name = as_text(entity.get("Name"))
        suffix = as_text(entity.get("UPNSuffix"))
        nt_domain = as_text(entity.get("NTDomain"))
        if name and suffix:
            b.entities.add_email(f"{name}@{suffix}")
        b.entities.add_user(f"{nt_domain}\\{name}" if name and nt_domain else name)
    elif kind == "ip":
        b.entities.add_ip(entity.get("Address"))
    elif kind == "url":
        b.entities.add_url(entity.get("Url"))
    elif kind == "filehash":
        b.entities.add_hash(entity.get("Value"))
    elif kind == "file":
        b.entities.add_process(entity.get("Name"))
        for h in entity.get("FileHashes") or []:
            if isinstance(h, Mapping):
                b.entities.add_hash(h.get("Value"))
    elif kind == "process":
        b.entities.add_command_line(entity.get("CommandLine"))
        image = entity.get("ImageFile")
        if isinstance(image, Mapping):
            b.entities.add_process(first(image.get("FullPath"), image.get("Name")))
    elif kind == "dns":
        b.entities.add_domain(entity.get("DomainName"))
    elif kind == "mailbox":
        b.entities.add_email(entity.get("MailboxPrimaryAddress"))
    elif kind == "mailmessage":
        b.entities.add_email(entity.get("Sender"))
        b.entities.add_email(entity.get("Recipient"))


def _add_entities(b: AlertBuilder, raw: Any) -> None:
    entities = parse_json_field(raw)
    if not isinstance(entities, list):
        return
    for entity in entities[:500]:
        if isinstance(entity, Mapping):
            _add_entity(b, entity)


class SentinelNormalizer:
    name = "sentinel"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        if isinstance(event.get("properties"), Mapping):
            return self._rest_incident(event, ctx)
        if "SystemAlertId" in event or "AlertName" in event:
            return self._security_alert(event, ctx)
        if "IncidentName" in event or "IncidentNumber" in event:
            return self._security_incident(event, ctx)
        raise UnrecognizedEvent("sentinel event is not a SecurityAlert, SecurityIncident or incident resource")

    def _security_alert(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        b = AlertBuilder(event, ctx)
        b.consume(
            "SystemAlertId", "AlertName", "DisplayName", "AlertSeverity", "Description", "TimeGenerated",
            "StartTime", "Entities", "Tactics", "Techniques", "SubTechniques", "CompromisedEntity",
            "AlertType", "ProductName",
        )
        _add_entities(b, event.get("Entities"))
        b.entities.add_host(event.get("CompromisedEntity"))
        b.mitre.add_tactic(event.get("Tactics"))
        b.mitre.add_technique(parse_json_field(event.get("Techniques")))
        b.mitre.add_technique(parse_json_field(event.get("SubTechniques")))
        return b.build(
            title=as_text(first(event.get("DisplayName"), event.get("AlertName"))),
            severity=map_severity(as_text(event.get("AlertSeverity"))),
            time_candidates=(event.get("StartTime"), event.get("TimeGenerated")),
            source_alert_id=event.get("SystemAlertId"),
            description=as_text(event.get("Description")),
            category=as_text(first(event.get("Tactics"), event.get("ProductName"))),
            rule_name=as_text(first(event.get("AlertName"), event.get("AlertType"))),
        )

    def _security_incident(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        b = AlertBuilder(event, ctx)
        b.consume(
            "IncidentName", "IncidentNumber", "Title", "Description", "Severity", "CreatedTime",
            "FirstActivityTime", "TimeGenerated", "AdditionalData",
        )
        extra = parse_json_field(event.get("AdditionalData"))
        if isinstance(extra, Mapping):
            b.mitre.add_tactic(extra.get("tactics"))
            b.mitre.add_technique(extra.get("techniques"))
        return b.build(
            title=as_text(event.get("Title")),
            severity=map_severity(as_text(event.get("Severity"))),
            time_candidates=(event.get("FirstActivityTime"), event.get("CreatedTime"), event.get("TimeGenerated")),
            source_alert_id=first(event.get("IncidentName"), event.get("IncidentNumber")),
            description=as_text(event.get("Description")),
            category="incident",
            rule_name=as_text(event.get("Title")),
        )

    def _rest_incident(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        props = event["properties"]
        b = AlertBuilder(event, ctx)
        b.consume("id", "name", "properties", "etag", "type")
        extra = props.get("additionalData")
        if isinstance(extra, Mapping):
            b.mitre.add_tactic(extra.get("tactics"))
            b.mitre.add_technique(extra.get("techniques"))
        unmapped = {
            k: v
            for k, v in props.items()
            if k not in {"title", "severity", "description", "createdTimeUtc", "firstActivityTimeUtc", "additionalData"}
        }
        return b.build(
            title=as_text(props.get("title")),
            severity=map_severity(as_text(props.get("severity"))),
            time_candidates=(props.get("firstActivityTimeUtc"), props.get("createdTimeUtc")),
            source_alert_id=first(event.get("name"), props.get("incidentNumber")),
            description=as_text(props.get("description")),
            category="incident",
            rule_name=as_text(props.get("title")),
            extra_unmapped={"properties": unmapped},
        )
