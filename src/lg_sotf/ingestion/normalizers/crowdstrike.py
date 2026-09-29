"""CrowdStrike Falcon: Alerts API v2 entities and legacy Detects API detections."""

from __future__ import annotations

from typing import Any, Mapping

from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, first, require_mapping
from lg_sotf.models.alert import CanonicalAlert, Severity, map_severity


def _severity(name: Any, score: Any) -> Severity | None:
    return map_severity(as_text(name)) or map_severity(score, "0-100")


def _add_process_details(b: AlertBuilder, details: Any) -> None:
    if not isinstance(details, Mapping):
        return
    b.entities.add_command_line(details.get("cmdline"))
    b.entities.add_process(first(details.get("filepath"), details.get("filename")))
    b.entities.add_hash(details.get("sha256"))
    b.entities.add_hash(details.get("md5"))
    b.entities.add_user(details.get("user_name"))


def _add_device(b: AlertBuilder, device: Any) -> None:
    if not isinstance(device, Mapping):
        return
    b.entities.add_host(device.get("hostname"))
    b.entities.add_ip(device.get("local_ip"))
    b.entities.add_ip(device.get("external_ip"))


class CrowdStrikeNormalizer:
    name = "crowdstrike"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        if isinstance(event.get("behaviors"), list):
            return self._detection(event, ctx)
        if not any(k in event for k in ("composite_id", "id", "name", "display_name")):
            raise UnrecognizedEvent("crowdstrike event is neither an alert (v2) nor a detection")
        return self._alert_v2(event, ctx)

    def _alert_v2(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        b = AlertBuilder(event, ctx)
        b.consume(
            "composite_id", "id", "name", "display_name", "description", "severity", "severity_name",
            "created_timestamp", "timestamp", "tactic", "tactic_id", "technique", "technique_id",
            "device", "user_name", "user_principal", "cmdline", "filepath", "filename", "sha256", "md5",
            "sha1", "parent_details", "grandparent_details", "scenario", "objective", "product", "type",
            "local_ip", "external_ip", "hostname",
        )
        _add_device(b, event.get("device"))
        b.entities.add_host(event.get("hostname"))
        b.entities.add_ip(event.get("local_ip"))
        b.entities.add_ip(event.get("external_ip"))
        b.entities.add_user(event.get("user_name"))
        b.entities.add_email(event.get("user_principal"))
        b.entities.add_command_line(event.get("cmdline"))
        b.entities.add_process(first(event.get("filepath"), event.get("filename")))
        for key in ("sha256", "sha1", "md5"):
            b.entities.add_hash(event.get(key))
        _add_process_details(b, event.get("parent_details"))
        _add_process_details(b, event.get("grandparent_details"))
        b.mitre.add_tactic(first(event.get("tactic"), event.get("tactic_id")))
        b.mitre.add_technique(event.get("technique_id"))
        title = as_text(first(event.get("display_name"), event.get("name"), event.get("scenario")))
        return b.build(
            title=title,
            severity=_severity(event.get("severity_name"), event.get("severity")),
            time_candidates=(event.get("timestamp"), event.get("created_timestamp")),
            source_alert_id=first(event.get("composite_id"), event.get("id")),
            description=as_text(event.get("description")),
            category=as_text(first(event.get("tactic"), event.get("objective"), event.get("type"))),
            rule_name=as_text(first(event.get("name"), event.get("display_name"))),
        )

    def _detection(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        b = AlertBuilder(event, ctx)
        b.consume(
            "detection_id", "device", "behaviors", "max_severity", "max_severity_displayname",
            "first_behavior", "created_timestamp",
        )
        _add_device(b, event.get("device"))
        behaviors = [x for x in event.get("behaviors") or [] if isinstance(x, Mapping)]
        for beh in behaviors:
            b.entities.add_user(beh.get("user_name"))
            b.entities.add_command_line(beh.get("cmdline"))
            b.entities.add_process(first(beh.get("filepath"), beh.get("filename")))
            b.entities.add_hash(beh.get("sha256"))
            b.entities.add_hash(beh.get("md5"))
            _add_process_details(b, beh.get("parent_details"))
            b.mitre.add_tactic(beh.get("tactic"))
            b.mitre.add_technique(beh.get("technique_id"))
        top = max(behaviors, key=lambda x: x.get("severity") or 0, default={})
        title = as_text(first(top.get("display_name"), top.get("scenario"), top.get("technique")))
        if title is None:
            title = "CrowdStrike detection"
        return b.build(
            title=title,
            severity=_severity(event.get("max_severity_displayname"), event.get("max_severity")),
            time_candidates=(event.get("first_behavior"), event.get("created_timestamp"), top.get("timestamp")),
            source_alert_id=event.get("detection_id"),
            description=as_text(top.get("description")),
            category=as_text(first(top.get("tactic"), top.get("objective"))),
            rule_name=as_text(first(top.get("display_name"), top.get("scenario"))),
        )
