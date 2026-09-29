"""Amazon GuardDuty findings, bare or inside an EventBridge envelope.

GuardDuty has no pull connector: the supported path is an EventBridge rule
(``source = aws.guardduty``) with an API destination that POSTs to
``/api/v1/ingest/webhook/{source_id}`` using an ingest API key, where the
source has type ``guardduty``.
"""

from __future__ import annotations

from typing import Any, Mapping

from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, first, get_path, require_mapping
from lg_sotf.models.alert import CanonicalAlert, map_severity


def _remote_ip(details: Any) -> Any:
    if not isinstance(details, Mapping):
        return None
    return first(details.get("ipAddressV4"), details.get("ipAddressV6"))


class GuardDutyNormalizer:
    name = "guardduty"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        envelope: Mapping[str, Any] = {}
        finding = event
        if isinstance(event.get("detail"), Mapping):
            envelope, finding = event, event["detail"]
        if not as_text(finding.get("type")) or "id" not in finding:
            raise UnrecognizedEvent("guardduty finding requires 'type' and 'id'")
        b = AlertBuilder(finding, ctx)
        b.consume("id", "type", "title", "description", "severity", "createdAt", "updatedAt", "resource", "service")
        instance = get_path(finding, "resource.instanceDetails")
        if isinstance(instance, Mapping):
            b.entities.add_host(instance.get("instanceId"))
            for nic in instance.get("networkInterfaces") or []:
                if not isinstance(nic, Mapping):
                    continue
                b.entities.add_ip(nic.get("privateIpAddress"))
                b.entities.add_ip(nic.get("publicIp"))
                b.entities.add_domain(nic.get("publicDnsName"))
        access = get_path(finding, "resource.accessKeyDetails")
        if isinstance(access, Mapping):
            b.entities.add_user(access.get("userName"))
        action = get_path(finding, "service.action")
        if isinstance(action, Mapping):
            b.entities.add_ip(_remote_ip(get_path(action, "networkConnectionAction.remoteIpDetails")))
            b.entities.add_ip(_remote_ip(get_path(action, "awsApiCallAction.remoteIpDetails")))
            b.entities.add_ip(_remote_ip(get_path(action, "kubernetesApiCallAction.remoteIpDetails")))
            b.entities.add_domain(get_path(action, "dnsRequestAction.domain"))
            for probe in get_path(action, "portProbeAction.portProbeDetails") or []:
                if isinstance(probe, Mapping):
                    b.entities.add_ip(_remote_ip(probe.get("remoteIpDetails")))
        finding_type = as_text(finding.get("type")) or ""
        unmapped_service = get_path(finding, "service")
        extra: dict[str, Any] = {}
        if isinstance(unmapped_service, Mapping):
            extra["service"] = {k: v for k, v in unmapped_service.items() if k != "action"}
        if isinstance(finding.get("resource"), Mapping):
            extra["resource_type"] = finding["resource"].get("resourceType")
        if envelope:
            extra["eventbridge"] = {k: envelope.get(k) for k in ("id", "account", "region", "time") if k in envelope}
        return b.build(
            title=as_text(first(finding.get("title"), finding_type)),
            severity=map_severity(finding.get("severity"), "guardduty"),
            time_candidates=(
                get_path(finding, "service.eventFirstSeen"),
                finding.get("createdAt"),
                envelope.get("time") if envelope else None,
            ),
            source_alert_id=finding.get("id"),
            description=as_text(finding.get("description")),
            category=finding_type.split(":", 1)[0] or None,
            rule_name=finding_type,
            extra_unmapped=extra,
        )
