"""Wazuh ``alerts.json`` documents (as written by the manager or stored in the indexer)."""

from __future__ import annotations

from typing import Any, Mapping

from lg_sotf.ingestion.entities import sysmon_hashes
from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, first, get_path, require_mapping
from lg_sotf.models.alert import CanonicalAlert, map_severity

_DATA_IPS = ("srcip", "dstip", "src_ip", "dst_ip", "aws.sourceIPAddress")
_DATA_USERS = ("srcuser", "dstuser", "user", "win.eventdata.targetUserName", "win.eventdata.subjectUserName")
_DATA_URLS = ("url",)
_DATA_HASHES = ("md5", "sha1", "sha256")


class WazuhNormalizer:
    name = "wazuh"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        rule = event.get("rule")
        if not isinstance(rule, Mapping) or not as_text(rule.get("description")):
            raise UnrecognizedEvent("wazuh alert requires rule.description")
        b = AlertBuilder(event, ctx)
        b.consume("rule", "agent", "timestamp", "@timestamp", "id", "data", "syscheck")
        agent = event.get("agent")
        if isinstance(agent, Mapping):
            b.entities.add_host(agent.get("name"))
            b.entities.add_ip(agent.get("ip"))
        raw_data = event.get("data")
        data: Mapping[str, Any] = raw_data if isinstance(raw_data, Mapping) else {}
        for path in _DATA_IPS:
            b.entities.add_ip(get_path(data, path))
        for path in _DATA_USERS:
            b.entities.add_user(get_path(data, path))
        for path in _DATA_URLS:
            b.entities.add_url(get_path(data, path))
        for path in _DATA_HASHES:
            b.entities.add_hash(get_path(data, path))
        eventdata = get_path(data, "win.eventdata")
        if isinstance(eventdata, Mapping):
            b.entities.add_process(first(eventdata.get("image"), eventdata.get("newProcessName")))
            b.entities.add_process(eventdata.get("parentImage"))
            b.entities.add_command_line(first(eventdata.get("commandLine"), eventdata.get("processCommandLine")))
            b.entities.add_hash(sysmon_hashes(eventdata.get("hashes")))
            b.entities.add_ip(first(eventdata.get("sourceIp"), eventdata.get("ipAddress")))
            b.entities.add_ip(eventdata.get("destinationIp"))
            b.entities.add_domain(first(eventdata.get("queryName"), eventdata.get("destinationHostname")))
            b.entities.add_host(eventdata.get("workstationName"))
        syscheck = event.get("syscheck")
        if isinstance(syscheck, Mapping):
            b.entities.add_hash(syscheck.get("sha256_after"))
            b.entities.add_hash(syscheck.get("md5_after"))
            b.entities.add_process(syscheck.get("path"))
        mitre = rule.get("mitre")
        if isinstance(mitre, Mapping):
            b.mitre.add_tactic(mitre.get("tactic"))
            b.mitre.add_technique(mitre.get("id"))
        groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
        unmapped_rule = {k: v for k, v in rule.items() if k not in {"description", "level", "id", "mitre", "groups"}}
        unmapped_data = {k: v for k, v in data.items() if k not in {"srcip", "dstip", "srcuser", "dstuser", "url"}}
        extra: dict[str, Any] = {}
        if unmapped_rule:
            extra["rule"] = unmapped_rule
        if unmapped_data:
            extra["data"] = unmapped_data
        rule_id = as_text(rule.get("id"))
        description = as_text(rule.get("description"))
        return b.build(
            title=description,
            severity=map_severity(rule.get("level"), "0-15"),
            time_candidates=(event.get("timestamp"), event.get("@timestamp")),
            source_alert_id=event.get("id"),
            description=as_text(event.get("full_log")),
            category=as_text(groups[-1]) if groups else None,
            rule_name=f"{rule_id}: {description}" if rule_id else description,
            extra_unmapped=extra,
        )
