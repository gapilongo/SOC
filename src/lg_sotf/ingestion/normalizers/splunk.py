"""Splunk: Enterprise Security notable events and plain search results.

Field names follow the Splunk Common Information Model. Values may be
strings or multivalue lists. ``src``/``dest`` hold an address or a host name
and are classified per value.

The alert id is the notable's ``event_id``. Plain search results have none,
so the event's index address (``index:_bkt:_cd``, stable across searches) is
used, and failing that a hash that ignores per-search fields such as
``_serial`` (the result's position) and ``splunk_server``.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from lg_sotf.ingestion.errors import UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, as_text, first, require_mapping
from lg_sotf.models.alert import CanonicalAlert, map_severity

_HOST_OR_IP = ("src", "dest", "dvc", "orig_host")
_IPS = ("src_ip", "dest_ip", "dvc_ip", "remote_ip")
_HOSTS = ("src_host", "dest_host", "dvc_host", "host_name", "dest_nt_host", "src_nt_host")
_USERS = ("user", "src_user", "dest_user", "user_name", "orig_user")
_PROCESSES = ("process_name", "process_path", "parent_process_name", "parent_process_path", "process_exec")
_COMMANDS = ("process", "parent_process", "process_command_line", "cmdline")
_HASHES = ("file_hash", "process_hash", "hash", "md5", "sha1", "sha256", "parent_process_hash")
_DOMAINS = ("domain", "query", "dest_domain", "src_domain", "url_domain")
_URLS = ("url", "uri")
_EMAILS = ("recipient", "sender", "src_user_email", "user_email")
_TECHNIQUES = ("annotations.mitre_attack", "annotations.mitre_attack.mitre_technique_id", "mitre_technique_id")
_TACTICS = ("annotations.mitre_attack.mitre_tactic", "mitre_tactic", "annotations.mitre_attack.mitre_tactic_id")
_TITLE = ("rule_title", "rule_name", "search_name", "signature", "savedsearch_name", "source")
_INTERNAL_PREFIX = "lgsotf_"
VOLATILE_KEYS = ("_serial", "_si", "splunk_server", "splunk_server_group", "_indextime", "_eventtype_color")


def index_address(event: Mapping[str, Any]) -> Optional[str]:
    """``index:_bkt:_cd`` - where Splunk stored the event, identical in every search that returns it."""
    bkt, cd = as_text(event.get("_bkt")), as_text(event.get("_cd"))
    if bkt is None or cd is None:
        return None
    return f"{as_text(event.get('index')) or '-'}:{bkt}:{cd}"


class SplunkNormalizer:
    name = "splunk"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        title = as_text(first(*(event.get(k) for k in _TITLE)))
        if title is None:
            raise UnrecognizedEvent("splunk event has no rule_title, rule_name, search_name or signature")
        b = AlertBuilder(event, ctx)
        b.consume(*_TITLE, "urgency", "severity", "_time", "event_id", "rule_id", "description",
                  "rule_description", "security_domain", "category", "_indextime", *VOLATILE_KEYS)
        b.consume(*(k for k in event if k.startswith(_INTERNAL_PREFIX)))
        for key in _HOST_OR_IP:
            b.entities.add_host_or_ip(event.get(key))
        for keys, adder in (
            (_IPS, b.entities.add_ip),
            (_HOSTS, b.entities.add_host),
            (_USERS, b.entities.add_user),
            (_PROCESSES, b.entities.add_process),
            (_COMMANDS, b.entities.add_command_line),
            (_HASHES, b.entities.add_hash),
            (_DOMAINS, b.entities.add_domain),
            (_URLS, b.entities.add_url),
            (_EMAILS, b.entities.add_email),
        ):
            for key_name in keys:
                adder(event.get(key_name))
            b.consume(*keys)
        b.consume(*_HOST_OR_IP)
        for key in _TECHNIQUES:
            b.mitre.add_technique(event.get(key))
        for key in _TACTICS:
            b.mitre.add_tactic(event.get(key))
        b.consume(*_TECHNIQUES, *_TACTICS)
        severity = map_severity(as_text(event.get("urgency"))) or map_severity(as_text(event.get("severity")))
        rule_name = as_text(first(event.get("rule_name"), event.get("search_name"), event.get("savedsearch_name")))
        return b.build(
            title=title,
            severity=severity,
            time_candidates=(event.get("_time"), event.get("orig_time"), event.get("_indextime")),
            source_alert_id=first(event.get("event_id"), event.get("orig_event_id"), index_address(event)),
            description=as_text(first(event.get("description"), event.get("rule_description"))),
            category=as_text(first(event.get("security_domain"), event.get("category"))),
            rule_name=rule_name,
            hash_exclude=VOLATILE_KEYS,
        )
