from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest

from lg_sotf.ingestion.errors import NormalizationError, SourceConfigError, UnrecognizedEvent
from lg_sotf.ingestion.normalizers import NORMALIZERS, get_normalizer, resolve_format
from lg_sotf.ingestion.normalizers.base import FLAG_ID_FROM_HASH, FLAG_SEVERITY_DEFAULTED, event_hash, get_path
from lg_sotf.ingestion.timeparse import FLAG_CLAMPED, FLAG_MISSING
from tests.fixtures.vendors import load_vendor, vendor_events
from tests.unit.ingestion._support import NOW, ctx


def norm(fmt: str, event: dict, config: dict | None = None):
    return get_normalizer(fmt).normalize(event, ctx(fmt if fmt != "webhook" else "webhook", config))


# -- canonical -------------------------------------------------------------------


def test_canonical_full_event() -> None:
    event = vendor_events("canonical")[0]
    alert = norm("canonical", event)
    assert alert.source_alert_id == "custom-001"
    assert alert.severity == "high"
    assert alert.occurred_at == datetime(2024, 3, 5, 9, 15, 30, tzinfo=UTC)
    assert alert.entities.ips == ["203.0.113.10", "198.51.100.11"]
    assert alert.entities.users == ["carol@corp.example.com"]
    assert alert.mitre.techniques == ["T1078.004"] and alert.mitre.tactics == ["TA0001"]
    assert alert.rule_name == "impossible-travel"
    assert alert.unmapped == {"tenant_notes": "vip user"}
    assert "entities_invalid_dropped" in alert.flags


def test_canonical_minimal_event_uses_hash_id_and_epoch() -> None:
    event = vendor_events("canonical")[1]
    alert = norm("canonical", event)
    assert alert.severity == "info"
    assert alert.source_alert_id == event_hash(event)
    assert FLAG_ID_FROM_HASH in alert.flags
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 15, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("event", "error"),
    [
        ({"severity": "high"}, UnrecognizedEvent),
        ({"title": "x"}, NormalizationError),
        ({"title": "x", "severity": "urgent-ish"}, NormalizationError),
        ({"title": "x", "severity": "low", "entities": {"wallets": ["x"]}}, NormalizationError),
        ({"title": "x", "severity": "low", "entities": ["1.2.3.4"]}, NormalizationError),
        ({"title": "x", "severity": "low", "mitre": "T1003"}, NormalizationError),
    ],
)
def test_canonical_rejections(event: dict, error: type) -> None:
    with pytest.raises(error):
        norm("canonical", event)


def test_missing_time_defaults_to_ingestion_time_and_flags() -> None:
    alert = norm("canonical", {"title": "x", "severity": "low"})
    assert alert.occurred_at == NOW
    assert FLAG_MISSING in alert.flags


def test_far_future_time_is_clamped() -> None:
    alert = norm("canonical", {"title": "x", "severity": "low", "occurred_at": "2099-01-01T00:00:00Z"})
    assert alert.occurred_at == NOW
    assert FLAG_CLAMPED in alert.flags


# -- splunk ----------------------------------------------------------------------


def test_splunk_notable() -> None:
    alert = norm("splunk", vendor_events("splunk_notable")[0])
    assert alert.title == "Encoded PowerShell on WS-0142"
    assert alert.severity == "high"  # urgency wins over severity
    assert alert.source_alert_id.endswith("@@notable@@3f2a9c4e1b7d8a60")
    assert alert.category == "endpoint"
    assert alert.rule_name == "Endpoint - Suspicious PowerShell Encoded Command - Rule"
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 15, 30, tzinfo=UTC)
    assert alert.entities.hosts == ["ws-0142.corp.example.com"]
    assert alert.entities.ips == ["10.20.30.40"]
    assert alert.entities.users == ["CORP\\jdoe"]
    assert alert.entities.hashes == ["5f4dcc3b5aa765d61d8327deb882cf99"]
    assert alert.entities.processes == ["powershell.exe", "winword.exe"]
    assert alert.entities.command_lines[0].startswith("powershell.exe -NoProfile")
    assert alert.entities.urls == ["http://malicious-cdn.example.net/payload.ps1"]
    assert alert.entities.domains == ["malicious-cdn.example.net"]
    assert alert.mitre.techniques == ["T1059.001", "T1027"]
    assert alert.mitre.tactics == ["execution", "defense-evasion"]
    assert "lgsotf_indextime" not in alert.unmapped
    assert alert.unmapped["owner"] == "unassigned"


def test_splunk_multivalue_and_invalid_values() -> None:
    alert = norm("splunk", vendor_events("splunk_notable")[1])
    assert alert.severity == "critical"
    assert alert.entities.ips == ["192.0.2.10", "203.0.113.77"]
    assert alert.entities.hosts == ["db-02"]
    assert alert.entities.users == ["admin", "root"]
    assert alert.entities.hashes == []
    assert FLAG_ID_FROM_HASH in alert.flags
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 16, 40, tzinfo=UTC)


def test_splunk_unrecognized() -> None:
    with pytest.raises(UnrecognizedEvent):
        norm("splunk", {"_raw": "x"})


# -- crowdstrike -----------------------------------------------------------------


def test_crowdstrike_alert_v2() -> None:
    alert = norm("crowdstrike", vendor_events("crowdstrike_alerts")[0])
    assert alert.title == "Credential dumping via LSASS access"
    assert alert.severity == "critical"
    assert alert.source_alert_id.startswith("a1b2c3d4e5f60718293a4b5c6d7e8f90:ind:")
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 15, 29, 500000, tzinfo=UTC)
    assert alert.entities.hosts == ["fin-laptop-07"]
    assert alert.entities.ips == ["10.1.2.3", "198.51.100.23"]
    assert alert.entities.users == ["asmith"]
    assert alert.entities.emails == ["asmith@corp.example.com"]
    assert alert.entities.hashes == [
        "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "b99d114b267f4a79c7b4b1e1ff7f7fb6b7a2d3c4e5f60718293a4b5c6d7e8f90",
    ]
    assert len(alert.entities.command_lines) == 2
    assert alert.mitre.techniques == ["T1003.001"]
    assert alert.mitre.tactics == ["Credential Access"]
    assert alert.rule_name == "CredentialDumpingLsass"
    assert "falcon_host_link" in alert.unmapped


def test_crowdstrike_legacy_detection() -> None:
    alert = norm("crowdstrike", vendor_events("crowdstrike_alerts")[1])
    assert alert.source_alert_id == "ldt:0f1e2d3c4b5a69788796a5b4c3d2e1f0:99887766"
    assert alert.severity == "medium"
    assert alert.title == "SuspiciousScriptExecution"
    assert alert.entities.hosts == ["dev-box-01"]
    assert alert.entities.users == ["dev01"]
    assert alert.mitre.techniques == ["T1059"]
    assert alert.occurred_at == datetime(2024, 3, 5, 8, 59, 58, tzinfo=UTC)


def test_crowdstrike_numeric_severity_fallback() -> None:
    alert = norm("crowdstrike", {"composite_id": "c1", "display_name": "x", "severity": 45})
    assert alert.severity == "medium"


# -- sentinel --------------------------------------------------------------------


def test_sentinel_security_alert() -> None:
    alert = norm("sentinel", vendor_events("sentinel")[0])
    assert alert.source_alert_id == "7b9c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d"
    assert alert.title == "Suspicious sign-in from an anonymous IP address"
    assert alert.severity == "medium"
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 14, tzinfo=UTC)
    assert alert.entities.users == ["bwayne"]
    assert alert.entities.emails == ["bwayne@corp.example.com"]
    assert alert.entities.ips == ["203.0.113.200"]
    assert alert.entities.hosts == ["gotham-ws.corp.example.com"]
    assert alert.entities.hashes == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert alert.entities.urls == ["https://login.example.com/common/oauth2"]
    assert alert.mitre.tactics == ["InitialAccess", "CredentialAccess"]
    assert alert.mitre.techniques == ["T1078", "T1110.003"]
    assert "ExtendedProperties" in alert.unmapped


def test_sentinel_security_incident_row() -> None:
    alert = norm("sentinel", vendor_events("sentinel")[1])
    assert alert.source_alert_id == "0d1c2b3a-4958-6a7b-8c9d-0e1f2a3b4c5d"
    assert alert.severity == "high"
    assert alert.category == "incident"
    assert alert.mitre.techniques == ["T1078"]
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 14, tzinfo=UTC)


def test_sentinel_rest_incident() -> None:
    alert = norm("sentinel", vendor_events("sentinel")[2])
    assert alert.source_alert_id == "9a8b7c6d-5e4f-3a2b-1c0d-ffeeddccbbaa"
    assert alert.severity == "low"
    assert alert.title == "Mass download by a single user"
    assert alert.mitre.techniques == ["T1567"]
    assert alert.unmapped["properties"]["incidentNumber"] == 4212


def test_sentinel_tolerates_malformed_entities() -> None:
    event = copy.deepcopy(vendor_events("sentinel")[0])
    event["Entities"] = "[not json"
    alert = norm("sentinel", event)
    assert alert.entities.ips == []


# -- wazuh -----------------------------------------------------------------------


def test_wazuh_sshd() -> None:
    alert = norm("wazuh", vendor_events("wazuh_alerts")[0])
    assert alert.source_alert_id == "1709633730.1234567"
    assert alert.severity == "medium"  # level 10 on the 0-15 scale
    assert alert.title.startswith("sshd: brute force")
    assert alert.rule_name.startswith("5712: ")
    assert alert.category == "authentication_failures"
    assert alert.entities.hosts == ["web-01"]
    assert alert.entities.ips == ["10.0.0.5", "203.0.113.5"]
    assert alert.entities.users == ["oracle"]
    assert alert.mitre.techniques == ["T1110"]
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 15, 30, 123000, tzinfo=UTC)
    assert alert.description.startswith("Mar  5 10:15:30 web-01 sshd")
    assert alert.unmapped["rule"]["pci_dss"] == ["10.2.4", "10.2.5"]


def test_wazuh_sysmon() -> None:
    alert = norm("wazuh", vendor_events("wazuh_alerts")[1])
    assert alert.severity == "high"
    assert alert.entities.users == ["mjones"]
    assert "3f2a9c4e1b7d8a603f2a9c4e1b7d8a603f2a9c4e" in alert.entities.hashes
    assert "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" in alert.entities.hashes
    assert "0" * 32 not in alert.entities.hashes
    assert len(alert.entities.processes) == 2
    assert alert.entities.command_lines[0].startswith("powershell.exe -nop")


def test_wazuh_unrecognized() -> None:
    with pytest.raises(UnrecognizedEvent):
        norm("wazuh", {"timestamp": "2024-01-01T00:00:00Z"})


# -- guardduty -------------------------------------------------------------------


def test_guardduty_eventbridge_envelope() -> None:
    alert = norm("guardduty", vendor_events("guardduty_findings")[0])
    assert alert.source_alert_id == "d2c4a6e8f0b1d3c5e7a9b0c2d4e6f8a1"
    assert alert.severity == "medium"
    assert alert.category == "UnauthorizedAccess"
    assert alert.rule_name == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert alert.entities.hosts == ["i-0abc1234def567890"]
    assert alert.entities.ips == ["172.31.10.20", "198.51.100.44", "203.0.113.66"]
    assert alert.entities.domains == ["ec2-198-51-100-44.compute-1.amazonaws.com"]
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 0, tzinfo=UTC)
    assert alert.unmapped["eventbridge"]["account"] == "111122223333"


def test_guardduty_bare_finding() -> None:
    alert = norm("guardduty", vendor_events("guardduty_findings")[1])
    assert alert.severity == "high"
    assert alert.entities.users == ["ci-deployer"]
    assert alert.entities.ips == ["198.51.100.99"]
    assert alert.category == "CredentialAccess"


def test_guardduty_unrecognized() -> None:
    with pytest.raises(UnrecognizedEvent):
        norm("guardduty", {"detail": {"foo": 1}})


# -- qradar ----------------------------------------------------------------------


def test_qradar_offenses() -> None:
    first, second = vendor_events("qradar_offenses")
    a = norm("qradar", first)
    assert a.source_alert_id == "1042"
    assert a.severity == "high"
    assert a.title.startswith("Multiple Login Failures for the Same User containing")
    assert a.entities.users == ["svc_backup"]
    assert a.category == "User Login Failure"
    assert a.rule_name == "qradar-rules:100001,100205"
    assert a.occurred_at == datetime(2024, 3, 5, 10, 15, 30, tzinfo=UTC)
    b = norm("qradar", second)
    assert b.entities.ips == ["192.0.2.50"]
    assert b.severity == "low"


# -- generic webhook -------------------------------------------------------------


def test_webhook_field_map() -> None:
    fixture = load_vendor("webhook_generic")
    alert = norm("webhook", fixture["events"][0], fixture["config"])
    assert alert.title == "Outbound connection to newly registered domain"
    assert alert.severity == "high"  # severity_map, case-insensitive
    assert alert.source_alert_id == "8e7d6c5b-4a39-2817-0615-243342516071"
    assert alert.occurred_at == datetime(2024, 3, 5, 10, 15, 30, 123000, tzinfo=UTC)
    assert alert.entities.ips == ["10.30.0.3", "198.51.100.200"]
    assert alert.entities.hosts == ["kiosk-3"]
    assert alert.entities.users == ["kiosk", "svc-update"]
    assert alert.entities.domains == ["a1b2c3-new.example.org", "cdn.example.com"]
    assert alert.mitre.techniques == ["T1071.001", "T1568.002"]
    assert alert.rule_name == "NRD-OUTBOUND-01"
    assert alert.unmapped == {"vendor_extra": {"sensor": "edge-7", "ruleset": "2024.03"}}


def test_webhook_scale_and_offset_time() -> None:
    fixture = load_vendor("webhook_generic")
    alert = norm("webhook", fixture["events"][1], fixture["config"])
    assert alert.severity == "info"  # numeric 1 on the configured 1-5 scale
    assert alert.occurred_at == datetime(2024, 3, 5, 8, 15, tzinfo=UTC)
    assert FLAG_ID_FROM_HASH in alert.flags


def test_webhook_default_severity() -> None:
    config = {"field_map": {"title": "t"}}
    alert = norm("webhook", {"t": "x"}, config)
    assert alert.severity == "medium" and FLAG_SEVERITY_DEFAULTED in alert.flags
    with pytest.raises(NormalizationError):
        norm("webhook", {"t": "x"}, {**config, "default_severity": None})


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"field_map": {"severity": "s"}},
        {"field_map": {"title": "t", "entities.wallets": "w"}},
        {"field_map": {"title": ""}},
        {"field_map": {"title": "t"}, "severity_map": {"P1": "urgent"}},
        {"field_map": {"title": "t"}, "severity_scale": "0-7"},
        {"field_map": {"title": ["a"] * 17}},
    ],
)
def test_webhook_config_validation(config: dict) -> None:
    with pytest.raises(SourceConfigError):
        norm("webhook", {"t": "x"}, config)


def test_webhook_missing_title_is_unrecognized() -> None:
    with pytest.raises(UnrecognizedEvent):
        norm("webhook", {"other": 1}, {"field_map": {"title": "t"}})


# -- registry and helpers --------------------------------------------------------


def test_resolve_format() -> None:
    assert resolve_format(None) == "canonical"
    assert resolve_format("splunk", {"format": "wazuh"}) == "splunk"
    assert resolve_format("webhook", {}) == "canonical"
    assert resolve_format("webhook", {"field_map": {"title": "t"}}) == "webhook"
    assert resolve_format("webhook", {"format": "guardduty"}) == "guardduty"
    assert resolve_format("file", {"format": "wazuh"}) == "wazuh"
    with pytest.raises(SourceConfigError):
        resolve_format("webhook", {"format": "generic"})
    with pytest.raises(SourceConfigError):
        resolve_format("webhook", {"format": "nope"})
    with pytest.raises(SourceConfigError):
        resolve_format("carbonblack", {})


def test_get_path() -> None:
    data = {"a": {"b": [{"c": 1}, {"c": 2}, {"d": 3}]}, "x.y": 5}
    assert get_path(data, "a.b.1.c") == 2
    assert get_path(data, "a.b.*.c") == [1, 2]
    assert get_path(data, "x.y") == 5
    assert get_path(data, "a.b.9.c", "dflt") == "dflt"
    assert get_path(data, "a.zz") is None


@pytest.mark.parametrize(
    ("fmt", "fixture"),
    [
        ("canonical", "canonical"),
        ("splunk", "splunk_notable"),
        ("crowdstrike", "crowdstrike_alerts"),
        ("sentinel", "sentinel"),
        ("wazuh", "wazuh_alerts"),
        ("guardduty", "guardduty_findings"),
        ("qradar", "qradar_offenses"),
    ],
)
def test_normalizers_are_deterministic_and_do_not_mutate(fmt: str, fixture: str) -> None:
    for event in vendor_events(fixture):
        before = copy.deepcopy(event)
        a = norm(fmt, event)
        b = norm(fmt, event)
        assert a == b
        assert event == before


def test_every_format_rejects_non_objects() -> None:
    for name, normalizer in NORMALIZERS.items():
        with pytest.raises(UnrecognizedEvent):
            normalizer.normalize(["not", "a", "dict"], ctx(name, {"field_map": {"title": "t"}}))  # type: ignore[arg-type]


def test_splunk_unknown_urgency_defaults_to_medium_and_is_flagged() -> None:
    alert = norm("splunk", {"event_id": "x1", "rule_name": "Brute force", "urgency": "unknown"})
    assert alert.severity == "medium"
    assert FLAG_SEVERITY_DEFAULTED in alert.flags


def test_canonical_refuses_placeholder_severity() -> None:
    with pytest.raises(NormalizationError):
        norm("canonical", {"id": "c1", "title": "t", "severity": "unknown"})


def test_splunk_search_results_keep_their_id_across_searches() -> None:
    row = {"_time": "2024-03-05T10:00:00Z", "search_name": "Custom search", "src": "203.0.113.5",
           "index": "main", "_bkt": "main~12~3F2A", "_cd": "12:4567", "_serial": "0", "_si": ["idx1", "main"],
           "splunk_server": "idx1", "lgsotf_indextime": "1709632800"}
    again = {**row, "_serial": "17", "_si": ["idx2", "main"], "splunk_server": "idx2", "lgsotf_indextime": "1709632900"}
    first_alert, second_alert = norm("splunk", row), norm("splunk", again)
    assert first_alert.source_alert_id == "main:main~12~3F2A:12:4567"
    assert second_alert.source_alert_id == first_alert.source_alert_id
    assert "_serial" not in first_alert.unmapped and "lgsotf_indextime" not in first_alert.unmapped


def test_splunk_hash_id_ignores_per_search_fields() -> None:
    row = {"_time": "2024-03-05T10:00:00Z", "search_name": "Custom search", "src": "203.0.113.5", "_serial": "0",
           "splunk_server": "idx1"}
    a = norm("splunk", row)
    b = norm("splunk", {**row, "_serial": "3", "splunk_server": "idx2", "lgsotf_indextime": "1"})
    assert FLAG_ID_FROM_HASH in a.flags and a.source_alert_id == b.source_alert_id
    assert norm("splunk", {**row, "src": "203.0.113.6"}).source_alert_id != a.source_alert_id


def test_event_hash_excludes_internal_and_listed_keys() -> None:
    base = {"a": 1}
    assert event_hash({**base, "lgsotf_x": 2}) == event_hash(base)
    assert event_hash({**base, "_serial": 5}, exclude=("_serial",)) == event_hash(base)
    assert event_hash({**base, "b": "\ud800"}) != event_hash(base)
