from __future__ import annotations

import pytest

from lg_sotf.ingestion.entities import (
    EntityCollector,
    MitreCollector,
    hash_type,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_url,
    sysmon_hashes,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.1", "10.0.0.1"),
        (" 203.0.113.5 ", "203.0.113.5"),
        ("198.51.100.200:443", "198.51.100.200"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("999.1.1.1", None),
        ("10.0.0", None),
        ("-", None),
        ("host.example.com", None),
    ],
)
def test_ip(value: str, expected: str | None) -> None:
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("5F4DCC3B5AA765D61D8327DEB882CF99", "5f4dcc3b5aa765d61d8327deb882cf99"),
        ("sha256:" + "a" * 64, "a" * 64),
        ("a" * 40, "a" * 40),
        ("a" * 33, None),
        ("g" * 32, None),
        ("0" * 32, None),
        ("", None),
    ],
)
def test_hash(value: str, expected: str | None) -> None:
    assert normalize_hash(value) == expected


def test_hash_type() -> None:
    assert hash_type("a" * 32) == "md5"
    assert hash_type("a" * 64) == "sha256"
    assert hash_type("xyz") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "bücher.example"),
        ("localhost", None),
        ("-bad.example.com", None),
        ("1.2.3.4", None),
        ("a..b", None),
        ("example.123", None),
        ("a" * 64 + ".com", None),
    ],
)
def test_domain(value: str, expected: str | None) -> None:
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("https://evil.example.com/a?b=c", True),
        ("http://203.0.113.9/a", True),
        ("hxxp://evil.example.com", False),
        ("javascript:alert(1)", False),
        ("https://", False),
        ("https://bad host/", False),
        ("https://[::1/", False),
    ],
)
def test_url(value: str, ok: bool) -> None:
    assert (normalize_url(value) is not None) is ok


def test_email() -> None:
    assert normalize_email("Carol@Corp.Example.com") == "carol@corp.example.com"
    assert normalize_email("mailto:x@example.org") == "x@example.org"
    assert normalize_email("not-an-email") is None
    assert normalize_email("a@localhost") is None


def test_collector_validates_dedups_and_counts_drops() -> None:
    c = EntityCollector()
    c.add_ip(["10.0.0.1", "10.0.0.1", "nope", None, ""])
    c.add_hash("zz")
    c.add_url("https://Evil.example.com/x")
    c.add_url("http://203.0.113.9/p")
    c.add_host_or_ip(["192.0.2.1", "WS-01"])
    c.add_user(["-", "N/A", "CORP\\jdoe"])
    c.add_command_line("cmd.exe /c whoami")
    c.add_process("C:\\Windows\\cmd.exe")
    entities = c.build()
    assert entities.ips == ["10.0.0.1", "203.0.113.9", "192.0.2.1"]
    assert entities.domains == ["evil.example.com"]
    assert entities.hosts == ["ws-01"]
    assert entities.users == ["CORP\\jdoe"]
    assert entities.command_lines == ["cmd.exe /c whoami"]
    assert c.dropped == 2


def test_collector_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError):
        EntityCollector().add_by_kind("wallets", "x")


def test_mitre_collector() -> None:
    m = MitreCollector()
    m.add_technique(["T1059.001 - PowerShell", "attack.t1071.001", "t1003", "T1059.001", "none"])
    m.add_tactic("InitialAccess, CredentialAccess")
    m.add_tactic(["ta0002", "Execution"])
    mitre = m.build()
    assert mitre.techniques == ["T1059.001", "T1071.001", "T1003"]
    assert mitre.tactics == ["InitialAccess", "CredentialAccess", "TA0002", "Execution"]


def test_sysmon_hashes() -> None:
    value = "SHA1=AAAA,MD5=9E107D9D372BB6826BD81D3542A419D6,SHA256=" + "B" * 64
    assert sysmon_hashes(value) == ["AAAA", "9E107D9D372BB6826BD81D3542A419D6", "B" * 64]


def test_huge_multivalue_fields_are_bounded_and_fast() -> None:
    import time

    from lg_sotf.ingestion.normalizers import get_normalizer
    from lg_sotf.models.alert import MAX_ENTITY_ITEMS, json_size
    from tests.unit.ingestion._support import ctx

    ips = [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}" for i in range(80_000)]
    users = [f"user{i}" for i in range(20_000)]
    event = {"id": "big", "title": "Many entities", "severity": "low", "entities": {"ips": ips, "users": users}}
    assert json_size(event) > 1_000_000
    started = time.perf_counter()
    alert = get_normalizer("canonical").normalize(event, ctx("canonical"))
    elapsed = time.perf_counter() - started
    assert elapsed < 0.1, elapsed
    assert len(alert.entities.ips) == MAX_ENTITY_ITEMS and alert.entities.ips[0] == "10.0.0.0"
    assert "entities_truncated" in alert.flags


def test_collector_dedups_in_constant_time_and_stops_at_the_cap() -> None:
    from lg_sotf.models.alert import MAX_ENTITY_ITEMS

    c = EntityCollector()
    c.add_ip(["203.0.113.1"] * 500 + [f"198.51.100.{i}" for i in range(200)])
    assert c.ips[0] == "203.0.113.1" and len(c.ips) == MAX_ENTITY_ITEMS
    assert c.truncated > 0
    c.add_url("https://203.0.113.1/x")
    assert c.urls == ["https://203.0.113.1/x"] and len(c.ips) == MAX_ENTITY_ITEMS
