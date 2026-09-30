"""Tenant templates, the sample alert set and the platform usage CSV."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from lg_sotf.api.routers.ingest import seconds_to_next_utc_day
from lg_sotf.api.routers.platform import TenantUsageOut, csv_cell, month_bounds, usage_csv
from lg_sotf.ingestion.normalizers import NormalizeContext, get_normalizer
from lg_sotf.ingestion.service import is_reserved_source_id
from lg_sotf.onboarding.samples import SAMPLE_COUNT, SAMPLE_SOURCE_ID, sample_events
from lg_sotf.services.escalation import ReviewPolicy
from lg_sotf.services.response import validate_response_settings
from lg_sotf.services.tenancy import PROFILES, copyable_settings, profile_settings
from lg_sotf.settings import RetentionSettings

RESERVED_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
RESERVED_DOMAIN = re.compile(r"(^|\.)(example\.(com|net|org)|[a-z0-9-]+\.example)$")


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_every_profile_passes_the_settings_validation(profile: str) -> None:
    settings = profile_settings(profile)
    validate_response_settings({k: settings[k] for k in ("response", "autonomy") if k in settings})
    ReviewPolicy.model_validate(settings["review"])
    assert settings["response"]["dry_run"] is True, "templates never switch live execution on"
    settings["autonomy"]["low"] = "changed"
    assert PROFILES[profile]["autonomy"]["low"] != "changed", "callers get a copy"


def test_only_the_conservative_profile_requires_mfa() -> None:
    assert profile_settings("conservative")["security"] == {"require_mfa": True}
    assert all("security" not in profile_settings(p) for p in ("balanced", "autonomous"))


def test_profiles_grow_in_autonomy() -> None:
    order = {"disabled": 0, "approval": 1, "auto": 2}
    levels = [sum(order[v] for v in PROFILES[p]["autonomy"].values()) for p in ("conservative", "balanced", "autonomous")]
    assert levels == sorted(levels) and len(set(levels)) == 3


def test_copyable_settings_keep_policy_and_drop_secrets_destinations_and_assets() -> None:
    source = {
        "autonomy": {"low": "auto"},
        "review": {"sla_minutes": {"L1": 10}},
        "llm_daily_token_budget": 10,
        "retention": {"alerts_days": 30},
        "protected_assets": {"hosts": ["dc01"]},
        "protected_cidrs": ["10.0.0.0/8"],
        "response": {
            "connector": "webhook",
            "webhook_url": "https://soar.example.com",
            "webhook_secret_ciphertext": "v1:abc",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----",
            "dry_run": False,
            "blast_radius": {"block_ip": 2},
            "autonomy": {"high": "approval"},
        },
        "tools": {
            "virustotal": {"enabled": True, "api_key_ciphertext": "v1:def"},
            "abuseipdb": {"api_key_ciphertext": "v1:ghi"},
            "internal_domains": ["corp.example"],
        },
        "integrations": {"slack": {"token_ciphertext": "v1:jkl"}},
        "security": {"require_mfa": True, "future_key": "x"},
        "reporting": {"minutes_per_alert": 12},
        "phishing": {"protected_brands": ["Customer B"], "executives": ["B CEO"]},
    }
    copied = copyable_settings(source)
    assert copied == {
        "autonomy": {"low": "auto"},
        "review": {"sla_minutes": {"L1": 10}},
        "llm_daily_token_budget": 10,
        "retention": {"alerts_days": 30},
        "security": {"require_mfa": True},
        "reporting": {"minutes_per_alert": 12},
        "response": {"dry_run": False, "blast_radius": {"block_ip": 2}, "autonomy": {"high": "approval"}},
        "tools": {"virustotal": {"enabled": True}},
    }
    copied["autonomy"]["low"] = "disabled"
    assert source["autonomy"]["low"] == "auto"
    assert copyable_settings({}) == {}


def test_sample_alerts_use_reserved_indicators_only_and_normalize() -> None:
    now = datetime(2026, 9, 30, 12, tzinfo=UTC)
    events = sample_events(now)
    assert len(events) == SAMPLE_COUNT == 5
    assert len({e["source_alert_id"] for e in events}) == SAMPLE_COUNT
    assert sample_events(now) == events, "the set is deterministic (idempotent re-sends)"
    ctx = NormalizeContext(source_id=SAMPLE_SOURCE_ID, source_type="canonical", config={}, now=now)
    normalizer = get_normalizer("canonical")
    for event in events:
        entities = event["entities"]
        for ip in entities.get("ips", []):
            assert any(ipaddress.ip_address(ip) in net for net in RESERVED_NETS), ip
        for host in [*entities.get("hosts", []), *entities.get("domains", [])]:
            assert host.endswith((".example", ".example.com", ".example.net", ".example.org")), host
        for user in entities.get("users", []):
            assert RESERVED_DOMAIN.search(user.rpartition("@")[2]), user
        alert = normalizer.normalize(event, ctx)
        assert alert.source_alert_id == event["source_alert_id"]
        assert alert.occurred_at <= now
    assert "http" not in json.dumps(events)


def test_sample_source_id_is_reserved() -> None:
    assert is_reserved_source_id(SAMPLE_SOURCE_ID)
    assert is_reserved_source_id("api") and is_reserved_source_id("api:key")
    assert not is_reserved_source_id("demo:other")


def test_month_bounds() -> None:
    assert month_bounds("2026-02") == (datetime(2026, 2, 1).date(), datetime(2026, 2, 28).date())
    assert month_bounds("2024-02")[1].day == 29
    assert month_bounds("2026-12") == (datetime(2026, 12, 1).date(), datetime(2026, 12, 31).date())


def test_usage_csv_guards_against_formula_injection() -> None:
    row = TenantUsageOut(
        tenant_id="t1",
        tenant_name="=SUM(A1:A9)",
        tenant_status="active",
        alerts_ingested=5,
        alerts_processed=4,
        alerts_rejected_quota=0,
        llm_calls=1,
        llm_input_tokens=10,
        llm_output_tokens=2,
        llm_cost_usd=Decimal("0.001500"),
        active_users=1,
        users=2,
        sources=0,
    )
    text = usage_csv([row])
    lines = text.split("\r\n")
    assert lines[0].startswith("tenant_id,tenant_name,tenant_status,alerts_ingested")
    assert lines[1] == "t1,'=SUM(A1:A9),active,5,4,0,1,10,2,0.001500,1,2,0"
    assert csv_cell(" +1") == "' +1" and csv_cell(-3) == "-3" and csv_cell(None) == ""


def test_retry_after_points_at_the_next_utc_day() -> None:
    assert seconds_to_next_utc_day(datetime(2026, 9, 30, 23, 59, 30, tzinfo=UTC)) == 30
    assert seconds_to_next_utc_day(datetime(2026, 9, 30, 0, 0, tzinfo=UTC)) == 86_400


def test_retention_bounds_must_be_ordered() -> None:
    with pytest.raises(ValueError):
        RetentionSettings(tenant_min_days=100, tenant_max_days=10)
    assert RetentionSettings().tenant_min_days <= RetentionSettings().alerts_days <= RetentionSettings().tenant_max_days
