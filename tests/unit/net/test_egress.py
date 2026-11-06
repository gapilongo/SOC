"""Egress destination policy (SSRF, cleartext credentials, DNS rebinding)."""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from lg_sotf.net.egress import REFUSED_MESSAGE, DestinationPolicy, DestinationRefused, GuardedTransport, egress_policy
from lg_sotf.services.connectors.registry import ConnectorRegistry
from lg_sotf.settings import Settings
from tests.unit.ingestion._support import MapResolver

STRICT = DestinationPolicy(require_https=True)
ON_PREM = DestinationPolicy(require_https=True, allow_private=True)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "::1", "169.254.169.254", "169.254.10.1", "fe80::1",
        "0.0.0.0",  # noqa: S104 - a refused destination, not a bind address
        "::", "224.0.0.1", "fd00:ec2::254", "100.100.100.200", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
        "240.0.0.1",
    ],
)
def test_always_refused_addresses(address: str) -> None:
    assert not STRICT.address_allowed(ipaddress.ip_address(address))
    assert not ON_PREM.address_allowed(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["10.0.0.5", "172.16.3.4", "192.168.1.10", "100.64.0.1", "fd12:3456::1"])
def test_private_addresses_need_the_install_setting(address: str) -> None:
    assert not STRICT.address_allowed(ipaddress.ip_address(address))
    assert ON_PREM.address_allowed(ipaddress.ip_address(address))


def test_public_addresses_are_allowed() -> None:
    assert STRICT.address_allowed(ipaddress.ip_address("93.184.216.34"))
    assert STRICT.address_allowed(ipaddress.ip_address("2606:4700::1111"))


def test_url_checks() -> None:
    assert STRICT.check_url("https://splunk.example.com:8089") == ("splunk.example.com", 8089)
    with pytest.raises(SourceConfigError, match="https"):
        STRICT.check_url("http://splunk.example.com")
    assert DestinationPolicy(require_https=False).check_url("http://splunk.example.com") == ("splunk.example.com", 80)
    with pytest.raises(SourceConfigError):
        STRICT.check_url("https://user:pw@splunk.example.com")
    with pytest.raises(SourceConfigError):
        STRICT.check_url("gopher://splunk.example.com")


async def test_any_refused_address_in_a_dns_answer_refuses_the_host() -> None:
    resolver = MapResolver({"mixed.example.com": ["93.184.216.34", "10.0.0.1"]})
    with pytest.raises(DestinationRefused) as info:
        await STRICT.check("https://mixed.example.com", resolver)
    assert str(info.value) == REFUSED_MESSAGE
    await ON_PREM.check("https://mixed.example.com", resolver)


class Capture(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.requests: List[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={})


async def test_requests_are_pinned_to_the_checked_address() -> None:
    inner = Capture()
    resolver = MapResolver({"siem.example.com": ["93.184.216.34"]})
    transport = GuardedTransport(inner, STRICT, resolver, pin=True)
    async with httpx.AsyncClient(transport=transport) as client:
        await client.get("https://siem.example.com:8089/services/server/info")
    sent = inner.requests[0]
    assert sent.url.host == "93.184.216.34" and sent.url.port == 8089
    assert sent.headers["Host"] == "siem.example.com:8089"
    assert sent.extensions["sni_hostname"] == "siem.example.com"


async def test_dns_rebinding_to_metadata_is_refused_per_request() -> None:
    inner = Capture()
    resolver = MapResolver({"siem.example.com": ["93.184.216.34"]})
    transport = GuardedTransport(inner, STRICT, resolver, pin=True)
    async with httpx.AsyncClient(transport=transport) as client:
        await client.get("https://siem.example.com/")
        resolver.table["siem.example.com"] = ["169.254.169.254"]
        with pytest.raises(DestinationRefused):
            await client.get("https://siem.example.com/")
    assert len(inner.requests) == 1


# --- egress_policy: the one lenient reader of ingestion.allow_private_destinations (F4, ADR-0007) ---


def test_egress_policy_defaults_refuse_private_destinations(make_settings: Callable[..., Settings]) -> None:
    assert egress_policy(make_settings()) == DestinationPolicy(require_https=False, allow_private=False)


def test_egress_policy_reads_allow_private_destinations(make_settings: Callable[..., Settings]) -> None:
    assert egress_policy(make_settings(ingestion={"allow_private_destinations": True})).allow_private is True
    # The section is free-form YAML/env text: "true" is read as true, as every ingestion reader does.
    assert egress_policy(make_settings(ingestion={"allow_private_destinations": "true"})).allow_private is True


def test_egress_policy_fails_closed_on_an_invalid_section(make_settings: Callable[..., Settings]) -> None:
    # An unrelated invalid key refuses private destinations, without raising.
    settings = make_settings(ingestion={"allow_private_destinations": True, "batch_size": 0})
    assert egress_policy(settings).allow_private is False
    assert egress_policy(make_settings(ingestion={"allow_private_destinations": "maybe"})).allow_private is False
    # Pull sources read the same section strictly and refuse to run.
    with pytest.raises(SourceConfigError, match="batch_size"):
        IngestionOptions.from_settings(settings)


def test_egress_policy_requires_https_in_production(make_settings: Callable[..., Settings]) -> None:
    prod = make_settings(environment="production", ingestion={"allow_private_destinations": True})
    assert egress_policy(prod) == DestinationPolicy(require_https=True, allow_private=True)
    assert egress_policy(make_settings(environment="staging")).require_https is True
    assert egress_policy(make_settings()).require_https is False
    # An explicit require_https (Microsoft Graph) wins over the environment; allow_private is still the install's.
    dev = make_settings(ingestion={"allow_private_destinations": True})
    assert egress_policy(dev, require_https=True) == DestinationPolicy(require_https=True, allow_private=True)


@pytest.mark.parametrize("ingestion", [{}, {"allow_private_destinations": True}, {"batch_size": 0}])
@pytest.mark.parametrize("environment", ["development", "production"])
def test_every_integration_client_uses_egress_policy(
    make_settings: Callable[..., Settings], environment: str, ingestion: Dict[str, Any]
) -> None:
    settings = make_settings(environment=environment, ingestion=ingestion)
    expected = egress_policy(settings)
    assert IntegrationHttp(settings).policy == expected
    assert ConnectorRegistry(settings)._policy == expected
    assert MicrosoftHttpFactory(settings)._policy == egress_policy(settings, require_https=True)
