"""Destination policy for pull connectors (SSRF, cleartext credentials, DNS rebinding)."""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, List

import httpx
import pytest

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, create_connector
from lg_sotf.ingestion.sources import http as http_mod
from lg_sotf.ingestion.sources.http import SourceHttpClient
from lg_sotf.ingestion.sources.netpolicy import REFUSED_MESSAGE, DestinationPolicy, DestinationRefused, GuardedTransport
from lg_sotf.settings import Settings
from tests.unit.ingestion._support import MapResolver, make_source, public_resolver

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


def _qradar(settings: Settings, base_url: str, handler: Callable[[httpx.Request], httpx.Response], **deps: Any) -> Any:
    source = make_source("qradar", {"base_url": base_url})
    return create_connector(
        source,
        {"token": "qr-token"},
        settings=settings,
        options=IngestionOptions.from_settings(settings),
        deps=ConnectorDeps(transport=httpx.MockTransport(handler), **deps),
    )


def test_cleartext_source_urls_are_refused_in_production(make_settings: Callable[..., Settings]) -> None:
    prod = make_settings(environment="production")
    with pytest.raises(SourceConfigError, match="https"):
        _qradar(prod, "http://169.254.169.254", lambda r: httpx.Response(200, json=[]))
    with pytest.raises(SourceConfigError, match="https"):
        create_connector(
            make_source("sentinel", {"workspace_id": "w1", "azure_tenant_id": "contoso.example.com",
                                     "authority_url": "http://login.example.com"}),
            {"client_id": "a", "client_secret": "b"},
            settings=prod,
            options=IngestionOptions.from_settings(prod),
        )


async def test_connectors_never_reach_internal_addresses(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    reached: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reached.append(str(request.url))
        return httpx.Response(200, json=[])

    metadata = _qradar(settings, "http://169.254.169.254", handler, resolver=public_resolver)
    with pytest.raises(DestinationRefused):
        await metadata.check_destinations()
    with pytest.raises(DestinationRefused):
        async for _ in metadata.pages(None):
            pass
    await metadata.aclose()

    internal = _qradar(settings, "https://qradar.corp.example", handler, resolver=MapResolver(
        {"qradar.corp.example": ["10.1.2.3"]}))
    with pytest.raises(DestinationRefused):
        await internal.test()
    await internal.aclose()
    assert reached == []

    on_prem = make_settings(ingestion={"allow_private_destinations": True})
    allowed = _qradar(on_prem, "https://qradar.corp.example", handler, resolver=MapResolver(
        {"qradar.corp.example": ["10.1.2.3"]}))
    await allowed.check_destinations()
    await allowed.aclose()


def test_allow_private_destinations_cannot_be_set_per_source(make_settings: Callable[..., Settings]) -> None:
    options = IngestionOptions.from_settings(make_settings())
    assert options.for_source({"allow_private_destinations": True}).allow_private_destinations is False


def test_pinned_client_verifies_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    real = httpx.AsyncHTTPTransport

    def spy(**kwargs: Any) -> httpx.AsyncHTTPTransport:
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(http_mod.httpx, "AsyncHTTPTransport", spy)
    SourceHttpClient(source_type="t", base_url="https://api.example.com", policy=STRICT)
    assert captured["verify"] is True
