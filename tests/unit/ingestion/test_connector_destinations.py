"""Pull connectors apply the egress policy (https in production, no internal addresses, TLS on)."""

from __future__ import annotations

from typing import Any, Callable, List

import httpx
import pytest

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, create_connector
from lg_sotf.ingestion.sources import http as http_mod
from lg_sotf.ingestion.sources.http import SourceHttpClient
from lg_sotf.net.egress import DestinationPolicy, DestinationRefused
from lg_sotf.settings import Settings
from tests.unit.ingestion._support import MapResolver, make_source, public_resolver

STRICT = DestinationPolicy(require_https=True)


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
