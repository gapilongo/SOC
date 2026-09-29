"""IngestionService behaviour that needs no database: connector leases, test_source, text cleaning."""

from __future__ import annotations

from typing import Any, AsyncGenerator, Callable, Dict, List, Mapping, Optional, cast

import httpx
import pytest

import lg_sotf.ingestion.service as service_module
from lg_sotf.db.repos import Source
from lg_sotf.ingestion.errors import SourceConfigError, SourceUnavailable
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.service import IngestionService, api_source_id, clean_text, is_reserved_source_id, strip_nul_deep
from lg_sotf.ingestion.sources import ConnectorDeps, FetchedPage, PullConnector, SourceHealth, create_connector
from lg_sotf.ingestion.sources.netpolicy import REFUSED_MESSAGE
from lg_sotf.settings import Settings
from tests.unit.ingestion._support import MapResolver, make_source, public_resolver


class Idle(PullConnector):
    source_type = "splunk"

    def __init__(self, source: Source, settings: Settings, test_error: Optional[BaseException] = None):
        super().__init__(source, {}, settings=settings, options=IngestionOptions.from_settings(settings))
        self.closed = False
        self.test_error = test_error

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        if False:
            yield  # pragma: no cover

    async def test(self) -> SourceHealth:
        if self.test_error is not None:
            raise self.test_error
        return SourceHealth(True, "ok")

    async def aclose(self) -> None:
        self.closed = True


def service(settings: Settings, factory: Callable[[Source, Mapping[str, Any]], PullConnector]) -> IngestionService:
    return IngestionService(cast(Any, None), settings, repos=cast(Any, object()), connector_factory=factory)


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


async def test_eviction_never_closes_a_connector_in_use(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "MAX_CACHED_CONNECTORS", 1)
    built: Dict[str, Idle] = {}

    def factory(src: Source, creds: Mapping[str, Any]) -> PullConnector:
        built[src.id] = Idle(src, settings)
        return built[src.id]

    svc = service(settings, factory)
    a, b, c = (make_source("splunk", {}, source_id=i) for i in ("a", "b", "c"))
    async with svc._lease(a):
        async with svc._lease(b):
            assert not built["a"].closed and not built["b"].closed
        # b is idle now and over the cap; a is still in use.
        async with svc._lease(c):
            assert not built["a"].closed
        assert built["b"].closed
        await svc.close()
        assert not built["a"].closed, "close() must wait for the poll that is using the connector"
    assert built["a"].closed and built["c"].closed


async def test_config_change_retires_the_old_connector_after_its_poll(settings: Settings) -> None:
    built: List[Idle] = []

    def factory(src: Source, creds: Mapping[str, Any]) -> PullConnector:
        built.append(Idle(src, settings))
        return built[-1]

    svc = service(settings, factory)
    old = make_source("splunk", {"search": "search a"})
    new = make_source("splunk", {"search": "search b"})
    async with svc._lease(old):
        async with svc._lease(new):
            assert not built[0].closed
        assert not built[0].closed
    assert built[0].closed and not built[1].closed
    await svc.close()
    assert built[1].closed


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (KeyError(0), "unexpected response (KeyError)"),
        (SourceUnavailable("splunk GET /x failed after 3 attempts (ConnectError)"), service_module.UNREACHABLE_DETAIL),
        (TimeoutError(), "unexpected response (TimeoutError)"),
    ],
)
async def test_test_source_never_raises_for_a_failing_source(settings: Settings, error: BaseException, detail: str) -> None:
    svc = service(settings, lambda src, creds: Idle(src, settings, test_error=error))
    health = await svc.test_source("tenant-a", make_source("splunk", {}))
    assert health == SourceHealth(False, detail)


async def test_test_source_with_a_malformed_splunk_answer(settings: Settings) -> None:
    deps = ConnectorDeps(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"entry": {"content": {"version": "9"}}})),
        resolver=public_resolver,
    )

    def factory(src: Source, creds: Mapping[str, Any]) -> PullConnector:
        return _connector(src, {"token": "splunk-token"}, settings, deps)

    svc = service(settings, factory)
    health = await svc.test_source("tenant-a", make_source("splunk", {"base_url": "https://splunk.example.com:8089"}))
    assert health.ok is False and "no entry list" in health.detail


async def test_test_source_and_validate_source_hide_internal_network_details(settings: Settings) -> None:
    resolver = MapResolver({"internal.example.com": ["10.0.0.8"]})
    deps = ConnectorDeps(transport=httpx.MockTransport(lambda r: httpx.Response(200)), resolver=resolver)
    svc = service(settings, lambda src, creds: _connector(src, {"token": "t"}, settings, deps))
    source = make_source("qradar", {"base_url": "https://internal.example.com"})
    health = await svc.test_source("tenant-a", source)
    assert health == SourceHealth(False, REFUSED_MESSAGE)
    with pytest.raises(SourceConfigError, match=REFUSED_MESSAGE):
        await svc.validate_source("tenant-a", source)


def _connector(
    source: Source, credentials: Mapping[str, Any], settings: Settings, deps: Optional[ConnectorDeps]
) -> PullConnector:
    return create_connector(
        source, credentials, settings=settings, options=IngestionOptions.from_settings(settings), deps=deps
    )


def test_clean_text_replaces_lone_surrogates_and_nul() -> None:
    assert clean_text("a\x00b") == "ab"
    cleaned = clean_text("bad \ud800 text \udc80")
    cleaned.encode("utf-8")
    assert cleaned.startswith("bad ") and "�" in cleaned
    assert clean_text("fine \U0001F600") == "fine \U0001F600"
    deep = strip_nul_deep({"k\udc80": ["v\x00", {"x": "\ud800"}]})
    assert list(deep) == ["k�"]
    assert deep["k�"][0] == "v"


def test_reserved_push_ids() -> None:
    assert is_reserved_source_id("api") and is_reserved_source_id("api:k1")
    assert not is_reserved_source_id("apix") and not is_reserved_source_id("qradar-1")
    assert api_source_id("k1") == "api:k1"
    with pytest.raises(ValueError):
        api_source_id("bad key/id")
