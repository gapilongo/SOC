"""The Wazuh indexer behind an alert (INT3.4): a tool call reaches its own tenant's source, and only that."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
import pytest

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Source
from lg_sotf.ingestion.sources import ConnectorDeps, encrypt_source_secret
from lg_sotf.ingestion.wazuh_indexer import WazuhIndexers
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from lg_sotf.tools.wazuh.tools import HOST_ACTIVITY, wazuh_tools
from tests.unit.ingestion._support import make_source, public_resolver
from tests.unit.tools._support import Ctx, registry
from tests.unit.tools.wazuh._support import nothing_found

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
EMPTY = nothing_found()
PARAMS = {"host": "SRV-01", "at": T0, "before_min": 5, "after_min": 5}


def password(tenant: str) -> str:
    return f"test-only-{tenant}-" + "p" * 8


class Estate:
    """Two tenants, each with alerts and sources of its own: repositories that answer one tenant at a time."""

    def __init__(self, box: Optional[SecretBox]) -> None:
        self.box = box
        self.alerts: Dict[Tuple[str, str], str] = {}
        self.sources: Dict[Tuple[str, str], Source] = {}
        self.requests: List[httpx.Request] = []

    def add(self, tenant: str, alert: str, source_id: str, *, kind: str = "wazuh", secret: Any = ..., **config: Any) -> Source:
        self.alerts[(tenant, alert)] = source_id
        credentials = {"username": f"reader-{tenant}", "password": password(tenant)} if secret is ... else secret
        ciphertext = encrypt_source_secret(self.box, tenant, source_id, credentials) if credentials and self.box else None
        base = {"base_url": f"https://indexer.{tenant}.example:9200", "index": f"wazuh-alerts-{tenant}-*"}
        source = make_source(kind, {**base, **config}, source_id=source_id, tenant_id=tenant, secret_ciphertext=ciphertext)
        self.sources[(tenant, source_id)] = source
        return source

    @property
    def repos(self) -> Any:
        estate = self

        class Alerts:
            async def get(self, tenant_id: str, alert_id: str, *, conn: Any = None) -> Any:
                if (tenant_id, alert_id) not in estate.alerts:
                    raise NotFound("alert", alert_id)
                return SimpleNamespace(id=alert_id, source_id=estate.alerts[(tenant_id, alert_id)])

        class Sources:
            async def get(self, tenant_id: str, source_id: str, *, conn: Any = None) -> Source:
                if (tenant_id, source_id) not in estate.sources:
                    raise NotFound("source", source_id)
                return estate.sources[(tenant_id, source_id)]

        return SimpleNamespace(alerts=Alerts(), sources=Sources())

    def ctx(self, tenant: str, alert: str) -> Ctx:
        return Ctx(tenant_id=tenant, alert_id=alert, repos=self.repos)

    def deps(self) -> ConnectorDeps:
        def server(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(200, json=EMPTY)

        return ConnectorDeps(transport=httpx.MockTransport(server), resolver=public_resolver, now=lambda: T0 + timedelta(hours=2))


@pytest.fixture
def production(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


@pytest.fixture
def estate(production: Settings) -> Estate:
    return Estate(SecretBox.from_settings(production))


def indexers(estate: Estate, settings: Settings, **kwargs: Any) -> WazuhIndexers:
    return WazuhIndexers(settings, estate.box, deps=estate.deps(), **kwargs)


def basic(tenant: str) -> str:
    return "Basic " + base64.b64encode(f"reader-{tenant}:{password(tenant)}".encode()).decode()


async def test_a_call_reaches_the_source_of_its_own_alert_with_that_sources_credentials(estate: Estate, production: Settings) -> None:
    estate.add("tenant-a", "a1", "src-a", max_event_lag_s=300)
    estate.add("tenant-b", "b1", "src-b")
    resolve = indexers(estate, production)
    tools = registry(*wazuh_tools(resolve))
    for tenant, alert in (("tenant-a", "a1"), ("tenant-b", "b1")):
        result = await tools.call(estate.ctx(tenant, alert), HOST_ACTIVITY, PARAMS, agent="investigation")
        assert (result.outcome, result.value.error) == ("empty", None)
    hosts = [(r.url.host, r.url.path, r.headers["authorization"]) for r in estate.requests]
    assert hosts == [
        ("indexer.tenant-a.example", "/wazuh-alerts-tenant-a-*/_search", basic("tenant-a")),
        ("indexer.tenant-a.example", "/wazuh-alerts-tenant-a-*/_search", basic("tenant-a")),
        ("indexer.tenant-b.example", "/wazuh-alerts-tenant-b-*/_search", basic("tenant-b")),
        ("indexer.tenant-b.example", "/wazuh-alerts-tenant-b-*/_search", basic("tenant-b")),
    ]
    client = await resolve(estate.ctx("tenant-a", "a1"))
    assert (client.lag, client.now()) == (timedelta(seconds=300), T0 + timedelta(hours=2))
    assert (await resolve(estate.ctx("tenant-b", "b1"))).lag == timedelta(seconds=900), "the source's default ingest lag"
    # Another tenant's alert or source is not there for this run: nothing is sent anywhere.
    before = len(estate.requests)
    for tenant, alert in (("tenant-b", "a1"), ("tenant-a", "b1"), ("tenant-c", "a1")):
        crossed = await tools.call(estate.ctx(tenant, alert), HOST_ACTIVITY, PARAMS, agent="investigation")
        assert (crossed.outcome, crossed.value.error) == ("failed", "no_wazuh_source")
    estate.alerts[("tenant-b", "b9")] = "src-a"  # an alert row naming the other tenant's source id
    stray = await tools.call(estate.ctx("tenant-b", "b9"), HOST_ACTIVITY, PARAMS, agent="investigation")
    assert stray.value.error == "no_wazuh_source" and len(estate.requests) == before
    await resolve.aclose()


async def test_why_a_call_cannot_be_answered_is_a_bounded_reason(estate: Estate, production: Settings, make_settings: Any) -> None:
    resolve = indexers(estate, production)

    async def reason(tenant: str, alert: str, using: Optional[WazuhIndexers] = None) -> str:
        with pytest.raises(IndexerUnavailable) as failed:
            await (using or resolve)(estate.ctx(tenant, alert))
        return failed.value.reason

    with pytest.raises(IndexerUnavailable) as failed:
        await resolve(Ctx())  # a run without repositories
    assert failed.value.reason == "not_configured"
    estate.add("t", "splunk", "s1", kind="splunk")
    estate.add("t", "disabled", "s2")
    estate.sources[("t", "s2")] = estate.sources[("t", "s2")].model_copy(update={"enabled": False})
    assert [await reason("t", "splunk"), await reason("t", "disabled"), await reason("t", "unknown")] == ["no_wazuh_source"] * 3
    estate.add("t", "no-secret", "s3", secret=None)
    estate.add("t", "no-password", "s4", secret={"username": "reader"})
    estate.add("t", "copied", "s5")
    estate.sources[("t", "s5")] = estate.sources[("t", "s5")].model_copy(
        update={"secret_ciphertext": estate.sources[("t", "s2")].secret_ciphertext})  # another source's ciphertext
    assert [await reason("t", a) for a in ("no-secret", "no-password", "copied")] == ["credentials_missing"] * 3
    assert await reason("t", "disabled", WazuhIndexers(production, None)) == "no_wazuh_source"
    estate.add("t", "keyless", "s6")
    assert await reason("t", "keyless", WazuhIndexers(production, None, deps=estate.deps())) == "credentials_missing"
    for n, config in enumerate((
        {"index": "wazuh-alerts-*/_delete_by_query"}, {"base_url": "ftp://indexer.example"}, {"base_url": None},
        {"base_url": "https://indexer.t.example:9200/_all/_delete_by_query?q="}, {"base_url": "https://indexer.t.example:9200/proxy"},
        {"max_event_lag_s": -1}, {"max_event_lag_s": "soon"}, {"tls_verify": "no"},
    )):
        estate.add("t", f"bad{n}", f"bad{n}", **config)
        assert await reason("t", f"bad{n}") == "source_misconfigured", config
    # The install's destination rules hold as they do for the pull source.
    estate.add("t", "listed", "s7")
    allow_listed = make_settings(ingestion={"allowed_destination_hosts": ["siem.other.example"]})
    assert await reason("t", "listed", indexers(estate, allow_listed)) == "destination_refused"
    assert estate.requests == [], "nothing was sent"
    await resolve.aclose()


async def test_one_client_per_source_rebuilt_when_the_source_changes(estate: Estate, production: Settings) -> None:
    estate.add("t", "a1", "s1")
    estate.add("t", "a2", "s1")
    estate.add("t", "a3", "s2")
    resolve = indexers(estate, production, max_clients=2)
    first = await resolve(estate.ctx("t", "a1"))
    assert await resolve(estate.ctx("t", "a2")) is first, "two alerts of one source share its client"
    other = await resolve(estate.ctx("t", "a3"))
    assert other is not first
    # The source's index changes: the next call gets a client for the new pattern, and the old one is closed.
    estate.add("t", "a1", "s1", index="wazuh-alerts-new-*")
    rebuilt = await resolve(estate.ctx("t", "a1"))
    assert rebuilt is not first and "wazuh-alerts-new-*" in repr(rebuilt)
    # A third source: the least recently used client goes.
    estate.add("t", "a4", "s3")
    await resolve(estate.ctx("t", "a4"))
    assert await resolve(estate.ctx("t", "a1")) is rebuilt and await resolve(estate.ctx("t", "a3")) is not other
    await resolve.aclose()
    assert await resolve(estate.ctx("t", "a1")) is not rebuilt
    await resolve.aclose()
