"""The client for a tenant's Wazuh indexer (INT3.4): one request shape, the destination policy, bounded failures."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.errors import SourceConfigError
from lg_sotf.ingestion.sources import wazuh as wazuh_source
from lg_sotf.net.egress import DestinationPolicy, DestinationRefused
from lg_sotf.net.http import guarded_client
from lg_sotf.security.shadow import EGRESS_POINTS, ShadowRun, shadow_scope
from lg_sotf.tools.wazuh import indexer, templates
from lg_sotf.tools.wazuh.indexer import IndexerClient, IndexerUnavailable
from lg_sotf.tools.wazuh.templates import HostActivityParams, PrevalenceParams
from lg_sotf.tools.wazuh.tools import HOST_ACTIVITY, PREVALENCE
from tests.unit.ingestion._support import MapResolver, public_resolver
from tests.unit.tools._support import Ctx
from tests.unit.tools.wazuh._support import over

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
URL = "https://indexer.customer.example:9200"
EMPTY = {"timed_out": False, "_shards": {"total": 1, "failed": 0}, "hits": {"hits": []},
         "aggregations": {"total": {"value": 0}, "oldest": {"value": 1.7e12}}}
BODY = templates.host_activity(HostActivityParams(host="SRV-01", at=T0, before_min=5, after_min=5))
PASSWORD = "test-only-" + "p" * 12
Server = Callable[[httpx.Request], Any]


def client(server: Server, **overrides: Any) -> IndexerClient:
    settings: Dict[str, Any] = {
        "base_url": URL, "index": "wazuh-alerts-*", "username": "lgsotf-reader", "password": PASSWORD,
        "policy": DestinationPolicy(require_https=True), "transport": httpx.MockTransport(server),
        "resolver": public_resolver, "now": lambda: T0 + timedelta(hours=1),
    }
    return IndexerClient(**{**settings, **overrides})


def answering(seen: List[httpx.Request], status: int = 200, **kwargs: Any) -> Server:
    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, **(kwargs or {"json": EMPTY}))

    return server


async def test_the_client_only_posts_a_search_to_the_tenants_index() -> None:
    seen: List[httpx.Request] = []
    indexer_client = client(answering(seen), index="wazuh-alerts-4.x-acme-*", lag=timedelta(seconds=900))
    assert await indexer_client.search(BODY) == EMPTY
    assert await indexer_client.search(templates.coverage()) == EMPTY
    await indexer_client.search(templates.prevalence(PrevalenceParams(kind="service_name", value="_all/_delete_by_query", days=1), T0))
    for request in seen:
        assert (request.method, str(request.url)) == ("POST", f"{URL}/wazuh-alerts-4.x-acme-*/_search")
        assert request.headers["authorization"] == "Basic " + base64.b64encode(f"lgsotf-reader:{PASSWORD}".encode()).decode()
        assert request.headers["user-agent"] == "lg-sotf-evidence/1" and request.headers["content-type"] == "application/json"
    assert json.loads(seen[0].content) == BODY and len(seen) == 3
    assert (indexer_client.lag, indexer_client.now()) == (timedelta(seconds=900), T0 + timedelta(hours=1))
    assert PASSWORD not in repr(indexer_client) and "lgsotf-reader" not in repr(indexer_client)
    await indexer_client.aclose()
    await indexer_client.aclose()


@pytest.mark.parametrize(
    "index", ["", "Wazuh-Alerts-*", "wazuh-alerts-*/_delete_by_query", "../_all", "_all", "a b", "wazuh-alerts-*?expand_wildcards=all",
              "wazuh\n", "x" * 256],
)
def test_an_index_that_is_not_a_name_or_pattern_is_refused(index: str) -> None:
    with pytest.raises(SourceConfigError):
        client(answering([]), index=index)


def test_the_index_rule_is_the_pull_sources_rule_and_the_boundary_is_registered() -> None:
    assert indexer.INDEX.pattern == wazuh_source._INDEX.pattern
    point = EGRESS_POINTS["lg_sotf.tools.wazuh.indexer:IndexerClient.search"]
    assert (point.boundary, point.policy.action) == ("wazuh_indexer", "allow") and "POST _search only" in point.policy.reason
    for missing in ({"username": ""}, {"password": ""}):
        with pytest.raises(SourceConfigError):
            client(answering([]), **missing)


@pytest.mark.parametrize(
    ("status", "reason"),
    [(401, "credentials_refused"), (403, "credentials_refused"), (404, "index_not_found"), (429, "rate_limited"),
     (400, "request_refused"), (500, "indexer_error"), (503, "indexer_error")],
)
async def test_a_refusing_indexer_is_a_bounded_reason_and_is_not_asked_again(status: int, reason: str) -> None:
    seen: List[httpx.Request] = []
    secret_body = {"error": {"reason": "no permissions for [indices:data/read/search] and User [name=lgsotf-reader]"}}
    refusing = client(answering(seen, status, json=secret_body, headers={"Retry-After": "1"}))
    with pytest.raises(IndexerUnavailable) as failed:
        await refusing.search(BODY)
    assert (failed.value.reason, str(failed.value), len(seen)) == (reason, reason, 1)
    # Through the registry: failed, with the reason and nothing of the indexer's text.
    result = await over(refusing).call(Ctx(), HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 5, "after_min": 5}, agent="a")
    assert (result.outcome, result.value.error, result.complete, len(seen)) == ("failed", reason, False, 2)
    await refusing.aclose()


@pytest.mark.parametrize(
    ("server", "reason"),
    [
        (lambda request: (_ for _ in ()).throw(httpx.ConnectError("connection refused")), "unreachable"),
        (lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "timeout"),
        (lambda request: httpx.Response(200, text="<html>proxy login</html>"), "bad_response"),
        (lambda request: httpx.Response(200, json=[EMPTY]), "bad_response"),
        (lambda request: httpx.Response(302, headers={"Location": "https://198.51.100.9/"}), "bad_response"),
        (lambda request: httpx.Response(200, json={**EMPTY, "_shards": {"total": 0, "failed": 0}}), "index_not_found"),
        (lambda request: httpx.Response(200, content=b"x", headers={"Content-Length": str(64 * 1024 * 1024)}), "response_too_large"),
    ],
    ids=["down", "slow", "not json", "not an object", "a redirect is not followed", "the pattern matches no index", "too large"],
)
async def test_an_unreachable_or_broken_indexer_is_failed_with_a_reason(server: Server, reason: str) -> None:
    calls: List[httpx.Request] = []

    def counting(request: httpx.Request) -> Any:
        calls.append(request)
        return server(request)

    down = client(counting)
    with pytest.raises(IndexerUnavailable) as failed:
        await down.search(BODY)
    assert (failed.value.reason, len(calls)) == (reason, 1), "one request: a failed search is never retried"
    result = await over(down).call(Ctx(), PREVALENCE, {"kind": "service_name", "value": "svc", "days": 7}, agent="a")
    assert (result.outcome, result.value.error, tuple(result.value)) == ("failed", reason, ())
    await down.aclose()


async def test_the_destination_policy_holds_for_the_indexer() -> None:
    seen: List[httpx.Request] = []
    with pytest.raises(SourceConfigError):  # plain http where https is required
        client(answering(seen), base_url="http://indexer.customer.example:9200")
    with pytest.raises(DestinationRefused):  # the install's egress allow-list does not name the host
        client(answering(seen), policy=DestinationPolicy(require_https=True, allowed_hosts=frozenset({"other.example"})))
    with pytest.raises(SourceConfigError):
        client(answering(seen), base_url="https://user:pass@indexer.customer.example:9200")
    for address in ("127.0.0.1", "169.254.169.254", "10.0.0.5"):  # loopback, cloud metadata, a private network
        resolver = MapResolver({"indexer.customer.example": [address]})
        inside = client(answering(seen), resolver=resolver)
        with pytest.raises(IndexerUnavailable) as failed:
            await inside.search(BODY)
        assert failed.value.reason == "destination_refused" and resolver.lookups == ["indexer.customer.example"]
        await inside.aclose()
    assert seen == [], "nothing was sent"
    private = client(answering(seen), resolver=MapResolver({"indexer.customer.example": ["10.0.0.5"]}),
                     policy=DestinationPolicy(require_https=True, allow_private=True))
    assert await private.search(BODY) == EMPTY and len(seen) == 1  # an on-premises install that allows private destinations
    await private.aclose()


async def test_at_most_two_searches_run_at_once() -> None:
    running, peak, release = 0, 0, asyncio.Event()

    async def server(request: httpx.Request) -> httpx.Response:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await release.wait()
        running -= 1
        return httpx.Response(200, json=EMPTY)

    busy = client(server)
    searches = [asyncio.create_task(busy.search(BODY)) for _ in range(6)]
    for _ in range(20):
        await asyncio.sleep(0)
    assert (running, peak) == (2, 2)
    release.set()
    assert await asyncio.gather(*searches) == [EMPTY] * 6 and peak == 2
    await busy.aclose()


async def test_a_shadow_run_reads_the_tenants_indexer_and_the_tool_crosses_no_other_boundary() -> None:
    """The tools' shadow rule (ADR 0014 section 3.2): a read of the tenant's own system runs in a shadow run too."""
    seen: List[httpx.Request] = []
    live = client(answering(seen))
    params = {"host": "SRV-01", "at": T0, "before_min": 5, "after_min": 5}
    with shadow_scope(ShadowRun("shadow/int34")) as run:
        result = await over(live).call(Ctx(), HOST_ACTIVITY, params, agent="a")
    assert (result.outcome, result.complete) == ("empty", True) and len(seen) == 2  # the search and the coverage search
    assert run.sink.effects == (), "nothing was diverted or refused: the read is the tenant's own, and declared"
    await live.aclose()

    class Elsewhere:
        """A backend that tries the general HTTP stack: not the boundary the tools declared."""

        lag = timedelta(0)

        def now(self) -> datetime:
            return T0

        async def search(self, body: Any) -> Any:
            http = guarded_client(policy=None, verify=True, user_agent="x", timeout=httpx.Timeout(1.0),
                                  transport=httpx.MockTransport(answering(seen)), pin=False)
            return (await http.post("https://third-party.example/collect", json=body)).json()

    before = len(seen)
    for scope in (None, ShadowRun("shadow/int34-2")):
        if scope is None:
            strayed = await over(Elsewhere()).call(Ctx(), HOST_ACTIVITY, params, agent="a")
        else:
            with shadow_scope(scope):
                strayed = await over(Elsewhere()).call(Ctx(), HOST_ACTIVITY, params, agent="a")
        assert (strayed.outcome, strayed.reason, strayed.value.error) == ("failed", "error:EgressNotDeclared", "error")
    assert len(seen) == before
