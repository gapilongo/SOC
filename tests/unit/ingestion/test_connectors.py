from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

import httpx
import pytest

from lg_sotf.ingestion.errors import (
    SourceAuthError,
    SourceConfigError,
    SourceNotPullable,
    SourceProtocolError,
    SourceUnavailable,
)
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, FetchedPage, PullConnector, create_connector
from lg_sotf.ingestion.sources.base import iso
from lg_sotf.settings import Settings
from tests.fixtures.vendors import vendor_events
from tests.unit.ingestion._support import NOW, FakeClock, make_source, public_resolver

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(ingestion={"page_size": 2, "overlap_s": 300, "http_max_retries": 2})


def build(
    settings: Settings,
    source_type: str,
    config: Dict[str, Any],
    credentials: Dict[str, Any],
    handler: Handler,
    clock: Optional[FakeClock] = None,
    cursor: Optional[Dict[str, Any]] = None,
    now: datetime = NOW,
) -> PullConnector:
    source = make_source(source_type, config, cursor=cursor)
    deps = ConnectorDeps(
        transport=httpx.MockTransport(handler),
        sleep=(clock or FakeClock()).sleep,
        now=lambda: now,
        rand=lambda: 0.0,
        resolver=public_resolver,
    )
    return create_connector(
        source, credentials, settings=settings, options=IngestionOptions.from_settings(settings), deps=deps
    )


async def collect(
    connector: PullConnector, cursor: Optional[Dict[str, Any]] = None
) -> Tuple[List[FetchedPage], Optional[BaseException]]:
    pages: List[FetchedPage] = []
    try:
        async for page in connector.pages(cursor):
            pages.append(page)
    except Exception as exc:  # noqa: BLE001 - the test inspects what was yielded before the failure
        return pages, exc
    finally:
        await connector.aclose()
    return pages, None


def body(request: httpx.Request) -> Dict[str, Any]:
    return json.loads(request.content) if request.content else {}


def form(request: httpx.Request) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def ts(value: datetime) -> float:
    return value.timestamp()


# -- splunk ----------------------------------------------------------------------


class SplunkServer:
    def __init__(self, events: List[Dict[str, Any]], *, fail_results_after: Optional[int] = None):
        self.events = events
        self.jobs_created: List[Dict[str, str]] = []
        self.status_calls = 0
        self.deleted: List[str] = []
        self.result_calls = 0
        self.fail_results_after = fail_results_after
        self.expired: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer splunk-token"
        path = request.url.path
        if request.method == "POST" and path == "/services/search/jobs":
            self.jobs_created.append(form(request))
            return httpx.Response(201, json={"sid": f"sid-{len(self.jobs_created)}"})
        if request.method == "DELETE":
            self.deleted.append(path.rsplit("/", 1)[-1])
            return httpx.Response(200, json={})
        if path.endswith("/results"):
            sid = path.split("/")[-2]
            if sid in self.expired:
                return httpx.Response(404, json={"messages": []})
            self.result_calls += 1
            if self.fail_results_after is not None and self.result_calls > self.fail_results_after:
                return httpx.Response(503)
            offset = int(request.url.params["offset"])
            count = int(request.url.params["count"])
            return httpx.Response(200, json={"results": self.events[offset : offset + count]})
        if path.startswith("/services/search/jobs/"):
            self.status_calls += 1
            state = "RUNNING" if self.status_calls == 1 else "DONE"
            return httpx.Response(200, json={"entry": [{"content": {"dispatchState": state}}]})
        if path == "/services/server/info":
            return httpx.Response(200, json={"entry": [{"content": {"version": "9.2.1"}}]})
        return httpx.Response(404)


def splunk_events(n: int) -> List[Dict[str, Any]]:
    base = ts(NOW) - 600
    return [
        {"event_id": f"e{i}", "rule_title": f"r{i}", "urgency": "high", "lgsotf_indextime": str(int(base + i))}
        for i in range(n)
    ]


SPLUNK = {"base_url": "https://splunk.example.com:8089"}
SPLUNK_CREDS = {"token": "splunk-token"}


async def test_splunk_pages_through_a_job_and_advances_cursor(settings: Settings) -> None:
    server = SplunkServer(splunk_events(5))
    clock = FakeClock()
    conn = build(settings, "splunk", SPLUNK, SPLUNK_CREDS, server, clock)
    since = NOW - timedelta(hours=1)
    pages, error = await collect(conn, {"v": 1, "since": since.isoformat()})
    assert error is None
    assert [len(p.events) for p in pages] == [2, 2, 1]
    assert [e["event_id"] for p in pages for e in p.events] == [f"e{i}" for i in range(5)]
    job = server.jobs_created[0]
    assert float(job["index_earliest"]) == pytest.approx(ts(since) - 300)
    assert float(job["index_latest"]) == pytest.approx(ts(NOW))
    assert "lgsotf_indextime" in job["search"] and job["search"].startswith("search `notable`")
    assert pages[0].cursor["job"] == {"sid": "sid-1", "offset": 2, "until": NOW.isoformat(),
                                      "newest": (NOW - timedelta(seconds=599)).isoformat()}
    assert pages[0].watermark == since
    assert pages[-1].cursor == {"v": 1, "since": (NOW - timedelta(seconds=300)).isoformat().replace("+00:00", "Z")}
    assert "job" not in pages[-1].cursor
    assert server.deleted == ["sid-1"]
    assert clock.sleeps == [1.0]


async def test_splunk_resumes_a_job_from_the_cursor(settings: Settings) -> None:
    server = SplunkServer(splunk_events(3))
    conn = build(settings, "splunk", SPLUNK, SPLUNK_CREDS, server)
    cursor = {"v": 1, "since": "2024-03-05T11:00:00Z", "job": {"sid": "sid-9", "offset": 2, "until": NOW.isoformat()}}
    pages, error = await collect(conn, cursor)
    assert error is None
    assert server.jobs_created == []
    assert [e["event_id"] for p in pages for e in p.events] == ["e2"]


async def test_splunk_reruns_an_expired_job(settings: Settings) -> None:
    server = SplunkServer(splunk_events(3))
    server.expired.add("sid-9")
    conn = build(settings, "splunk", SPLUNK, SPLUNK_CREDS, server)
    cursor = {"v": 1, "since": "2024-03-05T11:00:00Z", "job": {"sid": "sid-9", "offset": 2, "until": NOW.isoformat()}}
    pages, error = await collect(conn, cursor)
    assert error is None
    assert len(server.jobs_created) == 1
    assert [e["event_id"] for p in pages for e in p.events] == ["e0", "e1", "e2"]


async def test_splunk_outage_mid_job_stops_after_last_good_page(settings: Settings) -> None:
    server = SplunkServer(splunk_events(5), fail_results_after=1)
    conn = build(settings, "splunk", SPLUNK, SPLUNK_CREDS, server)
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceUnavailable)
    assert len(pages) == 1
    assert pages[0].cursor["job"]["offset"] == 2


async def test_splunk_basic_auth_and_test(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"].startswith("Basic ")
        return httpx.Response(200, json={"entry": [{"content": {"version": "9.2.1"}}]})

    conn = build(settings, "splunk", SPLUNK, {"username": "u", "password": "p"}, handler)
    health = await conn.test()
    assert health.ok and "9.2.1" in health.detail
    await conn.aclose()


def test_splunk_requires_credentials(settings: Settings) -> None:
    with pytest.raises(SourceConfigError):
        build(settings, "splunk", SPLUNK, {}, lambda r: httpx.Response(200))


@pytest.mark.parametrize("key", ["max_event_lag_s", "search_timeout_s"])
@pytest.mark.parametrize("value", [None, "300", True, -1, float("nan"), float("inf"), 1e12])
def test_splunk_rejects_bad_numeric_config(settings: Settings, key: str, value: Any) -> None:
    # A null crashed with TypeError (HTTP 500); NaN made the job wait poll forever.
    with pytest.raises(SourceConfigError, match=key):
        build(settings, "splunk", {**SPLUNK, key: value}, SPLUNK_CREDS, lambda r: httpx.Response(200))


# -- sentinel --------------------------------------------------------------------


SENTINEL = {"workspace_id": "11111111-2222-3333-4444-555555555555", "azure_tenant_id": "contoso.onmicrosoft.com"}
SENTINEL_CREDS = {"client_id": "app-id", "client_secret": "app-secret"}


def la_table(rows: List[List[Any]]) -> Dict[str, Any]:
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "lgsotf_ingestion_time", "type": "datetime"},
                    {"name": "SystemAlertId", "type": "string"},
                    {"name": "AlertName", "type": "string"},
                ],
                "rows": rows,
            }
        ]
    }


class SentinelServer:
    def __init__(self, pages: List[List[List[Any]]], reject_first_token: bool = False):
        self.pages = pages
        self.queries: List[Dict[str, Any]] = []
        self.tokens = 0
        self.reject_first_token = reject_first_token

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            assert request.url.path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
            f = form(request)
            assert f["scope"] == "https://api.loganalytics.io/.default"
            assert f["client_secret"] == "app-secret"
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"t{self.tokens}", "expires_in": 3599})
        assert request.url.path == "/v1/workspaces/11111111-2222-3333-4444-555555555555/query"
        if self.reject_first_token and request.headers["Authorization"] == "Bearer t1":
            return httpx.Response(401)
        self.queries.append(body(request))
        return httpx.Response(200, json=la_table(self.pages[len(self.queries) - 1]))


async def test_sentinel_keyset_pages(settings: Settings) -> None:
    server = SentinelServer(
        [
            [["2024-03-05T11:50:00.1234567Z", "a1", "x"], ["2024-03-05T11:50:00.1234567Z", "a'2", "y"]],
            [["2024-03-05T11:55:00Z", "a3", "z"]],
        ]
    )
    conn = build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, server)
    since = NOW - timedelta(minutes=30)
    pages, error = await collect(conn, {"v": 1, "since": since.isoformat()})
    assert error is None
    assert [e["SystemAlertId"] for p in pages for e in p.events] == ["a1", "a'2", "a3"]
    first, second = server.queries
    assert "SecurityAlert" in first["query"] and "| take 2" in first["query"]
    assert "| extend lgsotf_ingestion_time = ingestion_time()" in first["query"]
    assert "lgsotf_ingestion_time > datetime(2024-03-05T11:25:00Z)" in first["query"]
    assert "| order by lgsotf_ingestion_time asc, SystemAlertId asc" in first["query"]
    # TimeGenerated is only bounded max_event_lag_s (default one day) before the window.
    assert "TimeGenerated > datetime(2024-03-04T11:25:00Z)" in first["query"]
    assert first["timespan"] == "2024-03-04T11:25:00Z/2024-03-05T13:00:00Z"
    assert "lgsotf_ingestion_time > datetime(2024-03-05T11:50:00.1234567Z)" in second["query"]
    assert "SystemAlertId > 'a\\'2'" in second["query"]
    assert pages[0].cursor["query"]["after"] == ["2024-03-05T11:50:00.1234567Z", "a'2"]
    assert pages[0].watermark == since
    assert pages[-1].watermark == NOW - timedelta(minutes=5)
    assert server.tokens == 1


async def test_sentinel_refreshes_token_on_401(settings: Settings) -> None:
    server = SentinelServer([[]], reject_first_token=True)
    conn = build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, server)
    pages, error = await collect(conn, None)
    assert error is None and len(pages) == 1 and pages[0].events == []
    assert server.tokens == 2


async def test_sentinel_partial_results_are_an_error(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
        return httpx.Response(200, json={**la_table([]), "error": {"code": "PartialError"}})

    conn = build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, handler)
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceProtocolError) and pages == []


async def test_sentinel_rejects_a_suspicious_timestamp_for_kql(settings: Settings) -> None:
    injected = "2024-03-05T11:50:00Z) | union X"
    server = SentinelServer([[["2024-03-05T11:49:00Z", "a1", "x"], [injected, "a2", "y"]], []])
    conn = build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, server)
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceProtocolError)
    assert len(pages) == 1 and len(server.queries) == 1


def test_sentinel_config_validation(settings: Settings) -> None:
    with pytest.raises(SourceConfigError):
        build(settings, "sentinel", {**SENTINEL, "table": "Heartbeat"}, SENTINEL_CREDS, lambda r: httpx.Response(200))
    with pytest.raises(SourceConfigError):
        build(settings, "sentinel", {**SENTINEL, "workspace_id": "x/../y"}, SENTINEL_CREDS, lambda r: httpx.Response(200))


def _kql_bound(query: str, pattern: str) -> datetime:
    match = re.search(pattern, query)
    assert match, (pattern, query)
    return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))


class LateArrivalWorkspace:
    """Evaluates the connector's window filters over rows with separate event and ingestion times."""

    def __init__(self, rows: List[Tuple[str, datetime, datetime]]):
        self.rows = rows  # (id, TimeGenerated, ingestion time)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
        query = body(request)["query"]
        generated_lo = _kql_bound(query, r"TimeGenerated > datetime\(([^)]+)\)")
        ingest_lo = _kql_bound(query, r"lgsotf_ingestion_time > datetime\(([^)]+)\) and")
        ingest_hi = _kql_bound(query, r"lgsotf_ingestion_time <= datetime\(([^)]+)\)")
        rows = [
            [ingested.isoformat().replace("+00:00", "Z"), rid, f"alert {rid}"]
            for rid, generated, ingested in self.rows
            if generated > generated_lo and ingest_lo < ingested <= ingest_hi
        ]
        return httpx.Response(200, json=la_table(rows))


async def test_sentinel_picks_up_rows_that_arrive_late(settings: Settings) -> None:
    # Generated at 11:00 but only ingested at 12:03, after the 12:00 poll ran.
    workspace = LateArrivalWorkspace([("late-1", NOW - timedelta(hours=1), NOW + timedelta(minutes=3))])
    first, error = await collect(
        build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, workspace), {"v": 1, "since": iso(NOW - timedelta(minutes=5))}
    )
    assert error is None and [e for p in first for e in p.events] == []
    second, error = await collect(
        build(settings, "sentinel", SENTINEL, SENTINEL_CREDS, workspace, now=NOW + timedelta(minutes=5)),
        first[-1].cursor,
    )
    assert error is None
    assert [e["SystemAlertId"] for p in second for e in p.events] == ["late-1"]
    assert second[-1].watermark == NOW + timedelta(minutes=3)


def test_sentinel_max_event_lag_validation(settings: Settings) -> None:
    with pytest.raises(SourceConfigError):
        build(settings, "sentinel", {**SENTINEL, "max_event_lag_s": -1}, SENTINEL_CREDS, lambda r: httpx.Response(200))


# -- crowdstrike -----------------------------------------------------------------


class FalconServer:
    def __init__(self, alerts: List[Dict[str, Any]], *, rate_limit_once: bool = False, drop_detail: bool = False):
        self.alerts = alerts
        self.tokens = 0
        self.queries: List[Dict[str, str]] = []
        self.rate_limit_once = rate_limit_once
        self.drop_detail = drop_detail

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            self.tokens += 1
            return httpx.Response(201, json={"access_token": "cs-token", "expires_in": 1799, "token_type": "bearer"})
        assert request.headers["Authorization"] == "Bearer cs-token"
        if request.url.path == "/alerts/queries/alerts/v2":
            if self.rate_limit_once:
                self.rate_limit_once = False
                return httpx.Response(429, headers={"Retry-After": "1"}, json={"errors": [{"code": 429}]})
            params = dict(request.url.params)
            self.queries.append(params)
            offset, limit = int(params["offset"]), int(params["limit"])
            ids = [a["composite_id"] for a in self.alerts[offset : offset + limit]]
            return httpx.Response(
                200,
                json={"meta": {"pagination": {"offset": offset, "limit": limit, "total": len(self.alerts)}},
                      "resources": ids, "errors": []},
            )
        if request.url.path == "/alerts/entities/alerts/v2":
            ids = body(request)["composite_ids"]
            found = [a for a in self.alerts if a["composite_id"] in ids]
            if self.drop_detail:
                found = found[:-1]
            return httpx.Response(200, json={"resources": list(reversed(found)), "errors": []})
        return httpx.Response(404)


def falcon_alerts(n: int) -> List[Dict[str, Any]]:
    template = vendor_events("crowdstrike_alerts")[0]
    out = []
    for i in range(n):
        alert = dict(template)
        alert["composite_id"] = f"cid:ind:{i}"
        alert["created_timestamp"] = (NOW - timedelta(minutes=10 - i)).isoformat()
        out.append(alert)
    return out


CS_CREDS = {"client_id": "cs-id", "client_secret": "cs-secret"}


async def test_crowdstrike_offset_paging_and_detail_order(settings: Settings) -> None:
    server = FalconServer(falcon_alerts(3), rate_limit_once=True)
    clock = FakeClock()
    conn = build(settings, "crowdstrike", {"filter": "product:'epp'"}, CS_CREDS, server, clock)
    pages, error = await collect(conn, None)
    assert error is None
    assert [a["composite_id"] for p in pages for a in p.events] == ["cid:ind:0", "cid:ind:1", "cid:ind:2"]
    assert [q["offset"] for q in server.queries] == ["0", "2"]
    q = server.queries[0]
    assert q["sort"] == "created_timestamp.asc"
    assert q["filter"].startswith("created_timestamp:>='2024-03-05T10:55:00Z'+created_timestamp:<='2024-03-05T12:00:00Z'")
    assert q["filter"].endswith("+(product:'epp')")
    assert pages[0].cursor["query"]["offset"] == 2
    assert clock.sleeps == [1.0]
    assert server.tokens == 1
    assert pages[-1].watermark == NOW - timedelta(minutes=5)


async def test_crowdstrike_missing_details_do_not_advance(settings: Settings) -> None:
    server = FalconServer(falcon_alerts(2), drop_detail=True)
    conn = build(settings, "crowdstrike", {}, CS_CREDS, server)
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceProtocolError) and pages == []


async def test_crowdstrike_bad_credentials(settings: Settings) -> None:
    conn = build(settings, "crowdstrike", {}, CS_CREDS, lambda r: httpx.Response(401, json={}))
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceAuthError)


# -- wazuh -----------------------------------------------------------------------


class IndexerServer:
    def __init__(self, docs: List[Dict[str, Any]], failed_shards: int = 0):
        self.docs = docs
        self.requests: List[Dict[str, Any]] = []
        self.failed_shards = failed_shards

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"].startswith("Basic ")
        assert request.url.path == "/wazuh-alerts-*/_search"
        q = body(request)
        self.requests.append(q)
        start = 0
        if "search_after" in q:
            start = next(i for i, d in enumerate(self.docs) if d["sort"] == q["search_after"]) + 1
        hits = self.docs[start : start + q["size"]]
        return httpx.Response(
            200,
            json={"_shards": {"total": 1, "failed": self.failed_shards},
                  "hits": {"hits": [{"_id": h["id"], "_source": h["src"], "sort": h["sort"]} for h in hits]}},
        )


def wazuh_docs(n: int) -> List[Dict[str, Any]]:
    template = vendor_events("wazuh_alerts")[0]
    docs = []
    for i in range(n):
        t = int((NOW - timedelta(minutes=10 - i)).timestamp() * 1000)
        docs.append({"id": f"w{i}", "src": {**template, "id": f"w{i}"}, "sort": [t, f"w{i}"]})
    return docs


WAZUH = {"base_url": "https://indexer.example.com:9200", "min_level": 5}
WAZUH_CREDS = {"username": "reader", "password": "pw"}


async def test_wazuh_search_after_paging(settings: Settings) -> None:
    server = IndexerServer(wazuh_docs(4))
    conn = build(settings, "wazuh", WAZUH, WAZUH_CREDS, server)
    pages, error = await collect(conn, None)
    assert error is None
    assert [e["id"] for p in pages for e in p.events] == ["w0", "w1", "w2", "w3"]
    assert [len(p.events) for p in pages] == [2, 2, 0]
    assert "search_after" not in server.requests[0]
    assert server.requests[1]["search_after"] == server.docs[1]["sort"]
    assert {"range": {"rule.level": {"gte": 5}}} in server.requests[0]["query"]["bool"]["filter"]
    assert pages[0].cursor["query"]["after"][1] == "w1"


async def test_wazuh_failed_shards_are_an_error(settings: Settings) -> None:
    conn = build(settings, "wazuh", WAZUH, WAZUH_CREDS, IndexerServer(wazuh_docs(1), failed_shards=1))
    pages, error = await collect(conn, None)
    assert isinstance(error, SourceProtocolError) and pages == []


class RangeIndexer:
    """Applies the query's range filter on its time field; records the queries."""

    def __init__(self, docs: List[Dict[str, Any]]):
        self.docs = docs
        self.requests: List[Dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        q = body(request)
        self.requests.append(q)
        field, bounds = next(iter(q["query"]["bool"]["filter"][0]["range"].items()))
        lo = datetime.fromisoformat(bounds["gt"].replace("Z", "+00:00"))
        hi = datetime.fromisoformat(bounds["lte"].replace("Z", "+00:00"))
        hits = [d for d in self.docs if lo < d[field] <= hi]
        return httpx.Response(200, json={"_shards": {"failed": 0}, "hits": {"hits": [
            {"_id": d["id"], "_source": {"id": d["id"]}, "sort": [int(d[field].timestamp() * 1000), d["id"]]}
            for d in hits
        ]}})


async def test_wazuh_lag_window_keeps_late_documents(settings: Settings) -> None:
    # Raised at 11:50, indexed only after the previous poll had moved the cursor to 11:58.
    indexer = RangeIndexer([{"id": "late", "timestamp": NOW - timedelta(minutes=10)}])
    cursor = {"v": 1, "since": iso(NOW - timedelta(minutes=2))}
    pages, error = await collect(build(settings, "wazuh", WAZUH, WAZUH_CREDS, indexer), cursor)
    assert error is None and [e["id"] for p in pages for e in p.events] == ["late"]
    assert indexer.requests[0]["query"]["bool"]["filter"][0]["range"]["timestamp"]["gt"] == iso(
        NOW - timedelta(minutes=2, seconds=300 + 900)
    )

    no_lag = RangeIndexer(indexer.docs)
    pages, _ = await collect(build(settings, "wazuh", {**WAZUH, "max_event_lag_s": 0}, WAZUH_CREDS, no_lag), cursor)
    assert [e for p in pages for e in p.events] == []


async def test_wazuh_can_window_on_an_ingest_timestamp(settings: Settings) -> None:
    indexer = RangeIndexer([{"id": "a", "event.ingested": NOW - timedelta(minutes=1)}])
    config = {**WAZUH, "time_field": "event.ingested", "max_event_lag_s": 0}
    pages, error = await collect(build(settings, "wazuh", config, WAZUH_CREDS, indexer), None)
    assert error is None and [e["id"] for p in pages for e in p.events] == ["a"]
    assert indexer.requests[0]["sort"][0] == {"event.ingested": {"order": "asc"}}


def test_wazuh_config_validation(settings: Settings) -> None:
    with pytest.raises(SourceConfigError):
        build(settings, "wazuh", {**WAZUH, "index": "../_all"}, WAZUH_CREDS, lambda r: httpx.Response(200))
    with pytest.raises(SourceConfigError):
        build(settings, "wazuh", {**WAZUH, "time_field": "a b"}, WAZUH_CREDS, lambda r: httpx.Response(200))
    with pytest.raises(SourceConfigError):
        build(settings, "wazuh", {**WAZUH, "max_event_lag_s": True}, WAZUH_CREDS, lambda r: httpx.Response(200))
    with pytest.raises(SourceConfigError):
        build(settings, "wazuh", {**WAZUH, "min_level": "high"}, WAZUH_CREDS, lambda r: httpx.Response(200))


# -- qradar ----------------------------------------------------------------------


class QRadarServer:
    def __init__(self, offenses: List[Dict[str, Any]]):
        self.offenses = offenses
        self.requests: List[Tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["SEC"] == "qr-token"
        assert request.headers["Version"] == "20.0"
        fql = request.url.params["filter"]
        self.requests.append((fql, request.headers["Range"]))
        if fql.startswith("id > "):
            last = int(fql.split(">")[1])
            items = [o for o in self.offenses if o["id"] > last]
        else:
            floor = int(fql.split(">=")[1])
            items = [o for o in self.offenses if o["start_time"] >= floor]
        end = int(request.headers["Range"].split("-")[1])
        return httpx.Response(200, json=items[: end + 1])


async def test_qradar_id_keyset(settings: Settings) -> None:
    base = int((NOW - timedelta(minutes=30)).timestamp() * 1000)
    offenses = [{"id": 100 + i, "description": f"o{i}", "start_time": base + i * 1000} for i in range(3)]
    server = QRadarServer(offenses)
    conn = build(settings, "qradar", {"base_url": "https://qradar.example.com"}, {"token": "qr-token"}, server)
    pages, error = await collect(conn, None)
    assert error is None
    assert [o["id"] for p in pages for o in p.events] == [100, 101, 102]
    assert server.requests[0][0].startswith("start_time >= ")
    assert server.requests[1] == ("id > 101", "items=0-1")
    assert pages[-1].cursor["last_id"] == 102
    again = build(settings, "qradar", {"base_url": "https://qradar.example.com"}, {"token": "qr-token"}, server)
    pages2, _ = await collect(again, pages[-1].cursor)
    assert [p.events for p in pages2] == [[]]
    assert pages2[0].cursor["last_id"] == 102
    assert pages2[0].watermark >= pages[-1].watermark


# -- file ------------------------------------------------------------------------


async def test_file_source_reads_complete_lines(settings: Settings, tmp_path: Any) -> None:
    path = tmp_path / "alerts.jsonl"
    path.write_text('{"title": "a", "severity": "low"}\n\n{"title": "b", "severity": "low"}\n{"title": "c"')
    conn = build(settings, "file", {"path": str(path)}, {}, lambda r: httpx.Response(500))
    pages, error = await collect(conn, None)
    assert error is None
    assert [e["title"] for p in pages for e in p.events] == ["a", "b"]
    offset = pages[-1].cursor["offset"]
    with path.open("a") as fh:
        fh.write(', "severity": "low"}\nnot json\n')
    conn = build(settings, "file", {"path": str(path)}, {}, lambda r: httpx.Response(500))
    pages, _ = await collect(conn, pages[-1].cursor)
    events = [e for p in pages for e in p.events]
    assert events[0]["title"] == "c"
    assert "_lgsotf_unparsed_line" in events[1]
    assert pages[-1].cursor["offset"] > offset


def test_file_source_is_refused_in_production(make_settings: Callable[..., Settings], tmp_path: Any) -> None:
    prod = make_settings(environment="production")
    with pytest.raises(SourceConfigError):
        build(prod, "file", {"path": str(tmp_path / "x")}, {}, lambda r: httpx.Response(500))


def test_push_only_types_have_no_connector(settings: Settings) -> None:
    for source_type in ("webhook", "guardduty"):
        with pytest.raises(SourceNotPullable):
            build(settings, source_type, {}, {}, lambda r: httpx.Response(500))


def test_insecure_tls_is_refused_in_production(make_settings: Callable[..., Settings]) -> None:
    prod = make_settings(environment="production")
    with pytest.raises(SourceConfigError):
        build(prod, "qradar", {"base_url": "https://q.example.com", "tls_verify": False}, {"token": "t"},
              lambda r: httpx.Response(500))
