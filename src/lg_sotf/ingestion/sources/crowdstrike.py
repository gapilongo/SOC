"""CrowdStrike Falcon pull connector (Alerts API v2).

Config: ``base_url`` (cloud API host, default ``https://api.crowdstrike.com``;
``api.us-2.crowdstrike.com``, ``api.eu-1.crowdstrike.com``,
``api.laggar.gcw.crowdstrike.com``), optional ``filter`` (extra FQL ANDed to
the time window) and ``member_cid`` (MSSP child CID). Credentials:
``client_id`` and ``client_secret`` of an API client with Alerts: Read.

``/alerts/queries/alerts/v2`` returns ids for a fixed window sorted by
``created_timestamp`` with ``offset`` paging; the full alerts come from
``/alerts/entities/alerts/v2``. The API refuses offsets beyond 10,000, so
long windows are re-anchored at the newest timestamp seen.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError
from lg_sotf.ingestion.sources.base import FetchedPage, PullConnector, SourceHealth, iso, window_cursor
from lg_sotf.ingestion.sources.http import OAuth2ClientCredentials, SourceHttpClient, json_mapping
from lg_sotf.ingestion.timeparse import parse_timestamp

MAX_OFFSET = 10_000
MAX_PAGE = 1_000
QUERY_PATH = "/alerts/queries/alerts/v2"
ENTITIES_PATH = "/alerts/entities/alerts/v2"


def _fql_time(value: datetime) -> str:
    return iso(value)


class CrowdStrikeConnector(PullConnector):
    source_type = "crowdstrike"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        extra_filter = self.config.get("filter")
        if extra_filter is not None and (not isinstance(extra_filter, str) or len(extra_filter) > 2_000):
            raise SourceConfigError("crowdstrike config.filter must be an FQL string of at most 2000 characters")
        self._extra_filter = extra_filter.strip() if extra_filter else None
        base_url = self.config_str("base_url", "https://api.crowdstrike.com").rstrip("/")
        member_cid = self.config.get("member_cid")
        self._auth = OAuth2ClientCredentials(
            self.destination(f"{base_url}/oauth2/token"),
            self.credential("client_id"),
            self.credential("client_secret"),
            extra_form={"member_cid": str(member_cid)} if member_cid else None,
        )
        self._http: SourceHttpClient = self.http(base_url, self._auth)
        self._page_size = min(self.options.page_size, MAX_PAGE)

    async def test(self) -> SourceHealth:
        await self._http.request("GET", QUERY_PATH, params={"limit": 1})
        return SourceHealth(True, "authenticated and listed alerts")

    def _filter(self, lo: datetime, until: datetime) -> str:
        fql = f"created_timestamp:>='{_fql_time(lo)}'+created_timestamp:<='{_fql_time(until)}'"
        if self._extra_filter:
            fql = f"{fql}+({self._extra_filter})"
        return fql

    async def _ids(self, lo: datetime, until: datetime, offset: int) -> tuple[List[str], Optional[int]]:
        resp = await self._http.request(
            "GET",
            QUERY_PATH,
            params={
                "filter": self._filter(lo, until),
                "sort": "created_timestamp.asc",
                "limit": self._page_size,
                "offset": offset,
            },
        )
        body = json_mapping(resp, "alert query")
        _raise_errors(body)
        ids = body.get("resources") or []
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise SourceProtocolError("crowdstrike alert query returned malformed resources")
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
        return ids, total if isinstance(total, int) else None

    async def _details(self, ids: List[str]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        resp = await self._http.request("POST", ENTITIES_PATH, json_body={"composite_ids": ids})
        body = json_mapping(resp, "alert details")
        _raise_errors(body)
        resources = [r for r in body.get("resources") or [] if isinstance(r, dict)]
        by_id = {r.get("composite_id"): r for r in resources}
        missing = [i for i in ids if i not in by_id]
        if missing:
            # An alert listed a moment ago that cannot be fetched now would be lost if the cursor moved on.
            raise SourceProtocolError(f"crowdstrike returned {len(missing)} of {len(ids)} alerts without details")
        return [by_id[i] for i in ids]

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        since = self.cursor_since(cursor)
        state = cursor.get("query") if cursor else None
        newest: Optional[datetime] = None
        if isinstance(state, Mapping) and state.get("until") and state.get("lo"):
            until = parse_timestamp(state["until"]).value or self.deps.now()
            lo = parse_timestamp(state["lo"]).value or (since - self.overlap)
            offset = int(state.get("offset", 0))
            newest = parse_timestamp(state.get("newest")).value if state.get("newest") else None
        else:
            until = self.deps.now()
            lo = since - self.overlap
            offset = 0
        while True:
            if offset + self._page_size > MAX_OFFSET:
                if newest is None or newest <= lo:
                    raise SourceProtocolError("crowdstrike has more than 10000 alerts at one timestamp")
                lo, offset = newest, 0
            ids, total = await self._ids(lo, until, offset)
            alerts = await self._details(ids)
            for alert in alerts:
                t = parse_timestamp(alert.get("created_timestamp")).value
                if t is not None and (newest is None or t > newest):
                    newest = t
            offset += len(ids)
            done = len(ids) < self._page_size or (total is not None and offset >= total)
            if done:
                drained = self.drained_since(since, until, newest)
                yield FetchedPage(alerts, window_cursor(drained), drained)
                return
            yield FetchedPage(
                alerts,
                window_cursor(
                    since,
                    query={"until": iso(until), "lo": iso(lo), "offset": offset,
                           "newest": iso(newest) if newest else None},
                ),
                since,
            )


def _raise_errors(body: Mapping[str, Any]) -> None:
    errors = body.get("errors")
    if isinstance(errors, list) and errors:
        codes = sorted({str(e.get("code")) for e in errors if isinstance(e, Mapping)})
        raise SourceProtocolError(f"crowdstrike API reported errors (codes {', '.join(codes) or 'unknown'})")
