"""Splunk pull connector (REST search jobs API).

Config: ``base_url`` (management port, e.g. ``https://splunk.example.com:8089``),
``search`` (default ``search `notable```), ``max_event_lag_s`` (event time
may precede index time by at most this much, default 86400),
``search_timeout_s`` (default 300). Credentials: ``token`` (Splunk
authentication token, sent as a bearer token) or ``username``/``password``.

Windows are selected on index time (``index_earliest``/``index_latest``), so
events that arrive late are still picked up. Each poll creates a search job
and pages through its results with ``offset``/``count``; the cursor keeps the
job id and offset while a job is being paged, and a job that expired (404) is
re-run for the same window.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional
from urllib.parse import quote

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError, SourceRequestError, SourceUnavailable
from lg_sotf.ingestion.sources.base import FetchedPage, PullConnector, SourceHealth, window_cursor
from lg_sotf.ingestion.sources.http import BasicAuth, HeaderAuth, SourceHttpClient, json_mapping
from lg_sotf.ingestion.timeparse import parse_timestamp

INDEXTIME_FIELD = "lgsotf_indextime"
DEFAULT_SEARCH = "search `notable`"
STATUS_POLL_S = 1.0


class SplunkConnector(PullConnector):
    source_type = "splunk"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        search = self.config.get("search", DEFAULT_SEARCH)
        if not isinstance(search, str) or not search.strip():
            raise SourceConfigError("splunk config.search must be a non-empty SPL string")
        search = search.strip()
        if not search.startswith(("search ", "|")):
            search = f"search {search}"
        self._search = search
        self._max_lag_s = self.config_seconds("max_event_lag_s", 86_400, 0, 30 * 86_400)
        self._search_timeout_s = self.config_seconds("search_timeout_s", 300, 1, 3_600)
        if self.has_credential("token"):
            auth: Any = HeaderAuth({"Authorization": f"Bearer {self.credential('token')}"})
        else:
            auth = BasicAuth(self.credential("username"), self.credential("password"))
        self._http: SourceHttpClient = self.http(self.config_str("base_url"), auth)

    async def test(self) -> SourceHealth:
        body = json_mapping(await self._http.request("GET", "/services/server/info", params={"output_mode": "json"}),
                            "server info")
        entries = body.get("entry")
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], Mapping):
            raise SourceProtocolError("splunk server info response has no entry list")
        content = entries[0].get("content")
        version = content.get("version") if isinstance(content, Mapping) else None
        return SourceHealth(True, f"connected to Splunk {version or '(unknown version)'}")

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        since = self.cursor_since(cursor)
        job = cursor.get("job") if cursor else None
        sid: Optional[str] = None
        offset = 0
        newest: Optional[datetime] = None
        if isinstance(job, Mapping) and job.get("sid") and job.get("until"):
            until = parse_timestamp(job["until"]).value or self.deps.now()
            sid, offset = str(job["sid"]), int(job.get("offset", 0))
            newest = parse_timestamp(job.get("newest")).value if job.get("newest") else None
        else:
            until = self.deps.now()
        page_size = self.options.page_size
        while True:
            if sid is None:
                sid = await self._start_job(since, until)
                offset = 0
            try:
                results = await self._results(sid, offset, page_size)
            except SourceRequestError as exc:
                if exc.status_code == 404 and offset > 0:
                    # The job expired between polls: re-run the same window from the start.
                    sid = None
                    continue
                raise
            for row in results:
                t = parse_timestamp(row.get(INDEXTIME_FIELD)).value
                if t is not None and (newest is None or t > newest):
                    newest = t
            offset += len(results)
            if len(results) < page_size:
                drained = self.drained_since(since, until, newest)
                yield FetchedPage(results, window_cursor(drained), drained)
                await self._delete_job(sid)
                return
            yield FetchedPage(
                results,
                window_cursor(
                    since,
                    job={"sid": sid, "offset": offset, "until": until.isoformat(),
                         "newest": newest.isoformat() if newest else None},
                ),
                since,
            )

    async def _start_job(self, since: datetime, until: datetime) -> str:
        lo = since - self.overlap
        search = f"{self._search} | eval {INDEXTIME_FIELD}=_indextime | sort 0 {INDEXTIME_FIELD}"
        resp = await self._http.request(
            "POST",
            "/services/search/jobs",
            data={
                "search": search,
                "index_earliest": f"{lo.timestamp():.3f}",
                "index_latest": f"{until.timestamp():.3f}",
                "earliest_time": f"{lo.timestamp() - self._max_lag_s:.3f}",
                "latest_time": "now",
                "exec_mode": "normal",
                "output_mode": "json",
            },
        )
        sid = json_mapping(resp, "search job").get("sid")
        if not isinstance(sid, str) or not sid:
            raise SourceProtocolError("splunk did not return a search job id")
        await self._wait(sid)
        return sid

    async def _wait(self, sid: str) -> None:
        waited = 0.0
        while True:
            resp = await self._http.request("GET", f"/services/search/jobs/{quote(sid, safe='')}", params={"output_mode": "json"})
            entries = json_mapping(resp, "search job status").get("entry")
            first_entry = entries[0] if isinstance(entries, list) and entries else None
            content = first_entry.get("content") if isinstance(first_entry, Mapping) else None
            if not isinstance(content, Mapping):
                raise SourceProtocolError("splunk search job status response has no content")
            state = content.get("dispatchState")
            if state == "DONE" or content.get("isDone") is True:
                return
            if state == "FAILED" or content.get("isFailed") is True:
                raise SourceProtocolError("splunk search job failed")
            if waited >= self._search_timeout_s:
                raise SourceUnavailable(f"splunk search job did not finish within {self._search_timeout_s:.0f}s")
            await self.deps.sleep(STATUS_POLL_S)
            waited += STATUS_POLL_S

    async def _results(self, sid: str, offset: int, count: int) -> List[Dict[str, Any]]:
        resp = await self._http.request(
            "GET",
            f"/services/search/v2/jobs/{quote(sid, safe='')}/results",
            params={"output_mode": "json", "offset": offset, "count": count},
        )
        results = json_mapping(resp, "search results").get("results", [])
        if not isinstance(results, list):
            raise SourceProtocolError("splunk results are not a list")
        return [r for r in results if isinstance(r, dict)]

    async def _delete_job(self, sid: str) -> None:
        try:
            await self._http.request("DELETE", f"/services/search/jobs/{quote(sid, safe='')}")
        except (SourceRequestError, SourceUnavailable):
            # Splunk expires jobs on its own (dispatch TTL); a failed cleanup changes nothing.
            return
