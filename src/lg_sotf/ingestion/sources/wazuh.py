"""Wazuh pull connector (Wazuh indexer / OpenSearch search API).

The Wazuh manager API does not serve alerts; they are read from the indexer.
Config: ``base_url`` (e.g. ``https://wazuh-indexer:9200``), ``index``
(default ``wazuh-alerts-*``), ``min_level`` (lowest ``rule.level``, default
0). Credentials: ``username``/``password`` of an indexer user with read
access to the alert indices.

Windows and paging use ``time_field`` (default ``timestamp``, the time the
manager raised the alert) with ``search_after`` on ``(time_field, id)``; a
response with failed shards is incomplete and treated as an error.

Documents can reach the indexer well after their ``timestamp`` (a Filebeat
backlog after an indexer outage). To keep those, either point
``time_field`` at an indexer-side ingest timestamp set by an ingest pipeline
(for example ``event.ingested`` via a ``set`` processor with
``{{_ingest.timestamp}}``), which is the robust option, or rely on
``max_event_lag_s`` (default 900): each window's lower bound is moved back by
that much, so documents that arrive up to that late are still read (repeats
are absorbed by deduplication). Documents later than that are missed when
``time_field`` is an event time.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional
from urllib.parse import quote

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError
from lg_sotf.ingestion.sources.base import FetchedPage, PullConnector, SourceHealth, iso, window_cursor
from lg_sotf.ingestion.sources.http import BasicAuth, SourceHttpClient, json_mapping
from lg_sotf.ingestion.timeparse import parse_timestamp

_INDEX = re.compile(r"^[a-z0-9*][a-z0-9*_.,-]{0,254}$")
_FIELD = re.compile(r"^[A-Za-z@_][A-Za-z0-9@_.]{0,127}$")
DEFAULT_TIME_FIELD = "timestamp"
DEFAULT_MAX_EVENT_LAG_S = 900


class WazuhConnector(PullConnector):
    source_type = "wazuh"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        index = self.config_str("index", "wazuh-alerts-*")
        if not _INDEX.match(index):
            raise SourceConfigError("wazuh config.index must be an index name or pattern")
        self._index = quote(index, safe="*,")
        level = self.config.get("min_level", 0)
        if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
            raise SourceConfigError("wazuh config.min_level must be an integer between 0 and 16")
        self._min_level = level
        time_field = self.config_str("time_field", DEFAULT_TIME_FIELD)
        if not _FIELD.match(time_field):
            raise SourceConfigError("wazuh config.time_field must be a field name")
        self._time_field = time_field
        lag = self.config.get("max_event_lag_s", DEFAULT_MAX_EVENT_LAG_S)
        if isinstance(lag, bool) or not isinstance(lag, (int, float)) or not 0 <= lag <= 7 * 86_400:
            raise SourceConfigError("wazuh config.max_event_lag_s must be between 0 and 604800 seconds")
        self._max_lag = timedelta(seconds=float(lag))
        self._http: SourceHttpClient = self.http(
            self.config_str("base_url"), BasicAuth(self.credential("username"), self.credential("password"))
        )

    async def test(self) -> SourceHealth:
        body = json_mapping(await self._http.request("GET", f"/{self._index}/_count"), "count")
        return SourceHealth(True, f"indexer reachable; {body.get('count', 'unknown')} alerts in {self._index}")

    def _query(self, lo: datetime, until: datetime, after: Optional[List[Any]]) -> Dict[str, Any]:
        filters: List[Dict[str, Any]] = [{"range": {self._time_field: {"gt": iso(lo), "lte": iso(until)}}}]
        if self._min_level:
            filters.append({"range": {"rule.level": {"gte": self._min_level}}})
        query: Dict[str, Any] = {
            "size": self.options.page_size,
            "sort": [{self._time_field: {"order": "asc"}}, {"id": {"order": "asc", "unmapped_type": "keyword"}}],
            "query": {"bool": {"filter": filters}},
            "track_total_hits": False,
        }
        if after is not None:
            query["search_after"] = after
        return query

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        since = self.cursor_since(cursor)
        state = cursor.get("query") if cursor else None
        after: Optional[List[Any]] = None
        newest: Optional[datetime] = None
        if isinstance(state, Mapping) and state.get("until"):
            until = parse_timestamp(state["until"]).value or self.deps.now()
            if isinstance(state.get("after"), list):
                after = list(state["after"])
                newest = parse_timestamp(after[0]).value if after else None
        else:
            until = self.deps.now()
        lo = since - self.overlap - self._max_lag
        while True:
            resp = await self._http.request("POST", f"/{self._index}/_search", json_body=self._query(lo, until, after))
            body = json_mapping(resp, "search")
            shards = body.get("_shards") or {}
            if isinstance(shards, Mapping) and shards.get("failed"):
                raise SourceProtocolError(f"wazuh search had {shards.get('failed')} failed shards")
            hits = (body.get("hits") or {}).get("hits")
            if not isinstance(hits, list):
                raise SourceProtocolError("wazuh search response has no hits list")
            events: List[Dict[str, Any]] = []
            for hit in hits:
                source = hit.get("_source") if isinstance(hit, Mapping) else None
                if isinstance(source, dict):
                    events.append(source)
            if hits:
                sort_values = hits[-1].get("sort") if isinstance(hits[-1], Mapping) else None
                if not isinstance(sort_values, list) or not sort_values:
                    raise SourceProtocolError("wazuh hits lack sort values")
                after = sort_values
                t = parse_timestamp(sort_values[0]).value
                if t is not None and (newest is None or t > newest):
                    newest = t
            if len(hits) < self.options.page_size:
                drained = self.drained_since(since, until, newest)
                yield FetchedPage(events, window_cursor(drained), drained)
                return
            yield FetchedPage(events, window_cursor(since, query={"until": iso(until), "after": after}), since)
