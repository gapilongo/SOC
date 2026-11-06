"""Helpers shared by the ingestion tests (and the e2e recovery and scheduler tests): scripted pull sources."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional

import httpx

from lg_sotf.db.repos import Source
from lg_sotf.ingestion.errors import SourceUnavailable
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import FetchedPage, PullConnector, SourceHealth
from lg_sotf.settings import Settings

T0 = datetime(2024, 3, 5, 10, 0, tzinfo=UTC)


def page(n0: int, n: int, *, watermark_min: int) -> FetchedPage:
    events = [{"event_id": f"e{i}", "rule_title": f"event {i}", "urgency": "high"} for i in range(n0, n0 + n)]
    wm = T0 + timedelta(minutes=watermark_min)
    return FetchedPage(events, {"v": 1, "since": wm.isoformat(), "page": watermark_min}, wm)


class ScriptedConnector(PullConnector):
    """Yields scripted pages; ``fail_after`` raises an outage after that many pages."""

    source_type = "splunk"

    def __init__(self, source: Source, pages: List[FetchedPage], *, settings: Settings, fail_after: Optional[int] = None):
        super().__init__(source, {}, settings=settings, options=IngestionOptions.from_settings(settings))
        self.scripted = pages
        self.fail_after = fail_after
        self.seen_cursors: List[Optional[Mapping[str, Any]]] = []
        self.closed = False

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        self.seen_cursors.append(cursor)
        for i, p in enumerate(self.scripted):
            if self.fail_after is not None and i >= self.fail_after:
                raise SourceUnavailable("splunk GET /services/search/v2/jobs/x/results returned HTTP 503")
            yield p

    async def test(self) -> SourceHealth:
        return SourceHealth(True, "ok")

    async def aclose(self) -> None:
        self.closed = True


class QRadarMock:
    def __init__(self, offenses: List[Dict[str, Any]], token: str = "qr-secret-token"):  # noqa: S107 - mock server credential
        self.offenses = offenses
        self.token = token
        self.filters: List[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("SEC") != self.token:
            return httpx.Response(401, json={"message": "bad token"})
        if request.url.path == "/api/system/about":
            return httpx.Response(200, json={"external_version": "7.5.0"})
        fql = request.url.params["filter"]
        self.filters.append(fql)
        items = self.offenses if fql.startswith("start_time") else [
            o for o in self.offenses if o["id"] > int(fql.split(">")[1])
        ]
        end = int(request.headers["Range"].split("-")[1])
        return httpx.Response(200, json=items[: end + 1])
