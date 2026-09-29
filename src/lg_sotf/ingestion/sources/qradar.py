"""IBM QRadar pull connector (``GET /api/siem/offenses``).

Config: ``base_url`` (console URL), ``api_version`` (default ``20.0``).
Credentials: ``token`` (an authorized service token, sent as the ``SEC``
header).

Offense ids increase monotonically, so the cursor is the highest id
committed (``id > last_id``, sorted by id, ``Range: items=0-N``). No overlap
window is needed for an id watermark. The first poll starts from offenses
created within ``initial_lookback_s``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError
from lg_sotf.ingestion.sources.base import CURSOR_VERSION, FetchedPage, PullConnector, SourceHealth, iso
from lg_sotf.ingestion.sources.http import HeaderAuth, SourceHttpClient
from lg_sotf.ingestion.timeparse import parse_timestamp


class QRadarConnector(PullConnector):
    source_type = "qradar"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        version = str(self.config.get("api_version", "20.0"))
        if not version.replace(".", "").isdigit():
            raise SourceConfigError("qradar config.api_version must look like 20.0")
        self._http: SourceHttpClient = self.http(
            self.config_str("base_url"),
            HeaderAuth({"SEC": self.credential("token")}),
            headers={"Version": version, "Accept": "application/json"},
        )

    async def test(self) -> SourceHealth:
        resp = await self._http.request("GET", "/api/system/about")
        body = resp.json()
        version = body.get("external_version") if isinstance(body, Mapping) else None
        return SourceHealth(True, f"connected to QRadar {version or '(unknown version)'}")

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        last_id = cursor.get("last_id") if cursor else None
        if last_id is not None and (isinstance(last_id, bool) or not isinstance(last_id, int)):
            raise SourceProtocolError("stored qradar cursor is malformed")
        watermark = parse_timestamp(cursor.get("since")).value if cursor and cursor.get("since") else None
        start_floor = self.initial_since()
        if watermark is None:
            watermark = start_floor
        page_size = self.options.page_size
        while True:
            if last_id is None:
                fql = f"start_time >= {int(start_floor.timestamp() * 1000)}"
            else:
                fql = f"id > {int(last_id)}"
            resp = await self._http.request(
                "GET",
                "/api/siem/offenses",
                params={"filter": fql, "sort": "+id"},
                headers={"Range": f"items=0-{page_size - 1}"},
            )
            offenses = resp.json()
            if not isinstance(offenses, list):
                raise SourceProtocolError("qradar offenses response is not a list")
            events: List[Dict[str, Any]] = [o for o in offenses if isinstance(o, dict)]
            for offense in events:
                oid = offense.get("id")
                if isinstance(oid, int) and not isinstance(oid, bool) and (last_id is None or oid > last_id):
                    last_id = oid
                started = parse_timestamp(offense.get("start_time")).value
                if started is not None and started > watermark:
                    watermark = started
            page_cursor: Dict[str, Any] = {"v": CURSOR_VERSION, "since": iso(watermark)}
            if last_id is not None:
                page_cursor["last_id"] = last_id
            yield FetchedPage(events, page_cursor, _not_future(watermark, self.deps.now()))
            if len(offenses) < page_size:
                return


def _not_future(value: datetime, now: datetime) -> datetime:
    return min(value, now)
