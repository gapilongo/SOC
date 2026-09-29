"""Microsoft Sentinel pull connector (Azure AD client credentials + Log Analytics query API).

Config: ``workspace_id``, ``azure_tenant_id``, ``table`` (``SecurityAlert``
default, or ``SecurityIncident``), ``authority_url`` (default
``https://login.microsoftonline.com``) and ``api_url`` (default
``https://api.loganalytics.io``) for sovereign clouds. Credentials:
``client_id`` and ``client_secret`` of an app registration with the Log
Analytics Reader role on the workspace.

Windows are selected on ingestion time (``ingestion_time()``, exposed as the
``lgsotf_ingestion_time`` column), not ``TimeGenerated``: a row that reaches
the workspace late still falls into the window that is open when it arrives.
``TimeGenerated`` is only bounded below by ``max_event_lag_s`` (default
86400) before the window, which keeps the scan cheap.

The query API has no server-side paging, so pages are keyset queries ordered
by ``(lgsotf_ingestion_time, id)``. The last row's time text is reused
verbatim (Log Analytics keeps 100 ns precision, Python only microseconds) and
validated before it is placed in KQL; ids are escaped as KQL string literals.
A response flagged as a partial result is an error, never a page.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional, Tuple

from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError
from lg_sotf.ingestion.sources.base import FetchedPage, PullConnector, SourceHealth, iso, window_cursor
from lg_sotf.ingestion.sources.http import OAuth2ClientCredentials, SourceHttpClient, json_mapping
from lg_sotf.ingestion.timeparse import parse_timestamp

TABLE_ID_COLUMN = {"SecurityAlert": "SystemAlertId", "SecurityIncident": "IncidentName"}
_KQL_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$")
_GUID = re.compile(r"^[0-9A-Za-z-]{1,64}$")
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
INGESTION_TIME_COLUMN = "lgsotf_ingestion_time"
DEFAULT_MAX_EVENT_LAG_S = 86_400
# TimeGenerated may run slightly ahead of ingestion time (source clock skew).
_TIMESPAN_SLACK = timedelta(hours=1)


def kql_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    return f"'{escaped}'"


def kql_datetime(text: str) -> str:
    if not _KQL_DATETIME.match(text):
        raise SourceProtocolError("sentinel returned an unexpected TimeGenerated format")
    return f"datetime({text})"


def rows_to_dicts(body: Mapping[str, Any]) -> List[Dict[str, Any]]:
    if body.get("error"):
        code = body["error"].get("code") if isinstance(body["error"], Mapping) else None
        raise SourceProtocolError(f"sentinel query returned an error ({code or 'unknown'})")
    tables = body.get("tables")
    if not isinstance(tables, list) or not tables:
        raise SourceProtocolError("sentinel query response has no tables")
    table = tables[0]
    columns = [c.get("name") for c in table.get("columns", []) if isinstance(c, Mapping)]
    rows = table.get("rows", [])
    names = [n for n in columns if isinstance(n, str)]
    if not isinstance(rows, list) or len(names) != len(columns):
        raise SourceProtocolError("sentinel query response is malformed")
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(names):
            raise SourceProtocolError("sentinel query row does not match its columns")
        out.append(dict(zip(names, row, strict=True)))
    return out


class SentinelConnector(PullConnector):
    source_type = "sentinel"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._workspace = self.config_str("workspace_id")
        if not _GUID.match(self._workspace):
            raise SourceConfigError("sentinel config.workspace_id must be a workspace GUID")
        directory = self.config_str("azure_tenant_id")
        if not _GUID.match(directory) and not re.match(r"^[A-Za-z0-9.-]{1,253}$", directory):
            raise SourceConfigError("sentinel config.azure_tenant_id must be a tenant GUID or domain")
        self._table = self.config.get("table", "SecurityAlert")
        if self._table not in TABLE_ID_COLUMN:
            raise SourceConfigError(f"sentinel config.table must be one of {', '.join(TABLE_ID_COLUMN)}")
        self._id_column = TABLE_ID_COLUMN[self._table]
        lag = self.config.get("max_event_lag_s", DEFAULT_MAX_EVENT_LAG_S)
        if isinstance(lag, bool) or not isinstance(lag, (int, float)) or not 0 <= lag <= 30 * 86_400:
            raise SourceConfigError("sentinel config.max_event_lag_s must be between 0 and 2592000 seconds")
        self._max_lag = timedelta(seconds=float(lag))
        authority = self.config_str("authority_url", "https://login.microsoftonline.com").rstrip("/")
        api_url = self.config_str("api_url", "https://api.loganalytics.io").rstrip("/")
        self._auth = OAuth2ClientCredentials(
            self.destination(f"{authority}/{directory}/oauth2/v2.0/token"),
            self.credential("client_id"),
            self.credential("client_secret"),
            scope=str(self.config.get("scope", LOG_ANALYTICS_SCOPE)),
        )
        self._http: SourceHttpClient = self.http(api_url, self._auth)

    async def test(self) -> SourceHealth:
        await self._query(f"{self._table} | take 0", None)
        return SourceHealth(True, f"queried {self._table} in workspace {self._workspace}")

    async def _query(self, kql: str, timespan: Optional[str]) -> List[Dict[str, Any]]:
        body: Dict[str, Any] = {"query": kql}
        if timespan:
            body["timespan"] = timespan
        resp = await self._http.request("POST", f"/v1/workspaces/{self._workspace}/query", json_body=body)
        return rows_to_dicts(json_mapping(resp, "query"))

    def _kql(self, lo: datetime, until: datetime, after: Optional[Tuple[str, str]], limit: int) -> str:
        col = INGESTION_TIME_COLUMN
        parts = [
            self._table,
            f"| where TimeGenerated > datetime({iso(lo - self._max_lag)})",
            f"| extend {col} = ingestion_time()",
            f"| where {col} > datetime({iso(lo)}) and {col} <= datetime({iso(until)})",
        ]
        if after is not None:
            t = kql_datetime(after[0])
            parts.append(f"| where {col} > {t} or ({col} == {t} and {self._id_column} > {kql_string(after[1])})")
        parts.append(f"| order by {col} asc, {self._id_column} asc")
        parts.append(f"| take {int(limit)}")
        return "\n".join(parts)

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        since = self.cursor_since(cursor)
        state = cursor.get("query") if cursor else None
        after: Optional[Tuple[str, str]] = None
        newest: Optional[datetime] = None
        if isinstance(state, Mapping) and state.get("until"):
            until = parse_timestamp(state["until"]).value or self.deps.now()
            raw_after = state.get("after")
            if isinstance(raw_after, list) and len(raw_after) == 2:
                after = (str(raw_after[0]), str(raw_after[1]))
                newest = parse_timestamp(after[0]).value
        else:
            until = self.deps.now()
        lo = since - self.overlap
        timespan = f"{iso(lo - self._max_lag)}/{iso(until + _TIMESPAN_SLACK)}"
        page_size = self.options.page_size
        while True:
            rows = await self._query(self._kql(lo, until, after, page_size), timespan)
            if rows:
                last = rows[-1]
                last_t, last_id = last.get(INGESTION_TIME_COLUMN), last.get(self._id_column)
                if not isinstance(last_t, str) or last_id is None:
                    raise SourceProtocolError(f"sentinel rows lack {INGESTION_TIME_COLUMN} or {self._id_column}")
                after = (last_t, str(last_id))
                parsed = parse_timestamp(last_t).value
                if parsed is not None and (newest is None or parsed > newest):
                    newest = parsed
            if len(rows) < page_size:
                drained = self.drained_since(since, until, newest)
                yield FetchedPage(rows, window_cursor(drained), drained)
                return
            assert after is not None
            yield FetchedPage(
                rows, window_cursor(since, query={"until": iso(until), "after": [after[0], after[1]]}), since
            )
