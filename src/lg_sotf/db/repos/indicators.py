"""Indicator sightings: the correlation index (hashed indicator -> alerts)."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import Connection, Record, Repository, require_aware, to_models, truncate
from lg_sotf.security.shadow import egress, sink

MAX_DISPLAY_CHARS = 256
MAX_QUERY_INDICATORS = 500
MAX_RELATED_ALERTS = 500

Sighting = Tuple[str, str, Optional[str], datetime]
"""``(indicator_type, value_hash, value_display, seen_at)``."""


class IndicatorSighting(Record):
    tenant_id: str
    indicator_type: str
    value_hash: str
    value_display: Optional[str]
    alert_id: str
    seen_at: datetime


class RelatedAlert(Record):
    alert_id: str
    shared_indicator_count: int
    last_seen: datetime


class IndicatorsRepo(Repository):
    @egress("indicator_sighting", sink(lambda a: 0, detail=lambda a: {"sightings": len(a["sightings"])}))
    async def add_sightings(
        self,
        tenant_id: str,
        alert_id: str,
        sightings: Sequence[Sighting],
        *,
        conn: Optional[Connection] = None,
    ) -> int:
        """Record indicators seen in an alert; repeats are ignored. Returns rows inserted.

        ``value_display`` must already be redacted; it is truncated here.
        """
        latest: Dict[Tuple[str, str], Tuple[Optional[str], datetime]] = {}
        for indicator_type, value_hash, display, seen_at in sightings:
            require_aware(seen_at, "seen_at")
            key = (indicator_type, value_hash)
            if key not in latest or seen_at > latest[key][1]:
                latest[key] = (truncate(display, MAX_DISPLAY_CHARS), seen_at)
        if not latest:
            return 0
        types = [k[0] for k in latest]
        hashes = [k[1] for k in latest]
        displays = [v[0] for v in latest.values()]
        seen = [v[1] for v in latest.values()]
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                INSERT INTO indicator_sightings (tenant_id, indicator_type, value_hash, value_display, alert_id, seen_at)
                SELECT $1, u.t, u.h, u.d, $2, u.s
                FROM unnest($3::text[], $4::text[], $5::text[], $6::timestamptz[]) AS u(t, h, d, s)
                ON CONFLICT (tenant_id, alert_id, indicator_type, value_hash) DO NOTHING
                """,
                tenant_id,
                alert_id,
                types,
                hashes,
                displays,
                seen,
            )
        return int(status.split()[-1])

    async def related_alerts(
        self,
        tenant_id: str,
        indicators: Sequence[Tuple[str, str]],
        *,
        since: datetime,
        until: Optional[datetime] = None,
        limit: int = 20,
        exclude_alert_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> List[RelatedAlert]:
        """Alerts sharing any of ``indicators`` (type, value_hash) seen since ``since`` (and before ``until``).

        Ordered by number of shared indicators, then recency. ``until`` gives a
        point-in-time view (the history backtest).
        """
        require_aware(since, "since")
        require_aware(until, "until")
        check_limit(limit, MAX_RELATED_ALERTS)
        unique = list(dict.fromkeys(indicators))[:MAX_QUERY_INDICATORS]
        if not unique:
            return []
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT s.alert_id,
                       count(*)::int AS shared_indicator_count,
                       max(s.seen_at) AS last_seen
                FROM unnest($2::text[], $3::text[]) AS q(t, h)
                JOIN indicator_sightings s
                  ON s.tenant_id = $1 AND s.indicator_type = q.t AND s.value_hash = q.h
                WHERE s.seen_at >= $4
                  AND ($5::text IS NULL OR s.alert_id <> $5)
                  AND ($7::timestamptz IS NULL OR s.seen_at < $7)
                GROUP BY s.alert_id
                ORDER BY shared_indicator_count DESC, last_seen DESC, s.alert_id
                LIMIT $6
                """,
                tenant_id,
                [i[0] for i in unique],
                [i[1] for i in unique],
                since,
                exclude_alert_id,
                limit,
                until,
            )
        return to_models(RelatedAlert, rows)

    async def sightings_for_alert(
        self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None
    ) -> List[IndicatorSighting]:
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM indicator_sightings
                WHERE tenant_id = $1 AND alert_id = $2
                ORDER BY indicator_type, value_hash
                """,
                tenant_id,
                alert_id,
            )
        return to_models(IndicatorSighting, rows)
