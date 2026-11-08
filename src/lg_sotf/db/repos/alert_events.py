"""Alert timeline events (partitioned, append-only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lg_sotf.db.pagination import Page, check_limit, decode_cursor_bigint, paginate
from lg_sotf.db.repos._base import Connection, Record, Repository, check_choice, fetch_one, require_aware, to_models
from lg_sotf.security.shadow import egress, sink

EVENT_ACTOR_TYPES = ("system", "user", "agent")


class AlertEvent(Record):
    id: int
    tenant_id: str
    alert_id: str
    ts: datetime
    node: Optional[str]
    event_type: str
    actor_type: str
    actor_id: Optional[str]
    data: Dict[str, Any]


class NewAlertEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_type: str = Field(min_length=1, max_length=128)
    node: Optional[str] = None
    actor_type: str = "system"
    actor_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    ts: Optional[datetime] = None

    @field_validator("actor_type")
    @classmethod
    def _actor(cls, v: str) -> str:
        return check_choice(v, EVENT_ACTOR_TYPES, "actor type")

    @field_validator("ts")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return require_aware(v, "ts")


class AlertEventsRepo(Repository):
    @egress("alert_event", sink(detail=lambda a: {"event_type": a["event_type"]}))
    async def append(
        self,
        tenant_id: str,
        alert_id: str,
        event_type: str,
        *,
        node: Optional[str] = None,
        actor_type: str = "system",
        actor_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        ts: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> AlertEvent:
        event = NewAlertEvent(
            alert_id=alert_id,
            event_type=event_type,
            node=node,
            actor_type=actor_type,
            actor_id=actor_id,
            data=dict(data or {}),
            ts=ts,
        )
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO alert_events (tenant_id, alert_id, ts, node, event_type, actor_type, actor_id, data)
                VALUES ($1, $2, COALESCE($3::timestamptz, clock_timestamp()), $4, $5, $6, $7, $8)
                RETURNING *
                """,
                tenant_id,
                event.alert_id,
                event.ts,
                event.node,
                event.event_type,
                event.actor_type,
                event.actor_id,
                event.data,
            )
        return AlertEvent.model_validate(dict(row))

    async def append_many(
        self, tenant_id: str, events: Sequence[NewAlertEvent], *, conn: Optional[Connection] = None
    ) -> int:
        if not events:
            return 0
        payload = [e.model_dump(mode="json") for e in events]
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                INSERT INTO alert_events (tenant_id, alert_id, ts, node, event_type, actor_type, actor_id, data)
                SELECT $1, e.alert_id, COALESCE(e.ts, clock_timestamp()), e.node, e.event_type,
                       e.actor_type, e.actor_id, COALESCE(e.data, '{}'::jsonb)
                FROM ROWS FROM (
                    jsonb_to_recordset($2::jsonb) AS (
                        alert_id text, ts timestamptz, node text, event_type text,
                        actor_type text, actor_id text, data jsonb
                    )
                ) WITH ORDINALITY AS e(alert_id, ts, node, event_type, actor_type, actor_id, data, ord)
                ORDER BY e.ord
                """,
                tenant_id,
                payload,
            )
        return int(status.split()[-1])

    async def list_for_alert(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[AlertEvent]:
        """Chronological timeline (oldest first), keyset-paginated over (ts, id)."""
        check_limit(limit)
        after_ts: Optional[datetime] = None
        after_id: Optional[int] = None
        if cursor:
            after_ts, after_id = decode_cursor_bigint(cursor)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM alert_events
                WHERE tenant_id = $1 AND alert_id = $2
                  AND ($3::timestamptz IS NULL OR (ts, id) > ($3::timestamptz, $4::bigint))
                ORDER BY ts, id
                LIMIT $5
                """,
                tenant_id,
                alert_id,
                after_ts,
                after_id,
                limit + 1,
            )
        return paginate(to_models(AlertEvent, rows), limit, lambda e: (e.ts, e.id))
