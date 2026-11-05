"""Alert sources (SIEM/EDR/cloud connectors) and their polling state."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

import asyncpg
from pydantic import Field

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.pagination import Params
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    require_aware,
    set_clauses,
    to_model,
    to_models,
    truncate,
)

SOURCE_TYPES = (
    "splunk", "qradar", "sentinel", "wazuh", "crowdstrike", "guardduty", "webhook", "file", "m365_mailbox", "imap"
)
PUSH_SOURCE_TYPES = ("webhook", "guardduty")
SOURCE_HEALTH = ("unknown", "healthy", "degraded", "failing")

FAILING_AFTER = 3
DEFAULT_MAX_BACKOFF_S = 3_600
MAX_ERROR_CHARS = 2_000


class Source(Record):
    id: str
    tenant_id: str
    type: str
    name: str
    enabled: bool
    config: Dict[str, Any]
    secret_ciphertext: Optional[str] = Field(default=None, repr=False)
    poll_interval_s: int
    cursor: Optional[Dict[str, Any]]
    cursor_watermark: Optional[datetime]
    last_polled_at: Optional[datetime]
    next_poll_at: Optional[datetime]
    consecutive_failures: int
    last_error: Optional[str]
    health: str
    created_at: datetime
    updated_at: datetime


class SourcesRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        type: str,  # noqa: A002 - the sources.type column
        name: str,
        *,
        source_id: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        secret_ciphertext: Optional[str] = None,
        poll_interval_s: int = 60,
        enabled: bool = True,
        conn: Optional[Connection] = None,
    ) -> Source:
        """Create a source. ``source_id`` (optional, else a UUID) is unique within the tenant only."""
        check_choice(type, SOURCE_TYPES, "source type")
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    """
                    INSERT INTO sources (id, tenant_id, type, name, enabled, config, secret_ciphertext, poll_interval_s)
                    VALUES (COALESCE($1, gen_random_uuid()::text), $2, $3, $4, $5, $6, $7, $8)
                    RETURNING *
                    """,
                    source_id,
                    tenant_id,
                    type,
                    name,
                    enabled,
                    dict(config or {}),
                    secret_ciphertext,
                    poll_interval_s,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("this tenant already has a source with this id or name") from exc
        return Source.model_validate(dict(row))

    async def get(self, tenant_id: str, source_id: str, *, conn: Optional[Connection] = None) -> Source:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM sources WHERE tenant_id = $1 AND id = $2", tenant_id, source_id)
        source = to_model(Source, row)
        if source is None:
            raise NotFound("source", source_id)
        return source

    async def list(
        self,
        tenant_id: str,
        *,
        enabled: Optional[bool] = None,
        type: Optional[str] = None,  # noqa: A002 - the sources.type column
        conn: Optional[Connection] = None,
    ) -> List[Source]:
        if type is not None:
            check_choice(type, SOURCE_TYPES, "source type")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM sources
                WHERE tenant_id = $1
                  AND ($2::boolean IS NULL OR enabled = $2)
                  AND ($3::text IS NULL OR type = $3)
                ORDER BY name
                """,
                tenant_id,
                enabled,
                type,
            )
        return to_models(Source, rows)

    async def update(
        self,
        tenant_id: str,
        source_id: str,
        *,
        name: str = UNSET,
        enabled: bool = UNSET,
        config: Mapping[str, Any] = UNSET,
        secret_ciphertext: Optional[str] = UNSET,
        poll_interval_s: int = UNSET,
        conn: Optional[Connection] = None,
    ) -> Source:
        params = Params(tenant_id, source_id)
        sets = set_clauses(
            {
                "name": name,
                "enabled": enabled,
                "config": dict(config) if config is not UNSET else UNSET,
                "secret_ciphertext": secret_ciphertext,
                "poll_interval_s": poll_interval_s,
            },
            params,
        )
        if poll_interval_s is not UNSET or enabled is not UNSET:
            sets.append("next_poll_at = NULL")
        if not sets:
            return await self.get(tenant_id, source_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    f"UPDATE sources SET {', '.join(sets)} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
                    *params.values,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("this tenant already has a source with this name") from exc
        source = to_model(Source, row)
        if source is None:
            raise NotFound("source", source_id)
        return source

    async def delete(self, tenant_id: str, source_id: str, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute("DELETE FROM sources WHERE tenant_id = $1 AND id = $2", tenant_id, source_id)
        return status.endswith(" 1")

    async def set_cursor(
        self,
        tenant_id: str,
        source_id: str,
        cursor: Mapping[str, Any],
        watermark: datetime,
        *,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Persist a polling cursor, only ever moving it forward.

        ``watermark`` is the source event time the cursor represents. The
        write is skipped (returns False) if a later watermark is already
        stored, so a slow poller cannot rewind the cursor.
        """
        require_aware(watermark, "watermark")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE sources SET cursor = $3, cursor_watermark = $4
                WHERE tenant_id = $1 AND id = $2
                  AND (cursor_watermark IS NULL OR cursor_watermark <= $4)
                """,
                tenant_id,
                source_id,
                dict(cursor),
                watermark,
            )
            if status.endswith(" 1"):
                return True
            exists = await c.fetchval("SELECT 1 FROM sources WHERE tenant_id = $1 AND id = $2", tenant_id, source_id)
        if exists is None:
            raise NotFound("source", source_id)
        return False

    async def record_poll_result(
        self,
        tenant_id: str,
        source_id: str,
        *,
        ok: bool,
        error: Optional[str] = None,
        polled_at: Optional[datetime] = None,
        next_poll_at: Optional[datetime] = None,
        max_backoff_s: int = DEFAULT_MAX_BACKOFF_S,
        conn: Optional[Connection] = None,
    ) -> Source:
        """Update health and schedule the next poll.

        Without an explicit ``next_poll_at``, success schedules one interval
        ahead; failure backs off exponentially (``interval * 2**failures``,
        capped at ``max_backoff_s``). ``error`` must already be free of secrets.
        """
        require_aware(polled_at, "polled_at")
        require_aware(next_poll_at, "next_poll_at")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                WITH p AS (SELECT COALESCE($5::timestamptz, now()) AS at)
                UPDATE sources s SET
                    last_polled_at = p.at,
                    consecutive_failures = CASE WHEN $3 THEN 0 ELSE s.consecutive_failures + 1 END,
                    last_error = CASE WHEN $3 THEN NULL ELSE $4 END,
                    health = CASE WHEN $3 THEN 'healthy'
                                  WHEN s.consecutive_failures + 1 >= $8 THEN 'failing'
                                  ELSE 'degraded' END,
                    next_poll_at = COALESCE($6::timestamptz, p.at + make_interval(secs => CASE
                        WHEN $3 THEN s.poll_interval_s::double precision
                        ELSE LEAST(s.poll_interval_s * power(2, LEAST(s.consecutive_failures + 1, 20)), $7)
                    END))
                FROM p
                WHERE s.tenant_id = $1 AND s.id = $2
                RETURNING s.*
                """,
                tenant_id,
                source_id,
                ok,
                None if ok else truncate(error or "unknown error", MAX_ERROR_CHARS),
                polled_at,
                next_poll_at,
                float(max_backoff_s),
                FAILING_AFTER,
            )
        source = to_model(Source, row)
        if source is None:
            raise NotFound("source", source_id)
        return source

    async def list_due_sources_all_tenants(self, *, now: Optional[datetime] = None, limit: int = 100) -> List[Source]:
        """Enabled pull sources of active tenants whose next poll is due.

        Tenants that used up today's ``max_alerts_per_day`` quota are left out:
        their cursors stay put and the events are fetched on the next UTC day.
        """
        require_aware(now, "now")
        async with self._system() as c:
            rows = await c.fetch(
                """
                SELECT s.* FROM sources s
                JOIN tenants t ON t.id = s.tenant_id
                WHERE s.enabled
                  AND t.status = 'active'
                  AND (t.max_alerts_per_day IS NULL OR COALESCE((
                        SELECT u.alerts_ingested FROM usage_daily u
                        WHERE u.tenant_id = t.id AND u.day = (now() AT TIME ZONE 'UTC')::date
                      ), 0) < t.max_alerts_per_day)
                  AND s.type <> ALL($1::text[])
                  AND (s.next_poll_at IS NULL OR s.next_poll_at <= COALESCE($2::timestamptz, now()))
                ORDER BY s.next_poll_at NULLS FIRST, s.tenant_id, s.id
                LIMIT $3
                """,
                list(PUSH_SOURCE_TYPES),
                now,
                limit,
            )
        return to_models(Source, rows)
