"""Analyst escalations with optimistic locking (``version``)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID

from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.pagination import Page, Params, check_limit, decode_cursor_text, paginate
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    require_aware,
    to_model,
    to_models,
)
from lg_sotf.db.tenancy import thread_id_for

ESCALATION_LEVELS = ("L1", "L2", "L3")
ESCALATION_STATUSES = ("open", "claimed", "decided", "expired", "cancelled")
ACTIVE_ESCALATION_STATUSES = ("open", "claimed")
DECISIONS = ("true_positive", "false_positive", "benign_positive", "needs_more_info")

_CREATE_ATTEMPTS = 3


class Escalation(Record):
    id: str
    tenant_id: str
    alert_id: str
    thread_id: str
    level: str
    status: str
    reason: str
    priority: int
    summary: Dict[str, Any]
    related_alert_ids: List[str]
    assigned_to: Optional[UUID]
    sla_deadline: Optional[datetime]
    decision: Optional[str]
    decision_notes: Optional[str]
    approved_actions: List[str]
    decided_by: Optional[UUID]
    decided_at: Optional[datetime]
    claimed_at: Optional[datetime]
    version: int
    created_at: datetime
    updated_at: datetime

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_ESCALATION_STATUSES


class EscalationsRepo(Repository):
    async def create_or_attach(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        reason: str,
        level: str = "L1",
        priority: int = 5,
        summary: Optional[Mapping[str, Any]] = None,
        related_alert_ids: Sequence[str] = (),
        sla_deadline: Optional[datetime] = None,
        assigned_to: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[Escalation, bool]:
        """Return the alert's open/claimed escalation, creating one if none exists.

        Idempotent: returns ``(escalation, created)``. Safe under concurrent
        callers thanks to the partial unique index on active escalations.
        """
        check_choice(level, ESCALATION_LEVELS, "escalation level")
        require_aware(sla_deadline, "sla_deadline")
        async with self._tenant(tenant_id, conn) as c:
            for _ in range(_CREATE_ATTEMPTS):
                row = await c.fetchrow(
                    """
                    INSERT INTO escalations (tenant_id, alert_id, thread_id, level, reason, priority, summary,
                                             related_alert_ids, sla_deadline, assigned_to)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (tenant_id, alert_id) WHERE status IN ('open', 'claimed') DO NOTHING
                    RETURNING *
                    """,
                    tenant_id,
                    alert_id,
                    thread_id_for(tenant_id, alert_id),
                    level,
                    reason,
                    priority,
                    dict(summary or {}),
                    list(related_alert_ids),
                    sla_deadline,
                    assigned_to,
                )
                if row is not None:
                    return Escalation.model_validate(dict(row)), True
                existing = await c.fetchrow(
                    """
                    SELECT * FROM escalations
                    WHERE tenant_id = $1 AND alert_id = $2 AND status IN ('open', 'claimed')
                    """,
                    tenant_id,
                    alert_id,
                )
                if existing is not None:
                    return Escalation.model_validate(dict(existing)), False
        raise Conflict(f"could not create or find an active escalation for alert {alert_id}")

    async def get(self, tenant_id: str, escalation_id: str, *, conn: Optional[Connection] = None) -> Escalation:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2", tenant_id, escalation_id
            )
        esc = to_model(Escalation, row)
        if esc is None:
            raise NotFound("escalation", escalation_id)
        return esc

    async def get_active_for_alert(
        self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None
    ) -> Optional[Escalation]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                SELECT * FROM escalations
                WHERE tenant_id = $1 AND alert_id = $2 AND status IN ('open', 'claimed')
                """,
                tenant_id,
                alert_id,
            )
        return to_model(Escalation, row)

    async def list(
        self,
        tenant_id: str,
        *,
        status: Union[str, Sequence[str], None] = None,
        level: Union[str, Sequence[str], None] = None,
        assigned_to: Optional[UUID] = None,
        alert_id: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[Escalation]:
        """Newest first, keyset-paginated over (created_at, id)."""
        check_limit(limit)
        params = Params(tenant_id)
        where = ["tenant_id = $1"]
        statuses = check_choices(status, ESCALATION_STATUSES, "escalation status")
        if statuses:
            where.append(f"status = ANY({params.add(statuses)}::text[])")
        levels = check_choices(level, ESCALATION_LEVELS, "escalation level")
        if levels:
            where.append(f"level = ANY({params.add(levels)}::text[])")
        if assigned_to is not None:
            where.append(f"assigned_to = {params.add(assigned_to)}")
        if alert_id is not None:
            where.append(f"alert_id = {params.add(alert_id)}")
        if cursor:
            ts, key = decode_cursor_text(cursor)
            where.append(f"(created_at, id) < ({params.add(ts)}, {params.add(key)})")
        sql = (
            f"SELECT * FROM escalations WHERE {' AND '.join(where)} "  # noqa: S608
            f"ORDER BY created_at DESC, id DESC LIMIT {params.add(limit + 1)}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, *params.values)
        return paginate(to_models(Escalation, rows), limit, lambda e: (e.created_at, e.id))

    async def claim(
        self,
        tenant_id: str,
        escalation_id: str,
        user_id: UUID,
        expected_version: int,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> Escalation:
        """Assign an active escalation to ``user_id``; :class:`Conflict` if the version moved."""
        require_aware(now, "now")
        return await self._guarded_update(
            tenant_id,
            escalation_id,
            "claimed",
            ACTIVE_ESCALATION_STATUSES,
            expected_version,
            "status = 'claimed', assigned_to = $5, claimed_at = COALESCE(claimed_at, COALESCE($6::timestamptz, now()))",
            [user_id, now],
            conn=conn,
        )

    async def decide(
        self,
        tenant_id: str,
        escalation_id: str,
        *,
        decision: str,
        decided_by: UUID,
        expected_version: int,
        notes: Optional[str] = None,
        approved_actions: Sequence[str] = (),
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> Escalation:
        """Record the analyst decision; :class:`Conflict` if the version moved."""
        check_choice(decision, DECISIONS, "decision")
        require_aware(now, "now")
        return await self._guarded_update(
            tenant_id,
            escalation_id,
            "decided",
            ACTIVE_ESCALATION_STATUSES,
            expected_version,
            """
            status = 'decided', decision = $5, decided_by = $6, decision_notes = $7,
            approved_actions = $8, decided_at = COALESCE($9::timestamptz, now()),
            claimed_at = COALESCE(claimed_at, COALESCE($9::timestamptz, now())),
            assigned_to = COALESCE(assigned_to, $6)
            """,
            [decision, decided_by, notes, list(approved_actions), now],
            conn=conn,
        )

    async def escalate_level(
        self,
        tenant_id: str,
        escalation_id: str,
        *,
        sla_deadline: Optional[datetime],
        expected_version: Optional[int] = None,
        conn: Optional[Connection] = None,
    ) -> Escalation:
        """Raise L1 -> L2 -> L3 with a new SLA deadline and clear the assignee.

        :class:`InvalidTransition` if already L3 or no longer active.
        """
        require_aware(sla_deadline, "sla_deadline")
        current = await self.get(tenant_id, escalation_id, conn=conn)
        if current.level == ESCALATION_LEVELS[-1]:
            raise InvalidTransition("escalation", escalation_id, current.level, "beyond L3")
        next_level = ESCALATION_LEVELS[ESCALATION_LEVELS.index(current.level) + 1]
        return await self._guarded_update(
            tenant_id,
            escalation_id,
            "open",
            ACTIVE_ESCALATION_STATUSES,
            expected_version if expected_version is not None else current.version,
            "status = 'open', level = $5, sla_deadline = $6, assigned_to = NULL",
            [next_level, sla_deadline],
            conn=conn,
        )

    async def expire(
        self,
        tenant_id: str,
        escalation_id: str,
        *,
        expected_version: Optional[int] = None,
        conn: Optional[Connection] = None,
    ) -> Escalation:
        return await self._guarded_update(
            tenant_id,
            escalation_id,
            "expired",
            ACTIVE_ESCALATION_STATUSES,
            expected_version,
            "status = 'expired'",
            [],
            conn=conn,
        )

    async def cancel(
        self,
        tenant_id: str,
        escalation_id: str,
        *,
        expected_version: Optional[int] = None,
        conn: Optional[Connection] = None,
    ) -> Escalation:
        return await self._guarded_update(
            tenant_id,
            escalation_id,
            "cancelled",
            ACTIVE_ESCALATION_STATUSES,
            expected_version,
            "status = 'cancelled'",
            [],
            conn=conn,
        )

    async def _guarded_update(
        self,
        tenant_id: str,
        escalation_id: str,
        target: str,
        allowed_from: Sequence[str],
        expected_version: Optional[int],
        set_sql: str,
        extra: List[Any],
        *,
        conn: Optional[Connection],
    ) -> Escalation:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"""
                UPDATE escalations SET {set_sql}, version = version + 1
                WHERE tenant_id = $1 AND id = $2 AND status = ANY($3::text[])
                  AND ($4::integer IS NULL OR version = $4)
                RETURNING *
                """,  # noqa: S608
                tenant_id,
                escalation_id,
                list(allowed_from),
                expected_version,
                *extra,
            )
            if row is None:
                current = await c.fetchrow(
                    "SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2", tenant_id, escalation_id
                )
        if row is not None:
            return Escalation.model_validate(dict(row))
        esc = to_model(Escalation, current)
        if esc is None:
            raise NotFound("escalation", escalation_id)
        if expected_version is not None and esc.version != expected_version:
            raise Conflict(
                f"escalation {escalation_id} was modified (version {esc.version}, expected {expected_version})"
            )
        raise InvalidTransition("escalation", escalation_id, esc.status, target)

    async def find_sla_breached_all_tenants(
        self, *, now: Optional[datetime] = None, limit: int = 100
    ) -> List[Escalation]:
        """Active escalations past their deadline, in active tenants only.

        A suspended tenant's escalations are frozen: nobody can act on them,
        so the sweep must not escalate or expire them (see
        :meth:`extend_sla_deadlines` for reactivation).
        """
        require_aware(now, "now")
        async with self._system() as c:
            rows = await c.fetch(
                """
                SELECT e.* FROM escalations e
                JOIN tenants t ON t.id = e.tenant_id AND t.status = 'active'
                WHERE e.status IN ('open', 'claimed') AND e.sla_deadline < COALESCE($1::timestamptz, now())
                ORDER BY e.sla_deadline
                LIMIT $2
                """,
                now,
                limit,
            )
        return to_models(Escalation, rows)

    async def extend_sla_deadlines(
        self, tenant_id: str, deadlines: Mapping[str, datetime], *, conn: Optional[Connection] = None
    ) -> int:
        """Give every active escalation at least ``deadlines[level]``; the number of rows moved.

        Used on tenant reactivation. A deadline is never shortened, the
        version is left alone (a deadline move is not a state change an
        analyst's pending claim or decision should conflict with).
        """
        for level in ESCALATION_LEVELS:
            require_aware(deadlines[level], "deadline")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE escalations
                SET sla_deadline = CASE level WHEN 'L1' THEN $2::timestamptz WHEN 'L2' THEN $3::timestamptz
                                              ELSE $4::timestamptz END
                WHERE tenant_id = $1 AND status IN ('open', 'claimed') AND sla_deadline IS NOT NULL
                  AND sla_deadline < CASE level WHEN 'L1' THEN $2::timestamptz WHEN 'L2' THEN $3::timestamptz
                                                ELSE $4::timestamptz END
                """,
                tenant_id,
                *(deadlines[level] for level in ESCALATION_LEVELS),
            )
        return int(status.split()[-1])

    async def count_active(self, tenant_id: str, *, conn: Optional[Connection] = None) -> int:
        async with self._tenant(tenant_id, conn) as c:
            return await c.fetchval(
                "SELECT count(*) FROM escalations WHERE tenant_id = $1 AND status IN ('open', 'claimed')",
                tenant_id,
            )

    async def count_active_all_tenants(self) -> int:
        """Platform-wide open/claimed count for the ``lgsotf_escalations_open`` gauge."""
        async with self._system() as c:
            return await c.fetchval("SELECT count(*) FROM escalations WHERE status IN ('open', 'claimed')")
