"""Response action ledger: idempotent proposals and a strict status machine."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID

from lg_sotf.db.errors import AlreadyInState, InvalidTransition, NotFound
from lg_sotf.db.pagination import Page, Params, check_limit, decode_cursor_uuid, paginate
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    require_aware,
    set_clauses,
    to_model,
    to_models,
)

ACTION_STATUSES = (
    "proposed",
    "awaiting_approval",
    "approved",
    "rejected",
    "executing",
    "succeeded",
    "failed",
    "dry_run",
    "blocked",
)
RISK_LEVELS = ("low", "medium", "high", "critical")

ACTION_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "proposed": frozenset({"awaiting_approval", "approved", "rejected", "blocked", "dry_run"}),
    "awaiting_approval": frozenset({"approved", "rejected", "blocked"}),
    "approved": frozenset({"executing", "dry_run", "blocked"}),
    "executing": frozenset({"succeeded", "failed", "dry_run"}),
    "failed": frozenset({"executing"}),
    "succeeded": frozenset(),
    "rejected": frozenset(),
    "dry_run": frozenset(),
    "blocked": frozenset(),
}
TERMINAL_ACTION_STATUSES = tuple(s for s, targets in ACTION_TRANSITIONS.items() if not targets)
EXECUTED_STATUSES = ("executing", "succeeded", "failed")


def action_idempotency_key(tenant_id: str, alert_id: str, action_type: str, target: str) -> str:
    """sha256 over an unambiguous encoding of (tenant, alert, action_type, target)."""
    canonical = json.dumps([tenant_id, alert_id, action_type, target], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def can_transition(current: str, target: str) -> bool:
    return target in ACTION_TRANSITIONS.get(current, frozenset())


class ResponseAction(Record):
    id: UUID
    tenant_id: str
    alert_id: str
    action_type: str
    target: str
    params: Dict[str, Any]
    risk_level: str
    idempotency_key: str
    status: str
    blocked_reason: Optional[str]
    requested_by: Optional[str]
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    executed_at: Optional[datetime]
    connector: Optional[str]
    result: Optional[Dict[str, Any]]
    rollback_of: Optional[UUID]
    created_at: datetime
    updated_at: datetime


class ActionsRepo(Repository):
    async def propose(
        self,
        tenant_id: str,
        alert_id: str,
        action_type: str,
        target: str,
        risk_level: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        requested_by: Optional[str] = None,
        status: str = "proposed",
        blocked_reason: Optional[str] = None,
        connector: Optional[str] = None,
        rollback_of: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[ResponseAction, bool]:
        """Write a ledger row, or return the existing one for the same idempotency key.

        ``status`` may be ``proposed`` or any status directly reachable from
        it, so a guardrail decision can be recorded atomically with the row.
        Returns ``(action, created)``.
        """
        check_choice(risk_level, RISK_LEVELS, "risk level")
        if status != "proposed" and not can_transition("proposed", status):
            raise ValueError(f"invalid initial action status: {status!r}")
        key = action_idempotency_key(tenant_id, alert_id, action_type, target)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO response_actions (
                    tenant_id, alert_id, action_type, target, params, risk_level, idempotency_key,
                    status, blocked_reason, requested_by, connector, rollback_of, approved_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                        CASE WHEN $8 = 'approved' THEN now() END)
                ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                RETURNING *
                """,
                tenant_id,
                alert_id,
                action_type,
                target,
                dict(params or {}),
                risk_level,
                key,
                status,
                blocked_reason,
                requested_by,
                connector,
                rollback_of,
            )
            if row is not None:
                return ResponseAction.model_validate(dict(row)), True
            row = await c.fetchrow(
                "SELECT * FROM response_actions WHERE tenant_id = $1 AND idempotency_key = $2", tenant_id, key
            )
        return ResponseAction.model_validate(dict(row)), False

    async def get(self, tenant_id: str, action_id: UUID, *, conn: Optional[Connection] = None) -> ResponseAction:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM response_actions WHERE tenant_id = $1 AND id = $2", tenant_id, action_id
            )
        action = to_model(ResponseAction, row)
        if action is None:
            raise NotFound("response action", action_id)
        return action

    async def get_many(
        self, tenant_id: str, action_ids: Sequence[UUID], *, conn: Optional[Connection] = None
    ) -> List[ResponseAction]:
        if not action_ids:
            return []
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM response_actions
                WHERE tenant_id = $1 AND id = ANY($2::uuid[])
                ORDER BY created_at, id
                """,
                tenant_id,
                list(action_ids),
            )
        return to_models(ResponseAction, rows)

    async def list(
        self,
        tenant_id: str,
        *,
        status: Union[str, Sequence[str], None] = None,
        risk_level: Union[str, Sequence[str], None] = None,
        alert_id: Optional[str] = None,
        action_type: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[ResponseAction]:
        """Newest first, keyset-paginated over (created_at, id)."""
        check_limit(limit)
        params = Params(tenant_id)
        where = ["tenant_id = $1"]
        statuses = check_choices(status, ACTION_STATUSES, "action status")
        if statuses:
            where.append(f"status = ANY({params.add(statuses)}::text[])")
        risks = check_choices(risk_level, RISK_LEVELS, "risk level")
        if risks:
            where.append(f"risk_level = ANY({params.add(risks)}::text[])")
        if alert_id is not None:
            where.append(f"alert_id = {params.add(alert_id)}")
        if action_type is not None:
            where.append(f"action_type = {params.add(action_type)}")
        if cursor:
            ts, key = decode_cursor_uuid(cursor)
            where.append(f"(created_at, id) < ({params.add(ts)}, {params.add(key)}::uuid)")
        sql = (
            f"SELECT * FROM response_actions WHERE {' AND '.join(where)} "  # noqa: S608
            f"ORDER BY created_at DESC, id DESC LIMIT {params.add(limit + 1)}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, *params.values)
        return paginate(to_models(ResponseAction, rows), limit, lambda a: (a.created_at, str(a.id)))

    async def transition(
        self,
        tenant_id: str,
        action_id: UUID,
        to_status: str,
        *,
        expected_from: Union[str, Sequence[str], None] = None,
        blocked_reason: Optional[str] = UNSET,
        approved_by: Optional[str] = UNSET,
        connector: Optional[str] = UNSET,
        result: Optional[Mapping[str, Any]] = UNSET,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> ResponseAction:
        """Move an action to ``to_status`` if the ledger's state machine allows it.

        A normal return means this call made the change: of several
        concurrent callers (for example two workers claiming an approved
        action with ``to_status="executing"``), exactly one succeeds, so only
        that caller may run the connector. The others get
        :class:`AlreadyInState` when the row already has ``to_status`` and
        :class:`InvalidTransition` for any other illegal move.
        ``expected_from`` further restricts the accepted current statuses.
        ``approved_at`` is stamped on entering ``approved`` and ``executed_at``
        on entering ``executing``.
        """
        check_choice(to_status, ACTION_STATUSES, "action status")
        require_aware(now, "now")
        allowed_from = [s for s, targets in ACTION_TRANSITIONS.items() if to_status in targets]
        expected = check_choices(expected_from, ACTION_STATUSES, "action status")
        if expected is not None:
            allowed_from = [s for s in allowed_from if s in expected]
        params = Params(tenant_id, action_id, to_status, allowed_from)
        sets = ["status = $3"]
        sets += set_clauses(
            {
                "blocked_reason": blocked_reason,
                "approved_by": approved_by,
                "connector": connector,
                "result": dict(result) if result not in (UNSET, None) else result,
            },
            params,
        )
        if to_status == "approved":
            sets.append(f"approved_at = COALESCE({params.add(now)}::timestamptz, now())")
        if to_status == "executing":
            sets.append(f"executed_at = COALESCE({params.add(now)}::timestamptz, now())")
        current: Optional[str] = None
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"""
                UPDATE response_actions SET {", ".join(sets)}
                WHERE tenant_id = $1 AND id = $2 AND status = ANY($4::text[])
                RETURNING *
                """,  # noqa: S608
                *params.values,
            )
            if row is None:
                current = await c.fetchval(
                    "SELECT status FROM response_actions WHERE tenant_id = $1 AND id = $2", tenant_id, action_id
                )
        if row is not None:
            return ResponseAction.model_validate(dict(row))
        if current is None:
            raise NotFound("response action", action_id)
        if current == to_status:
            raise AlreadyInState("response action", action_id, current)
        raise InvalidTransition("response action", action_id, current, to_status)

    async def count_executed_since(self, tenant_id: str, since: datetime, *, conn: Optional[Connection] = None) -> int:
        """Actions that started real execution since ``since`` (per-tenant hourly cap)."""
        require_aware(since, "since")
        async with self._tenant(tenant_id, conn) as c:
            return await c.fetchval(
                """
                SELECT count(*) FROM response_actions
                WHERE tenant_id = $1 AND executed_at >= $2 AND status = ANY($3::text[])
                """,
                tenant_id,
                since,
                list(EXECUTED_STATUSES),
            )
