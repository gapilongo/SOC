"""Response action ledger: idempotent proposals and a strict status machine.

Besides the status machine the ledger carries (migration 0009):

* ``execution_owner``: ``workflow`` (the alert's run executes the row) or
  ``scheduler`` (the background executor does: rollbacks, retries, late
  approvals and deferred or orphaned stateful executions). It only ever
  goes ``workflow -> scheduler``.
* ``integration_id``: the integration the connector used (pinned for
  re-runs, retries and rollbacks; set to NULL when it is deleted).
* ``external_ref``: the stateful connector's checkpointed progress (object
  ids, steps, ``reversible``, ``rollback_until``), at most 64 KiB.
* ``attempts`` and ``lease_until``: execution attempts and the scheduler's
  lease on a background row.
* ``verification`` (``pending|verified|failed|inconclusive``, NULL when not
  applicable) with its schedule (``verify_after``, ``verify_deadline``),
  ``verification_detail``, ``verified_at`` and ``verify_attempts``: proof by
  re-query that a succeeded change is in effect.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, Optional, Sequence, Tuple, Union
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
MIN_DEFER_S = 30.0

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
EXECUTION_OWNERS = ("workflow", "scheduler")
VERIFICATION_STATES = ("pending", "verified", "failed", "inconclusive")
FINAL_VERIFICATION_STATES = ("verified", "failed", "inconclusive")
# A rollback row in one of these statuses is "live": at most one per original (unique index).
LIVE_ROLLBACK_STATUSES = ("proposed", "awaiting_approval", "approved", "executing", "succeeded")
VerificationStateName = Literal["pending", "verified", "failed", "inconclusive"]


def action_idempotency_key(
    tenant_id: str, alert_id: str, action_type: str, target: str, scope: Optional[str] = None
) -> str:
    """sha256 over an unambiguous encoding of (tenant, alert, action_type, target[, scope]).

    ``scope`` is appended only when set, so keys of rows without one are
    byte-identical to those written before it existed.
    """
    parts: List[str] = [tenant_id, alert_id, action_type, target]
    if scope is not None:
        parts.append(scope)
    canonical = json.dumps(parts, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationWrite:
    """A verification state to write. ``pending`` needs ``verify_after`` and ``verify_deadline``."""

    state: VerificationStateName
    detail: Mapping[str, Any]
    verify_after: Optional[datetime] = None
    verify_deadline: Optional[datetime] = None

    def __post_init__(self) -> None:
        check_choice(self.state, VERIFICATION_STATES, "verification state")
        if self.state == "pending" and (self.verify_after is None or self.verify_deadline is None):
            raise ValueError("a pending verification needs verify_after and verify_deadline")
        require_aware(self.verify_after, "verify_after")
        require_aware(self.verify_deadline, "verify_deadline")


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
    execution_owner: str = "workflow"
    integration_id: Optional[UUID] = None
    external_ref: Optional[Dict[str, Any]] = None
    attempts: int = 0
    lease_until: Optional[datetime] = None
    verification: Optional[str] = None
    verification_detail: Optional[Dict[str, Any]] = None
    verify_after: Optional[datetime] = None
    verify_deadline: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    verify_attempts: int = 0


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
        scope: Optional[str] = None,
        execution_owner: Optional[str] = None,
        integration_id: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[ResponseAction, bool]:
        """Write a ledger row, or return the existing one for the same idempotency key.

        ``status`` may be ``proposed`` or any status directly reachable from
        it, so a guardrail decision can be recorded atomically with the row.
        ``scope`` joins the idempotency key (a rollback's
        ``rollback:<original>:<generation>``). ``execution_owner`` defaults
        to ``scheduler`` for a rollback (``rollback_of``) and ``workflow``
        otherwise. Returns ``(action, created)``.
        """
        check_choice(risk_level, RISK_LEVELS, "risk level")
        if status != "proposed" and not can_transition("proposed", status):
            raise ValueError(f"invalid initial action status: {status!r}")
        owner = execution_owner or ("scheduler" if rollback_of is not None else "workflow")
        check_choice(owner, EXECUTION_OWNERS, "execution owner")
        key = action_idempotency_key(tenant_id, alert_id, action_type, target, scope)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO response_actions (
                    tenant_id, alert_id, action_type, target, params, risk_level, idempotency_key,
                    status, blocked_reason, requested_by, connector, rollback_of, approved_at,
                    execution_owner, integration_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                        CASE WHEN $8 = 'approved' THEN now() END, $13, $14)
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
                owner,
                integration_id,
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
        verification: Union[str, Sequence[str], None] = None,
        execution_owner: Optional[str] = None,
        rollback_of: Optional[UUID] = None,
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
        states = check_choices(verification, VERIFICATION_STATES, "verification state")
        if states:
            where.append(f"verification = ANY({params.add(states)}::text[])")
        if execution_owner is not None:
            check_choice(execution_owner, EXECUTION_OWNERS, "execution owner")
            where.append(f"execution_owner = {params.add(execution_owner)}")
        if rollback_of is not None:
            where.append(f"rollback_of = {params.add(rollback_of)}::uuid")
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
        integration_id: Optional[UUID] = UNSET,
        external_ref: Optional[Mapping[str, Any]] = UNSET,
        verification: Optional[VerificationWrite] = UNSET,
        execution_owner: str = UNSET,
        lease_until: Optional[datetime] = UNSET,
        bump_attempts: bool = False,
        reset_attempts: bool = False,
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
        on entering ``executing``. ``verification`` (only with ``succeeded``)
        writes the verification state in the same statement; a final state
        stamps ``verified_at``. ``bump_attempts`` counts an execution
        attempt; ``reset_attempts`` starts a fresh count (a retry).
        """
        check_choice(to_status, ACTION_STATUSES, "action status")
        require_aware(now, "now")
        if isinstance(lease_until, datetime):
            require_aware(lease_until, "lease_until")
        if verification not in (UNSET, None) and to_status != "succeeded":
            raise ValueError("a verification state is only written with 'succeeded'")
        if execution_owner is not UNSET:
            check_choice(execution_owner, EXECUTION_OWNERS, "execution owner")
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
                "integration_id": integration_id,
                "external_ref": dict(external_ref) if external_ref not in (UNSET, None) else external_ref,
                "execution_owner": execution_owner,
                "lease_until": lease_until,
            },
            params,
        )
        if isinstance(verification, VerificationWrite):
            sets += _verification_sets(verification, params)
        if reset_attempts:
            sets.append("attempts = 0")
        elif bump_attempts:
            sets.append("attempts = attempts + 1")
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

    async def count_attempt(
        self, tenant_id: str, action_id: UUID, *, conn: Optional[Connection] = None
    ) -> Optional[ResponseAction]:
        """One more execution attempt of an ``executing`` row (a re-run); ``None`` when it is not executing."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE response_actions SET attempts = attempts + 1
                WHERE tenant_id = $1 AND id = $2 AND status = 'executing'
                RETURNING *
                """,
                tenant_id,
                action_id,
            )
        return to_model(ResponseAction, row)

    async def lock(self, tenant_id: str, action_id: UUID, *, conn: Connection) -> ResponseAction:
        """The row, locked ``FOR UPDATE`` until the caller's transaction ends."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM response_actions WHERE tenant_id = $1 AND id = $2 FOR UPDATE", tenant_id, action_id
            )
        action = to_model(ResponseAction, row)
        if action is None:
            raise NotFound("response action", action_id)
        return action

    async def checkpoint(
        self, tenant_id: str, action_id: UUID, patch: Mapping[str, Any], *, conn: Optional[Connection] = None
    ) -> bool:
        """Merge ``patch`` into ``external_ref`` of an ``executing`` row; False when it is not executing (any more)."""
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE response_actions SET external_ref = COALESCE(external_ref, '{}'::jsonb) || $3::jsonb
                WHERE tenant_id = $1 AND id = $2 AND status = 'executing'
                """,
                tenant_id,
                action_id,
                dict(patch),
            )
        return str(status).endswith(" 1")

    async def defer(
        self,
        tenant_id: str,
        action_id: UUID,
        *,
        retry_after_s: float,
        detail: Mapping[str, Any],
        external_ref: Optional[Mapping[str, Any]] = UNSET,
        conn: Optional[Connection] = None,
    ) -> ResponseAction:
        """Keep an ``executing`` row executing, owned by the scheduler, leased until ``now() + max(retry_after_s, 30)``.

        ``detail`` becomes ``result`` (what happened so far); ``external_ref``
        replaces the checkpointed state when given.
        """
        params = Params(tenant_id, action_id, max(float(retry_after_s), MIN_DEFER_S), dict(detail))
        sets = [
            "execution_owner = 'scheduler'",
            "lease_until = now() + make_interval(secs => $3)",
            "result = $4",
        ]
        if external_ref is not UNSET:
            sets.append(f"external_ref = {params.add(dict(external_ref) if external_ref is not None else None)}")
        current: Optional[str] = None
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"""
                UPDATE response_actions SET {", ".join(sets)}
                WHERE tenant_id = $1 AND id = $2 AND status = 'executing'
                RETURNING *
                """,  # noqa: S608
                *params.values,
            )
            if row is None:
                current = await c.fetchval(
                    "SELECT status FROM response_actions WHERE tenant_id = $1 AND id = $2", tenant_id, action_id
                )
        if row is None:
            if current is None:
                raise NotFound("response action", action_id)
            raise InvalidTransition("response action", action_id, str(current), "executing")
        return ResponseAction.model_validate(dict(row))

    async def hand_off(
        self, tenant_id: str, action_ids: Sequence[UUID], *, reason: str, conn: Optional[Connection] = None
    ) -> List[UUID]:
        """Give workflow rows (``approved`` or ``executing``) to the scheduler, due now; returns the ids handed off.

        ``reason`` is for the caller's audit entry (``late_approval``,
        ``orphaned_execution``); the row only records the new owner.
        """
        if not action_ids:
            return []
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                UPDATE response_actions SET execution_owner = 'scheduler', lease_until = now()
                WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND execution_owner = 'workflow'
                  AND status IN ('approved', 'executing')
                RETURNING id
                """,
                tenant_id,
                list(action_ids),
            )
        return [r["id"] for r in rows]

    async def claim_background(
        self, *, limit: int, lease_s: float, conn: Optional[Connection] = None
    ) -> List[Tuple[str, UUID, str]]:
        """Claim due scheduler rows of every active tenant: ``(tenant, id, status)`` (system transaction).

        Due: ``approved`` or ``executing`` with ``lease_until`` NULL or past.
        ``FOR UPDATE SKIP LOCKED`` lets concurrent schedulers split the work;
        the claim moves ``lease_until`` to ``now() + lease_s``, so a claim
        whose process dies is taken again once the lease ends.
        """
        async with self._system(conn) as c:
            rows = await c.fetch(
                """
                WITH due AS (
                    SELECT a.id FROM response_actions a
                    JOIN tenants t ON t.id = a.tenant_id AND t.status = 'active'
                    WHERE a.execution_owner = 'scheduler' AND a.status IN ('approved', 'executing')
                      AND (a.lease_until IS NULL OR a.lease_until <= now())
                    ORDER BY a.lease_until NULLS FIRST, a.created_at
                    LIMIT $1
                    FOR UPDATE OF a SKIP LOCKED
                )
                UPDATE response_actions a SET lease_until = now() + make_interval(secs => $2)
                FROM due WHERE a.id = due.id
                RETURNING a.tenant_id, a.id, a.status
                """,
                limit,
                float(lease_s),
            )
        return [(str(r["tenant_id"]), r["id"], str(r["status"])) for r in rows]

    async def expire_approvals(self, *, ttl_s: float, conn: Optional[Connection] = None) -> List[Tuple[str, UUID]]:
        """Scheduler rows still ``approved`` longer than ``ttl_s`` after approval: ``(tenant, id)`` to block.

        The caller blocks each one (``approval_expired``) with its audit entry.
        """
        async with self._system(conn) as c:
            rows = await c.fetch(
                """
                SELECT tenant_id, id FROM response_actions
                WHERE execution_owner = 'scheduler' AND status = 'approved'
                  AND approved_at < now() - make_interval(secs => $1)
                ORDER BY approved_at
                LIMIT 500
                """,
                float(ttl_s),
            )
        return [(str(r["tenant_id"]), r["id"]) for r in rows]

    async def stranded_approvals(
        self, *, limit: int, ttl_s: float, conn: Optional[Connection] = None
    ) -> List[Tuple[str, UUID, bool, bool]]:
        """Workflow rows still ``approved`` whose run ended (or never existed).

        Returns ``(tenant, id, approved_after_run_end, expired)``.
        ``approved_after_run_end``: approved at or after the run's end (its
        ``completed_at``, else ``updated_at``), an approval that arrived too
        late for the run: it goes to the scheduler, unless ``expired``
        (approved more than ``ttl_s`` ago, or without an approval time), in
        which case the approval TTL applies to it like to any scheduler row.
        The others were approved while the run was active and the run ended
        without them (superseded).
        """
        async with self._system(conn) as c:
            rows = await c.fetch(
                """
                SELECT a.tenant_id, a.id,
                       COALESCE(a.approved_at >= COALESCE(r.completed_at, r.updated_at), true) AS late,
                       COALESCE(a.approved_at < now() - make_interval(secs => $2), true) AS expired
                FROM response_actions a
                LEFT JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.alert_id
                WHERE a.status = 'approved' AND a.execution_owner = 'workflow'
                  AND (r.alert_id IS NULL OR r.status IN ('completed', 'dead_lettered'))
                ORDER BY a.approved_at NULLS FIRST
                LIMIT $1
                """,
                limit,
                float(ttl_s),
            )
        return [(str(r["tenant_id"]), r["id"], bool(r["late"]), bool(r["expired"])) for r in rows]

    async def claim_due_verifications(
        self, *, limit: int, lease_s: float, conn: Optional[Connection] = None
    ) -> List[Tuple[str, UUID]]:
        """Claim due pending verifications of every active tenant (system transaction); pushes ``verify_after``.

        ``verify_after`` moves by ``lease_s``, so a check whose process dies
        comes back after the lease. A suspended tenant's checks wait (no
        Microsoft call, audit or event while the tenant's other work is frozen).
        """
        async with self._system(conn) as c:
            rows = await c.fetch(
                """
                WITH due AS (
                    SELECT a.id FROM response_actions a
                    JOIN tenants t ON t.id = a.tenant_id AND t.status = 'active'
                    WHERE a.verification = 'pending' AND a.verify_after <= now()
                    ORDER BY a.verify_after
                    LIMIT $1
                    FOR UPDATE OF a SKIP LOCKED
                )
                UPDATE response_actions a SET verify_after = now() + make_interval(secs => $2)
                FROM due WHERE a.id = due.id
                RETURNING a.tenant_id, a.id
                """,
                limit,
                float(lease_s),
            )
        return [(str(r["tenant_id"]), r["id"]) for r in rows]

    async def record_verification(
        self, tenant_id: str, action_id: UUID, write: VerificationWrite, *, conn: Optional[Connection] = None
    ) -> ResponseAction:
        """Write a check's outcome while the verification is still ``pending`` (compare-and-set).

        A final state stamps ``verified_at``; every call counts one
        ``verify_attempts``. :class:`InvalidTransition` when it is no longer pending.
        """
        params = Params(tenant_id, action_id)
        sets = _verification_sets(write, params) + ["verify_attempts = verify_attempts + 1"]
        current: Optional[str] = None
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"""
                UPDATE response_actions SET {", ".join(sets)}
                WHERE tenant_id = $1 AND id = $2 AND verification = 'pending'
                RETURNING *
                """,  # noqa: S608
                *params.values,
            )
            if row is None:
                current = await c.fetchval(
                    "SELECT coalesce(verification, 'none') FROM response_actions WHERE tenant_id = $1 AND id = $2",
                    tenant_id,
                    action_id,
                )
        if row is None:
            if current is None:
                raise NotFound("response action", action_id)
            raise InvalidTransition("response action verification", action_id, str(current), write.state)
        return ResponseAction.model_validate(dict(row))

    async def reopen_verification(
        self, tenant_id: str, action_id: UUID, *, window_s: float, conn: Optional[Connection] = None
    ) -> ResponseAction:
        """A final verification of a succeeded action back to ``pending``: due now, deadline ``now() + window_s``."""
        current: Optional[str] = None
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE response_actions SET verification = 'pending', verify_after = now(),
                    verify_deadline = now() + make_interval(secs => $3), verified_at = NULL
                WHERE tenant_id = $1 AND id = $2 AND status = 'succeeded'
                  AND verification IN ('verified', 'failed', 'inconclusive')
                RETURNING *
                """,
                tenant_id,
                action_id,
                float(window_s),
            )
            if row is None:
                current = await c.fetchval(
                    "SELECT coalesce(verification, 'none') FROM response_actions WHERE tenant_id = $1 AND id = $2",
                    tenant_id,
                    action_id,
                )
        if row is None:
            if current is None:
                raise NotFound("response action", action_id)
            raise InvalidTransition("response action verification", action_id, str(current), "pending")
        return ResponseAction.model_validate(dict(row))

    async def live_rollback(
        self, tenant_id: str, original_id: UUID, *, conn: Optional[Connection] = None
    ) -> Optional[ResponseAction]:
        """The original's rollback row that is proposed, pending, approved, executing or succeeded, if any."""
        found = await self.live_rollbacks(tenant_id, [original_id], conn=conn)
        return found.get(original_id)

    async def live_rollbacks(
        self, tenant_id: str, original_ids: Sequence[UUID], *, conn: Optional[Connection] = None
    ) -> Dict[UUID, ResponseAction]:
        """:meth:`live_rollback` for many originals at once (``{original id: rollback}``)."""
        if not original_ids:
            return {}
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM response_actions
                WHERE tenant_id = $1 AND rollback_of = ANY($2::uuid[]) AND status = ANY($3::text[])
                ORDER BY created_at
                """,
                tenant_id,
                list(original_ids),
                list(LIVE_ROLLBACK_STATUSES),
            )
        out: Dict[UUID, ResponseAction] = {}
        for action in to_models(ResponseAction, rows):
            if action.rollback_of is not None:
                out[action.rollback_of] = action
        return out

    async def rollback_generation(self, tenant_id: str, original_id: UUID, *, conn: Connection) -> int:
        """How many rollback rows (any status) the original has (the next rollback's idempotency scope)."""
        async with self._tenant(tenant_id, conn) as c:
            count = await c.fetchval(
                "SELECT count(*) FROM response_actions WHERE tenant_id = $1 AND rollback_of = $2",
                tenant_id,
                original_id,
            )
        return int(count or 0)

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


def _verification_sets(write: VerificationWrite, params: Params) -> List[str]:
    sets = [
        f"verification = {params.add(write.state)}",
        f"verification_detail = {params.add(dict(write.detail))}",
    ]
    if write.state == "pending":
        sets.append(f"verify_after = {params.add(write.verify_after)}::timestamptz")
        sets.append(f"verify_deadline = {params.add(write.verify_deadline)}::timestamptz")
    else:
        sets.append("verified_at = now()")
    return sets
