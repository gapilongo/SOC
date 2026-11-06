"""In-memory stand-ins for the repositories the services use."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.db.errors import AlreadyInState, InvalidTransition, NotFound
from lg_sotf.db.repos._base import UNSET
from lg_sotf.db.repos.actions import ACTION_TRANSITIONS, EXECUTED_STATUSES, ResponseAction, action_idempotency_key


class FakeActions:
    def __init__(self) -> None:
        self.rows: Dict[uuid.UUID, ResponseAction] = {}
        # Executions "from earlier in the hour" that are not ledger rows here, per action type.
        self.executed_earlier: Dict[str, int] = {}

    @property
    def executed_last_hour(self) -> int:
        return sum(self.executed_earlier.values())

    @executed_last_hour.setter
    def executed_last_hour(self, value: int) -> None:
        self.executed_earlier = {"_other": value}

    async def propose(self, tenant_id: str, alert_id: str, action_type: str, target: str, risk_level: str, *,
                      params: Optional[Mapping[str, Any]] = None, requested_by: Optional[str] = None,
                      status: str = "proposed", blocked_reason: Optional[str] = None, **_: Any) -> Tuple[ResponseAction, bool]:
        key = action_idempotency_key(tenant_id, alert_id, action_type, target)
        for row in self.rows.values():
            if row.idempotency_key == key:
                return row, False
        now = datetime.now(UTC)
        row = ResponseAction(
            id=uuid.uuid4(), tenant_id=tenant_id, alert_id=alert_id, action_type=action_type, target=target,
            params=dict(params or {}), risk_level=risk_level, idempotency_key=key, status=status,
            blocked_reason=blocked_reason, requested_by=requested_by, approved_by=None, approved_at=None,
            executed_at=None, connector=None, result=None, rollback_of=None, created_at=now, updated_at=now,
        )
        self.rows[row.id] = row
        return row, True

    async def get(self, tenant_id: str, action_id: uuid.UUID, **_: Any) -> ResponseAction:
        if action_id not in self.rows:
            raise NotFound("response action", action_id)
        return self.rows[action_id]

    async def get_many(self, tenant_id: str, ids: Sequence[uuid.UUID], **_: Any) -> List[ResponseAction]:
        return [self.rows[i] for i in ids if i in self.rows]

    async def list(self, tenant_id: str, *, status: Any = None, alert_id: Optional[str] = None, **_: Any) -> Any:
        statuses = [status] if isinstance(status, str) else list(status or [])
        items = [r for r in self.rows.values()
                 if (not statuses or r.status in statuses) and (alert_id is None or r.alert_id == alert_id)]
        return type("Page", (), {"items": items, "next_cursor": None})()

    async def transition(self, tenant_id: str, action_id: uuid.UUID, to_status: str, *,
                         expected_from: Any = None, blocked_reason: Any = UNSET, approved_by: Any = UNSET,
                         connector: Any = UNSET, result: Any = UNSET, **_: Any) -> ResponseAction:
        row = self.rows[action_id]
        allowed = [s for s, t in ACTION_TRANSITIONS.items() if to_status in t]
        if expected_from is not None:
            expected = [expected_from] if isinstance(expected_from, str) else list(expected_from)
            allowed = [s for s in allowed if s in expected]
        if row.status not in allowed:
            if row.status == to_status:
                raise AlreadyInState("response action", action_id, to_status)
            raise InvalidTransition("response action", action_id, row.status, to_status)
        changes: Dict[str, Any] = {"status": to_status}
        for name, value in (("blocked_reason", blocked_reason), ("approved_by", approved_by),
                            ("connector", connector), ("result", result)):
            if value is not UNSET:
                changes[name] = value
        if to_status == "executing":
            changes["executed_at"] = datetime.now(UTC)
        self.rows[action_id] = row.model_copy(update=changes)
        return self.rows[action_id]

    async def executed_counts(self, tenant_id: str, since: Optional[datetime] = None,
                              **_: Any) -> Tuple[int, Dict[str, int]]:
        counts = dict(self.executed_earlier)
        for row in self.rows.values():
            if row.status in EXECUTED_STATUSES:
                counts[row.action_type] = counts.get(row.action_type, 0) + 1
        return sum(counts.values()), counts


class FakeIntegrations:
    """No integrations unless a test adds some (routing reads them once per execution pass)."""

    def __init__(self) -> None:
        self.items: List[Any] = []

    async def list(self, tenant_id: str, *, enabled: Optional[bool] = None, kinds: Any = None, **_: Any) -> List[Any]:
        return [
            i for i in self.items
            if (enabled is None or i.enabled == enabled) and (kinds is None or i.kind in kinds)
        ]


@dataclass
class FakeTenant:
    settings: Dict[str, Any] = field(default_factory=dict)


class FakeTenants:
    def __init__(self, settings: Optional[Dict[str, Any]] = None) -> None:
        self.tenant = FakeTenant(settings or {})

    async def get(self, tenant_id: str, **_: Any) -> FakeTenant:
        return self.tenant


class FakeAudit:
    def __init__(self) -> None:
        self.entries: List[Tuple[Any, ...]] = []

    async def append(self, tenant_id: str, actor_type: str, actor_id: Any, action: str, resource_type: str,
                     resource_id: Any = None, details: Any = None, **_: Any) -> None:
        self.entries.append((tenant_id, actor_type, action, resource_type, resource_id, dict(details or {})))

    def actions(self) -> List[str]:
        return [e[2] for e in self.entries]


class FakeEvents:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        self.events.append(event)


class FakeConnection:
    """Records statements (the advisory locks); queries go through the fake repositories, not SQL."""

    def __init__(self) -> None:
        self.statements: List[Tuple[str, Tuple[Any, ...]]] = []

    async def execute(self, sql: str, *args: Any) -> str:
        self.statements.append((sql, args))
        return "SELECT 1"

    async def fetch(self, sql: str, *args: Any) -> List[Dict[str, Any]]:
        self.statements.append((sql, args))
        return []


class FakeDb:
    def __init__(self) -> None:
        self.conn = FakeConnection()
        self.transactions = 0

    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str, **_: Any) -> AsyncIterator[FakeConnection]:
        self.transactions += 1
        yield self.conn


@dataclass
class FakeRepos:
    actions: FakeActions = field(default_factory=FakeActions)
    tenants: FakeTenants = field(default_factory=FakeTenants)
    audit: FakeAudit = field(default_factory=FakeAudit)
    escalations: Any = None
    db: FakeDb = field(default_factory=FakeDb)
    integrations: FakeIntegrations = field(default_factory=FakeIntegrations)
