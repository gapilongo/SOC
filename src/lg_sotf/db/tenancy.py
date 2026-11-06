"""Tenant identifier rules, re-scoping a transaction to another tenant, and LangGraph thread-id helpers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Tuple

from lg_sotf.db.errors import InvalidTenantId

if TYPE_CHECKING:
    from lg_sotf.db.types import Connection

TENANT_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{1,62}$"
_TENANT_ID_RE = re.compile(TENANT_ID_PATTERN)

DEFAULT_TENANT_ID = "default"


def is_valid_tenant_id(tenant_id: object) -> bool:
    return isinstance(tenant_id, str) and _TENANT_ID_RE.fullmatch(tenant_id) is not None


def validate_tenant_id(tenant_id: object) -> str:
    """Return ``tenant_id`` unchanged or raise :class:`InvalidTenantId`."""
    if not is_valid_tenant_id(tenant_id):
        raise InvalidTenantId(f"invalid tenant id: {tenant_id!r}")
    return tenant_id  # type: ignore[return-value]


async def switch_tenant(conn: Connection, tenant_id: str) -> None:
    """Re-scope an open ``db.tenant_tx`` transaction to ``tenant_id`` (transaction-local ``app.tenant_id``).

    For one transaction that writes to several tenants (multi-tenant batch
    writes, tenant provisioning and its platform-level audit entries). RLS
    then checks every following statement against ``tenant_id``.
    """
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", validate_tenant_id(tenant_id))


def thread_id_for(tenant_id: str, alert_id: str) -> str:
    """LangGraph thread id for an alert's workflow run."""
    validate_tenant_id(tenant_id)
    if not alert_id:
        raise ValueError("alert_id must be non-empty")
    return f"{tenant_id}:{alert_id}"


def parse_thread_id(thread_id: str) -> Tuple[str, str]:
    """Split a thread id into ``(tenant_id, alert_id)``."""
    tenant_id, sep, alert_id = thread_id.partition(":")
    if not sep or not alert_id:
        raise ValueError(f"malformed thread id: {thread_id!r}")
    return validate_tenant_id(tenant_id), alert_id
