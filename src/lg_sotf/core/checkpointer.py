"""Tenant-scoped LangGraph checkpointer and checkpoint-table row-level security.

The checkpoint tables (``checkpoints``, ``checkpoint_blobs``,
``checkpoint_writes``) hold each alert's serialised workflow state under
thread ids ``{tenant_id}:{alert_id}``. Like every other tenant-owned table
they are under ``FORCE ROW LEVEL SECURITY``: a row is visible only when the
thread id's tenant prefix equals the session's ``app.tenant_id`` (or the
schema owner bypasses RLS in ``system_tx``). LangGraph creates the tables in
``AsyncPostgresSaver.setup()``, so :func:`secure_checkpoint_tables` runs right
after it in ``lg-sotf migrate`` (idempotent; it re-applies the policy if the
tables are recreated).

:class:`TenantScopedPostgresSaver` sets ``app.tenant_id`` on the pooled
connection before every statement, from the thread id of the call being
served, so the worker reads and writes only the tenant's own threads.
"""

from __future__ import annotations

import contextvars
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional, Sequence

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg import AsyncConnection

from lg_sotf.db.tenancy import is_valid_tenant_id

CHECKPOINT_RLS_TABLES: Sequence[str] = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")

_TENANT: contextvars.ContextVar[str] = contextvars.ContextVar("lgsotf_checkpoint_tenant", default="")


def tenant_of_thread(thread_id: Any) -> str:
    """The tenant prefix of ``{tenant}:{alert}``; empty (matches nothing) when malformed."""
    tenant, sep, _ = str(thread_id or "").partition(":")
    return tenant if sep and is_valid_tenant_id(tenant) else ""


def _tenant_of_config(config: Optional[RunnableConfig]) -> str:
    configurable = (config or {}).get("configurable") or {}
    return tenant_of_thread(configurable.get("thread_id"))


class TenantScopedPostgresSaver(AsyncPostgresSaver):
    """``AsyncPostgresSaver`` whose every statement runs with ``app.tenant_id`` set."""

    @asynccontextmanager
    async def _cursor(self, *, pipeline: bool = False) -> AsyncIterator[Any]:
        async with super()._cursor(pipeline=pipeline) as cur:
            await cur.execute("SELECT set_config('app.tenant_id', %s, false)", (_TENANT.get(),))
            yield cur

    async def aget_tuple(self, config: RunnableConfig) -> Any:
        token = _TENANT.set(_tenant_of_config(config))
        try:
            return await super().aget_tuple(config)
        finally:
            _TENANT.reset(token)

    async def aput(self, config: RunnableConfig, *args: Any, **kwargs: Any) -> RunnableConfig:
        token = _TENANT.set(_tenant_of_config(config))
        try:
            return await super().aput(config, *args, **kwargs)
        finally:
            _TENANT.reset(token)

    async def aput_writes(self, config: RunnableConfig, *args: Any, **kwargs: Any) -> None:
        token = _TENANT.set(_tenant_of_config(config))
        try:
            await super().aput_writes(config, *args, **kwargs)
        finally:
            _TENANT.reset(token)

    async def adelete_thread(self, thread_id: str) -> None:
        token = _TENANT.set(tenant_of_thread(thread_id))
        try:
            await super().adelete_thread(thread_id)
        finally:
            _TENANT.reset(token)

    async def aget_delta_channel_history(self, config: RunnableConfig, *args: Any, **kwargs: Any) -> Any:
        token = _TENANT.set(_tenant_of_config(config))
        try:
            return await super().aget_delta_channel_history(config, *args, **kwargs)  # type: ignore[call-arg]
        finally:
            _TENANT.reset(token)

    async def alist(self, config: Optional[RunnableConfig], *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        tenant = _tenant_of_config(config)
        iterator = super().alist(config, *args, **kwargs)
        while True:
            token = _TENANT.set(tenant)
            try:
                item = await iterator.__anext__()
            except StopAsyncIteration:
                return
            finally:
                _TENANT.reset(token)
            yield item

    async def aprune_thread(self, thread_id: str) -> int:
        """Delete every checkpoint of a *finished* thread except the latest one.

        The latest checkpoint is all that ``aget_state`` (and a later
        ``reprocess``) needs; intermediate ones, their writes and the blob
        versions they alone reference are dead weight (~85% of the rows).
        Returns the number of checkpoints removed.
        """
        token = _TENANT.set(tenant_of_thread(thread_id))
        try:
            async with self._cursor(pipeline=False) as cur:
                await cur.execute(
                    """
                    WITH latest AS (
                        SELECT checkpoint_ns, max(checkpoint_id) AS checkpoint_id
                        FROM checkpoints WHERE thread_id = %(t)s GROUP BY checkpoint_ns
                    ), gone AS (
                        DELETE FROM checkpoints c
                        WHERE c.thread_id = %(t)s
                          AND NOT EXISTS (SELECT 1 FROM latest l
                                          WHERE l.checkpoint_ns = c.checkpoint_ns
                                            AND l.checkpoint_id = c.checkpoint_id)
                        RETURNING 1
                    ), writes AS (
                        DELETE FROM checkpoint_writes w
                        WHERE w.thread_id = %(t)s
                          AND NOT EXISTS (SELECT 1 FROM latest l
                                          WHERE l.checkpoint_ns = w.checkpoint_ns
                                            AND l.checkpoint_id = w.checkpoint_id)
                    ), blobs AS (
                        DELETE FROM checkpoint_blobs b
                        WHERE b.thread_id = %(t)s
                          AND NOT EXISTS (
                            SELECT 1 FROM checkpoints c
                            JOIN latest l ON l.checkpoint_ns = c.checkpoint_ns AND l.checkpoint_id = c.checkpoint_id
                            WHERE c.thread_id = %(t)s AND c.checkpoint_ns = b.checkpoint_ns
                              AND (c.checkpoint -> 'channel_versions' ->> b.channel) = b.version
                          )
                    )
                    SELECT count(*) AS removed FROM gone
                    """,
                    {"t": thread_id},
                )
                row = await cur.fetchone()
            return int(row["removed"]) if row else 0
        finally:
            _TENANT.reset(token)


def checkpoint_rls_statements(table: str) -> Sequence[str]:
    """Idempotent statements that put ``table`` under the tenant isolation policy."""
    predicate = (
        "(split_part(thread_id, ':', 1) = current_setting('app.tenant_id', true) OR (SELECT lgsotf_rls_bypass()))"
    )
    return (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS tenant_isolation ON {table}",
        f"CREATE POLICY tenant_isolation ON {table} USING {predicate} WITH CHECK {predicate}",
    )


async def secure_checkpoint_tables(conn: AsyncConnection[Any]) -> None:
    """Apply the tenant isolation policy to the checkpoint tables (psycopg async connection)."""
    for table in CHECKPOINT_RLS_TABLES:
        for statement in checkpoint_rls_statements(table):
            await conn.execute(statement)


__all__ = [
    "CHECKPOINT_RLS_TABLES",
    "TenantScopedPostgresSaver",
    "checkpoint_rls_statements",
    "secure_checkpoint_tables",
    "tenant_of_thread",
]
