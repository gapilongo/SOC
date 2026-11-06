"""Scheduler leader election with a PostgreSQL session advisory lock.

The leader holds ``pg_try_advisory_lock(SCHEDULER_LEADER, 0)`` on a dedicated
connection. PostgreSQL releases the lock when that session ends, so a leader
that crashes or loses its connection is replaced as soon as the server
notices, which the session's TCP keepalive settings bound to about
``scheduler.leader_lease_s``; a follower retries on every
:meth:`LeaderLease.refresh`. The leader
verifies on every refresh that its session still holds the lock and steps
down on any error or timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
from typing import Any, Awaitable, Callable, Dict, Optional, Protocol

import asyncpg

from lg_sotf.db import locks
from lg_sotf.db.pool import build_ssl_arg, owner_dsn
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings

log = get_logger(__name__)

LEADER_KEY = (locks.SCHEDULER_LEADER, 0)


class LeaderConnection(Protocol):
    async def fetchval(self, query: str, *args: Any, timeout: Optional[float] = None) -> Any: ...  # noqa: ASYNC109

    async def close(self, *, timeout: Optional[float] = None) -> None: ...  # noqa: ASYNC109

    def terminate(self) -> None: ...

    def is_closed(self) -> bool: ...


ConnectFn = Callable[[], Awaitable[LeaderConnection]]


class LeaderState(enum.Enum):
    FOLLOWER = "follower"
    LEADER = "leader"


def keepalive_settings(lease_s: float) -> Dict[str, str]:
    """Server-side TCP keepalive for the leader session, scaled to the lease.

    The advisory lock is released only when PostgreSQL drops the session.
    After a silent host crash or partition that takes as long as the server's
    keepalive (often over two hours by default); these settings make the
    server notice a dead leader within about ``lease_s``.
    """
    lease = max(int(lease_s), 3)
    idle = max(lease // 3, 1)
    interval = max(lease // 6, 1)
    count = 3
    return {
        "tcp_keepalives_idle": str(idle),
        "tcp_keepalives_interval": str(interval),
        "tcp_keepalives_count": str(count),
        # Also bounds how long unacknowledged data (e.g. a lock notice) keeps a dead peer alive.
        "tcp_user_timeout": str(lease * 1000),
    }


def asyncpg_connector(settings: Settings, *, application_name: str = "lg-sotf-scheduler-leader") -> ConnectFn:
    dsn = owner_dsn(settings)
    ssl_arg = build_ssl_arg(settings.database.ssl_mode, settings.database.ssl_root_cert)
    server_settings = {"application_name": application_name, **keepalive_settings(settings.scheduler.leader_lease_s)}

    async def connect() -> LeaderConnection:
        kwargs: dict[str, Any] = {
            "dsn": dsn,
            "timeout": settings.database.command_timeout_s,
            "server_settings": dict(server_settings),
        }
        if ssl_arg is not None:
            kwargs["ssl"] = ssl_arg
        conn: LeaderConnection = await asyncpg.connect(**kwargs)
        return conn

    return connect


_HOLDS_LOCK_SQL = """
SELECT EXISTS (
    SELECT 1 FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND classid = $1::int::oid AND objid = $2::int::oid AND objsubid = 2
)
"""


class LeaderLease:
    """Follower/leader state machine driven by :meth:`refresh`."""

    def __init__(self, connect: ConnectFn, *, check_timeout_s: float = 5.0) -> None:
        self._connect = connect
        self._check_timeout_s = check_timeout_s
        self._conn: Optional[LeaderConnection] = None
        self._state = LeaderState.FOLLOWER
        self._lock = asyncio.Lock()

    @classmethod
    def from_settings(cls, settings: Settings) -> LeaderLease:
        return cls(asyncpg_connector(settings), check_timeout_s=max(1.0, settings.scheduler.leader_lease_s / 3))

    @property
    def state(self) -> LeaderState:
        return self._state

    @property
    def is_leader(self) -> bool:
        return self._state is LeaderState.LEADER

    async def refresh(self) -> bool:
        """Try to become leader, or confirm leadership. Returns whether this process leads now."""
        async with self._lock:
            if self._state is LeaderState.LEADER:
                if await self._still_holds():
                    return True
                await self._step_down("lock_lost")
                return False
            return await self._try_acquire()

    async def _try_acquire(self) -> bool:
        try:
            if self._conn is None or self._conn.is_closed():
                self._conn = await asyncio.wait_for(self._connect(), timeout=self._check_timeout_s * 2)
            acquired = await self._conn.fetchval(
                "SELECT pg_try_advisory_lock($1::int, $2::int)", *LEADER_KEY, timeout=self._check_timeout_s
            )
        except (OSError, TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            log.warning("leader.acquire_failed", error=type(exc).__name__)
            await self._drop_connection()
            return False
        if acquired:
            self._state = LeaderState.LEADER
            log.info("leader.acquired")
            return True
        return False

    async def _still_holds(self) -> bool:
        if self._conn is None or self._conn.is_closed():
            return False
        try:
            return bool(await self._conn.fetchval(_HOLDS_LOCK_SQL, *LEADER_KEY, timeout=self._check_timeout_s))
        except (OSError, TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            log.warning("leader.check_failed", error=type(exc).__name__)
            return False

    async def _step_down(self, reason: str) -> None:
        self._state = LeaderState.FOLLOWER
        # The session may still hold the lock (e.g. a slow check); closing it guarantees release.
        await self._drop_connection()
        log.warning("leader.stepped_down", reason=reason)

    async def _drop_connection(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None or conn.is_closed():
            return
        try:
            await conn.close(timeout=self._check_timeout_s)
        except (OSError, TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError):
            conn.terminate()

    async def release(self) -> None:
        """Give up leadership (graceful shutdown) and close the connection."""
        async with self._lock:
            was_leader = self._state is LeaderState.LEADER
            self._state = LeaderState.FOLLOWER
            if was_leader and self._conn is not None and not self._conn.is_closed():
                with contextlib.suppress(OSError, TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError):
                    await self._conn.fetchval(
                        "SELECT pg_advisory_unlock($1::int, $2::int)", *LEADER_KEY, timeout=self._check_timeout_s
                    )
            await self._drop_connection()
            if was_leader:
                log.info("leader.released")
