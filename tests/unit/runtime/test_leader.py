from __future__ import annotations

from typing import Any, List, Optional

import asyncpg

from lg_sotf.runtime.leader import LeaderLease, LeaderState, keepalive_settings


class FakeConn:
    def __init__(self, *, acquire: bool = True, holds: bool = True, fail: bool = False) -> None:
        self.acquire = acquire
        self.holds = holds
        self.fail = fail
        self.closed = False
        self.queries: List[str] = []

    async def fetchval(self, query: str, *args: Any, timeout: Optional[float] = None) -> Any:  # noqa: ASYNC109
        self.queries.append(query)
        if self.fail:
            raise asyncpg.ConnectionDoesNotExistError("gone")
        if "pg_try_advisory_lock" in query:
            return self.acquire
        if "pg_advisory_unlock" in query:
            return True
        return self.holds

    async def close(self, *, timeout: Optional[float] = None) -> None:  # noqa: ASYNC109
        self.closed = True

    def terminate(self) -> None:
        self.closed = True

    def is_closed(self) -> bool:
        return self.closed


class Connector:
    def __init__(self, *conns: FakeConn) -> None:
        self.conns = list(conns)
        self.calls = 0

    async def __call__(self) -> FakeConn:
        self.calls += 1
        if not self.conns:
            raise OSError("connection refused")
        return self.conns.pop(0)


async def test_follower_becomes_leader_when_lock_acquired() -> None:
    conn = FakeConn(acquire=True)
    lease = LeaderLease(Connector(conn))
    assert lease.state is LeaderState.FOLLOWER
    assert await lease.refresh() is True
    assert lease.is_leader
    assert await lease.refresh() is True
    assert any("pg_locks" in q for q in conn.queries)


async def test_stays_follower_while_lock_is_held_elsewhere_and_reuses_connection() -> None:
    conn = FakeConn(acquire=False)
    connector = Connector(conn)
    lease = LeaderLease(connector)
    assert await lease.refresh() is False
    assert await lease.refresh() is False
    assert connector.calls == 1
    assert not lease.is_leader


async def test_steps_down_when_connection_lost_and_reacquires_on_new_connection() -> None:
    first = FakeConn(acquire=True)
    second = FakeConn(acquire=True)
    lease = LeaderLease(Connector(first, second))
    assert await lease.refresh()
    first.fail = True
    assert await lease.refresh() is False
    assert lease.state is LeaderState.FOLLOWER
    assert first.closed
    assert await lease.refresh() is True


async def test_steps_down_when_session_no_longer_holds_lock() -> None:
    conn = FakeConn(acquire=True)
    lease = LeaderLease(Connector(conn))
    assert await lease.refresh()
    conn.holds = False
    assert await lease.refresh() is False
    assert conn.closed


async def test_connect_failure_leaves_follower() -> None:
    lease = LeaderLease(Connector())
    assert await lease.refresh() is False
    assert lease.state is LeaderState.FOLLOWER


async def test_release_unlocks_and_closes() -> None:
    conn = FakeConn(acquire=True)
    lease = LeaderLease(Connector(conn))
    await lease.refresh()
    await lease.release()
    assert not lease.is_leader
    assert conn.closed
    assert any("pg_advisory_unlock" in q for q in conn.queries)


def test_keepalive_settings_detect_a_dead_leader_within_about_the_lease() -> None:
    for lease_s in (3, 10, 30, 120):
        cfg = keepalive_settings(lease_s)
        idle, interval, count = (
            int(cfg[k]) for k in ("tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count")
        )
        assert idle >= 1 and interval >= 1
        assert idle + interval * count <= max(lease_s, 4)
        assert int(cfg["tcp_user_timeout"]) == lease_s * 1000
