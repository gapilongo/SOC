"""Helpers for ingestion unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.db.repos import Source
from lg_sotf.ingestion.normalizers import NormalizeContext

NOW = datetime(2024, 3, 5, 12, 0, 0, tzinfo=UTC)


def ctx(source_type: str, config: Optional[Mapping[str, Any]] = None, source_id: str = "src-1") -> NormalizeContext:
    return NormalizeContext(source_id=source_id, source_type=source_type, config=dict(config or {}), now=NOW)


def make_source(
    source_type: str,
    config: Optional[Dict[str, Any]] = None,
    *,
    source_id: str = "src-1",
    tenant_id: str = "tenant-a",
    cursor: Optional[Dict[str, Any]] = None,
    secret_ciphertext: Optional[str] = None,
) -> Source:
    return Source(
        id=source_id,
        tenant_id=tenant_id,
        type=source_type,
        name=f"{source_type} test",
        enabled=True,
        config=config or {},
        secret_ciphertext=secret_ciphertext,
        poll_interval_s=60,
        cursor=cursor,
        cursor_watermark=None,
        last_polled_at=None,
        next_poll_at=None,
        consecutive_failures=0,
        last_error=None,
        health="unknown",
        created_at=NOW,
        updated_at=NOW,
    )


class FakeClock:
    """Async sleep that records delays instead of waiting."""

    def __init__(self) -> None:
        self.sleeps: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


PUBLIC_ADDRESS = "93.184.216.34"


async def public_resolver(host: str, port: int) -> Sequence[str]:
    """Resolves every name to one public address (tests never touch DNS)."""
    return [PUBLIC_ADDRESS]


class MapResolver:
    """Resolves from a fixed table and records lookups."""

    def __init__(self, table: Mapping[str, Sequence[str]]):
        self.table = dict(table)
        self.lookups: List[str] = []

    async def __call__(self, host: str, port: int) -> Sequence[str]:
        self.lookups.append(host)
        return list(self.table.get(host, [PUBLIC_ADDRESS]))
