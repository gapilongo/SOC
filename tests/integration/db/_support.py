"""Helpers shared by the database tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import SecretStr

from lg_sotf.db.repos import NewAlert, Repositories
from lg_sotf.settings import DatabaseSettings

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"


def db_settings(url: str, **overrides: object) -> DatabaseSettings:
    values = {"url": SecretStr(url), "pool_min": 1, "pool_max": 8, "command_timeout_s": 30.0}
    values.update(overrides)
    return DatabaseSettings(**values)  # type: ignore[arg-type]


def new_alert(
    source_alert_id: Optional[str] = None,
    *,
    source_id: str = "splunk-prod",
    title: str = "Suspicious login",
    severity: str = "high",
    ingested_at: Optional[datetime] = None,
    occurred_at: Optional[datetime] = None,
    raw: Optional[Dict[str, Any]] = None,
    normalized: Optional[Dict[str, Any]] = None,
    **extra: object,
) -> NewAlert:
    return NewAlert(
        source_id=source_id,
        source_alert_id=source_alert_id or uuid4().hex,
        fingerprint=f"fp-{source_alert_id or 'x'}",
        title=title,
        severity=severity,
        occurred_at=occurred_at or datetime.now(UTC),
        ingested_at=ingested_at,
        raw={"vendor": "test"} if raw is None else raw,
        normalized={"title": title} if normalized is None else normalized,
        **extra,  # type: ignore[arg-type]
    )


async def make_alert(repos: Repositories, tenant_id: str, **kwargs: object) -> str:
    alert = new_alert(**kwargs)  # type: ignore[arg-type]
    ids = await repos.alerts.insert_many_if_absent(tenant_id, [alert])
    assert ids == [alert.id]
    return alert.id
