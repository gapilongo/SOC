"""Helpers for the service integration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Optional, Sequence, Tuple
from uuid import uuid4

from lg_sotf.db.repos import NewAlert, Repositories
from lg_sotf.security.hashing import hmac_indicator

HMAC_KEY = b"integration-test-indicator-key-0123456789"


async def add_alert(
    repos: Repositories,
    tenant_id: str,
    *,
    fingerprint: Optional[str] = None,
    severity: str = "high",
    title: str = "Suspicious activity",
    entities: Optional[Dict[str, Any]] = None,
) -> str:
    alert = NewAlert(
        source_id="api",
        source_alert_id=uuid4().hex,
        fingerprint=fingerprint or f"fp-{uuid4().hex}",
        title=title,
        severity=severity,
        occurred_at=datetime.now(UTC),
        raw={"vendor": "test"},
        normalized={"title": title, "severity": severity, "entities": dict(entities or {})},
    )
    ids = await repos.alerts.insert_many_if_absent(tenant_id, [alert])
    assert ids == [alert.id]
    return alert.id


async def sight(repos: Repositories, tenant_id: str, alert_id: str, indicators: Sequence[Tuple[str, str]]) -> None:
    now = datetime.now(UTC)
    await repos.indicators.add_sightings(
        tenant_id,
        alert_id,
        [(t, hmac_indicator(t, v, key=HMAC_KEY), v[:32], now) for t, v in indicators],
    )
