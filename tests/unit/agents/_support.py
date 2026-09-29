"""In-memory stand-ins for the repositories agents use, and scripted-model helpers."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence, Tuple

from langchain_core.messages import BaseMessage

from lg_sotf.db.errors import NotFound
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.llm.fake import _message_text as message_text
from lg_sotf.settings import Settings

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


@dataclass
class Related:
    alert_id: str
    shared_indicator_count: int
    last_seen: datetime


@dataclass
class StoredAlert:
    id: str
    title: str = "Stored alert"
    severity: str = "medium"
    category: Optional[str] = None
    status: str = "closed"
    disposition: Optional[str] = None
    occurred_at: datetime = NOW
    normalized: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)


class FakeAlerts:
    def __init__(self, alerts: Sequence[StoredAlert] = ()) -> None:
        self.rows: Dict[Tuple[str, str], StoredAlert] = {}
        self.updates: List[Dict[str, Any]] = []
        for a in alerts:
            self.add("t1", a)

    def add(self, tenant_id: str, alert: StoredAlert) -> None:
        self.rows[(tenant_id, alert.id)] = alert

    async def get(self, tenant_id: str, alert_id: str, *, conn: Any = None) -> StoredAlert:
        try:
            return self.rows[(tenant_id, alert_id)]
        except KeyError:
            raise NotFound("alert", alert_id) from None

    async def update(self, tenant_id: str, alert_id: str, *, summary: Any = None, conn: Any = None, **_: Any) -> Any:
        alert = await self.get(tenant_id, alert_id)
        if summary is not None:
            alert.summary = {**alert.summary, **dict(summary)}
            self.updates.append(dict(summary))
        return alert


class FakeIndicators:
    def __init__(self, related: Sequence[Related] = ()) -> None:
        self.related = list(related)
        self.sightings: List[Tuple[Any, ...]] = []
        self.queries: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []

    async def add_sightings(self, tenant_id: str, alert_id: str, sightings: Any) -> int:
        self.sightings.extend(sightings)
        return len(sightings)

    async def related_alerts(self, tenant_id: str, indicators: Any, **kwargs: Any) -> List[Related]:
        self.queries.append(((tenant_id, tuple(indicators)), kwargs))
        return self.related[: kwargs.get("limit", 20)]


class FakeTenants:
    def __init__(self, settings: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.settings = settings or {}
        self.reads = 0

    async def get(self, tenant_id: str, *, conn: Any = None) -> Any:
        self.reads += 1
        return SimpleNamespace(id=tenant_id, settings=self.settings.get(tenant_id, {}))


class FakeDb:
    def __init__(self) -> None:
        self.transactions = 0

    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str, **_: Any) -> AsyncIterator[Any]:
        self.transactions += 1
        yield SimpleNamespace(tenant_id=tenant_id)


def fake_repos(
    *,
    alerts: Sequence[StoredAlert] = (),
    related: Sequence[Related] = (),
    tenant_settings: Optional[Dict[str, Dict[str, Any]]] = None,
    current: Optional[StoredAlert] = None,
) -> Any:
    """Repositories stand-in; ``current`` (default id ``a1``) is the alert being processed."""
    store = FakeAlerts(alerts)
    store.add("t1", current or StoredAlert(id="a1", status="processing"))
    return SimpleNamespace(
        alerts=store, indicators=FakeIndicators(related), tenants=FakeTenants(tenant_settings), db=FakeDb()
    )


def scripted(**script: List[Any]) -> ScriptedChatModel:
    return ScriptedChatModel(model_name="fake-scripted", script={k: list(v) for k, v in script.items()})


def factory(model: ScriptedChatModel) -> Any:
    def build(tier: str, settings: Settings) -> ScriptedChatModel:
        return model

    return build


def texts(messages: Sequence[BaseMessage]) -> List[str]:
    return [message_text(m) for m in messages]
