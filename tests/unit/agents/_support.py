"""In-memory stand-ins for the repositories agents use, and scripted-model helpers."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence, Tuple

from langchain_core.messages import BaseMessage

from lg_sotf.agents.base import AgentContext
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
    raw: Dict[str, Any] = field(default_factory=dict)
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


class FakeSteps:
    """The investigation trace store: ``(tenant_id, alert_id, run_id, step)`` per appended step."""

    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str, Any]] = []
        self.error: Optional[Exception] = None

    async def append(self, tenant_id: str, alert_id: str, run_id: str, steps: Sequence[Any]) -> int:
        if self.error is not None:
            raise self.error
        self.rows.extend((tenant_id, alert_id, run_id, step) for step in steps)
        return len(steps)

    @property
    def steps(self) -> List[Any]:
        return [row[3] for row in self.rows]


class FakeBlindAudit:
    """No alert waits for a blind-audit label unless ``pending`` names it."""

    def __init__(self, pending: Sequence[str] = ()) -> None:
        self.pending = set(pending)

    async def pending_alert_ids(self, tenant_id: str, alert_ids: Sequence[str], **_: Any) -> set[str]:
        return self.pending & set(alert_ids)


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
        alerts=store, indicators=FakeIndicators(related), tenants=FakeTenants(tenant_settings), db=FakeDb(),
        investigation_steps=FakeSteps(), blind_audit=FakeBlindAudit(),
    )


def scripted(**script: List[Any]) -> ScriptedChatModel:
    return ScriptedChatModel(model_name="fake-scripted", script={k: list(v) for k, v in script.items()})


def factory(model: ScriptedChatModel) -> Any:
    def build(tier: str, settings: Settings) -> ScriptedChatModel:
        return model

    return build


def texts(messages: Sequence[BaseMessage]) -> List[str]:
    return [message_text(m) for m in messages]


# ------------------------------------------------------------- triage inputs

BENIGN = {
    "title": "Scheduled backup maintenance test",
    "rule_name": "scheduled-backup-maintenance-test",
    "severity": "low",
    "source_id": "prod-siem",
}
MALICIOUS = {
    "title": "Malware backdoor exploit detected",
    "severity": "critical",
    "source_id": "edr-prod",
    "raw": {"destination_port": 4444, "file_hash": "d41d8cd98f00b204e9800998ecf8427e"},
}
AMBIGUOUS = {
    "title": "Unusual outbound connection from workstation",
    "severity": "medium",
    "source_id": "fw-prod",
    "entities": {"ips": ["203.0.113.7"], "hosts": ["ws-042"]},
}
ASSESSMENT = {
    "threat_likelihood": 90,
    "threat_assessment": "likely_threat",
    "false_positive_indicators": [],
    "true_positive_indicators": ["beaconing interval"],
    "threat_categories": ["c2"],
    "urgency_level": "high",
    "recommended_actions": ["isolate host"],
    "reasoning": "Regular beaconing to a rare external address.",
}


def ctx(settings: Settings, **kwargs: Any) -> AgentContext:
    return AgentContext(tenant_id="t1", alert_id="a1", settings=settings, **kwargs)
