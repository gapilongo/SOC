"""EscalationService: level, priority and SLA policy; idempotent creation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

from lg_sotf.services.escalation import EscalationService, compute_level, compute_priority
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeAudit, FakeEvents

NOW = datetime(2026, 9, 1, tzinfo=UTC)


class FakeEscalations:
    def __init__(self) -> None:
        self.active: Dict[str, Any] = {}
        self.created: List[Dict[str, Any]] = []

    async def get_active_for_alert(self, tenant_id: str, alert_id: str) -> Optional[Any]:
        return self.active.get(alert_id)

    async def create_or_attach(self, tenant_id: str, alert_id: str, **kw: Any) -> Any:
        if alert_id in self.active:
            return self.active[alert_id], False
        esc = SimpleNamespace(id=f"esc-{len(self.created)}", level=kw["level"], priority=kw["priority"],
                              sla_deadline=kw["sla_deadline"])
        self.created.append(kw)
        self.active[alert_id] = esc
        return esc, True


def test_priority_and_level() -> None:
    low = compute_priority(severity="low", threat_score=20, confidence=60, correlations_count=0, reason_code="false_positive_review")
    high = compute_priority(severity="critical", threat_score=90, confidence=20, correlations_count=12, reason_code="high_risk")
    assert low == 1 and high == 10
    assert compute_level(priority=10, threat_score=10, severity="low", reason_code="x") == "L3"
    assert compute_level(priority=8, threat_score=10, severity="low", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=85, severity="low", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=20, severity="critical", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=20, severity="low", reason_code="grey_zone") == "L1"


async def test_open_is_idempotent_and_audited(make_settings: Callable[..., Settings]) -> None:
    escalations, audit, events = FakeEscalations(), FakeAudit(), FakeEvents()
    repos = SimpleNamespace(escalations=escalations, audit=audit)
    service = EscalationService(repos, events, make_settings(agents={"human_loop": {"sla_minutes": {"L1": 15}}}))  # type: ignore[arg-type]
    kwargs = dict(severity="medium", confidence=50, threat_score=40, reason="grey zone", now=NOW)
    first = await service.open_or_attach("t1", "a1", **kwargs)
    second = await service.open_or_attach("t1", "a1", **kwargs)
    assert first.created and not second.created and first.id == second.id
    assert len(escalations.created) == 1 and len(audit.entries) == 1
    assert [e["type"] for e in events.events] == ["escalation.created"]
    assert first.level == "L1" and first.sla_deadline == NOW + timedelta(minutes=15)
    assert service.sla_minutes("L2") == 60 and service.sla_minutes("L3") == 120
