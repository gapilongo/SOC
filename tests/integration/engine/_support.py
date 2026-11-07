"""Helpers shared by the engine tests."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Union, get_args, get_origin, get_type_hints, is_typeddict
from uuid import UUID, uuid4

from lg_sotf.core.workflow import RunOutcome, WorkflowEngine
from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, make_alert


class RecordingEvents:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        assert event["tenant_id"] == tenant_id
        self.events.append(event)

    def of_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == event_type]


def undeclared_keys(value: Any, schema: Any, path: str = "summary") -> List[str]:
    """Keys of ``value`` its TypedDict ``schema`` does not declare, nested TypedDicts (in lists too) included."""
    if get_origin(schema) is Union:
        return [p for arg in get_args(schema) if arg is not type(None) for p in undeclared_keys(value, arg, path)]
    if get_origin(schema) in (list, List) and isinstance(value, list):
        (item,) = get_args(schema)
        return [p for i, v in enumerate(value) for p in undeclared_keys(v, item, f"{path}[{i}]")]
    if not is_typeddict(schema) or not isinstance(value, Mapping):
        return []
    hints = get_type_hints(schema)
    out = [f"{path}.{key}" for key in value if key not in hints]
    for key, child in value.items():
        if key in hints:
            out.extend(undeclared_keys(child, hints[key], f"{path}.{key}"))
    return out


SUSPICIOUS_ENTITIES = {
    "ips": ["185.220.101.44", "10.0.0.5"],
    "hosts": ["ws-042"],
    "users": ["jdoe"],
    "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
    "processes": ["powershell.exe"],
}


async def suspicious_alert(repos: Repositories, tenant_id: str = TENANT_A, **kwargs: Any) -> str:
    return await make_alert(
        repos,
        tenant_id,
        title="Possible C2 beacon from workstation",
        severity="medium",
        normalized={"entities": SUSPICIOUS_ENTITIES},
        raw={"vendor": "edr"},
        **kwargs,
    )


async def analyst(repos: Repositories, tenant_id: str = TENANT_A) -> str:
    user = await repos.users.create(tenant_id, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")
    return str(user.id)


async def decide(
    engine: WorkflowEngine, repos: Repositories, alert_id: str, escalation_id: str, decision: str, user_id: str,
    tenant_id: str = TENANT_A, **extra: Any,
) -> RunOutcome:
    """What the API does: record the decision with the analyst's version, then resume."""
    esc = await repos.escalations.get(tenant_id, escalation_id)
    await repos.escalations.decide(
        tenant_id, escalation_id, decision=decision, decided_by=UUID(user_id),
        expected_version=esc.version,
    )
    payload: Dict[str, Any] = {
        "type": "analyst_decision",
        "escalation_id": escalation_id,
        "decision": decision,
        "approved_actions": [],
        "decided_by": user_id,
        "notes": "",
    }
    payload.update(extra)
    return await engine.resume(tenant_id, alert_id, payload)
