"""Helpers of the blind audit API tests (PRD-10.2): seeded auto-closed alerts, runs, the queue and the
check that nothing of the AI's side reaches an analyst before the label."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Tuple

from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

API = "/api/v1"
START = datetime(2026, 10, 5, tzinfo=UTC)  # a Monday
END = START + timedelta(days=7)
WINDOW = {"from": START.isoformat(), "to": END.isoformat()}
VERDICT_MARKER = "model-conclusion-marker-41c9"
# Keys that carry the AI's side of an alert; none may appear before the label exists.
AI_KEYS = {"disposition", "confidence", "threat_score", "priority", "summary", "verdict", "routing", "close_reason",
           "conclusion", "ai_class", "agreement", "findings", "status"}


async def closed_alert(
    repos: Repositories,
    tenant_id: str,
    closed_at: datetime,
    *,
    disposition: Optional[str] = "benign",
    summary: Optional[Dict[str, Any]] = None,
    source_id: str = "splunk",
    title: str = "Auto-closed alert",
) -> str:
    """An alert automation closed at ``closed_at`` with the AI's verdict fields set."""
    alert_id = await make_alert(
        repos, tenant_id, source_id=source_id, title=title, raw={"event": "logon", "host": "ws-17"},
        normalized={"title": title, "entities": {"hosts": ["ws-17"], "users": ["j.doe"]}},
    )
    body = {
        "verdict": disposition, "close_reason": "triage:false_positive", "confidence": 87.5, "threat_score": 12.0,
        "analysis": {"conclusion": f"{VERDICT_MARKER}: routine logon.", "verdict": disposition},
        "decision": {"route": "close", "code": "auto_close", "reason": VERDICT_MARKER},
        **(summary or {}),
    }
    async with repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE alerts SET status = 'closed', disposition = $3, confidence = 87.5, threat_score = 12, "
            "priority = 2, closed_at = $4, summary = $5 WHERE tenant_id = $1 AND id = $2",
            tenant_id, alert_id, disposition, closed_at, body,
        )
    return alert_id


async def seed_frame(repos: Repositories, n: int = 30) -> List[str]:
    """``n`` eligible alerts in the window, and one of each kind the frame leaves out."""
    eligible = [await closed_alert(repos, TENANT_A, START + timedelta(hours=3 * i)) for i in range(n)]
    eligible.append(await closed_alert(repos, TENANT_A, START + timedelta(hours=1), disposition=None))
    middle = START + timedelta(days=2)
    await closed_alert(repos, TENANT_A, middle, disposition="malicious")  # the AI acted on it
    await closed_alert(repos, TENANT_A, middle, summary={"analyst_decision": "false_positive"})  # a person decided
    await closed_alert(repos, TENANT_A, START - timedelta(seconds=1))  # before the window
    await closed_alert(repos, TENANT_A, END)  # the window's end is exclusive
    await closed_alert(repos, TENANT_A, middle, source_id=SAMPLE_SOURCE_ID)  # built-in sample
    await closed_alert(repos, TENANT_B, middle)  # another tenant
    approved = await closed_alert(repos, TENANT_A, middle)  # a person approved one of its actions
    action, _ = await repos.actions.propose(TENANT_A, approved, "block_ip", "203.0.113.9", "low")
    async with repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'succeeded', approved_by = $2 WHERE id = $1",
            action.id, "8e0cbb2c-6f37-4a8f-9b43-0d5f1c3d2a10",
        )
    return eligible


async def sample(api: ApiHarness, headers: Dict[str, str], **body: Any) -> Dict[str, Any]:
    response = await api.client.post(f"{API}/blind-audit/runs", json={**WINDOW, **body}, headers=headers)
    assert response.status_code == 201, response.text
    return dict(response.json())


async def queue(api: ApiHarness, headers: Dict[str, str], status: str = "pending") -> List[Dict[str, Any]]:
    response = await api.client.get(f"{API}/blind-audit/items?status={status}&limit=200", headers=headers)
    assert response.status_code == 200, response.text
    return list(response.json()["items"])


def keys_and_strings(value: Any) -> Iterator[Tuple[Optional[str], Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from keys_and_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from keys_and_strings(item)


def assert_blind(body: Any) -> None:
    """No AI key anywhere in the JSON (``reveal`` may only be null) and no trace of the model's text."""
    for key, value in keys_and_strings(body):
        if key == "reveal":
            assert value is None, "the verdict was revealed before the label"
        assert key not in AI_KEYS, f"{key} reached the analyst before the label"
    text = str(body)
    for leak in (VERDICT_MARKER, "triage:false_positive", "auto_close", "87.5"):
        assert leak not in text


async def alert_of(api: ApiHarness, item: Dict[str, Any], tenant_id: str = TENANT_A) -> str:
    """The sampled alert's id (the API hands out only the item id)."""
    return (await api.repos.blind_audit.get_item(tenant_id, item["id"])).alert_id


