"""Round 2 of the review of PR #308 (blind audit), as passing proofs of the fixed behaviour.

The reviewer recovered a pending sample's verdict through the dashboard (window differencing), another
alert's correlation digest, the timeline's node path, the escalation routes and a reprocess. Each test
now asserts the path is closed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict

import pytest

from tests.integration.api._blind_audit import API, alert_of, closed_alert, queue
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def _one_sample(api: ApiHarness, ingested_hours_ago: float, disposition: str = "benign") -> str:
    now = datetime.now(UTC)
    alert_id = await closed_alert(api.repos, TENANT_A, now - timedelta(hours=2), disposition=disposition)
    async with api.repos.db.system_tx() as conn:
        await conn.execute("UPDATE alerts SET ingested_at = $2, occurred_at = $2 WHERE id = $1", alert_id,
                           now - timedelta(hours=ingested_hours_ago))
    admin = await api.login_headers(TENANT_A, "admin")
    r = await api.client.post(f"{API}/blind-audit/runs", json={"from": (now - timedelta(days=3)).isoformat(), "size": 1},
                              headers=admin)
    assert r.status_code == 201, r.text
    [item] = await queue(api, await api.login_headers(TENANT_A, "analyst"))
    assert await alert_of(api, item) == alert_id and item["label"] is None
    return alert_id


async def test_R1_dashboard_window_differencing_does_not_reveal_a_pending_samples_disposition(api: ApiHarness) -> None:
    # Background traffic in other hours.
    for hours, disp in ((2, "malicious"), (5, "benign"), (40, "malicious")):
        other = await make_alert(api.repos, TENANT_A)
        async with api.repos.db.system_tx() as conn:
            await conn.execute("UPDATE alerts SET ingested_at = now() - make_interval(hours => $2), disposition = $3,"
                               " status = 'processing' WHERE id = $1", other, hours, disp)
    await _one_sample(api, ingested_hours_ago=30.5, disposition="benign")
    analyst = await api.login_headers(TENANT_A, "analyst")

    async def by_disp(hours: int) -> Dict[str, int]:
        r = await api.client.get(f"{API}/dashboard/summary?window_hours={hours}", headers=analyst)
        assert r.status_code == 200, r.text
        return dict(r.json()["by_disposition"])

    wide, narrow = await by_disp(31), await by_disp(30)
    diff = {k: wide.get(k, 0) - narrow.get(k, 0) for k in set(wide) | set(narrow)}
    # The only alert ingested 30-31 h ago is the pending sample: the dashboard leaves it out.
    assert {k: v for k, v in diff.items() if v} == {}


async def test_R2_another_alerts_correlation_digest_no_longer_names_the_pending_sample(api: ApiHarness) -> None:
    sampled = await _one_sample(api, ingested_hours_ago=3, disposition="benign")
    analyst = await api.login_headers(TENANT_A, "analyst")
    listed = (await api.client.get(f"{API}/alerts?limit=200", headers=analyst)).json()["items"]
    assert [a["id"] for a in listed if a["hidden_for_blind_audit"]] == [sampled]
    # A later alert sharing an indicator, stored before the sample was drawn (agents/correlation/base.py).
    later = await make_alert(api.repos, TENANT_A, title="Later alert")
    await api.repos.alerts.update(TENANT_A, later, summary={"correlation": {
        "related_alert_ids": [sampled], "related_count": 1, "related_dispositions": {"benign": 1}}})
    body = (await api.client.get(f"{API}/alerts/{later}", headers=analyst)).json()
    assert body["hidden_for_blind_audit"] is False
    assert body["summary"]["correlation"] == {"related_alert_ids": [], "related_count": 0, "related_dispositions": {}}
    [row] = [a for a in (await api.client.get(f"{API}/alerts?limit=200", headers=analyst)).json()["items"]
             if a["id"] == later]
    assert row["summary"]["correlation"]["related_dispositions"] == {}
    pack = (await api.client.get(f"{API}/alerts/{later}/evidence", headers=analyst)).json()
    assert pack["correlation"]["digest"]["related_alert_ids"] == [] and sampled not in str(pack["alert"]["summary"])


async def test_R3_a_hidden_timeline_shows_only_ingestion_and_notes(api: ApiHarness) -> None:
    sampled = await _one_sample(api, ingested_hours_ago=3)
    for node in ("gate", "close"):
        await api.repos.alert_events.append(TENANT_A, sampled, "node.completed", node=node,
                                            data={"suppressed": True, "verdict_cache": True})
    await api.repos.alert_events.append(TENANT_A, sampled, "note", data={"text": "a person's note"})
    analyst = await api.login_headers(TENANT_A, "analyst")
    events = (await api.client.get(f"{API}/alerts/{sampled}/events", headers=analyst)).json()["items"]
    # The node path (gate straight to close: suppressed, closed benign) is not shown at all.
    assert [e["event_type"] for e in events] == ["note"]
    pack = (await api.client.get(f"{API}/alerts/{sampled}/evidence", headers=analyst)).json()
    assert [e["event_type"] for e in pack["timeline"]] == ["note"]


async def test_R4_escalation_routes_are_hidden_for_a_pending_sample(api: ApiHarness) -> None:
    sampled = await _one_sample(api, ingested_hours_ago=3)
    esc, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, sampled, reason="analysis verdict benign at 91% confidence",
        sla_deadline=datetime.now(UTC) + timedelta(hours=1),
        summary={"verdict": "benign", "confidence": 91.0, "routing": {"code": "inconclusive"}})
    action, _ = await api.repos.actions.propose(TENANT_A, sampled, "block_ip", "203.0.113.9", "low")
    await api.repos.audit.append(TENANT_A, "agent", "workflow", "escalation.created", "escalation", esc.id,
                                 {"alert_id": sampled, "verdict": "benign"})
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.get(f"{API}/escalations/{esc.id}", headers=analyst)).status_code == 404
    assert (await api.client.get(f"{API}/escalations/{esc.id}/response-preview", headers=analyst)).status_code == 404
    listed = (await api.client.get(f"{API}/escalations?alert_id={sampled}", headers=analyst)).json()
    assert listed["items"] == []
    assert (await api.client.get(f"{API}/actions/{action.id}", headers=analyst)).status_code == 404
    assert (await api.client.get(f"{API}/actions?alert_id={sampled}", headers=analyst)).json()["items"] == []
    admin = await api.login_headers(TENANT_A, "admin")
    entries = (await api.client.get(f"{API}/audit?resource_id={esc.id}", headers=admin)).json()["items"]
    assert entries and all(e["details"] == {"hidden_for_blind_audit": True} and e["redacted"] for e in entries)
    pack = (await api.client.get(f"{API}/alerts/{sampled}/evidence", headers=analyst)).json()
    assert pack["escalations"] == [] and pack["actions"] == [] and pack["feedback"] == []
    assert pack["audit"]["entries"] == [] and "91%" not in str(pack)


async def test_R5_a_pending_sample_cannot_be_reprocessed(api: ApiHarness) -> None:
    sampled = await _one_sample(api, ingested_hours_ago=3)
    admin = await api.login_headers(TENANT_A, "admin")
    r = await api.client.post(f"{API}/alerts/{sampled}/reprocess", headers=admin)
    assert r.status_code == 409 and r.json()["error"]["code"] == "hidden_for_blind_audit"
    assert (await api.repos.alerts.get(TENANT_A, sampled)).status == "closed"
