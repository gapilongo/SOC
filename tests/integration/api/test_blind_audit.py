"""``/blind-audit`` and ``GET /reports/blind-audit`` (PRD-10.2).

The frame and the seeded draw match the pure definition; the AI verdict never
reaches the analyst before the label exists (checked on the JSON of every
read, not in the UI); a malicious label opens an audited escalation; the
estimate is exact on a fixture; tenants are isolated; the weekly scheduled
run and the tenant setting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.domain.blind_audit import draw
from lg_sotf.services.blind_audit import BlindAuditService, week_window
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

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


async def test_sampling_is_the_seeded_uniform_draw_over_the_recorded_frame(api: ApiHarness) -> None:
    eligible = await seed_frame(api.repos)
    admin = await api.login_headers(TENANT_A, "admin")

    run = await sample(api, admin, seed=20261005, size=8)

    assert run["frame_size"] == len(eligible) == 31 and run["sample_size"] == 8 and run["seed"] == 20261005
    assert (run["window_start"], run["trigger"], run["fixed_size"], run["sample_rate"]) == (
        "2026-10-05T00:00:00Z", "api", 8, None,
    )
    items = await queue(api, await api.login_headers(TENANT_A, "analyst"))
    by_rank = sorted(items, key=lambda i: i["sample_rank"])
    # Reproducible: the same seed over the same frame gives the same alerts, in the same order.
    assert [i["alert"]["id"] for i in by_rank] == draw(eligible, 20261005, 8)
    assert {i["run_id"] for i in items} == {run["id"]}

    # Windows never overlap, so no alert is in two frames.
    again = await api.client.post(f"{API}/blind-audit/runs", json={**WINDOW, "seed": 1}, headers=admin)
    assert again.status_code == 409 and again.json()["error"]["code"] == "window_already_sampled"
    # The rate rule over the rest of the window: 2% of the frame, at least 5 a week.
    rest = await sample(api, admin, **{"from": END.isoformat(), "to": (END + timedelta(days=7)).isoformat()})
    assert rest["frame_size"] == 1 and rest["sample_size"] == 1  # the alert closed exactly at END
    listed = (await api.client.get(f"{API}/blind-audit/runs", headers=await api.login_headers(TENANT_A, "viewer")))
    assert [r["id"] for r in listed.json()["items"]] == [rest["id"], run["id"]]
    assert [e.action for e in (await api.repos.audit.list(TENANT_A)).items].count("blind_audit.sampled") == 2


async def test_sampling_validation_and_roles(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.post(f"{API}/blind-audit/runs", json=WINDOW, headers=analyst)).status_code == 403
    backwards = {"from": END.isoformat(), "to": START.isoformat()}
    response = await api.client.post(f"{API}/blind-audit/runs", json=backwards, headers=admin)
    assert response.status_code == 400 and response.json()["error"]["code"] == "invalid_window"
    future = {"from": (datetime.now(UTC) + timedelta(days=1)).isoformat()}
    assert (await api.client.post(f"{API}/blind-audit/runs", json=future, headers=admin)).status_code == 400
    assert (await api.client.post(f"{API}/blind-audit/runs", json={"size": 0}, headers=admin)).status_code == 422
    viewer = await api.login_headers(TENANT_A, "viewer")
    assert (await api.client.get(f"{API}/blind-audit/items", headers=viewer)).status_code == 403
    key = await api.key_headers(TENANT_A, ["read", "write"])
    assert (await api.client.get(f"{API}/blind-audit/items", headers=key)).status_code == 403  # people label


async def test_the_verdict_is_hidden_until_the_item_is_labelled(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=3)
    await sample(api, await api.login_headers(TENANT_A, "admin"), seed=7, size=2)
    analyst = await api.login_headers(TENANT_A, "analyst")

    listed = await queue(api, analyst)
    assert len(listed) == 2
    assert_blind(listed)
    item_id = listed[0]["id"]
    detail = await api.client.get(f"{API}/blind-audit/items/{item_id}", headers=analyst)
    assert detail.status_code == 200
    body = detail.json()
    assert_blind(body)
    # The evidence is there: the source event, the normalized fields and the entities.
    assert body["alert"]["raw"] == {"event": "logon", "host": "ws-17"}
    assert body["alert"]["entities_preview"]["counts"] == {"user": 1, "host": 1}
    assert body["alert"]["severity"] == "high" and body["alert"]["title"] == "Auto-closed alert"

    labelled = await api.client.post(
        f"{API}/blind-audit/items/{item_id}/label", json={"label": "benign", "notes": "routine"}, headers=analyst
    )
    assert labelled.status_code == 200, labelled.text
    out = labelled.json()
    assert out["escalation_created"] is False and out["item"]["label"] == "benign"
    reveal = out["item"]["reveal"]
    assert reveal["ai_class"] in ("benign", "inconclusive") and reveal["agreement"] is (reveal["ai_class"] == "benign")
    assert (reveal["confidence"], reveal["threat_score"], reveal["close_reason"]) == (87.5, 12.0, "triage:false_positive")
    assert reveal["conclusion"].startswith(VERDICT_MARKER) and reveal["routing_code"] == "auto_close"
    again = await api.client.get(f"{API}/blind-audit/items/{item_id}", headers=analyst)
    assert again.json()["reveal"] == reveal
    # The other item is still blind, and a label is given once.
    assert_blind((await api.client.get(f"{API}/blind-audit/items/{listed[1]['id']}", headers=analyst)).json())
    relabel = await api.client.post(
        f"{API}/blind-audit/items/{item_id}/label", json={"label": "malicious"}, headers=analyst
    )
    assert relabel.status_code == 409
    assert [i["id"] for i in await queue(api, analyst, "labelled")] == [item_id]
    assert [i["id"] for i in await queue(api, analyst)] == [listed[1]["id"]]


async def test_a_malicious_label_opens_an_audited_escalation(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=1)
    await sample(api, await api.login_headers(TENANT_A, "admin"), seed=3, size=1)
    analyst_user = await api.user(TENANT_A, "analyst")
    analyst = api.auth(analyst_user)
    [item] = await queue(api, analyst)

    response = await api.client.post(
        f"{API}/blind-audit/items/{item['id']}/label", json={"label": "malicious", "notes": "beacon"}, headers=analyst
    )

    assert response.status_code == 200, response.text
    out = response.json()
    assert out["escalation_created"] is True and out["item"]["reveal"]["agreement"] is False
    escalation = await api.repos.escalations.get(TENANT_A, out["escalation_id"])
    assert escalation.alert_id == item["alert"]["id"] and escalation.status == "open"
    assert escalation.summary["routing"] == {"code": "blind_audit"}
    assert escalation.summary["blind_audit_item_id"] == item["id"] and escalation.summary["analyst_notes"] == "beacon"
    assert escalation.sla_deadline is not None
    entries = {e.action: e for e in (await api.repos.audit.list(TENANT_A)).items}
    assert entries["blind_audit.labelled"].details["escalation_id"] == escalation.id
    assert entries["blind_audit.labelled"].actor_id == str(analyst_user.id)
    assert entries["escalation.created"].details["reason_code"] == "blind_audit"
    assert entries["escalation.created"].actor_id == str(analyst_user.id)
    stored = await api.repos.blind_audit.get_item(TENANT_A, item["id"])
    assert (stored.label, stored.labelled_by, stored.escalation_id) == ("malicious", analyst_user.id, escalation.id)


async def test_estimate_on_a_fixture(api: ApiHarness) -> None:
    """32 samples from a frame of 32: 2 malicious, 28 benign, 1 unsure, 1 pending."""
    await seed_frame(api.repos, n=31)
    run = await sample(api, await api.login_headers(TENANT_A, "admin"), seed=11, size=32)
    analyst = await api.login_headers(TENANT_A, "analyst")
    items = await queue(api, analyst)
    labels = ["malicious"] * 2 + ["benign"] * 28 + ["unsure"]
    for item, label in zip(items, labels, strict=False):
        response = await api.client.post(f"{API}/blind-audit/items/{item['id']}/label", json={"label": label},
                                         headers=analyst)
        assert response.status_code == 200, response.text

    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get(f"{API}/reports/blind-audit?from=2026-10-01&to=2026-10-31", headers=viewer)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["from"], body["to"]) == ("2026-10-01", "2026-10-31")
    e = body["estimate"]
    assert (e["frame_size"], e["sampled"], e["labelled"], e["pending"]) == (run["frame_size"], 32, 31, 1)
    assert (e["malicious"], e["benign"], e["unsure"], e["status"]) == (2, 28, 1, "ok")
    fn = e["false_negative_rate"]
    assert fn["n"] == 30 and fn["rate"] == pytest.approx(2 / 30)
    assert fn["ci_low"] == pytest.approx(0.018477, abs=1e-6) and fn["ci_high"] == pytest.approx(0.213235, abs=1e-6)
    assert e["estimated_missed"] == pytest.approx(round(2 / 30 * 32, 2))
    assert e["summary"] == "6.7% (2 of 30; 95% CI 1.8% to 21.3%)"
    assert [r["id"] for r in body["runs"]] == [run["id"]] and body["runs"][0]["malicious"] == 2

    # Another tenant's report and an empty window: the small-sample wording.
    other = await api.client.get(
        f"{API}/reports/blind-audit?from=2026-10-01&to=2026-10-31", headers=await api.login_headers(TENANT_B, "viewer")
    )
    assert other.json()["estimate"]["summary"] == "Not enough data (n=0; at least 30 needed)"


async def test_tenants_are_isolated(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=2)
    await sample(api, await api.login_headers(TENANT_A, "admin"), seed=5, size=2)
    [item, *_] = await queue(api, await api.login_headers(TENANT_A, "analyst"))
    other = await api.login_headers(TENANT_B, "analyst")

    assert await queue(api, other) == []
    assert (await api.client.get(f"{API}/blind-audit/items/{item['id']}", headers=other)).status_code == 404
    label = await api.client.post(f"{API}/blind-audit/items/{item['id']}/label", json={"label": "benign"}, headers=other)
    assert label.status_code == 404
    runs = await api.client.get(f"{API}/blind-audit/runs", headers=other)
    assert runs.json()["items"] == []
    # Below the API: tenant B's transaction sees none of tenant A's rows (RLS, no tenant filter in the query).
    async with api.repos.db.tenant_tx(TENANT_B, readonly=True) as conn:
        assert await conn.fetchval("SELECT count(*) FROM blind_audit_items") == 0
        assert await conn.fetchval("SELECT count(*) FROM blind_audit_runs") == 0
    assert (await api.repos.blind_audit.get_item(TENANT_A, item["id"])).label is None


async def test_scheduled_weekly_run_and_tenant_setting(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    bad = await api.client.patch(f"{API}/tenant/settings", json={"blind_audit": {"sample_rate": 2}}, headers=admin)
    assert bad.status_code == 422 and "blind_audit.sample_rate" in bad.text
    ok = await api.client.patch(
        f"{API}/tenant/settings", json={"blind_audit": {"enabled": True, "sample_rate": 0.1, "min_per_week": 2}},
        headers=admin,
    )
    assert ok.status_code == 200, ok.text
    now = datetime.now(UTC)
    week_start, week_end = week_window(now)
    for i in range(30):
        await closed_alert(api.repos, TENANT_A, week_start + timedelta(hours=5 * i))
    service = BlindAuditService(api.repos)

    run = await service.sample_due(TENANT_A, now=now)

    assert run is not None and (run.window_start, run.window_end) == (week_start, week_end)
    assert (run.frame_size, run.sample_size, run.trigger, run.sample_rate, run.min_sample) == (30, 3, "schedule", 0.1, 2)
    assert await service.sample_due(TENANT_A, now=now) is None  # the week is sampled
    assert await service.sample_due(TENANT_B, now=now) is None  # not enabled
