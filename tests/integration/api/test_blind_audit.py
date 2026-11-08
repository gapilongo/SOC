"""``/blind-audit`` and ``GET /reports/blind-audit`` (PRD-10.2).

The frame and the seeded draw match the pure definition; the AI verdict never
reaches the analyst before the label exists (checked on the JSON of every
read, not in the UI); a malicious label opens an audited escalation; the
estimate is exact on a fixture; tenants are isolated; the weekly scheduled
run and the tenant setting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.domain.blind_audit import draw
from lg_sotf.services.blind_audit import BlindAuditService, week_window
from tests.integration.api._blind_audit import (
    API,
    END,
    START,
    VERDICT_MARKER,
    WINDOW,
    alert_of,
    assert_blind,
    closed_alert,
    queue,
    sample,
    seed_frame,
)
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

async def test_sampling_is_the_uniform_draw_of_a_server_seed_over_the_recorded_frame(api: ApiHarness) -> None:
    eligible = await seed_frame(api.repos)
    admin = await api.login_headers(TENANT_A, "admin")

    run = await sample(api, admin, size=8)

    assert run["frame_size"] == len(eligible) == 31 and run["sample_size"] == 8 and run["seed_source"] == "server"
    assert (run["window_start"], run["trigger"], run["fixed_size"], run["sample_rate"]) == (
        "2026-10-05T00:00:00Z", "api", 8, None,
    )
    items = await queue(api, await api.login_headers(TENANT_A, "analyst"))
    assert all("id" not in i["alert"] for i in items)  # the item id is the handle
    by_rank = sorted(items, key=lambda i: i["sample_rank"])
    # Reproducible: the recorded seed over the frame gives the same alerts, in the same order ...
    drawn = [await alert_of(api, i) for i in by_rank]
    assert drawn == draw(eligible, run["seed"], 8)
    assert {i["run_id"] for i in items} == {run["id"]}
    # ... and a dry run of the recorded window and seed re-draws them, recording nothing.
    dry = await api.client.post(
        f"{API}/blind-audit/runs", json={**WINDOW, "dry_run": True, "seed": run["seed"], "size": 8}, headers=admin
    )
    assert dry.status_code == 200, dry.text
    assert dry.json()["alert_ids"] == drawn and dry.json()["frame_size"] == 31

    # Runs follow each other without gaps or overlap.
    again = await api.client.post(f"{API}/blind-audit/runs", json=WINDOW, headers=admin)
    assert again.status_code == 409 and again.json()["error"]["code"] == "window_not_contiguous"
    # The rate rule over the next window: 2% of the frame, at least 5 a week.
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
    seeded = await api.client.post(f"{API}/blind-audit/runs", json={**WINDOW, "seed": 7}, headers=admin)
    assert seeded.status_code == 400 and seeded.json()["error"]["code"] == "seed_needs_dry_run"
    viewer = await api.login_headers(TENANT_A, "viewer")
    assert (await api.client.get(f"{API}/blind-audit/items", headers=viewer)).status_code == 403
    key = await api.key_headers(TENANT_A, ["read", "write"])
    assert (await api.client.get(f"{API}/blind-audit/items", headers=key)).status_code == 403  # people label


async def test_the_verdict_is_hidden_until_the_item_is_labelled(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=3)
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=2)
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
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=1)
    analyst_user = await api.user(TENANT_A, "analyst")
    analyst = api.auth(analyst_user)
    [item] = await queue(api, analyst)
    alert_id = await alert_of(api, item)

    response = await api.client.post(
        f"{API}/blind-audit/items/{item['id']}/label", json={"label": "malicious", "notes": "beacon"}, headers=analyst
    )

    assert response.status_code == 200, response.text
    out = response.json()
    assert out["escalation_created"] is True and out["item"]["reveal"]["agreement"] is False
    escalation = await api.repos.escalations.get(TENANT_A, out["escalation_id"])
    assert escalation.alert_id == alert_id and escalation.status == "open"
    assert escalation.summary["routing"] == {"code": "blind_audit"}
    assert escalation.summary["blind_audit_item_id"] == item["id"] and escalation.summary["analyst_notes"] == "beacon"
    assert escalation.sla_deadline is not None
    assert (await api.repos.alerts.get(TENANT_A, alert_id)).summary["blind_audit_review"] == escalation.id
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
    run = await sample(api, await api.login_headers(TENANT_A, "admin"), size=32)
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
    assert (e["malicious"], e["benign"], e["unsure"]) == (2, 28, 1)
    # One run: the stratified rate is the run's own; one sample still waits, so the estimate is incomplete.
    assert (e["status"], e["complete"], e["method"], e["effective_n"]) == ("incomplete", False, "stratified", 30.0)
    fn = e["false_negative_rate"]
    assert fn["n"] == 30 and fn["rate"] == pytest.approx(2 / 30, abs=1e-6)
    assert fn["ci_low"] == pytest.approx(0.018477, abs=1e-6) and fn["ci_high"] == pytest.approx(0.213235, abs=1e-6)
    assert e["estimated_missed"] == pytest.approx(round(2 / 30 * 32, 2))
    assert e["summary"] == "6.7% (stratified over 1 run(s); n=30; 95% CI 1.8% to 21.3%); incomplete"
    # The worst case counts the unsure and the pending sample as malicious: 4 of 32.
    assert e["worst_case_rate"] == pytest.approx(4 / 32) and e["worst_case_missed"] == pytest.approx(4.0)
    assert e["worst_case_rate_high"] > e["worst_case_rate"]
    [stratum] = body["strata"]
    assert stratum["run_id"] == run["id"] and stratum["complete"] is False
    assert stratum["false_negative_rate"]["ci_high"] == pytest.approx(0.213235, abs=1e-6)
    assert [r["id"] for r in body["runs"]] == [run["id"]] and body["runs"][0]["malicious"] == 2
    # The report's window outside the run is uncovered time.
    assert [(u["from"][:10], u["to"][:10]) for u in body["uncovered"]] == [
        ("2026-10-01", "2026-10-05"), ("2026-10-12", "2026-11-01"),
    ]
    assert body["labels_by_organisation"] == [
        {"organisation": None, "labelled": 31, "malicious": 2, "benign": 28, "unsure": 1}
    ]

    # Another tenant's report and an empty window: the small-sample wording.
    other = await api.client.get(
        f"{API}/reports/blind-audit?from=2026-10-01&to=2026-10-31", headers=await api.login_headers(TENANT_B, "viewer")
    )
    assert other.json()["estimate"]["summary"] == "Not enough data (n=0; at least 30 needed)"


async def test_tenants_are_isolated(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=2)
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=2)
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

    [run] = await service.sample_due(TENANT_A, now=now)

    assert (run.window_start, run.window_end) == (week_start, week_end)
    assert (run.frame_size, run.sample_size, run.trigger, run.sample_rate, run.min_sample) == (30, 3, "schedule", 0.1, 2)
    assert await service.sample_due(TENANT_A, now=now) == []  # the week is sampled
    assert await service.sample_due(TENANT_B, now=now) == []  # not enabled
