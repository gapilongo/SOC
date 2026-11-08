"""The independent review of PR #308 (blind audit), as passing proofs of the fixed behaviour.

Each test was written by the reviewer to show a failure; here it asserts the safe behaviour instead:
F1 the verdict stays hidden on every alert path until the label exists; F2/F7 nobody inserts labelled or
extra items; F3 recorded runs use server seeds; F4 runs are contiguous; F5/F9 MSSP staff label (attributed
to their organisation) but do not sample; F6/F5 a decided blind-audit escalation re-triages the alert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import asyncpg
import pytest

from lg_sotf.api.routers.ws import HiddenAlerts
from lg_sotf.audit.logger import Actor
from lg_sotf.db.repos import User
from lg_sotf.domain.blind_audit import draw
from lg_sotf.services.blind_audit import SETTLE_LAG, BlindAuditService, SampleRequest, SamplingError, week_window
from tests.integration.api._blind_audit import (
    API,
    VERDICT_MARKER,
    WINDOW,
    alert_of,
    closed_alert,
    queue,
    sample,
    seed_frame,
)
from tests.integration.api._support import TENANT_A, ApiHarness

pytestmark = pytest.mark.integration

HIDDEN = {"hidden_for_blind_audit": True}
ORG = "mssp-org"


async def _staff(api: ApiHarness) -> User:
    """An admin of the MSSP organisation ``ORG`` (an account of its home tenant)."""
    if await api.repos.organisations.get(ORG) is None:
        await api.repos.tenants.create(ORG, "MSSP")
        await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    return staff


async def _grant(api: ApiHarness, tenant_id: str) -> None:
    await api.repos.grants.create(
        tenant_id, ORG, "admin", reason="night shift", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=4),
    )


async def _ingested(api: ApiHarness) -> int:
    """Alerts the value report counts today (straight from the aggregate, not the 60-second cache)."""
    now = datetime.now(UTC)
    rows = await api.repos.reports.value_daily(TENANT_A, now - timedelta(days=1), now + timedelta(minutes=1))
    return sum(r.ingested for r in rows)


async def _ids(api: ApiHarness, headers: Dict[str, str], query: str = "") -> List[Dict[str, Any]]:
    response = await api.client.get(f"{API}/alerts?limit=200{query}", headers=headers)
    assert response.status_code == 200, response.text
    return list(response.json()["items"])


async def test_F1_the_verdict_stays_hidden_on_every_alert_path_until_labelled(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=3)
    admin = await api.login_headers(TENANT_A, "admin")
    viewer = await api.login_headers(TENANT_A, "viewer")
    ingested_before = await _ingested(api)
    await sample(api, admin, size=1)
    analyst = await api.login_headers(TENANT_A, "analyst")
    [item] = await queue(api, analyst)
    assert "id" not in item["alert"] and item["reveal"] is None  # the blind view hands out no alert id
    alert_id = await alert_of(api, item)
    await api.repos.alert_events.append(
        TENANT_A, alert_id, "node.completed", node="analysis", actor_type="agent", actor_id="analysis",
        data={"verdict": "benign", "conclusion": VERDICT_MARKER},
    )
    await api.repos.alert_events.append(TENANT_A, alert_id, "note", data={"text": "seen by a person"})
    everyone = {
        "analyst": analyst, "viewer": viewer, "admin": admin,
        "platform admin": await api.login_headers(TENANT_A, "admin", platform_admin=True),
        "read key": await api.key_headers(TENANT_A, ["read"]),
    }
    for who, headers in everyone.items():
        detail = await api.client.get(f"{API}/alerts/{alert_id}", headers=headers)
        body = detail.json()
        assert detail.status_code == 200 and body["hidden_for_blind_audit"] is True, who
        assert (body["disposition"], body["confidence"], body["threat_score"], body["priority"]) == (None,) * 4, who
        assert body["summary"] == HIDDEN and body["findings"] == [] and VERDICT_MARKER not in detail.text, who
        [listed] = [a for a in await _ids(api, headers) if a["id"] == alert_id]
        assert listed["hidden_for_blind_audit"] is True and listed["disposition"] is None, who
        # Filtering on the verdict would reveal it: the sample is not in a disposition-filtered list.
        benign = await _ids(api, headers, "&disposition=benign")
        assert benign and alert_id not in {a["id"] for a in benign}, who
        events = (await api.client.get(f"{API}/alerts/{alert_id}/events", headers=headers)).json()["items"]
        by_type = {e["event_type"]: e["data"] for e in events}
        assert "node.completed" not in by_type and by_type["note"] == {"text": "seen by a person"}, who
        pack = await api.client.get(f"{API}/alerts/{alert_id}/evidence", headers=headers)
        assert pack.status_code == 200 and VERDICT_MARKER not in pack.text, who
        sealed = pack.json()
        assert sealed["hidden_for_blind_audit"] is True and sealed["alert"]["disposition"] is None, who
        assert sealed["agents"] == HIDDEN and sealed["correlation"] == HIDDEN, who
    # Live updates (WebSocket, and MCP rides on the routes above) carry no data for the sample.
    live = HiddenAlerts(api.ctx, TENANT_A)
    event = {"type": "alert.updated", "tenant_id": TENANT_A, "alert_id": alert_id, "data": {"disposition": "benign"}}
    assert (await live.shown(event))["data"] == HIDDEN
    other = {**event, "alert_id": "another-alert"}
    assert (await live.shown(other))["data"] == {"disposition": "benign"}
    # The value report (and its CSV) leaves the sample out until it is labelled (the API caches a minute).
    assert await _ingested(api) == ingested_before - 1

    labelled = await api.client.post(f"{API}/blind-audit/items/{item['id']}/label", json={"label": "benign"},
                                     headers=analyst)
    assert labelled.status_code == 200
    shown = (await api.client.get(f"{API}/alerts/{alert_id}", headers=viewer)).json()
    assert shown["hidden_for_blind_audit"] is False and shown["confidence"] == 87.5 and shown["summary"] != HIDDEN


async def test_F2_F7_nobody_inserts_labelled_or_extra_items_into_a_run(api: ApiHarness) -> None:
    eligible = await seed_frame(api.repos, n=4)
    run = await sample(api, await api.login_headers(TENANT_A, "admin"), size=1)
    async with api.repos.db.tenant_tx(TENANT_A, readonly=True) as conn:
        sampled = await conn.fetchval("SELECT alert_id FROM blind_audit_items")
    extra = [a for a in eligible if a != sampled][:2]
    with pytest.raises(asyncpg.CheckViolationError, match="starts unlabelled"):
        async with api.repos.db.tenant_tx(TENANT_A) as conn:
            await conn.execute(
                "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class, label, agreement,"
                " labelled_at, labelled_by_actor) VALUES ($1, $2, $3, 1, 'benign', 'benign', true, now(), 'x')",
                TENANT_A, run["id"], extra[0],
            )
    with pytest.raises(asyncpg.CheckViolationError, match="within its run"):
        async with api.repos.db.tenant_tx(TENANT_A) as conn:
            await conn.execute(
                "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class) "
                "VALUES ($1, $2, $3, 2, 'benign')",
                TENANT_A, run["id"], extra[1],
            )
    report = (await api.client.get(f"{API}/reports/blind-audit?from=2026-10-01&to=2026-10-31",
                                   headers=await api.login_headers(TENANT_A, "viewer"))).json()
    assert report["runs"][0]["sample_size"] == 1 and report["estimate"]["sampled"] == 1
    assert report["estimate"]["benign"] == 0


async def test_F3_recorded_runs_use_a_server_seed_and_a_chosen_seed_only_dry_runs(api: ApiHarness) -> None:
    eligible = await seed_frame(api.repos, n=30)
    target = eligible[0]  # an alert an operator would like to keep out of the sample
    seed = next(s for s in range(10_000) if target not in draw(eligible, s, 25))
    admin = await api.login_headers(TENANT_A, "admin")
    steered = await api.client.post(f"{API}/blind-audit/runs", json={**WINDOW, "seed": seed, "size": 25}, headers=admin)
    assert steered.status_code == 400 and steered.json()["error"]["code"] == "seed_needs_dry_run"
    dry = await api.client.post(
        f"{API}/blind-audit/runs", json={**WINDOW, "seed": seed, "size": 25, "dry_run": True}, headers=admin
    )
    assert dry.status_code == 200 and dry.json()["alert_ids"] == draw(eligible, seed, 25)
    assert (await api.client.get(f"{API}/blind-audit/runs", headers=admin)).json()["items"] == []  # nothing recorded
    run = await sample(api, admin, size=25)
    assert run["seed_source"] == "server"
    async with api.repos.db.tenant_tx(TENANT_A, readonly=True) as conn:
        assert await conn.fetchval("SELECT seed_source FROM blind_audit_runs") == "server"
    assert (await api.repos.audit.list(TENANT_A)).items[0].details["seed_source"] == "server"


async def test_F4_runs_are_contiguous_and_the_scheduler_catches_up(api: ApiHarness) -> None:
    service = BlindAuditService(api.repos)
    now = datetime.now(UTC)
    _, this_monday = week_window(now)
    last_monday = this_monday - timedelta(days=7)
    actor = Actor("user", "admin")
    first = await service.sample(
        TENANT_A, SampleRequest(since=last_monday - timedelta(days=7), until=last_monday - timedelta(days=3)),
        trigger="api", actor=actor, now=now,
    )
    missed = await closed_alert(api.repos, TENANT_A, last_monday - timedelta(days=1))
    # "The last minute only" is no longer possible: a run starts where the last one ended.
    with pytest.raises(SamplingError) as refused:
        await service.sample(TENANT_A, SampleRequest(since=now - timedelta(seconds=60)), trigger="api", actor=actor)
    assert refused.value.code == "window_not_contiguous"
    api_refused = await api.client.post(
        f"{API}/blind-audit/runs", json={"from": (now - timedelta(seconds=60)).isoformat()},
        headers=await api.login_headers(TENANT_A, "admin"),
    )
    assert api_refused.status_code == 409 and api_refused.json()["error"]["code"] == "window_not_contiguous"
    ok = await api.client.patch(f"{API}/tenant/settings", json={"blind_audit": {"enabled": True, "sample_rate": 1}},
                                headers=await api.login_headers(TENANT_A, "admin"))
    assert ok.status_code == 200
    runs = await service.sample_due(TENANT_A, now=now)
    # Week by week from where the last run ended: the rest of that week, then the last complete week.
    assert [(r.window_start, r.window_end) for r in runs] == [
        (first.window_end, last_monday), (last_monday, this_monday),
    ]
    async with api.repos.db.tenant_tx(TENANT_A, readonly=True) as conn:
        covered = await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM blind_audit_runs r JOIN alerts a ON a.id = $1 "
            "WHERE a.closed_at >= r.window_start AND a.closed_at < r.window_end)", missed)
        sampled = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM blind_audit_items WHERE alert_id = $1)", missed)
    assert covered is True and sampled is True
    # The report lists the time no run covered yet: from the last run's end to (nearly) now.
    start = (last_monday - timedelta(days=7)).date().isoformat()
    report = (await api.client.get(f"{API}/reports/blind-audit?from={start}&to={now.date().isoformat()}",
                                   headers=await api.login_headers(TENANT_A, "viewer"))).json()
    assert report["uncovered"][-1]["from"].startswith(this_monday.isoformat()[:19])
    assert datetime.fromisoformat(report["uncovered"][-1]["to"]) <= now - SETTLE_LAG + timedelta(seconds=5)


async def test_F5_F9_mssp_staff_label_for_their_organisation_but_do_not_sample(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=3)
    staff = await _staff(api)
    await _grant(api, TENANT_A)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_A}
    refused = await api.client.post(f"{API}/blind-audit/runs", json={**WINDOW, "size": 2}, headers=headers)
    assert refused.status_code == 403
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=2)
    [item, *_] = await queue(api, headers)
    r = await api.client.post(f"{API}/blind-audit/items/{item['id']}/label", json={"label": "benign"}, headers=headers)
    assert r.status_code == 200, r.text
    stored = await api.repos.blind_audit.get_item(TENANT_A, item["id"])
    assert stored.labelled_by is None and stored.labelled_by_actor == str(staff.id) and stored.labelled_by_org == ORG
    report = (await api.client.get(f"{API}/reports/blind-audit?from=2026-10-01&to=2026-10-31",
                                   headers=await api.login_headers(TENANT_A, "viewer"))).json()
    assert report["labels_by_organisation"] == [
        {"organisation": ORG, "labelled": 1, "malicious": 0, "benign": 1, "unsure": 0}
    ]


async def test_F6_deciding_the_blind_audit_escalation_re_triages_the_alert(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=1)
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=1)
    analyst = await api.login_headers(TENANT_A, "analyst")
    [item] = await queue(api, analyst)
    alert_id = await alert_of(api, item)
    await api.repos.runs.upsert_queued(TENANT_A, alert_id)
    async with api.repos.db.system_tx() as conn:
        await conn.execute("UPDATE workflow_runs SET status = 'completed' WHERE tenant_id = $1 AND alert_id = $2",
                           TENANT_A, alert_id)
    out = (await api.client.post(f"{API}/blind-audit/items/{item['id']}/label", json={"label": "malicious"},
                                 headers=analyst)).json()
    esc = await api.repos.escalations.get(TENANT_A, out["escalation_id"])
    decided = await api.client.post(f"{API}/escalations/{esc.id}/decision",
                                    json={"decision": "true_positive", "version": esc.version}, headers=analyst)
    assert decided.status_code == 200, decided.text
    alert = await api.repos.alerts.get(TENANT_A, alert_id)
    run = await api.repos.runs.get(TENANT_A, alert_id)
    # Re-queued through the reprocess path; its new run starts at this decision (tests/integration/engine).
    assert (alert.status, run.status, alert.summary.get("blind_audit_review")) == ("queued", "queued", esc.id)
    actions = [e.action for e in (await api.repos.audit.list(TENANT_A)).items]
    assert "alert.reprocess_requested" in actions and "escalation.decided" in actions
