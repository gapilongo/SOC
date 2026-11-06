"""Console read fields: tenant name, dashboard queue figures, escalation order and context, alert view counts,
action guardrails and analysis findings. Every figure stays inside the caller's tenant."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.db.repos import Escalation
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ENTITIES = {"users": ["j.doe@a.example"], "ips": ["203.0.113.4", "198.51.100.7"], "hosts": ["ws-042"]}


async def escalation(
    api: ApiHarness,
    tenant_id: str,
    *,
    deadline: Optional[datetime],
    severity: str = "high",
    summary: Optional[Dict[str, Any]] = None,
    **alert: Any,
) -> Escalation:
    alert_id = await make_alert(api.repos, tenant_id, severity=severity, **alert)
    created, _ = await api.repos.escalations.create_or_attach(
        tenant_id, alert_id, reason="review", sla_deadline=deadline, summary=summary or {}
    )
    return created


async def close(api: ApiHarness, tenant_id: str, alert_id: str) -> None:
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(tenant_id, alert_id, status)


async def get(api: ApiHarness, path: str, headers: Dict[str, str], **params: Any) -> Any:
    response = await api.client.get(f"{API}{path}", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_me_names_the_tenant(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_A, "viewer")
    tenant = await api.repos.tenants.get(TENANT_A)
    assert (await get(api, "/auth/me", headers))["tenant_name"] == tenant.name
    other = await api.repos.tenants.get(TENANT_B)
    assert (await get(api, "/auth/me", await api.login_headers(TENANT_B, "viewer")))["tenant_name"] == other.name


async def test_dashboard_queue_figures_depend_on_the_tenant_and_the_caller(api: ApiHarness) -> None:
    now = datetime.now(UTC)
    analyst = await api.user(TENANT_A, "analyst")
    admin = await api.user(TENANT_A, "admin")
    await escalation(api, TENANT_A, deadline=now - timedelta(minutes=5), severity="high")
    soon = await escalation(api, TENANT_A, deadline=now + timedelta(minutes=20), severity="medium")
    mine = await escalation(api, TENANT_A, deadline=now + timedelta(hours=2), severity="medium")
    await api.repos.escalations.claim(TENANT_A, mine.id, analyst.id, mine.version)
    action_alert = await make_alert(api.repos, TENANT_A)
    await api.repos.actions.propose(TENANT_A, action_alert, "block_ip", "203.0.113.9", "medium", status="awaiting_approval")
    await api.repos.actions.propose(TENANT_A, action_alert, "isolate_host", "ws-042", "high", status="awaiting_approval")
    # Tenant B: an overdue unassigned escalation and two pending actions, none of which A may see.
    await escalation(api, TENANT_B, deadline=now - timedelta(hours=1), severity="critical")
    b_alert = await make_alert(api.repos, TENANT_B)
    await api.repos.actions.propose(TENANT_B, b_alert, "block_ip", "203.0.113.10", "medium", status="awaiting_approval")
    await api.repos.actions.propose(TENANT_B, b_alert, "block_domain", "evil.example", "medium", status="awaiting_approval")

    figures = await get(api, "/dashboard/summary", api.auth(analyst))
    assert figures["open_escalations"] == 3
    assert figures["open_escalations_by_severity"] == {"high": 1, "medium": 2}
    assert figures["overdue_escalations"] == 1
    assert figures["unassigned_escalations"] == 2
    assert figures["unassigned_breaching"] == 1
    assert datetime.fromisoformat(figures["next_sla_deadline"]) == soon.sla_deadline
    assert figures["pending_approvals_total"] == 2
    assert figures["pending_approvals_by_risk"] == {"medium": 1, "high": 1}
    assert figures["pending_approvals"] == 1  # an analyst approves low and medium only
    assert figures["my_claimed"] == 1
    assert figures["llm_model"] == api.ctx.settings.llm.deep.model

    # Same cached tenant figures, the caller's own share computed again.
    as_admin = await get(api, "/dashboard/summary", api.auth(admin))
    assert (as_admin["pending_approvals"], as_admin["my_claimed"]) == (2, 0)
    assert as_admin["overdue_escalations"] == 1

    b_figures = await get(api, "/dashboard/summary", await api.login_headers(TENANT_B, "admin"))
    assert (b_figures["open_escalations"], b_figures["overdue_escalations"], b_figures["pending_approvals_total"]) == (1, 1, 2)
    assert b_figures["open_escalations_by_severity"] == {"critical": 1}


async def test_escalations_by_sla_put_overdue_first_and_page_stably(api: ApiHarness) -> None:
    now = datetime.now(UTC)
    later = await escalation(api, TENANT_A, deadline=now + timedelta(hours=3))
    none = await escalation(api, TENANT_A, deadline=None)
    overdue = await escalation(api, TENANT_A, deadline=now - timedelta(minutes=30))
    soon = await escalation(api, TENANT_A, deadline=now + timedelta(minutes=10))
    await escalation(api, TENANT_B, deadline=now - timedelta(hours=2))
    headers = await api.login_headers(TENANT_A, "viewer")

    first = await get(api, "/escalations", headers, order="sla_deadline")
    assert [e["id"] for e in first["items"]] == [overdue.id, soon.id, later.id, none.id]
    seen: List[str] = []
    cursor: Optional[str] = None
    while True:
        params: Dict[str, Any] = {"order": "sla_deadline", "limit": 1}
        if cursor:
            params["cursor"] = cursor
        page = await get(api, "/escalations", headers, **params)
        seen += [e["id"] for e in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert seen == [overdue.id, soon.id, later.id, none.id]
    breaching = await get(api, "/escalations", headers, overdue="true")
    assert [e["id"] for e in breaching["items"]] == [overdue.id]


async def test_escalation_owner_filters_and_addresses(api: ApiHarness) -> None:
    now = datetime.now(UTC)
    analyst = await api.user(TENANT_A, "analyst", email="owner@a.example")
    claimed = await escalation(api, TENANT_A, deadline=now + timedelta(hours=1))
    open_one = await escalation(api, TENANT_A, deadline=now + timedelta(hours=2))
    decided = await escalation(api, TENANT_A, deadline=now + timedelta(hours=3))
    await api.repos.escalations.claim(TENANT_A, claimed.id, analyst.id, claimed.version)
    await api.repos.escalations.decide(
        TENANT_A, decided.id, decision="false_positive", decided_by=analyst.id, expected_version=decided.version
    )
    headers = api.auth(analyst)

    unassigned = await get(api, "/escalations", headers, assigned_to="none", status=["open", "claimed"])
    assert [e["id"] for e in unassigned["items"]] == [open_one.id]
    mine = await get(api, "/escalations", headers, assigned_to="me", status=["open", "claimed"])
    assert [(e["id"], e["assigned_to_email"]) for e in mine["items"]] == [(claimed.id, "owner@a.example")]
    by_me = await get(api, "/escalations", headers, decided_by="me")
    assert [(e["id"], e["decided_by_email"]) for e in by_me["items"]] == [(decided.id, "owner@a.example")]
    bad = await api.client.get(f"{API}/escalations", headers=headers, params={"decided_by": "someone"})
    assert bad.status_code == 400


async def test_escalation_rows_carry_the_alert_digest_and_routing(api: ApiHarness) -> None:
    await api.repos.sources.create(TENANT_A, "webhook", "Entra ID sign-ins", source_id="entra", config={"format": "generic"})
    summary = {
        "conclusion": "TOR sign-in nine minutes after a normal one. MFA fatigue fits.",
        "llm_used": True,
        "routing": {"code": "grey_zone", "confidence": 42.0, "band": {"min": 30, "max": 70}},
    }
    created = await escalation(
        api,
        TENANT_A,
        deadline=datetime.now(UTC) + timedelta(hours=1),
        summary=summary,
        source_id="entra",
        normalized={"title": "Unusual sign-in", "rule_name": "Unusual sign-in pattern", "entities": ENTITIES},
    )
    row = await get(api, f"/escalations/{created.id}", await api.login_headers(TENANT_A, "viewer"))
    assert row["rule"] == "Unusual sign-in pattern"
    assert (row["source_id"], row["source_name"], row["alert_severity"]) == ("entra", "Entra ID sign-ins", "high")
    assert row["entities_preview"] == {
        "items": [
            {"kind": "user", "value": "j.doe@a.example"},
            {"kind": "host", "value": "ws-042"},
            {"kind": "ip", "value": "203.0.113.4"},
        ],
        "counts": {"user": 1, "host": 1, "ip": 2},
    }
    assert (row["ai_reason"], row["ai_reason_source"]) == ("TOR sign-in nine minutes after a normal one.", "model")
    assert row["routing"] == {"code": "grey_zone", "confidence": 42.0, "band": {"min": 30, "max": 70}}
    # A tenant B escalation is not found, so none of its digest leaks.
    b = await escalation(api, TENANT_B, deadline=None, normalized={"title": "B", "entities": ENTITIES})
    assert (await api.client.get(f"{API}/escalations/{b.id}", headers=await api.login_headers(TENANT_A, "viewer"))).status_code == 404


async def test_alert_rows_counts_and_closed_window(api: ApiHarness) -> None:
    await api.repos.sources.create(TENANT_A, "webhook", "Firewall", source_id="fw", config={"format": "generic"})
    waiting = await make_alert(api.repos, TENANT_A, source_id="fw", normalized={"title": "x", "entities": ENTITIES})
    for status in ("queued", "processing", "waiting_human"):
        await api.repos.alerts.update_status(TENANT_A, waiting, status)
    closed = await make_alert(api.repos, TENANT_A, source_id="gone")
    await close(api, TENANT_A, closed)
    await make_alert(api.repos, TENANT_A)
    for _ in range(3):
        b_alert = await make_alert(api.repos, TENANT_B)
        await close(api, TENANT_B, b_alert)
    headers = await api.login_headers(TENANT_A, "viewer")

    rows = {a["id"]: a for a in (await get(api, "/alerts", headers))["items"]}
    assert {waiting, closed} <= set(rows) and len(rows) == 3
    assert rows[waiting]["source_name"] == "Firewall"
    assert rows[waiting]["entities_preview"]["counts"] == {"user": 1, "host": 1, "ip": 2}
    assert rows[closed]["source_name"] is None and rows[closed]["entities_preview"] is None

    counts = await get(api, "/alerts/counts", headers)
    assert counts["by_status"]["waiting_human"] == 1
    assert counts["by_status"]["new"] == 1
    assert counts["by_status"]["closed"] == 1  # closed today, tenant B's three are not counted
    assert counts["closed_to"] is None
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert (await get(api, "/alerts/counts", headers, closed_from=future))["by_status"]["closed"] == 0

    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    in_window = await get(api, "/alerts", headers, closed_from=today)
    assert [a["id"] for a in in_window["items"]] == [closed]
    assert (await get(api, "/alerts", headers, closed_from=future))["items"] == []
    inverted = await api.client.get(f"{API}/alerts", headers=headers, params={"closed_from": future, "closed_to": today})
    assert inverted.status_code == 400


async def test_pending_actions_carry_a_current_guardrail_verdict(api: ApiHarness) -> None:
    alert_id = await make_alert(api.repos, TENANT_A)
    host, _ = await api.repos.actions.propose(
        TENANT_A, alert_id, "isolate_host", "ws-042", "high", status="awaiting_approval",
        params={"explanation": "awaiting approval: tenant autonomy for high risk is 'approval'"},
    )
    blocked, _ = await api.repos.actions.propose(
        TENANT_A, alert_id, "block_ip", "10.0.0.5", "medium", status="blocked", blocked_reason="non_public_ip",
        params={"explanation": "blocked: private/internal addresses are blocked only when ..."},
    )
    headers = await api.login_headers(TENANT_A, "viewer")

    view = await get(api, f"/actions/{host.id}", headers)
    assert view["guardrail"]["verdict"] == "passed" and view["guardrail"]["evaluated"] == "now"
    assert view["blast_radius"]["target_kind"] == "host"
    assert view["blast_radius"]["hourly_limit"] == 5 and view["blast_radius"]["executed_last_hour"] == 0
    assert view["reversible"] is True

    await api.repos.tenants.update_settings(TENANT_A, {"protected_assets": {"hosts": ["ws-*"]}})
    now_blocked = await get(api, f"/actions/{host.id}", headers)
    assert (now_blocked["guardrail"]["verdict"], now_blocked["guardrail"]["code"]) == ("blocked", "protected_asset")

    listed = {a["id"]: a for a in (await get(api, "/actions", headers))["items"]}
    recorded = listed[str(blocked.id)]["guardrail"]
    assert (recorded["verdict"], recorded["evaluated"], recorded["code"]) == ("blocked", "recorded", "non_public_ip")
    assert listed[str(blocked.id)]["blast_radius"]["hourly_limit"] is None


async def test_alert_detail_lists_findings_with_sources(api: ApiHarness) -> None:
    summary = {
        "analysis": {
            "tools": [
                {
                    "tool": "reputation", "kind": "ip", "target": "203.0.113.4", "simulated": False,
                    "checked_at": "2026-11-06T14:02:13+00:00",
                    "results": [{"provider": "abuseipdb", "status": "ok", "verdict": "malicious"}],
                }
            ],
            "history": [{"kind": "user", "value": "j.doe", "provider": "history", "status": "ok", "verdict": "unknown"}],
        }
    }
    alert_id = await make_alert(api.repos, TENANT_A, normalized={"title": "x", "entities": ENTITIES})
    await api.repos.alerts.update(TENANT_A, alert_id, summary=summary)
    detail = await get(api, f"/alerts/{alert_id}", await api.login_headers(TENANT_A, "viewer"))
    assert [(f["origin"], f["source"], f["checked_at"]) for f in detail["findings"]] == [
        ("threat_intel", "abuseipdb", "2026-11-06T14:02:13Z"),
        ("history", "history", None),
    ]
    assert detail["entities_preview"]["items"][0] == {"kind": "user", "value": "j.doe@a.example"}
