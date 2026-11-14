"""Adversarial review of PR #423 (AI-E3.15): the reviewer's probes, each asserting the behaviour the PR
promises (they failed before the fixes), and the tests added with the fixes."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core.retro_reopen import REOPEN_ACTION, link_related_model_closes
from lg_sotf.domain import closure
from tests.integration.api._safety_net import audited, model_closed, threat_with_linked
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def test_probe_evidence_pack_of_a_linked_alert_claims_no_human_decision(api: ApiHarness) -> None:
    """Priority 3: a benign decision on the case must not make the linked AI-closed alert look analyst-decided.
    The compliance evidence pack of the linked alert reads the case's claim and decision as its own."""
    threat, linked, case = await threat_with_linked(api, "srv-app-21")
    assert case is not None
    analyst = await api.login_headers(TENANT_A, "analyst")
    response = await api.client.post(
        f"/api/v1/escalations/{case.id}/decision",
        json={"decision": "false_positive", "version": case.version}, headers=analyst,
    )
    assert response.status_code == 200, response.text
    after = await api.repos.alerts.get(TENANT_A, linked)
    assert (after.status, after.summary["close_reason"]) == ("closed", closure.MODEL_CLOSE_REASON)

    pack = (await api.client.get(f"/api/v1/alerts/{linked}/evidence", headers=analyst)).json()
    oversight = pack["human_oversight"]
    print("OVERSIGHT", oversight["summary"], [(s["step"], s["mode"], s["detail"]) for s in oversight["steps"]])
    assert oversight["summary"]["human_decisions"] == 0, oversight["summary"]
    assert oversight["summary"]["closed_without_human"] is True, oversight["summary"]


async def test_probe_two_threats_linking_the_same_alert_at_once_keep_both_links(api: ApiHarness) -> None:
    """Priority 2: two threats link the same model close concurrently; its ``linked`` list must hold both."""
    lost = 0
    for n in range(5):
        host = f"srv-race-{n}"
        closed_alert = await model_closed(api, {"hosts": [host]})
        threats = [
            await api.repos.alerts.get(TENANT_A, await make_alert(
                api.repos, TENANT_A, title=f"Beacon {n} {i}", severity="medium", normalized={"entities": {"hosts": [host]}}))
            for i in range(2)
        ]
        results = await asyncio.gather(*[
            link_related_model_closes(api.repos, TENANT_A, t, actor=Actor("agent", "workflow")) for t in threats
        ])
        assert results == [[closed_alert], [closed_alert]]  # both report (and audit) a link
        links = (await api.repos.alerts.get(TENANT_A, closed_alert)).summary.get("linked") or []
        if sorted(m["threat_alert_id"] for m in links) != sorted(t.id for t in threats):
            lost += 1
    assert lost == 0, f"{lost}/5 alerts lost one of their two links"


async def test_probe_replaying_approve_on_an_action_nobody_approved_reopens(api: ApiHarness) -> None:
    """Priority 1/4: only a person's approval confirms. An action the policy approved and executed alone (no
    approver) is "accepted again without change" by approve: no approval is recorded, yet the safety net reopens."""
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": ["srv-app-22"]}})
    recent = await model_closed(api, {"hosts": ["srv-app-22"]})
    auto, _ = await api.repos.actions.propose(TENANT_A, threat, "isolate_host", "srv-app-22", "critical", status="approved")
    analyst = await api.login_headers(TENANT_A, "analyst")  # an analyst may not approve a critical action
    response = await api.client.post(f"/api/v1/actions/{auto.id}/approve", json={}, headers=analyst)
    print("REPLAY", response.status_code, response.text[:200])
    approvals = (await api.repos.audit.list(TENANT_A, action="response_action.approved")).items
    assert approvals == []  # control: nobody approved anything
    assert await audited(api, REOPEN_ACTION) == [], "a no-op approve by a role without authority reopened"
    assert (await api.repos.alerts.get(TENANT_A, recent)).status == "closed"


async def test_probe_link_never_gets_past_the_newest_cap(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    """Priority 2/4: linking does not drain the candidate set (the alerts stay closed), so repeated links return
    the same newest MAX_REOPEN and an older related close is never linked; it then leaves the 24-hour window and a
    later confirmation cannot reach it."""
    from lg_sotf.core import retro_reopen

    monkeypatch.setattr(retro_reopen, "MAX_REOPEN", 2)
    old = await model_closed(api, {"hosts": ["srv-app-23"]}, closed_at=datetime.now(UTC) - timedelta(hours=20))
    for _ in range(2):  # the flood: newer benign closes on the same host
        await model_closed(api, {"hosts": ["srv-app-23"]})
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": ["srv-app-23"]}})
    for _ in range(3):  # escalation, response plan, malicious close: three link calls
        await link_related_model_closes(api.repos, TENANT_A, await api.repos.alerts.get(TENANT_A, threat),
                                        actor=Actor("agent", "workflow"))
    stored = await api.repos.alerts.get(TENANT_A, threat)
    assert old in stored.summary["linked_alert_ids"], "the older related close was never linked"


async def test_probe_linked_closed_alerts_use_up_the_case_grouping_room(api: ApiHarness) -> None:
    """Priority 2/4: the case takes at most 50 attached alerts (grouping ``max_attached``, MAX_RELATED). Linked
    alerts are closed, wait on nothing, and are attached with no cap: 50 benign closes on the threat's host fill
    the case, and the next real alert of the same detection opens a case of its own."""
    from lg_sotf.services.escalation import MAX_RELATED

    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": ["srv-app-24"]}})
    for _ in range(MAX_RELATED):
        await model_closed(api, {"hosts": ["srv-app-24"]})
    case, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, threat, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1))
    stored = await api.repos.alerts.get(TENANT_A, threat)
    linked = await link_related_model_closes(api.repos, TENANT_A, stored, actor=Actor("agent", "workflow"), escalation_id=case.id)
    assert len(linked) == MAX_RELATED
    follow_up = await make_alert(api.repos, TENANT_A, title="Beacon again", severity="medium")
    async with api.repos.db.tenant_tx(TENANT_A) as conn:
        parent = await api.repos.escalations.find_group_parent(
            TENANT_A, follow_up, since=datetime.now(UTC) - timedelta(hours=1), related=[threat], fingerprint=None,
            max_attached=MAX_RELATED, conn=conn)
    assert parent is not None and parent.id == case.id, "the case no longer groups a related waiting alert"


async def test_the_incident_report_of_a_linked_alert_names_no_analyst_decision(api: ApiHarness) -> None:
    """Finding 1 (NIS2): the draft of a linked alert is built from its own case data. The decision on the case it
    was linked into was about the threat alert, whose own draft still carries it (the control)."""
    threat, linked, case = await threat_with_linked(api, "srv-app-25")
    assert case is not None
    analyst = await api.login_headers(TENANT_A, "analyst")
    response = await api.client.post(
        f"/api/v1/escalations/{case.id}/decision",
        json={"decision": "false_positive", "version": case.version}, headers=analyst,
    )
    assert response.status_code == 200, response.text

    async def draft(alert_id: str) -> str:
        report = await api.client.post(
            f"/api/v1/alerts/{alert_id}/incident-report", json={"stage": "final", "include_ai_narrative": False},
            headers=analyst,
        )
        assert report.status_code == 201, report.text
        return " ".join(str(field["value"]) for field in report.json()["fields"])

    assert "Analyst decision" in await draft(threat)
    text = await draft(linked)
    assert "Analyst decision" not in text and "Escalated" not in text, text


async def test_an_approval_by_this_person_reopens_and_one_by_somebody_else_does_not(api: ApiHarness) -> None:
    """Finding 2: the approve call confirms only when the caller's own approval stands on the action."""
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": ["srv-app-26"]}})
    recent = await model_closed(api, {"hosts": ["srv-app-26"]})
    other = await api.user(TENANT_A, "admin")
    action, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.26", "low", status="awaiting_approval")
    await api.repos.actions.transition(TENANT_A, action.id, "approved", expected_from="awaiting_approval",
                                       approved_by=str(other.id))
    analyst = await api.login_headers(TENANT_A, "analyst")
    response = await api.client.post(f"/api/v1/actions/{action.id}/approve", json={}, headers=analyst)
    assert response.status_code == 200, response.text
    assert await audited(api, REOPEN_ACTION) == []  # the admin's approval, replayed by an analyst: no confirmation

    mine, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.27", "low", status="awaiting_approval")
    response = await api.client.post(f"/api/v1/actions/{mine.id}/approve", json={}, headers=analyst)
    assert response.status_code == 200, response.text
    assert await audited(api, REOPEN_ACTION) == [recent]


async def test_a_failed_alert_read_after_an_approval_is_counted_not_raised(
    api: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approval is committed: a database error while reading the alert for the reopen is counted, like any
    failed reopen, and the request still answers."""
    from lg_sotf.api import common
    from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES

    threat = await make_alert(api.repos, TENANT_A, title="Beacon", normalized={"entities": {"hosts": ["srv-app-27"]}})
    action, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.28", "low", status="awaiting_approval")
    user = await api.user(TENANT_A, "analyst")
    await api.repos.actions.transition(TENANT_A, action.id, "approved", expected_from="awaiting_approval",
                                       approved_by=str(user.id))

    async def broken(*args: object, **kwargs: object) -> object:
        raise RuntimeError("database went away")

    approved = await api.repos.actions.get(TENANT_A, action.id)
    monkeypatch.setattr(api.ctx.repos.alerts, "get", broken)
    before = RETRO_REOPEN_FAILURES.labels(path="approval")._value.get()
    await common.reopen_for_approval(api.ctx, TENANT_A, approved, user.id)
    assert RETRO_REOPEN_FAILURES.labels(path="approval")._value.get() == before + 1
