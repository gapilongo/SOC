"""Decision policy v3 safety net (FIX-3, AI-E3.15) on the API's threat paths. A person confirms the threat: an
analyst's ``true_positive`` decision, an approved response action and a blind-audit ``malicious`` label reopen the
model-closed alerts that share an entity with the alert, and those linked to it earlier, attach them to its
escalation and queue their new run. An alert that was only linked is listed on the case and stays closed by the
models whatever the decision on the case."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core.retro_reopen import LINK_ACTION, REOPEN_ACTION, link_related_model_closes
from lg_sotf.db.repos import Escalation
from lg_sotf.domain import closure
from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES
from tests.integration.api._blind_audit import API, alert_of, queue, sample, seed_frame
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


LONG_AGO = datetime.now(UTC) - timedelta(days=3)  # outside the safety net's 24-hour window


async def model_closed(api: ApiHarness, entities: Dict[str, List[str]], closed_at: Optional[datetime] = None) -> str:
    alert_id = await make_alert(api.repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(TENANT_A, alert_id, status, now=closed_at)
    await api.repos.alerts.update(TENANT_A, alert_id, disposition="benign",
                                  summary={"close_reason": closure.MODEL_CLOSE_REASON})
    return alert_id


async def assert_reopened(api: ApiHarness, alert_id: str, escalation_id: str, mode: str) -> None:
    alert = await api.repos.alerts.get(TENANT_A, alert_id)
    assert alert.status == ("waiting_human" if mode == "folded" else "queued") and alert.disposition is None
    assert alert.summary["reopened"]["mode"] == mode
    assert alert.summary["reopened"]["reason"] == "related_threat"
    attached = alert_id in (await api.repos.escalations.get(TENANT_A, escalation_id)).related_alert_ids
    assert attached is (mode == "folded")
    assert alert.summary["reopened"]["escalation_id"] == escalation_id
    assert [e.resource_id for e in (await api.repos.audit.list(TENANT_A, action=REOPEN_ACTION)).items] == [alert_id]


async def threat_with_linked(api: ApiHarness, host: str, *, case: bool = True) -> tuple[str, str, Optional[Escalation]]:
    """A threat a model judged three days ago, its open case (if any) and the model close linked to it then."""
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": [host]}})
    linked = await model_closed(api, {"hosts": [host]}, closed_at=LONG_AGO)
    escalation = None
    if case:
        escalation, _ = await api.repos.escalations.create_or_attach(
            TENANT_A, threat, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
        )
    assert await link_related_model_closes(
        api.repos, TENANT_A, await api.repos.alerts.get(TENANT_A, threat), actor=Actor("agent", "workflow"),
        escalation_id=escalation.id if escalation else None, now=LONG_AGO + timedelta(hours=1),
    ) == [linked]
    return threat, linked, await api.repos.escalations.get(TENANT_A, escalation.id) if escalation else None


async def audited(api: ApiHarness, action: str) -> List[str]:
    return [e.resource_id for e in (await api.repos.audit.list(TENANT_A, action=action)).items]


async def test_a_linked_alert_is_listed_on_the_case_and_a_benign_decision_leaves_it_closed_by_the_models(
    api: ApiHarness,
) -> None:
    """AI-E3.15 acceptance: the case view lists the linked alert, which keeps the close reason
    ``ai_closed:audit_required``. A benign decision on the case is about the reviewed alert: the linked one gets no
    resume message and no review of its own, is not analyst-confirmed benign, and the suppression suggestion is
    built from the reviewed alert alone."""
    threat, linked, case = await threat_with_linked(api, "srv-app-02")
    assert case is not None
    analyst = await api.login_headers(TENANT_A, "analyst")

    shown = await api.client.get(f"/api/v1/escalations/{case.id}", headers=analyst)
    assert shown.status_code == 200 and shown.json()["related_alert_ids"] == [linked], shown.text
    detail = await api.client.get(f"/api/v1/alerts/{linked}", headers=analyst)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert (body["status"], body["disposition"], body["summary"]["close_reason"]) == (
        "closed", "benign", closure.MODEL_CLOSE_REASON)
    [link] = body["summary"]["linked"]
    assert (link["threat_alert_id"], link["escalation_id"]) == (threat, case.id) and link["at"]
    assert await audited(api, LINK_ACTION) == [linked]

    response = await api.client.post(
        f"/api/v1/escalations/{case.id}/decision",
        json={"decision": "false_positive", "version": case.version, "suggest_suppression": True}, headers=analyst,
    )
    assert response.status_code == 200, response.text
    decided = response.json()
    assert decided["resumed_alert_ids"] == [threat] and decided["own_review_alert_ids"] == []
    after = await api.repos.alerts.get(TENANT_A, linked)
    assert (after.status, after.disposition, after.summary["close_reason"]) == (
        "closed", "benign", closure.MODEL_CLOSE_REASON)
    assert after.summary.get("analyst_decision") is None and after.summary.get("reopened") is None
    assert await audited(api, "alert.folded_settled") == [] and await audited(api, REOPEN_ACTION) == []
    suggested = (await api.repos.audit.list(TENANT_A, action="suppression.suggested")).items
    assert [e.details["alert_id"] for e in suggested] in ([], [threat])


async def test_an_analyst_true_positive_reopens_the_alert_linked_to_the_case_and_resumes_only_the_threat(
    api: ApiHarness,
) -> None:
    """AI-E3.15: the analyst confirms three days after the link. The linked alert left the 24-hour window, and it
    reopens all the same: queued for its own review (the case is decided), never resumed with the case decision."""
    threat, linked, case = await threat_with_linked(api, "srv-app-03")
    assert case is not None
    response = await api.client.post(
        f"/api/v1/escalations/{case.id}/decision",
        json={"decision": "true_positive", "version": case.version}, headers=await api.login_headers(TENANT_A, "analyst"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["resumed_alert_ids"] == [threat]
    alert = await api.repos.alerts.get(TENANT_A, linked)
    assert (alert.status, alert.disposition, alert.summary["reopened"]["mode"]) == ("queued", None, "requeued")
    assert await audited(api, REOPEN_ACTION) == [linked]


async def test_an_approved_response_action_reopens_related_model_closes(api: ApiHarness) -> None:
    """AI-E3.15: a person approving a response for the threat confirms it. Rejecting one, or approving the
    rollback of one, confirms nothing. The workflow proposed the plan without a case, so the alert it linked then
    has no case either."""
    threat, linked, _ = await threat_with_linked(api, "srv-app-04", case=False)
    recent = await model_closed(api, {"hosts": ["srv-app-04"]})
    analyst = await api.login_headers(TENANT_A, "analyst")
    rejected, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.8", "low", status="awaiting_approval")
    approved, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.9", "low", status="awaiting_approval")
    rollback, _ = await api.repos.actions.propose(TENANT_A, threat, "unblock_ip", "203.0.113.8", "low",
                                                  status="awaiting_approval", rollback_of=rejected.id)

    for action, verb in ((rejected, "reject"), (rollback, "approve")):
        response = await api.client.post(f"/api/v1/actions/{action.id}/{verb}", json={}, headers=analyst)
        assert response.status_code == 200, response.text
        assert await audited(api, REOPEN_ACTION) == []
        assert (await api.repos.alerts.get(TENANT_A, recent)).status == "closed"

    response = await api.client.post(f"/api/v1/actions/{approved.id}/approve", json={}, headers=analyst)
    assert response.status_code == 200, response.text
    assert sorted(await audited(api, REOPEN_ACTION)) == sorted([linked, recent])
    for alert_id in (linked, recent):
        alert = await api.repos.alerts.get(TENANT_A, alert_id)
        assert (alert.status, alert.disposition, alert.summary["reopened"]["mode"]) == ("queued", None, "requeued")
    entry = (await api.repos.audit.list(TENANT_A, action=REOPEN_ACTION)).items[0]
    assert entry.actor_type == "user" and entry.details["threat_alert_id"] == threat


async def test_an_analyst_true_positive_reopens_related_model_closes(api: ApiHarness) -> None:
    threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                              normalized={"entities": {"hosts": ["srv-app-02"]}})
    closed_alert = await model_closed(api, {"hosts": ["srv-app-02"]})
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, threat, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    analyst = await api.login_headers(TENANT_A, "analyst")
    response = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "true_positive", "version": escalation.version}, headers=analyst,
    )
    assert response.status_code == 200, response.text
    await assert_reopened(api, closed_alert, escalation.id, "requeued")  # the case is decided: its own review


async def test_a_malicious_blind_audit_label_reopens_related_model_closes(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=1)
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=1)
    analyst = api.auth(await api.user(TENANT_A, "analyst"))
    [item] = await queue(api, analyst)
    sampled = await api.repos.alerts.get(TENANT_A, await alert_of(api, item))
    hosts = list(sampled.entities.get("hosts") or [])
    assert hosts, sampled.entities
    closed_alert = await model_closed(api, {"hosts": hosts})
    # Linked earlier, when a model judged another alert on this host a threat (AI-E3.15): it reopens too.
    assert await link_related_model_closes(
        api.repos, TENANT_A, await api.repos.alerts.get(TENANT_A, await make_alert(
            api.repos, TENANT_A, title="Beacon", normalized={"entities": {"hosts": hosts}})),
        actor=Actor("agent", "workflow"),
    ) == [closed_alert]
    response = await api.client.post(
        f"{API}/blind-audit/items/{item['id']}/label", json={"label": "malicious"}, headers=analyst
    )
    assert response.status_code == 200, response.text
    escalation = await api.repos.escalations.get_active_for_alert(TENANT_A, sampled.id)
    assert escalation is not None
    await assert_reopened(api, closed_alert, escalation.id, "folded")  # into the open blind-audit case


async def test_the_case_decision_settles_folded_alerts_in_its_own_transaction(api: ApiHarness) -> None:
    """INV-03 (FIX-3 review): an alert folded into an open case has no run waiting; the decision service closes it
    with the case decision (benign or malicious, audited) and sends it no resume message."""
    from lg_sotf.audit.logger import Actor
    from lg_sotf.core.retro_reopen import reopen_related_model_closes
    from lg_sotf.services.folded import SETTLED_ACTION

    for decision, disposition in (("false_positive", "benign"), ("true_positive", "malicious")):
        host = f"srv-{decision}"
        threat = await make_alert(api.repos, TENANT_A, title="Beacon", severity="medium",
                                  normalized={"entities": {"hosts": [host]}})
        closed_alert = await model_closed(api, {"hosts": [host]})
        case, _ = await api.repos.escalations.create_or_attach(
            TENANT_A, threat, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
        )
        await reopen_related_model_closes(api.repos, TENANT_A, await api.repos.alerts.get(TENANT_A, threat),
                                          actor=Actor("system", "test"), escalation_id=case.id)
        assert (await api.repos.alerts.get(TENANT_A, closed_alert)).status == "waiting_human"
        case = await api.repos.escalations.get(TENANT_A, case.id)
        analyst = await api.login_headers(TENANT_A, "analyst")
        response = await api.client.post(
            f"/api/v1/escalations/{case.id}/decision",
            json={"decision": decision, "version": case.version}, headers=analyst,
        )
        assert response.status_code == 200, response.text
        settled = await api.repos.alerts.get(TENANT_A, closed_alert)
        assert (settled.status, settled.disposition) == ("closed", disposition), decision
        audited = [e.resource_id for e in (await api.repos.audit.list(TENANT_A, action=SETTLED_ACTION)).items]
        assert closed_alert in audited


async def test_an_api_reopen_failure_is_counted_not_swallowed(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    from lg_sotf.api import common
    from lg_sotf.audit.logger import Actor

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database went away")

    monkeypatch.setattr(api.ctx.repos.alerts, "model_closed_sharing_entities", broken)
    alert_id = await make_alert(api.repos, TENANT_A, title="x", normalized={"entities": {"hosts": ["h1"]}})
    before = RETRO_REOPEN_FAILURES.labels(path="analyst")._value.get()
    analyst = await api.user(TENANT_A, "analyst")
    await common.invalidate_verdicts(api.ctx, TENANT_A, [alert_id], Actor("user", str(analyst.id)), path="analyst")
    assert RETRO_REOPEN_FAILURES.labels(path="analyst")._value.get() == before + 1
