"""Decision policy v3 safety net (FIX-3) on the API's threat paths: an analyst's ``true_positive`` decision and a
blind-audit ``malicious`` label reopen the model-closed alerts that share an entity with the alert, attach them to
its escalation and queue their new run."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import pytest

from lg_sotf.core.retro_reopen import REOPEN_ACTION
from lg_sotf.domain import closure
from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES
from tests.integration.api._blind_audit import API, alert_of, queue, sample, seed_frame
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration


async def model_closed(api: ApiHarness, entities: Dict[str, List[str]]) -> str:
    alert_id = await make_alert(api.repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(TENANT_A, alert_id, status)
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
