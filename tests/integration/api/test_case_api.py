"""``GET /cases/{id}`` (PRD-2.9): the case read model over stored rows.

A case is the escalation with its alerts. The tests cover the question the
page answers ("what did the AI close on this host while this case was open,
and why"), an alert the safety net linked and one it reopened (requeued, and
folded into the open case), the response actions with their status and
guardrail result, an analyst's close with the note, the blind-audit rule
that nobody sees the AI's side of a pending sample, tenant isolation and
MSSP grant access. The route only reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict

import pytest

from lg_sotf.domain import closure
from lg_sotf.domain.case import words
from lg_sotf.domain.investigation import words as investigation_words
from tests.integration.api._safety_net import threat_with_linked
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"
HOST = "ws-fin-0142"


async def case_view(api: ApiHarness, case_id: str, headers: Dict[str, str]) -> Dict[str, Any]:
    response = await api.client.get(f"{API}/cases/{case_id}", headers=headers)
    assert response.status_code == 200, response.text
    body: Dict[str, Any] = response.json()
    return body


def alert_of(body: Dict[str, Any], alert_id: str) -> Dict[str, Any]:
    found: Dict[str, Any] = next(a for a in body["alerts"] if a["id"] == alert_id)
    return found


async def node_event(api: ApiHarness, alert_id: str, node: str, data: Dict[str, Any]) -> None:
    await api.repos.alert_events.append(
        TENANT_A, alert_id, "node.completed", node=node, actor_type="system", actor_id="workflow", data=data
    )


async def model_close_steps(api: ApiHarness, alert_id: str) -> None:
    """The timeline the workflow leaves on an alert it closed on the model's word."""
    await node_event(api, alert_id, "triage", {"confidence": 20, "llm_used": True})
    await node_event(api, alert_id, "decide", {"route": "close", "code": "model_closed", "autonomy_tier": "auto_full_audit"})
    await node_event(api, alert_id, "close", {"disposition": "benign", "close_reason": closure.MODEL_CLOSE_REASON})


async def a_case_in(api: ApiHarness, tenant_id: str) -> str:
    alert_id = await make_alert(api.repos, tenant_id, title="Beacon to a new domain", severity="high",
                                normalized={"entities": {"hosts": [HOST]}})
    escalation, _ = await api.repos.escalations.create_or_attach(
        tenant_id, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1),
        summary={"verdict": "malicious", "routing": {"code": "inconclusive"}},
    )
    return escalation.id


# ------------------------------------------------------------------ the question the page answers


async def test_the_case_view_says_what_the_ai_closed_on_the_host_while_the_case_was_open_and_why(api: ApiHarness) -> None:
    """PRD-2.9 acceptance: one read answers "what did the AI close on this host while this case was open, and why"."""
    threat, linked, case = await threat_with_linked(api, HOST)
    assert case is not None
    await model_close_steps(api, linked)
    audits_before = len((await api.repos.audit.list(TENANT_A, limit=200)).items)

    body = await case_view(api, case.id, await api.login_headers(TENANT_A, "viewer"))
    assert (body["schema_version"], body["id"], body["alert_id"], body["tenant_id"]) == (1, case.id, threat, TENANT_A)
    assert (body["title"], body["status"], body["active"], body["version"]) == ("Beacon", "open", True, case.version)
    assert (body["owner"], body["decision"], body["alerts_truncated"]) == (None, None, False)
    counts = body["counts"]
    assert (counts["alerts"], counts["open"], counts["closed"], counts["linked"], counts["reopened"]) == (2, 0, 1, 1, 0)
    assert counts["closed_by"] == {"ai_evidence": 0, "ai_audit": 1, "suppression_rule": 0, "cached_verdict": 0, "analyst": 0}

    closed = alert_of(body, linked)
    assert (closed["role"], closed["state"], closed["status"], closed["category"]) == ("linked", "closed", "closed", "ai_closed_audit")
    by = closed["closed_by"]
    assert (by["kind"], by["reason"]["code"]) == ("ai", closure.MODEL_CLOSE_REASON)
    assert by["reason"]["sentence"] == investigation_words.CLOSE_REASONS[closure.MODEL_CLOSE_REASON].sentence
    assert by["policy"] == {"code": "model_closed", "sentence": investigation_words.DECIDE_SENTENCES["model_closed"]}
    assert (by["tier"], by["analyst"], by["at"] is not None) == ("auto_full_audit", None, True)
    assert closed["link"]["reason"] == {"code": "related_threat", "sentence": words.LINKED}
    assert closed["link"]["threat_alert_id"] == threat and closed["link"]["at"]
    assert closed["blind_audit"] == {"state": "not_sampled", "label": None, "agrees": None, "labelled_at": None}
    assert closed["entities"] == [{"kind": "host", "value": HOST}]

    primary = alert_of(body, threat)
    assert (primary["role"], primary["closed_by"], primary["link"], primary["reopened"]) == ("primary", None, None, None)
    assert body["entities"] == [{"kind": "host", "value": HOST, "alerts": 2}]
    kinds = [(e["kind"], e["alert_id"]) for e in body["timeline"]]
    assert ("alert.linked", linked) in kinds and ("step.close", linked) in kinds and ("case.opened", None) in kinds
    assert not any(kind in ("step.triage", "step.decide") for kind, _ in kinds)
    assert {"key", "summary"} <= {n["field"] for n in body["not_available"]}
    assert len((await api.repos.audit.list(TENANT_A, limit=200)).items) == audits_before  # the route only reads


# ------------------------------------------------------------------ reopened by the safety net


async def test_a_true_positive_reopens_the_linked_alert_and_the_case_says_who_confirmed(api: ApiHarness) -> None:
    threat, linked, case = await threat_with_linked(api, HOST)
    assert case is not None
    analyst = await api.user(TENANT_A, "analyst")
    response = await api.client.post(
        f"{API}/escalations/{case.id}/decision", headers=api.auth(analyst),
        json={"decision": "true_positive", "version": case.version, "notes": "The beacon is the script's callback."},
    )
    assert response.status_code == 200, response.text

    body = await case_view(api, case.id, api.auth(analyst))
    assert (body["status"], body["active"]) == ("decided", False)
    decision = body["decision"]
    assert (decision["decision"], decision["notes"]) == ("true_positive", "The beacon is the script's callback.")
    assert decision["decided_by"] == {"user_id": str(analyst.id), "email": analyst.email}
    back = alert_of(body, linked)
    assert (back["role"], back["state"], back["status"], back["closed_by"], back["link"]) == (
        "reopened", "processing", "queued", None, None)
    reopened = back["reopened"]
    assert (reopened["confirmed_by"], reopened["mode"], reopened["threat_alert_id"]) == ("person", "requeued", threat)
    assert reopened["by"] == {"user_id": str(analyst.id), "email": analyst.email}
    assert reopened["reason"] == {"code": "related_threat", "sentence": words.REOPENED_BY["person"]}
    # The helper leaves the threat alert as it arrived (new): it counts as processing too.
    assert (body["counts"]["linked"], body["counts"]["reopened"], body["counts"]["processing"]) == (0, 1, 2)
    by_kind = {e["kind"]: e for e in body["timeline"]}
    assert by_kind["case.decided"]["produced"] == "true positive" and by_kind["case.decided"]["by"]["email"] == analyst.email
    assert by_kind["alert.reopened"]["alert_id"] == linked


async def test_an_approval_while_the_case_is_open_folds_the_linked_alert_into_it_and_lists_the_actions(
    api: ApiHarness,
) -> None:
    threat, linked, case = await threat_with_linked(api, HOST)
    assert case is not None
    await api.repos.alerts.update(TENANT_A, threat, summary={"escalation_id": case.id})  # as the escalate step records it
    approve, _ = await api.repos.actions.propose(TENANT_A, threat, "block_ip", "203.0.113.9", "low", status="awaiting_approval")
    await api.repos.actions.propose(TENANT_A, threat, "isolate_host", HOST, "high", status="awaiting_approval")
    await api.repos.actions.propose(TENANT_A, threat, "reset_password", "m.keller@northwind.example", "critical",
                                    status="blocked", blocked_reason="autonomy_disabled")
    await api.repos.actions.propose(TENANT_A, linked, "block_domain", "cdn-invoice-portal.example", "medium", status="dry_run")
    analyst = await api.user(TENANT_A, "analyst")

    before = await case_view(api, case.id, api.auth(analyst))
    assert before["counts"]["actions_awaiting_approval"] == 2
    assert [(a["action_type"], a["status"], a["alert_id"]) for a in before["actions"]] == [
        ("block_ip", "awaiting_approval", threat), ("isolate_host", "awaiting_approval", threat),
        ("reset_password", "blocked", threat), ("block_domain", "dry_run", linked),
    ]
    blocked = before["actions"][2]
    assert (blocked["guardrail"]["verdict"], blocked["guardrail"]["code"]) == ("blocked", "autonomy_disabled")
    assert blocked["guardrail"]["reason"] and before["actions"][1]["reversible"] is True
    assert all(a["action_id"] and a["created_at"] for a in before["actions"])

    approved = await api.client.post(f"{API}/actions/{approve.id}/approve", json={}, headers=api.auth(analyst))
    assert approved.status_code == 200, approved.text
    body = await case_view(api, case.id, api.auth(analyst))
    assert body["active"] is True and body["counts"]["actions_awaiting_approval"] == 1
    folded = alert_of(body, linked)
    assert (folded["role"], folded["state"], folded["status"]) == ("reopened", "open", "waiting_human")
    assert (folded["reopened"]["mode"], folded["reopened"]["confirmed_by"]) == ("folded", "person")
    assert folded["why"] == {"code": "reopened", "sentence": investigation_words.DECIDE_SENTENCES["reopened"]}
    assert (body["counts"]["open"], body["counts"]["reopened"], body["counts"]["linked"]) == (1, 1, 0)


# ------------------------------------------------------------------ closed by an analyst


async def test_an_analyst_close_carries_the_decision_who_decided_and_the_note(api: ApiHarness) -> None:
    case_id = await a_case_in(api, TENANT_A)
    case = await api.repos.escalations.get(TENANT_A, case_id)
    analyst = await api.user(TENANT_A, "analyst")
    response = await api.client.post(
        f"{API}/escalations/{case_id}/decision", headers=api.auth(analyst),
        json={"decision": "benign_positive", "version": case.version, "notes": "The backup job talks to this domain."},
    )
    assert response.status_code == 200, response.text
    # What the resumed run records on the alert (no worker runs in this test).
    await api.repos.alert_events.append(
        TENANT_A, case.alert_id, "analyst.decision", node="await_analyst", actor_type="user", actor_id=str(analyst.id),
        data={"decision": "benign_positive", "escalation_id": case_id},
    )
    await api.repos.alerts.update(TENANT_A, case.alert_id, disposition="benign",
                                  summary={"close_reason": "analyst:benign_positive", "analyst_decision": "benign_positive"})
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(TENANT_A, case.alert_id, status)

    body = await case_view(api, case_id, await api.login_headers(TENANT_A, "viewer"))
    [alert] = body["alerts"]
    by = alert["closed_by"]
    assert (alert["state"], alert["disposition"], by["kind"], by["decision"]) == ("closed", "benign", "analyst", "benign_positive")
    assert by["analyst"] == {"user_id": str(analyst.id), "email": analyst.email}
    assert (by["notes"], by["decided_in_case_id"]) == ("The backup job talks to this domain.", case_id)
    assert by["reason"]["sentence"] == investigation_words.CLOSE_REASONS["analyst:benign_positive"].sentence
    assert body["counts"]["closed_by"]["analyst"] == 1
    assert [e["kind"] for e in body["timeline"] if "decision" in e["kind"] or e["kind"] == "case.decided"] == ["case.decided"]


# ------------------------------------------------------------------ blind audit


async def test_a_linked_alert_that_waits_for_its_blind_audit_label_shows_nothing_of_the_ai_side(api: ApiHarness) -> None:
    _, linked, case = await threat_with_linked(api, HOST)
    assert case is not None
    await model_close_steps(api, linked)
    await api.repos.actions.propose(TENANT_A, linked, "block_domain", "cdn-invoice-portal.example", "medium", status="dry_run")
    now = datetime.now(UTC)
    await api.repos.blind_audit.create_run(
        TENANT_A, since=now - timedelta(days=7), until=now, seed=1, sample_rate=0.02, min_sample=0, fixed_size=None,
        frame_size=1, items=[(linked, 1, "benign")], trigger="cli", created_by="seed",
    )
    headers = await api.login_headers(TENANT_A, "admin")

    hidden = await case_view(api, case.id, headers)
    alert = alert_of(hidden, linked)
    assert (alert["hidden_for_blind_audit"], alert["role"], alert["state"]) == (True, "withheld", "closed")
    assert (alert["closed_by"], alert["category"], alert["disposition"], alert["link"], alert["why"]) == (None,) * 5
    assert alert["blind_audit"]["state"] == "pending"
    assert (hidden["counts"]["withheld"], hidden["counts"]["linked"], hidden["counts"]["closed_by"]["ai_audit"]) == (1, 0, 0)
    assert [e["kind"] for e in hidden["timeline"] if e["alert_id"] == linked] == ["alert.received"]
    assert hidden["actions"] == []
    assert closure.MODEL_CLOSE_REASON not in str(hidden) and "model_closed" not in str(hidden)

    item = (await api.repos.blind_audit.list_items(TENANT_A)).items[0]
    assert await api.repos.blind_audit.label(
        TENANT_A, item.id, label="benign", notes=None, agreement=True, labelled_by=None, labelled_by_actor="seed",
        escalation_id=None, now=datetime.now(UTC),
    )
    shown = await case_view(api, case.id, headers)
    alert = alert_of(shown, linked)
    assert (alert["hidden_for_blind_audit"], alert["role"], alert["closed_by"]["kind"]) == (False, "linked", "ai")
    audit = alert["blind_audit"]
    assert (audit["state"], audit["label"], audit["agrees"], audit["labelled_at"] is not None) == ("labelled", "benign", True, True)
    assert [a["action_type"] for a in shown["actions"]] == ["block_domain"]


# ------------------------------------------------------------------ who may read it


async def test_another_tenant_cannot_read_the_case(api: ApiHarness) -> None:
    case_id = await a_case_in(api, TENANT_B)
    url = f"{API}/cases/{case_id}"
    for role in ("viewer", "analyst", "admin"):
        response = await api.client.get(url, headers=await api.login_headers(TENANT_A, role))
        assert response.status_code == 404, (role, response.text)
        assert HOST not in response.text and "Beacon" not in response.text
    assert (await api.client.get(url)).status_code == 401
    ingest_only = await api.client.get(url, headers=await api.key_headers(TENANT_B, ("ingest",)))
    assert ingest_only.status_code == 403
    own = await api.client.get(url, headers=await api.login_headers(TENANT_B, "viewer"))
    assert own.status_code == 200 and own.json()["tenant_id"] == TENANT_B
    missing = await api.client.get(f"{API}/cases/no-such-case", headers=await api.login_headers(TENANT_B, "viewer"))
    assert missing.status_code == 404


async def test_mssp_grant_access_follows_the_existing_rules(api: ApiHarness) -> None:
    case_id = await a_case_in(api, TENANT_B)
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    url = f"{API}/cases/{case_id}"

    assert (await api.client.get(url, headers=headers)).status_code == 403  # no grant
    grant = await api.repos.grants.create(
        TENANT_B, ORG, "viewer", reason="night shift", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=4),
    )
    granted = await api.client.get(url, headers=headers)
    assert granted.status_code == 200, granted.text
    assert (granted.json()["tenant_id"], granted.json()["category"]) == (TENANT_B, "needs_decision")
    # The grant reaches the customer only: the same case id in the organisation's own tenant is not found.
    assert (await api.client.get(url, headers=api.auth(staff))).status_code == 404
    await api.repos.grants.revoke(TENANT_B, grant.id, revoked_by="customer-admin")
    assert (await api.client.get(url, headers=headers)).status_code == 403
