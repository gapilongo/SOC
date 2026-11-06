"""Escalation triage endpoints: grouping by rule, bulk claim / close / suppression proposal, response preview.

Bulk items go through the single-item service calls: each is audited like the single endpoint, keeps RBAC
and the optimistic lock, and never reaches another tenant's escalations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.db.repos import Escalation
from lg_sotf.services.triage import MAX_BULK
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
SIGN_IN = "Unusual sign-in pattern"


async def escalation(
    api: ApiHarness,
    tenant_id: str = TENANT_A,
    *,
    rule: str = SIGN_IN,
    source_id: str = "entra",
    severity: str = "medium",
    deadline: Optional[datetime] = None,
    confidence: float = 40.0,
    entities: Optional[Dict[str, List[str]]] = None,
    **alert: Any,
) -> Escalation:
    alert_id = await make_alert(
        api.repos,
        tenant_id,
        source_id=source_id,
        severity=severity,
        normalized={"title": rule, "rule_name": rule, "entities": entities or {"users": ["j.doe@a.example"]}},
        **alert,
    )
    created, _ = await api.repos.escalations.create_or_attach(
        tenant_id,
        alert_id,
        reason="grey zone",
        sla_deadline=deadline or datetime.now(UTC) + timedelta(hours=1),
        summary={"confidence": confidence},
    )
    return created


def items(*escalations: Escalation) -> List[Dict[str, Any]]:
    return [{"escalation_id": e.id, "version": e.version} for e in escalations]


async def audit_actions(api: ApiHarness, tenant_id: str, action: str) -> List[str]:
    entries = (await api.repos.audit.list(tenant_id, resource_type="escalation", limit=200)).items
    return [e.resource_id for e in entries if e.action == action]


async def test_groups_by_rule_and_lists_a_group(api: ApiHarness) -> None:
    now = datetime.now(UTC)
    a = await escalation(api, severity="high", deadline=now - timedelta(minutes=5), confidence=31)
    b = await escalation(api, confidence=48)
    c = await escalation(api, severity="low", confidence=36)
    await escalation(api, rule="Impossible travel")
    await escalation(api, TENANT_B)
    await escalation(api, TENANT_B)
    await escalation(api, TENANT_B)
    headers = await api.login_headers(TENANT_A, "viewer")

    response = await api.client.get(f"{API}/escalations/groups", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["truncated"] is False
    assert len(body["items"]) == 1  # the single "Impossible travel" escalation is below min_size
    group = body["items"][0]
    assert (group["rule"], group["source_id"], group["size"], group["unassigned"], group["overdue"]) == (
        SIGN_IN, "entra", 3, 3, 1
    )
    assert group["by_severity"] == {"high": 1, "medium": 1, "low": 1}
    assert (group["min_confidence"], group["max_confidence"]) == (31.0, 48.0)
    assert group["escalation_ids"][0] == a.id and set(group["escalation_ids"]) == {a.id, b.id, c.id}

    listed = await api.client.get(
        f"{API}/escalations", headers=headers, params={"source_id": "entra", "rule": SIGN_IN, "order": "sla_deadline"}
    )
    assert [e["id"] for e in listed.json()["items"]][0] == a.id and len(listed.json()["items"]) == 3
    everything = await api.client.get(f"{API}/escalations/groups", headers=headers, params={"min_size": 1})
    assert {g["rule"] for g in everything.json()["items"]} == {SIGN_IN, "Impossible travel"}


async def test_bulk_claim_reports_each_item_and_audits_it_like_a_single_claim(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    first, second, outdated, taken = [await escalation(api) for _ in range(4)]
    other = await api.user(TENANT_A, "analyst")
    await api.repos.escalations.claim(TENANT_A, taken.id, other.id, taken.version)
    foreign = await escalation(api, TENANT_B)
    body = {
        "items": items(first, second)
        + [{"escalation_id": outdated.id, "version": outdated.version + 7}]
        + items(taken, foreign)
    }

    response = await api.client.post(f"{API}/escalations/bulk/claim", json=body, headers=api.auth(analyst))
    assert response.status_code == 200, response.text
    out = response.json()
    assert (out["succeeded"], out["failed"]) == (2, 3)
    by_id = {r["escalation_id"]: r for r in out["results"]}
    assert [r["escalation_id"] for r in out["results"]] == [first.id, second.id, outdated.id, taken.id, foreign.id]
    assert by_id[first.id]["ok"] and by_id[first.id]["escalation"]["assigned_to"] == str(analyst.id)
    assert by_id[first.id]["escalation"]["assigned_to_email"] == analyst.email
    # Each failure is what POST /escalations/{id}/claim answers for it.
    assert (by_id[outdated.id]["error"]["status"], by_id[outdated.id]["error"]["code"]) == (409, "conflict")
    assert (by_id[taken.id]["error"]["status"], by_id[taken.id]["error"]["code"]) == (403, "forbidden")
    assert (by_id[foreign.id]["error"]["status"], by_id[foreign.id]["error"]["code"]) == (404, "not_found")
    single = await api.client.post(
        f"{API}/escalations/{taken.id}/claim", json={"version": taken.version + 1}, headers=api.auth(analyst)
    )
    assert single.status_code == 403
    assert sorted(await audit_actions(api, TENANT_A, "escalation.claimed")) == sorted([first.id, second.id])
    assert (await api.repos.escalations.get(TENANT_B, foreign.id)).assigned_to is None
    assert (await api.repos.escalations.get(TENANT_A, taken.id)).assigned_to == other.id
    assert (await api.repos.escalations.get(TENANT_A, outdated.id)).assigned_to is None


async def test_bulk_close_decides_each_item_with_one_note_and_resumes_runs(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    one, two = await escalation(api), await escalation(api)
    decided = await escalation(api)
    await api.repos.escalations.decide(
        TENANT_A, decided.id, decision="true_positive", decided_by=analyst.id, expected_version=decided.version
    )
    body = {"items": items(one, two, decided), "notes": "  VPN egress, known  ", "decision": "false_positive"}

    response = await api.client.post(f"{API}/escalations/bulk/close", json=body, headers=api.auth(analyst))
    assert response.status_code == 200, response.text
    out = response.json()
    assert (out["succeeded"], out["failed"], out["suppression"]) == (2, 1, None)
    results = {r["escalation_id"]: r for r in out["results"]}
    assert results[one.id]["escalation"]["decision"] == "false_positive"
    assert results[one.id]["resumes_enqueued"] == 1 and results[one.id]["resumes_failed"] == 0
    assert results[decided.id]["error"]["code"] in ("invalid_transition", "conflict")
    for e in (one, two):
        stored = await api.repos.escalations.get(TENANT_A, e.id)
        assert (stored.status, stored.decision, stored.decision_notes) == ("decided", "false_positive", "VPN egress, known")
    assert sorted(await audit_actions(api, TENANT_A, "escalation.decided")) == sorted([one.id, two.id])


async def test_bulk_close_can_propose_one_suppression(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    low = await escalation(api, severity="low")
    medium = await escalation(api, severity="medium")
    body = {"items": items(low, medium), "notes": "known scanner", "propose_suppression": True}
    out = (await api.client.post(f"{API}/escalations/bulk/close", json=body, headers=api.auth(analyst))).json()
    assert out["succeeded"] == 2 and out["suppression_created"] is True
    rule = out["suppression"]
    assert rule["enabled"] is False
    assert rule["match"]["severity"] == {"in": ["info", "low", "medium"]}
    assert rule["match"]["source_id"] == {"in": ["entra"]}
    rules = (await api.repos.suppressions.list(TENANT_A))
    assert [r.id for r in rules] == [rule["id"]]  # one proposal, not one suggestion per escalation


async def test_propose_suppression_is_all_or_nothing(api: ApiHarness) -> None:
    analyst = await api.user(TENANT_A, "analyst")
    benign = await escalation(api, severity="high")
    await api.repos.escalations.decide(
        TENANT_A, benign.id, decision="benign_positive", decided_by=analyst.id, expected_version=benign.version
    )
    pending = await escalation(api)
    foreign = await escalation(api, TENANT_B)
    headers = api.auth(analyst)
    url = f"{API}/escalations/bulk/propose-suppression"

    refused = await api.client.post(url, json={"escalation_ids": [benign.id, pending.id]}, headers=headers)
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "not_confirmed_benign"
    assert refused.json()["error"]["details"] == [{"escalation_id": pending.id}]
    missing = await api.client.post(url, json={"escalation_ids": [benign.id, foreign.id]}, headers=headers)
    assert missing.status_code == 404
    assert await api.repos.suppressions.list(TENANT_A) == [] and await api.repos.suppressions.list(TENANT_B) == []

    created = await api.client.post(url, json={"escalation_ids": [benign.id], "name": "VPN noise"}, headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["suppression"]["name"] == "VPN noise" and created.json()["escalation_ids"] == [benign.id]
    again = await api.client.post(url, json={"escalation_ids": [benign.id]}, headers=headers)
    assert again.status_code == 200 and again.json()["created"] is False
    viewer = await api.client.post(url, json={"escalation_ids": [benign.id]}, headers=await api.login_headers(TENANT_A, "viewer"))
    assert viewer.status_code == 403


async def test_bulk_requests_are_bounded_and_need_distinct_ids(api: ApiHarness) -> None:
    headers = await api.login_headers(TENANT_A, "analyst")
    too_many = [{"escalation_id": f"e{i}", "version": 0} for i in range(MAX_BULK + 1)]
    for path, body in (
        ("claim", {"items": too_many}),
        ("close", {"items": too_many, "notes": "n"}),
        ("propose-suppression", {"escalation_ids": [f"e{i}" for i in range(MAX_BULK + 1)]}),
        ("claim", {"items": [{"escalation_id": "e1", "version": 0}] * 2}),
        ("close", {"items": [{"escalation_id": "e1", "version": 0}], "notes": "   "}),
        ("close", {"items": [{"escalation_id": "e1", "version": 0}], "notes": "n", "decision": "true_positive"}),
    ):
        response = await api.client.post(f"{API}/escalations/bulk/{path}", json=body, headers=headers)
        assert response.status_code == 422, (path, response.text)
    viewer = await api.login_headers(TENANT_A, "viewer")
    denied = await api.client.post(
        f"{API}/escalations/bulk/claim", json={"items": [{"escalation_id": "e1", "version": 0}]}, headers=viewer
    )
    assert denied.status_code == 403


async def test_response_preview_shows_risk_reversibility_connector_and_role_lock(api: ApiHarness) -> None:
    created = await escalation(
        api,
        severity="high",
        rule="Ransomware beacon on workstation",
        entities={"hosts": ["ws-042"], "ips": ["185.220.101.44"], "users": ["j.doe"]},
    )
    await api.repos.alerts.update(
        TENANT_A,
        created.alert_id,
        summary={"analysis": {"conclusion": "Ransomware C2 beacon; isolate the host.", "recommended_actions": ["isolate host"]}},
    )
    url = f"{API}/escalations/{created.id}/response-preview"

    as_analyst = await api.client.get(url, headers=await api.login_headers(TENANT_A, "analyst"))
    assert as_analyst.status_code == 200, as_analyst.text
    preview = as_analyst.json()
    assert preview["evidence"] == "analyst" and preview["alert_id"] == created.alert_id
    actions = {(a["action_type"], a["target"]): a for a in preview["actions"]}
    isolate = actions[("isolate_host", "ws-042")]
    assert (isolate["risk"], isolate["reversible"], isolate["inverse_action"]) == ("high", True, "release_host")
    assert (isolate["can_preapprove"], isolate["role_lock"]) == (False, "admin")
    assert isolate["approval_entry"] == "isolate_host:ws-042"
    assert isolate["guardrail"]["verdict"] == "passed"
    assert isolate["connector"]["name"] and isinstance(isolate["connector"]["ready"], bool)
    assert all(a["without_preapproval"] in ("automatic", "awaiting_approval", "blocked") for a in preview["actions"])

    as_admin = (await api.client.get(url, headers=await api.login_headers(TENANT_A, "admin"))).json()
    admin_isolate = next(a for a in as_admin["actions"] if a["approval_entry"] == "isolate_host:ws-042")
    assert admin_isolate["can_preapprove"] is True

    await api.repos.tenants.update_settings(TENANT_A, {"protected_assets": {"hosts": ["ws-*"]}})
    blocked = (await api.client.get(url, headers=await api.login_headers(TENANT_A, "admin"))).json()
    protected = next(a for a in blocked["actions"] if a["approval_entry"] == "isolate_host:ws-042")
    assert (protected["guardrail"]["code"], protected["without_preapproval"], protected["can_preapprove"]) == (
        "protected_asset", "blocked", False
    )
    assert await api.repos.actions.list(TENANT_A, alert_id=created.alert_id) is not None
    assert (await api.repos.actions.list(TENANT_A, alert_id=created.alert_id)).items == []  # nothing written

    foreign = await escalation(api, TENANT_B)
    other = await api.client.get(
        f"{API}/escalations/{foreign.id}/response-preview", headers=await api.login_headers(TENANT_A, "admin")
    )
    assert other.status_code == 404
