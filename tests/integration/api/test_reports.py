"""``/reports``: value, accuracy and detections numbers on seeded data, exports, tenant isolation and caching."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, Optional

import pytest

from lg_sotf.core.suppression import alert_match_view, first_matching_rule
from lg_sotf.db.repos import LLMUsageDelta, Repositories
from lg_sotf.services.report_render import REPORT_CSS
from tests.integration.api.conftest import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

D1 = datetime(2026, 9, 1, tzinfo=UTC)
D2 = datetime(2026, 9, 2, tzinfo=UTC)
WINDOW = "from=2026-09-01&to=2026-09-02"


async def seed_alert(
    repos: Repositories,
    tenant_id: str,
    ingested_at: datetime,
    *,
    status: str = "closed",
    disposition: Optional[str] = None,
    closed_after_s: Optional[float] = None,
    summary: Optional[Dict[str, Any]] = None,
    triage_after_s: Optional[float] = None,
    severity: str = "low",
    source_id: str = "splunk",
    rule: Optional[str] = None,
    title: str = "Alert",
) -> str:
    normalized: Dict[str, Any] = {"title": title}
    if rule is not None:
        normalized["rule_name"] = rule
    alert_id = await make_alert(
        repos, tenant_id, ingested_at=ingested_at, severity=severity, source_id=source_id, title=title,
        normalized=normalized,
    )
    closed_at = ingested_at + timedelta(seconds=closed_after_s) if closed_after_s is not None else None
    async with repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE alerts SET status = $3, disposition = $4, closed_at = $5, summary = $6 "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            alert_id,
            status,
            disposition,
            closed_at,
            summary or {},
        )
    if triage_after_s is not None:
        await repos.alert_events.append(
            tenant_id, alert_id, "node.completed", node="triage", actor_type="agent", actor_id="triage",
            ts=ingested_at + timedelta(seconds=triage_after_s),
        )
    return alert_id


async def seed_escalation(
    repos: Repositories,
    tenant_id: str,
    alert_id: str,
    created_at: datetime,
    *,
    summary: Optional[Dict[str, Any]] = None,
    claimed_after_s: Optional[float] = None,
    status: str = "cancelled",
) -> str:
    esc, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="review", summary=summary or {})
    claimed = created_at + timedelta(seconds=claimed_after_s) if claimed_after_s is not None else None
    async with repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE escalations SET created_at = $2, claimed_at = $3, status = $4 WHERE id = $1",
            esc.id,
            created_at,
            claimed,
            status,
        )
    return esc.id


async def seed_value_data(repos: Repositories) -> Dict[str, str]:
    """Ten alerts on 2026-09-01/02 with every outcome the value report distinguishes."""
    ids: Dict[str, str] = {}
    h = timedelta(hours=1)
    ids["a1"] = await seed_alert(repos, TENANT_A, D1 + 10 * h, disposition="benign", closed_after_s=60,
                                 summary={"close_reason": "triage:false_positive"}, triage_after_s=30)
    ids["a2"] = await seed_alert(repos, TENANT_A, D1 + 11 * h, disposition="benign", closed_after_s=10,
                                 summary={"close_reason": "suppression_rule",
                                          "suppressed_by": {"type": "suppression_rule", "rule_id": "r"}})
    ids["a3"] = await seed_alert(repos, TENANT_A, D1 + 12 * h, disposition="malicious", closed_after_s=120,
                                 summary={"close_reason": "policy:response", "dry_run": False}, triage_after_s=20)
    ids["a4"] = await seed_alert(repos, TENANT_A, D1 + 13 * h, disposition="malicious", closed_after_s=100,
                                 summary={"close_reason": "policy:response", "dry_run": True}, triage_after_s=40)
    ids["a5"] = await seed_alert(repos, TENANT_A, D2 + 9 * h, disposition="malicious", closed_after_s=3600,
                                 summary={"close_reason": "analyst:true_positive", "analyst_decision": "true_positive",
                                          "escalation_id": "e5"}, triage_after_s=50)
    ids["a6"] = await seed_alert(repos, TENANT_A, D2 + 10 * h, status="waiting_human",
                                 summary={"escalation_id": "e6"}, triage_after_s=10)
    ids["a7"] = await seed_alert(repos, TENANT_A, D2 + 11 * h, disposition="malicious", closed_after_s=500,
                                 summary={"close_reason": "policy:response", "dry_run": False}, triage_after_s=5)
    ids["a8"] = await seed_alert(repos, TENANT_A, D2 + 12 * h, status="processing")
    ids["a9"] = await seed_alert(repos, TENANT_A, D2 + 13 * h, disposition="benign", closed_after_s=5,
                                 summary={"close_reason": "verdict_cache",
                                          "suppressed_by": {"type": "verdict_cache", "decision": "false_positive"}})
    ids["a10"] = await seed_alert(repos, TENANT_A, D2 + 14 * h, disposition="benign", closed_after_s=7200,
                                  summary={"close_reason": "analyst:false_positive", "analyst_decision": "false_positive",
                                           "escalation_id": "e5", "escalation_attached": True}, triage_after_s=15)
    # Outside the window and in another tenant: never counted.
    await seed_alert(repos, TENANT_A, D1 - timedelta(seconds=1), disposition="benign", closed_after_s=1)
    await seed_alert(repos, TENANT_B, D1 + h, disposition="benign", closed_after_s=1)
    # a7's response action was approved by a person: a human handled it.
    action, _ = await repos.actions.propose(TENANT_A, ids["a7"], "block_ip", "203.0.113.7", "medium")
    # a3's action was approved by the policy: still handled without a human.
    auto, _ = await repos.actions.propose(TENANT_A, ids["a3"], "block_ip", "203.0.113.8", "low")
    async with repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'succeeded', approved_by = $2, created_at = $3 WHERE id = $1",
            action.id, "8e0cbb2c-6f37-4a8f-9b43-0d5f1c3d2a10", D2 + 11 * h,
        )
        await conn.execute(
            "UPDATE response_actions SET status = 'succeeded', approved_by = 'policy:auto', created_at = $2 "
            "WHERE id = $1",
            auto.id, D1 + 12 * h,
        )
    e5 = await seed_escalation(repos, TENANT_A, ids["a5"], D2 + 9 * h + timedelta(minutes=5), claimed_after_s=600)
    e6 = await seed_escalation(repos, TENANT_A, ids["a6"], D2 + 10 * h + timedelta(minutes=1), status="open")
    ids["e5"], ids["e6"] = e5, e6
    for day, cost in ((D1.date(), "0.50"), (D2.date(), "0.25"), (D1.date() - timedelta(days=1), "9.00")):
        await repos.llm_usage.upsert_daily(
            [LLMUsageDelta(tenant_id=TENANT_A, day=day, model="m", agent="triage", calls=1, cost_usd=Decimal(cost))]
        )
    # Two SLA sweep actions on the same escalation on day 2.
    for action_name in ("escalation.sla_escalated", "escalation.sla_expired"):
        entry = await repos.audit.append(TENANT_A, "system", "scheduler", action_name, "escalation", e6, {})
        async with repos.db.system_tx() as conn:
            await conn.execute("UPDATE audit_log SET ts = $2 WHERE id = $1", entry.id, D2 + 20 * h)
    return ids


async def test_value_report_numbers_are_exact(api: ApiHarness) -> None:
    await seed_value_data(api.repos)
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=viewer)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["from"] == "2026-09-01" and body["to"] == "2026-09-02" and body["minutes_per_alert"] == 15
    t = body["totals"]
    assert t["alerts_ingested"] == 10
    assert t["handled_without_human"] == 5 and t["needed_human"] == 4 and t["in_progress"] == 1
    assert t["handled_without_human_rate"] == pytest.approx(5 / 9)
    assert t["analyst_hours_saved"] == pytest.approx(1.25)
    assert (t["auto_closed_benign"], t["auto_contained"], t["auto_contained_dry_run"]) == (3, 1, 1)
    assert (t["escalated"], t["human_decided"]) == (3, 2)
    assert (t["suppressed_by_rule"], t["verdict_cache_hits"], t["grouped_into_escalation"]) == (1, 1, 1)
    assert t["resolved"] == 8
    assert t["mttr_s"] == pytest.approx((60 + 10 + 120 + 100 + 3600 + 500 + 5 + 7200) / 8)
    assert t["mttr_auto_s"] == pytest.approx((60 + 10 + 120 + 100 + 5) / 5)
    assert t["mttr_human_s"] == pytest.approx((3600 + 7200) / 2)
    assert t["verdicts"] == 9
    assert t["mean_time_to_verdict_s"] == pytest.approx((30 + 10 + 20 + 40 + 50 + 10 + 5 + 5 + 15) / 9)
    assert (t["escalations_created"], t["acknowledged"], t["mtta_s"]) == (2, 1, pytest.approx(600))
    assert t["sla_breaches"] == 2 and body["escalations_breached"] == 1
    assert t["llm_cost_usd"] == pytest.approx(0.75)
    assert t["llm_cost_per_alert_usd"] == pytest.approx(0.075)
    days = {d["day"]: d for d in body["days"]}
    assert list(days) == ["2026-09-01", "2026-09-02"]
    first, second = days["2026-09-01"], days["2026-09-02"]
    assert (first["alerts_ingested"], first["handled_without_human"], first["needed_human"]) == (4, 4, 0)
    assert first["handled_without_human_rate"] == 1.0 and first["analyst_hours_saved"] == pytest.approx(1.0)
    assert first["llm_cost_per_alert_usd"] == pytest.approx(0.125) and first["sla_breaches"] == 0
    assert (second["alerts_ingested"], second["handled_without_human"], second["needed_human"]) == (6, 1, 4)
    assert second["sla_breaches"] == 2 and second["mtta_s"] == pytest.approx(600)
    assert first["mtta_s"] is None


async def test_value_report_empty_window_and_validation(api: ApiHarness) -> None:
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get("/api/v1/reports/value?from=2020-01-01&to=2020-01-03", headers=viewer)
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["days"]) == 3
    t = body["totals"]
    assert t["alerts_ingested"] == 0 and t["handled_without_human_rate"] is None
    assert t["mttr_s"] is None and t["mtta_s"] is None and t["llm_cost_per_alert_usd"] is None
    assert t["analyst_hours_saved"] == 0.0
    too_long = await api.client.get("/api/v1/reports/value?from=2025-01-01&to=2026-01-02", headers=viewer)
    assert too_long.status_code == 400 and too_long.json()["error"]["code"] == "invalid_window"
    backwards = await api.client.get("/api/v1/reports/value?from=2026-01-02&to=2026-01-01", headers=viewer)
    assert backwards.status_code == 400
    default = await api.client.get("/api/v1/reports/value", headers=viewer)
    assert default.status_code == 200 and len(default.json()["days"]) == 30


async def test_minutes_per_alert_setting_drives_hours_saved(api: ApiHarness) -> None:
    await seed_value_data(api.repos)
    admin = await api.login_headers(TENANT_A, "admin")
    for bad in ({"minutes_per_alert": 0}, {"minutes_per_alert": "30"}, {"minutes_per_alert": True}, {"other": 1}, 5):
        refused = await api.client.patch("/api/v1/tenant/settings", json={"reporting": bad}, headers=admin)
        assert refused.status_code == 422, (bad, refused.text)
    patched = await api.client.patch(
        "/api/v1/tenant/settings", json={"reporting": {"minutes_per_alert": 30}}, headers=admin
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["settings"]["reporting"] == {"minutes_per_alert": 30}
    audit = (await api.repos.audit.list(TENANT_A, action="tenant.settings_updated")).items
    assert audit and audit[0].details["keys"] == ["reporting"]
    body = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=admin)).json()
    assert body["minutes_per_alert"] == 30 and body["totals"]["analyst_hours_saved"] == pytest.approx(2.5)
    # Removing the key restores the default.
    reset = await api.client.patch(
        "/api/v1/tenant/settings", json={"reporting": {"minutes_per_alert": None}}, headers=admin
    )
    assert reset.status_code == 200 and reset.json()["settings"]["reporting"] == {}
    api.ctx.tenants.invalidate(TENANT_A)
    body = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=admin)).json()
    assert body["minutes_per_alert"] == 15 and body["totals"]["analyst_hours_saved"] == pytest.approx(1.25)


async def test_value_csv_export(api: ApiHarness) -> None:
    await seed_value_data(api.repos)
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get(f"/api/v1/reports/value?{WINDOW}&format=csv", headers=viewer)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert [r["day"] for r in rows] == ["2026-09-01", "2026-09-02"]
    assert rows[0]["alerts_ingested"] == "4" and rows[1]["handled_without_human"] == "1"


async def seed_accuracy_data(repos: Repositories) -> None:
    """Six scored decisions, one needs_more_info-only alert and one decision outside the window."""
    in_window = D2 + timedelta(hours=1)

    async def case(
        esc_summaries: list,
        decisions: list,
        *,
        alert_summary: Optional[Dict[str, Any]] = None,
        feedback: Optional[Dict[str, Any]] = None,
        decided_at: datetime = in_window,
    ) -> None:
        alert_id = await seed_alert(repos, TENANT_A, D1, status="closed", disposition="benign", closed_after_s=1,
                                    summary=alert_summary)
        for i, (esc_summary, decision) in enumerate(zip(esc_summaries, decisions, strict=True)):
            esc = await seed_escalation(repos, TENANT_A, alert_id, D1 + timedelta(minutes=i), summary=esc_summary)
            await repos.feedback.create(TENANT_A, esc, alert_id, decision, **(feedback or {}))
            async with repos.db.system_tx() as conn:
                await conn.execute(
                    "UPDATE analyst_feedback SET created_at = $2 WHERE escalation_id = $1",
                    esc,
                    decided_at + timedelta(minutes=i),
                )

    claude = {"llm_usage": {"calls": 2, "by_agent": {"analysis": {"calls": 1, "provider": "anthropic",
                                                                   "model": "claude-x"}}}}
    await case([{"verdict": "malicious", "threat_score": 90}], ["true_positive"], alert_summary=claude,
               feedback={"triage_correct": True, "analysis_accurate": True})
    await case([{"verdict": "benign", "threat_score": 10}], ["true_positive"], alert_summary=claude,
               feedback={"triage_correct": False, "analysis_accurate": False})
    await case([{"verdict": None, "threat_score": 20, "confidence": 50}], ["false_positive"],
               alert_summary={"llm_usage": {"calls": 1, "by_agent": {"triage": {"calls": 1}}}},
               feedback={"triage_correct": True})
    await case([{"threat_score": None, "confidence": 90}], ["benign_positive"])
    await case([{"verdict": "inconclusive", "threat_score": 50}], ["false_positive"])
    # needs_more_info on the first escalation (AI said benign), then a true positive on the second:
    # the AI verdict of the FIRST escalation is scored, so this is a false negative.
    await case([{"verdict": "benign"}, {"verdict": "malicious"}], ["needs_more_info", "true_positive"])
    await case([{"verdict": "malicious"}], ["needs_more_info"])
    await case([{"verdict": "benign"}], ["true_positive"], decided_at=D1 - timedelta(days=3))
    await seed_alert(repos, TENANT_B, D1, disposition="benign", closed_after_s=1)


async def test_accuracy_report_confusion_matrix_and_rates(api: ApiHarness) -> None:
    await seed_accuracy_data(api.repos)
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get(f"/api/v1/reports/accuracy?{WINDOW}", headers=viewer)
    assert response.status_code == 200, response.text
    body = response.json()
    overall = body["overall"]
    assert overall["samples"] == 6 and overall["status"] == "insufficient_data"
    assert overall["confusion_matrix"] == {
        "malicious": {"malicious": 1, "benign": 2, "inconclusive": 0},
        "benign": {"malicious": 1, "benign": 1, "inconclusive": 1},
    }
    assert overall["agreement"] == 2 and overall["agreement_rate"] == pytest.approx(2 / 6)
    assert overall["false_negatives"] == 2 and overall["analyst_malicious"] == 3
    assert overall["false_negative_rate"] == pytest.approx(2 / 3)
    lo, hi = overall["false_negative_ci95"]
    assert lo < 2 / 3 < hi
    assert overall["false_positive_rate"] == pytest.approx(1 / 3)
    assert overall["ai_inconclusive_rate"] == pytest.approx(1 / 6)
    models = {m["model"]: m["accuracy"]["samples"] for m in body["by_model"]}
    assert models == {"anthropic/claude-x": 2, "unrecorded": 1, "rules only": 3}
    fb = body["feedback"]
    assert fb["total"] == 8  # every feedback row in the window, needs_more_info included
    assert fb["by_decision"] == {"true_positive": 3, "false_positive": 2, "benign_positive": 1, "needs_more_info": 2}
    assert fb["triage_correct"]["samples"] == 3 and fb["triage_correct"]["rate"] == pytest.approx(2 / 3)
    assert fb["triage_correct"]["status"] == "insufficient_data"
    assert fb["analysis_accurate"]["samples"] == 2 and fb["analysis_accurate"]["rate"] == pytest.approx(0.5)
    assert fb["correlation_helpful"]["samples"] == 0 and fb["correlation_helpful"]["rate"] is None
    assert body["low_score_below"] == 30 and body["high_score_from"] == 80


async def test_accuracy_report_without_decisions_is_insufficient(api: ApiHarness) -> None:
    viewer = await api.login_headers(TENANT_A, "viewer")
    body = (await api.client.get(f"/api/v1/reports/accuracy?{WINDOW}", headers=viewer)).json()
    overall = body["overall"]
    assert overall["samples"] == 0 and overall["status"] == "insufficient_data"
    assert overall["agreement_rate"] is None and overall["false_negative_rate"] is None
    assert overall["false_negative_ci95"] is None and body["by_model"] == []


async def seed_detections(repos: Repositories) -> None:
    h = timedelta(hours=1)
    for i in range(12):
        analyst = i < 4
        await seed_alert(
            repos, TENANT_A, D1 + i * h, disposition="benign", closed_after_s=5, rule="Noisy rule",
            severity="medium" if i == 0 else "low",
            summary={"analyst_decision": "false_positive"} if analyst else {"close_reason": "triage:false_positive"},
        )
    for i in range(10):
        malicious = i == 0
        await seed_alert(
            repos, TENANT_A, D1 + i * h, disposition="malicious" if malicious else "benign", closed_after_s=5,
            rule="Mixed rule", severity="high" if malicious else "low",
            summary={"analyst_decision": "true_positive"} if malicious else {},
        )
    for i in range(3):
        await seed_alert(repos, TENANT_A, D2 + i * h, source_id="edr", title="=HYPERLINK(1)", disposition="benign",
                         closed_after_s=5)
    await seed_alert(repos, TENANT_B, D1, rule="Noisy rule", disposition="benign", closed_after_s=5)


async def test_detections_report_and_suggestions(api: ApiHarness) -> None:
    await seed_detections(api.repos)
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get(f"/api/v1/reports/detections?{WINDOW}", headers=viewer)
    assert response.status_code == 200, response.text
    rows = {(d["source_id"], d["rule"]): d for d in response.json()["detections"]}
    assert set(rows) == {("splunk", "Noisy rule"), ("splunk", "Mixed rule"), ("edr", "=HYPERLINK(1)")}
    noisy = rows[("splunk", "Noisy rule")]
    assert (noisy["volume"], noisy["decided"], noisy["benign"], noisy["auto_closed"]) == (12, 12, 12, 8)
    assert noisy["analyst_false_positive"] == 4 and noisy["benign_rate"] == 1.0
    assert noisy["median_severity"] == "low" and noisy["max_confirmed_benign_severity"] == "medium"
    assert noisy["suggestion"] == "candidate_suppression" and noisy["can_propose_suppression"] is True
    mixed = rows[("splunk", "Mixed rule")]
    assert mixed["suggestion"] == "tune_rule" and mixed["malicious"] == 1 and mixed["analyst_true_positive"] == 1
    assert "malicious" in mixed["reason"]
    title_only = rows[("edr", "=HYPERLINK(1)")]
    assert title_only["rule_field"] == "title" and title_only["suggestion"] is None
    assert title_only["can_propose_suppression"] is False

    exported = await api.client.get(f"/api/v1/reports/detections?{WINDOW}&format=csv", headers=viewer)
    assert exported.status_code == 200 and exported.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK(1)" in exported.text and ",=HYPERLINK" not in exported.text


async def test_propose_suppression_creates_a_disabled_rule_once(api: ApiHarness) -> None:
    await seed_detections(api.repos)
    viewer = await api.login_headers(TENANT_A, "viewer")
    analyst_user = await api.user(TENANT_A, "analyst")
    analyst = api.auth(analyst_user)
    body = {"source_id": "splunk", "rule_field": "rule_name", "rule": "Noisy rule", "from": "2026-09-01",
            "to": "2026-09-02"}
    denied = await api.client.post("/api/v1/reports/detections/propose-suppression", json=body, headers=viewer)
    assert denied.status_code == 403
    created = await api.client.post("/api/v1/reports/detections/propose-suppression", json=body, headers=analyst)
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["enabled"] is False and rule["expires_at"] is not None
    assert rule["match"] == {"source_id": "splunk", "rule_name": "Noisy rule",
                             "severity": {"in": ["info", "low", "medium"]}}
    assert rule["created_by"] == str(analyst_user.id)
    again = await api.client.post("/api/v1/reports/detections/propose-suppression", json=body, headers=analyst)
    assert again.status_code == 200 and again.json()["id"] == rule["id"]
    assert len(await api.repos.suppressions.list(TENANT_A)) == 1
    audit = (await api.repos.audit.list(TENANT_A, action="suppression.suggested")).items
    assert len(audit) == 1 and audit[0].details["source"] == "detection_report" and audit[0].details["enabled"] is False
    # The rule matches the detection up to medium and never a more severe alert of it.
    stored = await api.repos.suppressions.get(TENANT_A, rule["id"])
    stored = stored.model_copy(update={"enabled": True})
    view = alert_match_view(title="t", severity="low", category=None, source_id="splunk", source_alert_id="x",
                            fingerprint="f", normalized={"rule_name": "Noisy rule"})
    assert first_matching_rule([stored], view) is not None
    assert first_matching_rule([stored], {**view, "severity": "high"}) is None

    no_evidence = {**body, "source_id": "edr", "rule_field": "title", "rule": "=HYPERLINK(1)"}
    refused = await api.client.post("/api/v1/reports/detections/propose-suppression", json=no_evidence,
                                    headers=analyst)
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "no_confirmed_benign"
    missing = await api.client.post("/api/v1/reports/detections/propose-suppression",
                                    json={**body, "rule": "No such rule"}, headers=analyst)
    assert missing.status_code == 404
    invalid = await api.client.post("/api/v1/reports/detections/propose-suppression",
                                    json={**body, "rule_field": "severity"}, headers=analyst)
    assert invalid.status_code == 422
    # Tenant B's copy of the detection is not reachable from tenant A (and has no confirmation there).
    other = await api.login_headers(TENANT_B, "analyst")
    cross = await api.client.post("/api/v1/reports/detections/propose-suppression", json=body, headers=other)
    assert cross.status_code == 422
    assert await api.repos.suppressions.list(TENANT_B) == []


async def test_reports_are_tenant_isolated_and_cached_per_tenant(api: ApiHarness) -> None:
    await seed_value_data(api.repos)
    viewer_a = await api.login_headers(TENANT_A, "viewer")
    viewer_b = await api.login_headers(TENANT_B, "viewer")
    a = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=viewer_a)).json()
    b = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=viewer_b)).json()
    assert a["totals"]["alerts_ingested"] == 10
    assert b["totals"]["alerts_ingested"] == 1 and b["totals"]["llm_cost_usd"] == 0
    detections_b = (await api.client.get(f"/api/v1/reports/detections?{WINDOW}", headers=viewer_b)).json()
    assert [d["source_id"] for d in detections_b["detections"]] == ["splunk"]
    assert detections_b["detections"][0]["volume"] == 1
    key = f"{api.ctx.prefix}:t:{TENANT_A}:cache:reports:value:2026-09-01:2026-09-02:m15"
    ttl = await api.ctx.redis.ttl(key)
    assert 0 < ttl <= 60
    # Cached: a new alert does not show until the entry expires.
    await seed_alert(api.repos, TENANT_A, D1 + timedelta(hours=2), status="processing")
    again = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=viewer_a)).json()
    assert again["totals"]["alerts_ingested"] == 10 and again["generated_at"] == a["generated_at"]
    await api.ctx.redis.delete(key)
    fresh = (await api.client.get(f"/api/v1/reports/value?{WINDOW}", headers=viewer_a)).json()
    assert fresh["totals"]["alerts_ingested"] == 11


async def test_monthly_report_html_and_json(api: ApiHarness) -> None:
    await seed_value_data(api.repos)
    await seed_detections(api.repos)
    async with api.repos.db.system_tx() as conn:
        await conn.execute("UPDATE tenants SET name = $2 WHERE id = $1", TENANT_A, "Acme <script>alert(1)</script>")
    viewer = await api.login_headers(TENANT_A, "viewer")
    response = await api.client.get("/api/v1/reports/monthly?month=2026-09", headers=viewer)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    digest = base64.b64encode(hashlib.sha256(REPORT_CSS.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in csp and "unsafe-inline" not in csp and "script-src" not in csp
    html = response.text
    assert "<script" not in html and "Acme &lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert f"<style>{REPORT_CSS}</style>" in html
    assert "September 2026" in html and "Handled without a human" in html and "Noisy rule" in html
    assert not re.search(r"<(link|img|iframe)\b", html) and "http://" not in html and "https://" not in html
    assert ' style="' not in html
    as_json = await api.client.get("/api/v1/reports/monthly?month=2026-09&format=json", headers=viewer)
    assert as_json.status_code == 200
    body = as_json.json()
    assert body["tenant_name"].startswith("Acme") and body["value"]["from"] == "2026-09-01"
    assert body["value"]["to"] == "2026-09-30" and len(body["value"]["days"]) == 30
    assert body["value"]["totals"]["alerts_ingested"] == 10 + 25
    for bad in ("2026-13", "26-09", "2026-9"):
        refused = await api.client.get(f"/api/v1/reports/monthly?month={bad}", headers=viewer)
        assert refused.status_code in (400, 422), bad


async def test_dashboard_shows_value_tiles(api: ApiHarness) -> None:
    now = datetime.now(UTC)
    await seed_alert(api.repos, TENANT_A, now - timedelta(hours=1), disposition="benign", closed_after_s=5)
    await seed_alert(api.repos, TENANT_A, now - timedelta(hours=1), disposition="benign", closed_after_s=5)
    await seed_alert(api.repos, TENANT_A, now - timedelta(hours=1), status="waiting_human",
                     summary={"escalation_id": "e"})
    viewer = await api.login_headers(TENANT_A, "viewer")
    body = (await api.client.get("/api/v1/dashboard/summary", headers=viewer)).json()
    assert body["handled_without_human"] == 2 and body["needed_human"] == 1
    assert body["handled_without_human_rate"] == pytest.approx(2 / 3)
    assert body["analyst_hours_saved"] == pytest.approx(0.5) and body["minutes_per_alert"] == 15


def test_window_dates_are_utc_days() -> None:
    assert D1.date() == date(2026, 9, 1)
