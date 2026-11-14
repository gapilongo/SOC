"""``GET /alerts/{id}/investigation`` (PRD-2.8a): the investigation read model over stored rows.

An escalated alert (the console v2 prototype's scenario), alerts the AI
closed, an alert with a response plan, the track record of an outcome
category, tenant isolation, MSSP grant access, and the blind-audit rule that
nobody sees the AI's side of a pending sample. The route only reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytest

from lg_sotf.db.repos import Escalation
from lg_sotf.domain.investigation import words
from lg_sotf.llm.trace import content_hash, tool_input_hash
from lg_sotf.models.trace import NewTraceStep
from tests.fixtures import investigation as prototype
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"


async def investigation(api: ApiHarness, alert_id: str, headers: Dict[str, str]) -> Dict[str, Any]:
    response = await api.client.get(f"{API}/alerts/{alert_id}/investigation", headers=headers)
    assert response.status_code == 200, response.text
    body: Dict[str, Any] = response.json()
    return body


async def set_status(api: ApiHarness, tenant_id: str, alert_id: str, *path: str) -> None:
    for status in path:
        await api.repos.alerts.update_status(tenant_id, alert_id, status)


async def node_event(api: ApiHarness, tenant_id: str, alert_id: str, node: str, data: Dict[str, Any]) -> None:
    await api.repos.alert_events.append(
        tenant_id, alert_id, "node.completed", node=node, actor_type="system", actor_id="workflow", data=data
    )


def trace_steps() -> List[NewTraceStep]:
    """The trace store's tool steps for the prototype's lookups, hashed as the analysis agent hashes them."""
    past, tools = prototype.lookups()
    steps: List[NewTraceStep] = []
    for entry in past:
        output = {k: v for k, v in entry.items() if k not in ("kind", "value", "checked_at")}
        steps.append(
            NewTraceStep(
                agent="analysis", kind="tool", tool="history", outcome="success", started_at=prototype.INGESTED_AT,
                input_hash=tool_input_hash("history", {"kind": entry["kind"], "value": entry["value"]}),
                output_hash=content_hash(output),
            )
        )
    for tool in tools:
        request = {
            "kind": tool["kind"], "value": tool["target"],
            "providers": sorted(r["provider"] for r in tool["results"]),
        }
        steps.append(
            NewTraceStep(
                agent="analysis", kind="tool", tool="reputation", outcome="success",
                started_at=prototype.INGESTED_AT + timedelta(seconds=3),
                input_hash=tool_input_hash("reputation", request), output_hash=content_hash(tool["results"]),
            )
        )
    return steps


async def seed_prototype(api: ApiHarness, tenant_id: str = TENANT_A) -> Tuple[str, Escalation]:
    """The prototype's alert as the workflow leaves it when it escalates: digests, timeline, trace, escalation."""
    alert_id = await make_alert(
        api.repos, tenant_id, title=prototype.TITLE, severity="high", normalized=prototype.normalized(),
        occurred_at=prototype.OCCURRED_AT,
    )
    await api.repos.alerts.update(tenant_id, alert_id, confidence=78, threat_score=74, summary=prototype.summary())
    for _, node, actor_type, data in prototype.node_events():
        await api.repos.alert_events.append(
            tenant_id, alert_id, "node.completed", node=node, actor_type=actor_type,
            actor_id=node if actor_type == "agent" else "workflow", data=data,
        )
    await api.repos.investigation_steps.append(tenant_id, alert_id, f"{tenant_id}:{alert_id}", trace_steps())
    escalation, _ = await api.repos.escalations.create_or_attach(
        tenant_id, alert_id, reason="no automatic policy applies", level="L2", priority=8,
        sla_deadline=datetime.now(UTC) + timedelta(minutes=30), summary=prototype.escalation_summary(),
    )
    await set_status(api, tenant_id, alert_id, "queued", "processing", "waiting_human")
    return alert_id, escalation


async def ai_closed(
    api: ApiHarness, tenant_id: str, reason: str, *, code: str, rule_fp: Optional[List[str]] = None
) -> str:
    """An alert the AI closed as benign, with its ``close`` step on the timeline."""
    summary = prototype.summary()
    summary["triage"].update(rule_fp=rule_fp or [], llm_tp=[], llm_fp=["Routine package install."], threat_assessment="benign")
    summary["analysis"].update(verdict="benign", threat_score=8, conclusion="A routine package install.")
    summary.update(
        verdict="benign", close_reason=reason,
        decision={"route": "close", "reason": "r", "disposition": "benign", "code": code},
    )
    alert_id = await make_alert(api.repos, tenant_id, title="Package installed", severity="low", normalized=prototype.normalized())
    await api.repos.alerts.update(tenant_id, alert_id, disposition="benign", summary=summary)
    await node_event(api, tenant_id, alert_id, "close", {"status": "closed", "disposition": "benign", "close_reason": reason})
    await set_status(api, tenant_id, alert_id, "queued", "processing", "closed")
    return alert_id


async def blind_labels(api: ApiHarness, tenant_id: str, labels: List[Tuple[str, str]]) -> None:
    """One blind-audit run over ``(alert_id, label)`` pairs, every sample labelled (``benign`` agrees with the AI)."""
    now = datetime.now(UTC)
    await api.repos.blind_audit.create_run(
        tenant_id, since=now - timedelta(days=7), until=now + timedelta(minutes=1), seed=7, sample_rate=None,
        min_sample=0, fixed_size=len(labels), frame_size=len(labels),
        items=[(alert_id, rank, "benign") for rank, (alert_id, _) in enumerate(labels, start=1)],
        trigger="cli", created_by="seed",
    )
    by_alert = {item.alert_id: item for item in (await api.repos.blind_audit.list_items(tenant_id, limit=200)).items}
    for alert_id, label in labels:
        agreement = None if label == "unsure" else label == "benign"
        assert await api.repos.blind_audit.label(
            tenant_id, by_alert[alert_id].id, label=label, notes=None, agreement=agreement, labelled_by=None,
            labelled_by_actor="seed", escalation_id=None, now=datetime.now(UTC),
        )


async def decided(api: ApiHarness, tenant_id: str, verdict: str, code: str, decision: str) -> None:
    """An escalated alert an analyst decided."""
    alert_id = await make_alert(api.repos, tenant_id, title="Decided", severity="medium")
    escalation, _ = await api.repos.escalations.create_or_attach(
        tenant_id, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1),
        summary={"verdict": verdict, "routing": {"code": code}},
    )
    await api.repos.feedback.create(tenant_id, escalation.id, alert_id, decision)


# ------------------------------------------------------------------ an escalated alert


async def test_escalated_alert_reproduces_the_prototype_scenario(api: ApiHarness) -> None:
    alert_id, escalation = await seed_prototype(api)
    audit_before = len((await api.repos.audit.list(TENANT_A, limit=200)).items)
    body = await investigation(api, alert_id, await api.login_headers(TENANT_A, "analyst"))
    assert (body["schema_version"], body["alert_id"], body["tenant_id"]) == (1, alert_id, TENANT_A)
    assert body["hidden_for_blind_audit"] is False

    outcome = body["outcome"]
    assert outcome["category"] == "needs_decision" and outcome["closed_by"] is None
    assert outcome["reason"] == {"code": "inconclusive", "sentence": words.DECIDE_SENTENCES["inconclusive"]}
    assert [b["code"] for b in outcome["blockers"]] == ["tier_off", "fast_tier_threat", "deep_tier_not_benign"]
    assert body["summary"] == {"text": prototype.CONCLUSION, "written_by": "model"}

    model_claims = [c for c in body["claims"] if c["written_by"] == "model"]
    assert [c["text"] for c in model_claims] == prototype.MODEL_CLAIMS_MALICIOUS + prototype.MODEL_CLAIMS_BENIGN
    assert {(c["check"], len(c["observation_ids"])) for c in model_claims} == {("unsupported", 0)}
    [rule_claim] = [c for c in body["claims"] if c["written_by"] == "rules"]
    assert (rule_claim["check"], rule_claim["observation_ids"], rule_claim["direction"]) == ("supported", ["O-03"], "malicious")

    observations = body["observations"]
    assert [(o["id"], o["tool"], o["outcome"]) for o in observations] == [
        ("O-01", "history", "empty"), ("O-02", "history", "empty"), ("O-03", "reputation", "success"),
        ("O-04", "reputation", "empty"), ("O-05", "reputation", "empty"), ("O-06", "reputation", "failed"),
    ]
    # The hashes come from the trace store, matched by the input hash of each call.
    expected = trace_steps()
    assert [(o["input_sha256"], o["output_sha256"]) for o in observations] == [
        (step.input_hash, step.output_hash) for step in expected
    ]
    assert observations[2]["target"] == prototype.DOMAIN and observations[2]["verdict"] == "suspicious"
    assert observations[2]["excerpt"][0] == {"text": "virustotal  ok  suspicious", "marks": []}

    assert body["not_established"]["empty"] == ["O-01", "O-02", "O-04", "O-05"]
    assert [i["what"] for i in body["not_established"]["not_checked"]] == [words.NO_TELEMETRY[0]]
    assert [(u["kind"], u["observation_id"]) for u in body["not_established"]["unavailable"]] == [("tool_failed", "O-06")]

    assert [s["actor"] for s in body["steps"]] == ["code", "policy", "model", "code", "model", "policy", "policy"]
    assert body["steps"][5]["text"] == words.DECIDE_SENTENCES["inconclusive"]
    assert not any("_" in s["text"] for s in body["steps"])

    # The proposed response is the preview of a true_positive decision, with exact targets; nothing has run.
    response = body["response"]
    assert response["source"] == "preview"
    targets = {(a["action_type"], a["target"]) for a in response["actions"]}
    assert ("isolate_host", prototype.HOST) in targets
    isolate = next(a for a in response["actions"] if a["action_type"] == "isolate_host")
    assert (isolate["risk"], isolate["reversible"], isolate["status"], isolate["action_id"]) == ("high", True, None, None)
    assert (isolate["can_preapprove"], isolate["role_lock"], isolate["guardrail"]["verdict"]) == (False, "admin", "passed")

    assert body["track_record"] == {
        "category": "needs_decision", "basis": "analyst_decisions", "window_days": 90, "total": 0, "confirmed": 0,
        "min_samples": 30, "rate": None,
    }
    # The fields the harness will fill are named and empty.
    pending = {p["field"]: p["issue"] for p in body["pending_harness"]}
    assert {"claims[].observation_ids", "claims[].check", "observations[].excerpt[].marks", "observations"} <= set(pending)
    assert all(line["marks"] == [] for o in observations for line in o["excerpt"])
    assert {201, 356} <= set(pending.values())

    # Read-only: no action, no audit entry, the escalation untouched.
    assert (await api.repos.actions.list(TENANT_A, alert_id=alert_id)).items == []
    assert len((await api.repos.audit.list(TENANT_A, limit=200)).items) == audit_before
    assert (await api.repos.escalations.get(TENANT_A, escalation.id)).version == escalation.version

    admin = await investigation(api, alert_id, await api.login_headers(TENANT_A, "admin"))
    assert next(a for a in admin["response"]["actions"] if a["action_type"] == "isolate_host")["can_preapprove"] is True


async def test_decided_escalation_keeps_the_ai_category_and_names_the_analyst_close(api: ApiHarness) -> None:
    alert_id, escalation = await seed_prototype(api)
    analyst = await api.user(TENANT_A, "analyst")
    await api.repos.escalations.claim(TENANT_A, escalation.id, analyst.id, escalation.version)
    await set_status(api, TENANT_A, alert_id, "processing")
    await api.repos.alerts.update(
        TENANT_A, alert_id, disposition="benign",
        summary={"close_reason": "analyst:benign_positive", "analyst_decision": "benign_positive"},
    )
    await set_status(api, TENANT_A, alert_id, "closed")
    body = await investigation(api, alert_id, api.auth(analyst))
    outcome = body["outcome"]
    assert (outcome["category"], outcome["reason"]["code"]) == ("needs_decision", "inconclusive")
    assert outcome["closed_by"]["kind"] == "analyst" and outcome["closed_by"]["decision"] == "benign_positive"
    assert outcome["closed_by"]["reason"]["sentence"] == words.CLOSE_REASONS["analyst:benign_positive"].sentence
    assert outcome["closed_by"]["at"] is not None


# ------------------------------------------------------------------ alerts the AI closed


async def test_ai_closed_alerts_and_their_track_record(api: ApiHarness) -> None:
    on_model = [
        await ai_closed(api, TENANT_A, "ai_closed:audit_required", code="model_closed") for _ in range(4)
    ]
    on_evidence = await ai_closed(
        api, TENANT_A, "policy:close", code="rule_corroborated_benign", rule_fp=["known_scanner"]
    )
    # Another tenant's labels never count.
    foreign = await ai_closed(api, TENANT_B, "ai_closed:audit_required", code="model_closed")
    await blind_labels(api, TENANT_B, [(foreign, "malicious")])
    # Three of the four closes on the model's word were audited: two confirmed, one found malicious.
    await blind_labels(api, TENANT_A, [(on_model[0], "benign"), (on_model[1], "benign"), (on_model[2], "malicious")])
    headers = await api.login_headers(TENANT_A, "viewer")

    audit = await investigation(api, on_model[3], headers)
    outcome = audit["outcome"]
    assert outcome["category"] == "ai_closed_audit" and outcome["blockers"] == []
    assert outcome["closed_by"]["kind"] == "ai"
    assert outcome["closed_by"]["reason"] == {
        "code": "ai_closed:audit_required", "sentence": words.CLOSE_REASONS["ai_closed:audit_required"].sentence
    }
    assert audit["summary"] == {"text": "A routine package install.", "written_by": "model"}
    assert audit["track_record"] == {
        "category": "ai_closed_audit", "basis": "blind_audit_labels", "window_days": 90, "total": 3, "confirmed": 2,
        "min_samples": 30, "rate": None,
    }
    assert audit["response"] == {"source": "none", "actions": []}
    assert [s["text"] for s in audit["steps"]][-1] == words.CLOSE_REASONS["ai_closed:audit_required"].sentence

    evidence = await investigation(api, on_evidence, headers)
    assert evidence["outcome"]["category"] == "ai_closed_evidence"
    assert evidence["outcome"]["evidence"] == ["known_scanner"]
    assert evidence["outcome"]["reason"]["code"] == "policy:close"
    # No evidence-backed close was audited: the model-word labels belong to the other category.
    assert (evidence["track_record"]["total"], evidence["track_record"]["confirmed"]) == (0, 0)


async def test_suppressed_alert_has_no_ai_category(api: ApiHarness) -> None:
    alert_id = await make_alert(api.repos, TENANT_A, title="Nightly backup", severity="low")
    by = {"type": "suppression_rule", "rule_id": "rule-1", "name": "Nightly backup jobs"}
    await api.repos.alerts.update(
        TENANT_A, alert_id, disposition="benign", summary={"close_reason": "suppression_rule", "suppressed_by": by}
    )
    await node_event(api, TENANT_A, alert_id, "gate", {"suppressed": True, "rule_id": "rule-1"})
    await set_status(api, TENANT_A, alert_id, "queued", "processing", "closed")
    body = await investigation(api, alert_id, await api.login_headers(TENANT_A, "viewer"))
    assert body["outcome"]["category"] is None and body["track_record"] is None
    closed_by = body["outcome"]["closed_by"]
    assert (closed_by["kind"], closed_by["rule_id"], closed_by["rule_name"]) == ("suppression_rule", "rule-1", "Nightly backup jobs")
    assert [i["what"] for i in body["not_established"]["not_checked"]] == [words.NOT_INVESTIGATED[0]]
    assert body["steps"][1]["text"] == words.NODE_STEP_VARIANTS["gate:suppression_rule"].text


# ------------------------------------------------------------------ an alert with a response plan


async def test_alert_with_a_response_plan_lists_the_planned_actions(api: ApiHarness) -> None:
    alert_id = await make_alert(
        api.repos, TENANT_A, title=prototype.TITLE, severity="high", normalized=prototype.normalized()
    )
    summary = prototype.summary()
    summary["analysis"].update(threat_score=92, rule_corroborated=True)
    summary["response"] = {"threat_type": "malware", "evidence": "rules", "auto": 1, "awaiting": 1, "blocked": 1, "done": 0}
    await api.repos.alerts.update(TENANT_A, alert_id, summary=summary)
    await node_event(api, TENANT_A, alert_id, "decide", {"route": "plan_response", "code": "high_risk", "autonomy_tier": "off"})
    await node_event(api, TENANT_A, alert_id, "plan_response", dict(summary["response"]))
    await api.repos.actions.propose(TENANT_A, alert_id, "block_domain", prototype.DOMAIN, "medium", status="dry_run")
    await api.repos.actions.propose(TENANT_A, alert_id, "isolate_host", prototype.HOST, "high", status="awaiting_approval")
    await api.repos.actions.propose(
        TENANT_A, alert_id, "reset_password", f"{prototype.USER}@northwind.example", "critical", status="blocked",
        blocked_reason="autonomy_disabled",
    )
    await set_status(api, TENANT_A, alert_id, "queued", "processing", "waiting_approval")

    body = await investigation(api, alert_id, await api.login_headers(TENANT_A, "analyst"))
    assert body["outcome"]["category"] == "needs_decision"
    assert body["outcome"]["reason"] == {"code": "awaiting_approval", "sentence": words.DECIDE_SENTENCES["awaiting_approval"]}
    response = body["response"]
    assert response["source"] == "plan"
    assert [(a["action_type"], a["target"], a["status"], a["risk"]) for a in response["actions"]] == [
        ("block_domain", prototype.DOMAIN, "dry_run", "medium"),
        ("isolate_host", prototype.HOST, "awaiting_approval", "high"),
        ("reset_password", f"{prototype.USER}@northwind.example", "blocked", "critical"),
    ]
    isolate, reset = response["actions"][1], response["actions"][2]
    assert isolate["action_id"] and isolate["reversible"] is True and isolate["inverse_action"] == "release_host"
    assert isolate["guardrail"]["verdict"] == "passed"  # checked now, against the tenant's policy
    assert (reset["guardrail"]["verdict"], reset["guardrail"]["code"]) == ("blocked", "autonomy_disabled")
    assert all(a["without_preapproval"] is None and a["approval_entry"] is None for a in response["actions"])
    plan_step = next(s for s in body["steps"] if s["text"] == words.NODE_STEPS["plan_response"].text)
    assert plan_step["produced"] == "1 automatic · 1 awaiting approval · 1 blocked"
    assert words.DECIDE_SENTENCES["high_risk"] in [s["text"] for s in body["steps"]]


# ------------------------------------------------------------------ track record


async def test_track_record_counts_analyst_decisions_of_the_category_and_tenant(api: ApiHarness) -> None:
    for decision in ("true_positive", "true_positive", "benign_positive"):
        await decided(api, TENANT_A, "malicious", "inconclusive", decision)
    await decided(api, TENANT_A, "benign", "high_risk", "true_positive")  # likely malicious by its routing code
    await decided(api, TENANT_A, "inconclusive", "grey_zone", "false_positive")  # the other category
    await decided(api, TENANT_A, "malicious", "inconclusive", "needs_more_info")  # not a final decision
    await decided(api, TENANT_B, "malicious", "inconclusive", "true_positive")  # another tenant
    alert_id, _ = await seed_prototype(api)
    record = (await investigation(api, alert_id, await api.login_headers(TENANT_A, "viewer")))["track_record"]
    assert (record["category"], record["total"], record["confirmed"], record["rate"]) == ("needs_decision", 4, 3, None)

    for _ in range(26):
        await decided(api, TENANT_A, "malicious", "inconclusive", "true_positive")
    enough = (await investigation(api, alert_id, await api.login_headers(TENANT_A, "viewer")))["track_record"]
    assert (enough["total"], enough["confirmed"], enough["min_samples"], enough["rate"]) == (30, 29, 30, 0.9667)


# ------------------------------------------------------------------ who may read it


async def test_another_tenant_cannot_read_the_investigation(api: ApiHarness) -> None:
    alert_id, _ = await seed_prototype(api, TENANT_B)
    url = f"{API}/alerts/{alert_id}/investigation"
    for role in ("viewer", "analyst", "admin"):
        response = await api.client.get(url, headers=await api.login_headers(TENANT_A, role))
        assert response.status_code == 404, (role, response.text)
        assert prototype.DOMAIN not in response.text and "Word" not in response.text
    assert (await api.client.get(url)).status_code == 401
    ingest_only = await api.client.get(url, headers=await api.key_headers(TENANT_B, ("ingest",)))
    assert ingest_only.status_code == 403
    own = await api.client.get(url, headers=await api.login_headers(TENANT_B, "viewer"))
    assert own.status_code == 200 and own.json()["tenant_id"] == TENANT_B
    missing = await api.client.get(f"{API}/alerts/no-such-alert/investigation", headers=await api.login_headers(TENANT_B, "viewer"))
    assert missing.status_code == 404


async def test_mssp_grant_access_follows_the_existing_rules(api: ApiHarness) -> None:
    alert_id, _ = await seed_prototype(api, TENANT_B)
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    url = f"{API}/alerts/{alert_id}/investigation"

    assert (await api.client.get(url, headers=headers)).status_code == 403  # no grant
    grant = await api.repos.grants.create(
        TENANT_B, ORG, "analyst", reason="night shift", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=4),
    )
    granted = await api.client.get(url, headers=headers)
    assert granted.status_code == 200, granted.text
    body = granted.json()
    assert (body["tenant_id"], body["outcome"]["category"]) == (TENANT_B, "needs_decision")
    # The grant's role decides what the preview offers: an analyst may not pre-approve a high-risk action.
    isolate = next(a for a in body["response"]["actions"] if a["action_type"] == "isolate_host")
    assert (isolate["can_preapprove"], isolate["role_lock"]) == (False, "admin")
    # The grant reaches the customer only: the same alert id in the organisation's own tenant is not found.
    assert (await api.client.get(url, headers=api.auth(staff))).status_code == 404

    await api.repos.grants.revoke(TENANT_B, grant.id, revoked_by="customer-admin")
    assert (await api.client.get(url, headers=headers)).status_code == 403


# ------------------------------------------------------------------ blind audit


async def test_pending_blind_audit_sample_shows_nothing_of_the_ai_side(api: ApiHarness) -> None:
    alert_id = await ai_closed(api, TENANT_A, "ai_closed:audit_required", code="model_closed")
    await api.repos.alert_events.append(TENANT_A, alert_id, "note", actor_type="user", actor_id="u1", data={"text": "seen"})
    now = datetime.now(UTC)
    await api.repos.blind_audit.create_run(
        TENANT_A, since=now - timedelta(days=7), until=now, seed=1, sample_rate=0.02, min_sample=0, fixed_size=None,
        frame_size=1, items=[(alert_id, 1, "benign")], trigger="cli", created_by="seed",
    )
    headers = await api.login_headers(TENANT_A, "admin")
    hidden = await investigation(api, alert_id, headers)
    assert hidden["hidden_for_blind_audit"] is True
    assert (hidden["outcome"], hidden["track_record"], hidden["summary"]["text"]) == (None, None, None)
    assert (hidden["claims"], hidden["observations"], hidden["response"]["source"]) == ([], [], "none")
    assert hidden["not_established"] == {"empty": [], "not_checked": [], "unavailable": []}
    assert [s["text"] for s in hidden["steps"]] == ["Alert received.", words.EVENT_STEPS["note"].text]

    item = (await api.repos.blind_audit.list_items(TENANT_A)).items[0]
    assert await api.repos.blind_audit.label(
        TENANT_A, item.id, label="benign", notes=None, agreement=True, labelled_by=None, labelled_by_actor="seed",
        escalation_id=None, now=datetime.now(UTC),
    )
    shown = await investigation(api, alert_id, headers)
    assert shown["hidden_for_blind_audit"] is False and shown["outcome"]["category"] == "ai_closed_audit"
    assert (shown["track_record"]["total"], shown["track_record"]["confirmed"]) == (1, 1)
