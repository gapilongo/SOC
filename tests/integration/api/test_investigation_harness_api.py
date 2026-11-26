"""The evidence lookups in ``GET /alerts/{id}/investigation`` and the settings that turn them on (AI-E3.3).

The record is written here as the analysis node writes it: the real executor runs a Wazuh alert's plan on
stand-in tools, records it on the tenant's fact ledger (PostgreSQL, row-level security), and the claims
are checked against that ledger. The API then shows the lookups, the budgets, the claims beside the
observations they cite, and, for an alert without lookups, why none ran.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import pytest

from lg_sotf.agents.analysis.react import Claim
from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.investigation.claims import blocking, checked_claims
from lg_sotf.agents.investigation.executor import InvestigationRun, SkillInvestigator, switched_on
from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation_budget import tenant_limits
from lg_sotf.domain.ledger import new_run_id
from lg_sotf.tools.wazuh.tools import LOGON_FANOUT, Evidence
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert
from tests.unit.agents.investigation._executor import AT, HOSTILE, LOGON, SWITCH_ON, Answers, logon_fact

pytestmark = pytest.mark.integration

API = "/api/v1"
DOWN = Evidence(error="unreachable")


async def investigation(api: ApiHarness, alert_id: str, tenant_id: str = TENANT_A, role: str = "analyst") -> Dict[str, Any]:
    response = await api.client.get(f"{API}/alerts/{alert_id}/investigation", headers=await api.login_headers(tenant_id, role))
    assert response.status_code == 200, response.text
    body: Dict[str, Any] = response.json()
    return body


async def wazuh_alert(api: ApiHarness, tenant_id: str, **normalized: Any) -> str:
    view = {"title": "Logon failure", "normalizer": "wazuh", "entities": {"hosts": ["FIN-SRV-02"], "users": ["j.doe"]}, **normalized}
    return await make_alert(api.repos, tenant_id, title="Logon failure", severity="low", occurred_at=AT, raw=dict(LOGON), normalized=view)


async def investigated(api: ApiHarness, tenant_id: str, answers: Answers, *claims: Dict[str, Any]) -> Tuple[str, InvestigationRun]:
    """A Wazuh alert of ``tenant_id`` analysed with the harness on: the ledger, the stored record, the timeline event."""
    await api.repos.tenants.update_settings(tenant_id, SWITCH_ON)
    alert_id = await wazuh_alert(api, tenant_id)
    settings = api.ctx.settings
    ctx = AgentContext(tenant_id, alert_id, settings, repos=api.repos, investigation_run_id=new_run_id())
    state = {"normalizer": "wazuh", "occurred_at": AT.isoformat(), "raw": dict(LOGON)}
    run = await SkillInvestigator(answers.registry, settings).investigate(ctx, state)
    assert run is not None
    record = {**run.record(), "claims": checked_claims(run.ledger, [Claim.model_validate(c) for c in claims]),
              "claims_checked": True, "verdict_findings": []}
    record["blocking"] = blocking(run, record)
    analysis = {"verdict": "benign", "threat_score": 20, "llm_used": True, "conclusion": "A mistyped password.",
                "investigation": record}
    await api.repos.alerts.update(tenant_id, alert_id, summary={"analysis": analysis})
    digest = {**run.digest(), "citation_findings": sum(len(c["findings"]) for c in record["claims"])}
    await api.repos.alert_events.append(
        tenant_id, alert_id, "node.completed", node="analysis", actor_type="agent", actor_id="analysis",
        data={"verdict": "benign", "llm_used": True, "tool_steps": 0, "investigation": {k: v for k, v in digest.items() if v is not None}},
    )
    return alert_id, run


async def test_the_view_shows_the_lookups_the_budgets_and_each_claim_beside_its_fact(api: ApiHarness) -> None:
    answers = Answers({LOGON_FANOUT: lambda p: Evidence([logon_fact()]) if p.pivot == "target_user" else DOWN})
    alert_id, run = await investigated(
        api, TENANT_A, answers,
        {"text": "The account logged on from the same address before.", "supports": "benign", "cites": ["logons_user:0"]},
        {"text": "No other source tried the account.", "supports": "benign", "cites": ["logons_source:0", "host:4"]},
    )

    body = await investigation(api, alert_id)

    shown = body["evidence_run"]
    assert (shown["status"], shown["reason"], shown["stop_reason"]) == ("ran", None, "finished")
    assert (shown["playbook_id"], shown["playbook_version"], shown["run_id"]) == ("wazuh.default", "1.0.0", run.run_id)
    assert [(look["evidence_id"], look["tool"], look["outcome"], look["reason"], look["observation_ids"]) for look in shown["lookups"]] == [
        ("host", "wazuh.host_activity", "success", None, ["host:0"]),
        ("prevalence", "wazuh.prevalence", "skipped", "no_binding", []),
        ("logons_user", "wazuh.logon_fanout", "success", None, ["logons_user:0"]),
        ("logons_source", "wazuh.logon_fanout", "failed", "unreachable", ["logons_source:0"]),
    ]
    assert {b["kind"]: (b["used"], b["limit"]) for b in shown["budgets"] if b["kind"] != "wall_s"} == {
        "steps": (3, 8), "tokens": (0, 20_000), "usd": (0, 0.25)}
    assert {i["id"]: i["state"] for i in shown["indicators"]} == {
        "never_close_class_on_host": "false", "high_level_alert_on_host": "false"}
    # What of the evidence holds a model-led close: the second claim cites a failed lookup and an id nobody recorded.
    assert shown["holds_close"] == [{"code": "evidence_citation", "sentence": words.BLOCKER_SENTENCES["evidence_citation"]}]
    assert [(i["holds_close"], i["observation_ids"]) for i in shown["indicators"]] == [(False, []), (False, [])]
    assert (shown["steering_observation_ids"], shown["benign_without_claims"]) == ([], False)
    # The observations are the ledger's, under the ids the lookups name; each claim sits beside what it cites.
    observations = {o["id"]: o for o in body["observations"]}
    assert set(observations) == {"host:0", "logons_user:0", "logons_source:0"}
    first, second = body["claims"][:2]
    assert (first["observation_ids"], first["check"], first["findings"], first["written_by"]) == (["logons_user:0"], "supported", [], "model")
    assert observations[first["observation_ids"][0]]["citable_as_benign_evidence"] is True
    assert second["observation_ids"] == ["logons_source:0"] and second["check"] == "unsupported"
    assert [(f["code"], f["cited"]) for f in second["findings"]] == [("not_benign_evidence", "logons_source:0"), ("unknown_fact", "host:4")]
    assert second["check_reason"] == words.CITATION_FINDINGS["not_benign_evidence"] and "host:4" not in observations
    # What was skipped or failed is named, and the lookups are a step of the investigation.
    assert {"what": words.EVIDENCE_TOOL_TITLES["wazuh.prevalence"], "why": words.SKIPPED_LOOKUP_REASONS["no_binding"]} in (
        body["not_established"]["not_checked"])
    assert [u["observation_id"] for u in body["not_established"]["unavailable"]] == ["logons_source:0"]
    step = next(s for s in body["steps"] if s["text"] == words.EVIDENCE_STEP.text)
    assert (step["actor"], step["produced"]) == ("code", "3 lookups · 2 facts · 1 failed · 1 skipped · 2 citation findings")


async def test_a_degraded_run_and_an_alert_without_lookups_say_why(api: ApiHarness) -> None:
    down, _ = await investigated(api, TENANT_A, Answers({"wazuh.host_activity": DOWN, LOGON_FANOUT: DOWN}))
    body = await investigation(api, down)
    shown = body["evidence_run"]
    assert (shown["status"], shown["reason"]) == ("degraded", {"code": "circuit_open", "sentence": words.EVIDENCE_REASONS["circuit_open"]})
    assert [look["outcome"] for look in shown["lookups"]] == ["failed", "skipped", "failed", "skipped"]
    assert shown["holds_close"] == []  # lookups that could not answer leave the indicators unknown: nothing is held
    assert any(s["text"] == words.EVIDENCE_REASONS["circuit_open"] and s["produced"] == "2 lookups · 2 failed · 2 skipped" for s in body["steps"])

    # Tenant B never switched the lookups on: its Wazuh alert, another source's alert, an alert not analysed.
    switched_off = await wazuh_alert(api, TENANT_B)
    other_source = await make_alert(api.repos, TENANT_B, title="Sign-in from a new country", normalized={"title": "x", "normalizer": "sentinel"})
    not_analysed = await wazuh_alert(api, TENANT_B)
    for alert_id in (switched_off, other_source):
        await api.repos.alerts.update(TENANT_B, alert_id, summary={"analysis": {"verdict": "inconclusive", "llm_used": True}})
    for alert_id, code in ((switched_off, "switched_off"), (other_source, "no_evidence_tools"), (not_analysed, "not_analysed")):
        run = (await investigation(api, alert_id, TENANT_B))["evidence_run"]
        assert (run["status"], run["reason"], run["lookups"], run["budgets"]) == (
            "not_run", {"code": code, "sentence": words.EVIDENCE_REASONS[code]}, [], [])


async def test_another_tenants_lookups_and_claims_are_never_shown(api: ApiHarness) -> None:
    hostile = Answers({LOGON_FANOUT: Evidence([logon_fact("svc-tenant-b", failed_users=[HOSTILE])])})
    theirs, _ = await investigated(
        api, TENANT_B, hostile, {"text": "TENANT-B-CLAIM", "supports": "malicious", "cites": ["logons_user:0"]})
    mine = await wazuh_alert(api, TENANT_A)
    await api.repos.alerts.update(TENANT_A, mine, summary={"analysis": {"verdict": "benign", "llm_used": True}})
    admin = await api.login_headers(TENANT_A, "admin")

    foreign = await api.client.get(f"{API}/alerts/{theirs}/investigation", headers=admin)
    assert foreign.status_code == 404 and "TENANT-B-CLAIM" not in foreign.text and "svc-tenant-b" not in foreign.text
    own = await api.client.get(f"{API}/alerts/{mine}/investigation", headers=admin)
    assert own.status_code == 200 and "TENANT-B-CLAIM" not in own.text and "svc-tenant-b" not in own.text
    assert own.json()["evidence_run"]["reason"]["code"] == "switched_off" and own.json()["observations"] == []
    # Tenant B sees its own, and the attacker's text in a fact comes back as data, bounded, never as a sentence.
    body = await investigation(api, theirs, TENANT_B, "viewer")
    assert body["claims"][0]["text"] == "TENANT-B-CLAIM" and body["evidence_run"]["status"] == "ran"
    fixed = [body["evidence_run"]["reason"], *(s["text"] for s in body["steps"]), *(c["check_reason"] for c in body["claims"])]
    assert not any("IGNORE PREVIOUS" in str(text) for text in fixed)


async def test_a_tenant_admin_switches_the_lookups_on_and_sets_their_budget(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    assert not switched_on((await api.repos.tenants.get(TENANT_A)).settings, ["wazuh_indexer"])
    patch = {"tools": {"wazuh_indexer": {"enabled": True}}, "investigation": {"budget": {"steps": 4, "usd": 0.1}}}
    saved = await api.client.patch(f"{API}/tenant/settings", json=patch, headers=admin)
    assert saved.status_code == 200, saved.text
    assert saved.json()["settings"]["investigation"] == {"budget": {"steps": 4, "usd": 0.1}}
    stored = (await api.repos.tenants.get(TENANT_A)).settings
    assert switched_on(stored, ["wazuh_indexer"])
    install = api.ctx.settings.investigation
    limits = SkillInvestigator(Answers().registry, api.ctx.settings).limits(stored)
    assert (limits.steps, limits.usd, limits.tokens) == (4, 0.1, install.budget.tokens)
    assert tenant_limits(limits, limits, {"investigation": {"budget": {"steps": 30}}}).steps == 4  # cut to the maximum
    for bad in ({"budget": {"steps": 0}}, {"budget": {"steps": 99}}, {"budget": {"lookups": 3}}, {"enabled": True}, "max"):
        refused = await api.client.patch(f"{API}/tenant/settings", json={"investigation": bad}, headers=admin)
        assert refused.status_code == 422, (bad, refused.text)
    assert (await api.repos.tenants.get(TENANT_A)).settings["investigation"] == {"budget": {"steps": 4, "usd": 0.1}}
    analyst = await api.client.patch(f"{API}/tenant/settings", json=patch, headers=await api.login_headers(TENANT_A, "analyst"))
    assert analyst.status_code == 403
    off = await api.client.patch(f"{API}/tenant/settings", json={"tools": {"wazuh_indexer": {"enabled": False}}, "investigation": None}, headers=admin)
    assert off.status_code == 200 and "investigation" not in off.json()["settings"]
    assert not switched_on((await api.repos.tenants.get(TENANT_A)).settings, ["wazuh_indexer"])
