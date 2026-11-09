"""Model-led closure through the real workflow (FIX-1): the tenant's tier, read when ``decide`` runs, decides it.

Real Postgres, Redis and checkpoints; the fake model, which calls an alert
whose text is full of benign words benign at both tiers (likelihood 2,
certainty 95). The detection rule's name holds no benign word, so the alert
has no approved benign evidence: only a model-led close can close it.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, make_alert

pytestmark = pytest.mark.integration

ROUTINE = "Authorized approved expected patch healthcheck, allowlisted and sanctioned"


async def routine_alert(repos: Repositories, name: str, severity: str = "low", **normalized: Any) -> str:
    fields: Dict[str, Any] = {
        "title": ROUTINE,
        "rule_name": "60106: Windows logon success",
        "description": ROUTINE,
        "entities": {"hosts": [f"build-{name}"]},
        "mitre": {"tactics": ["Initial Access"], "techniques": ["T1078"]},
        **normalized,
    }
    return await make_alert(
        repos, TENANT_A, source_alert_id=f"fix1-{name}", title=ROUTINE, severity=severity, normalized=fields
    )


async def decide_event(repos: Repositories, alert_id: str) -> Dict[str, Any]:
    events = (await repos.alert_events.list_for_alert(TENANT_A, alert_id, limit=100)).items
    (event,) = [e for e in events if e.node == "decide"]
    return dict(event.data)


async def test_the_tenant_tier_decides_whether_the_models_close(engine: WorkflowEngine, repos: Repositories) -> None:
    # Tier off (the default): both models say benign, but nothing corroborates them, so an analyst decides.
    off = await routine_alert(repos, "off")
    assert (await engine.run(TENANT_A, off)).status == "waiting_human"
    alert = await repos.alerts.get(TENANT_A, off)
    triage, analysis = alert.summary["triage"], alert.summary["analysis"]
    assert triage["rule_fp"] == [] and triage["threat_assessment"] == "benign" and triage["threat_likelihood"] <= 8
    assert analysis["verdict"] == "benign" and analysis["certainty"] >= 85 and analysis["llm_used"] is True
    assert {"code": "false_positive_review", "autonomy_tier": "off"}.items() <= (await decide_event(repos, off)).items()

    # The tenant opts in: the same alert now closes on the models' word, marked for audit.
    await repos.tenants.update_settings(TENANT_A, {"ai_closure": {"tier": "auto_full_audit"}})
    on = await routine_alert(repos, "on")
    assert (await engine.run(TENANT_A, on)).status == "completed"
    alert = await repos.alerts.get(TENANT_A, on)
    assert (alert.status, alert.disposition) == ("closed", "benign")
    assert alert.summary["close_reason"] == "ai_closed:audit_required"
    assert alert.summary["decision"]["code"] == "model_closed"
    assert {"code": "model_closed", "autonomy_tier": "auto_full_audit"}.items() <= (await decide_event(repos, on)).items()

    # Never for high severity or a never-close class, whatever the tier.
    high = await routine_alert(repos, "high", severity="high")
    assert (await engine.run(TENANT_A, high)).status != "completed"
    assert (await repos.alerts.get(TENANT_A, high)).disposition != "benign"
    spray = await routine_alert(
        repos, "spray", mitre={"tactics": ["Credential Access"], "techniques": ["T1110.003"]}
    )
    assert (await engine.run(TENANT_A, spray)).status == "waiting_human"
    assert (await decide_event(repos, spray))["code"] == "false_positive_review"

    # Turned off again: read at every decision, so the next alert goes back to an analyst.
    await repos.tenants.update_settings(TENANT_A, {"ai_closure": {"tier": "off"}})
    again = await routine_alert(repos, "again")
    assert (await engine.run(TENANT_A, again)).status == "waiting_human"
