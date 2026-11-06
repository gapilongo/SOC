"""The escalate node records the routing that sent an alert to an analyst, and the analysis records when it looked."""

from __future__ import annotations

from datetime import datetime

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.routing import RoutingThresholds, review_band
from tests.integration.db._support import TENANT_A, make_alert

pytestmark = pytest.mark.integration

ESCALATION_CODES = {
    "analyst_request", "model_refused", "grey_zone", "false_positive_review", "llm_normalized", "inconclusive",
    "response_review",
}


async def test_an_escalation_records_its_routing_code_band_and_author(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    alert_id = await make_alert(
        repos,
        TENANT_A,
        title="Possible C2 beacon from workstation",
        severity="medium",
        normalized={"entities": {"ips": ["185.220.101.44"], "hosts": ["ws-042"], "users": ["jdoe"]}},
        raw={"vendor": "edr"},
    )
    outcome = await engine.run(TENANT_A, alert_id)
    assert outcome.status == "waiting_human"
    escalation = await repos.escalations.get(TENANT_A, outcome.interrupt["escalation_id"])
    routing = escalation.summary["routing"]
    assert routing["code"] in ESCALATION_CODES
    band = review_band(routing["code"], routing["confidence"], RoutingThresholds.from_settings(engine.settings.routing))
    assert routing["band"] == ({"min": band[0], "max": band[1]} if band else None)
    assert routing["confidence"] == escalation.summary["confidence"]
    assert escalation.summary["llm_used"] in (True, False, None)

    analysis = (await repos.alerts.get(TENANT_A, alert_id)).summary.get("analysis") or {}
    for entry in analysis.get("history") or []:
        assert datetime.fromisoformat(entry["checked_at"]).tzinfo is not None
    for tool in analysis.get("tools") or []:
        assert datetime.fromisoformat(tool["checked_at"]).tzinfo is not None
