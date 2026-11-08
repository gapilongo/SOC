"""Shadow agreement report (AI-E1.5b): a fixture replay, stored, then read through the platform API.

Production's verdicts are the pipeline's own records (``decide`` node events,
workflow-planned actions, the alert's LLM usage summary, its trace); the
candidate is a fixed set of shadow outcomes, so every figure of the report is
known in advance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, cast

import pytest

from lg_sotf.core.shadow import ShadowOutcome, ShadowRunner
from lg_sotf.core.shadow_replay import ShadowReplay
from lg_sotf.domain.rates import rate_interval
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.models.vocabulary import REQUESTED_BY
from lg_sotf.security.shadow import ShadowEffect
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert, sha256_hex

pytestmark = pytest.mark.integration


class FixedCandidate:
    """A stand-in for :class:`ShadowRunner`: the candidate's outcome for each alert, or the error it raises."""

    def __init__(self, outcomes: Dict[str, Any]) -> None:
        self.outcomes = outcomes
        self.calls: List[str] = []

    async def run(self, tenant_id: str, alert_id: str) -> ShadowOutcome:
        self.calls.append(alert_id)
        result = self.outcomes[alert_id]
        if isinstance(result, Exception):
            raise result
        return cast(ShadowOutcome, result)


def shadow(route: str, disposition: Optional[str] = None, *, actions: tuple = (), cost: str = "0.001",  # type: ignore[type-arg]
           ms: int = 200) -> ShadowOutcome:
    effects = (ShadowEffect(0, "response_plan", "ResponseService.plan", "sunk", {"actions": list(actions)}),) if actions else ()
    step = NewTraceStep(agent="triage", kind="tool", tool="history", input_hash=sha256_hex("x"), outcome="success",
                        latency_ms=ms, started_at=datetime.now(UTC))
    return ShadowOutcome(
        run_id="shadow/" + "f" * 32, state={"decision": {"route": route, "disposition": disposition}, "confidence": 60},
        interrupt=None, effects=effects, trace=(step,), llm_calls=1, llm_tokens=500, llm_cost_usd=Decimal(cost),
    )


async def produced(
    api: ApiHarness, tenant_id: str, severity: str, route: Optional[str], *, disposition: Optional[str] = None,
    actions: tuple = (), status: str = "waiting_human", cost: float = 0.004, ms: int = 1000,  # type: ignore[type-arg]
) -> str:
    """An alert production decided: its ``decide`` event, planned actions, LLM usage and trace."""
    repos = api.repos
    alert_id = await make_alert(
        repos, tenant_id, severity=severity, summary={"llm_usage": {"total_tokens": 2000, "cost_usd": cost}}
    )
    for step in ("queued", "processing", status):
        await repos.alerts.update_status(tenant_id, alert_id, step)
    await repos.alerts.update(tenant_id, alert_id, confidence=70.0)
    if route is not None:
        await repos.alert_events.append(
            tenant_id, alert_id, "node.completed", node="decide", actor_type="system", actor_id="workflow",
            data={"route": route, "disposition": disposition, "code": "test", "reason": "fixture"},
        )
    for action in actions:
        action_type, target = action.split(":", 1)
        await repos.actions.propose(tenant_id, alert_id, action_type, target, "low", requested_by=REQUESTED_BY)
    await repos.investigation_steps.append(
        tenant_id, alert_id, f"{tenant_id}:{alert_id}",
        [NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash=sha256_hex(alert_id),
                      outcome="success", latency_ms=ms, started_at=datetime.now(UTC))],
    )
    return alert_id


async def test_agreement_report(api: ApiHarness) -> None:
    """Acceptance (AI-E1.5b): from a fixture run, the report shows the agreement rate with n and a 95% CI."""
    miss = await produced(api, TENANT_B, "critical", "escalate")
    plan = await produced(api, TENANT_B, "high", "plan_response", disposition="malicious",
                          actions=("block_ip:203.0.113.7",), status="closed")
    more = await produced(api, TENANT_B, "low", None, status="closed")  # suppressed: closed without a decision
    agree_esc = await produced(api, TENANT_B, "medium", "escalate")
    agree_close = await produced(api, TENANT_B, "low", "close", disposition="benign", status="closed")
    failed = await produced(api, TENANT_B, "medium", "escalate")
    candidate = FixedCandidate({
        miss: shadow("close", "benign"),
        plan: shadow("plan_response", "malicious", actions=("isolate_host:ws-1", "block_ip:203.0.113.7")),
        more: shadow("escalate"),
        agree_esc: shadow("escalate"),
        agree_close: shadow("close", "benign"),
        failed: TimeoutError("candidate model timed out"),
    })
    ids = [miss, plan, more, agree_esc, agree_close, failed]
    replay = ShadowReplay(cast(ShadowRunner, candidate), api.repos, candidate="local-llama")
    report_id = await replay.run(TENANT_B, ids)
    assert candidate.calls == ids

    headers = await api.login_headers(TENANT_A, "admin", email="platform@a.example.com", platform_admin=True)
    response = await api.client.get(
        f"/api/v1/platform/shadow/reports/{report_id}", params={"tenant_id": TENANT_B}, headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()

    # The agreement rate, with its sample size and Wilson interval: 3 of the 6 alerts production decided (the
    # failed candidate run counts as a disagreement); 3 of 5 over the usable candidate verdicts, shown beside it.
    assert (body["alerts"], body["compared"], body["candidate_failed"]) == (6, 5, 1)
    expected = rate_interval(3, 6)
    assert body["agreement"] == expected.model_dump()
    assert body["agreement"]["n"] == 6 and body["agreement"]["ci_low"] < 0.5 < body["agreement"]["ci_high"]
    assert body["agreement_text"].startswith("Not enough data (n=6; at least 30 needed): 50.0% (3 of 6; 95% CI ")
    assert body["agreement_usable"] == rate_interval(3, 5).model_dump()
    assert not body["enough_data"] and body["data_warnings"][0] == "Not enough data (n=6; at least 30 needed)"
    assert [c["alert_id"] for c in body["candidate_failures"]["items"]] == [failed]
    assert body["candidate_failures"]["items"][0]["candidate_error"] == "TimeoutError"
    by_class = {c["production_route"]: c["agreement"] for c in body["by_class"]}
    assert by_class["escalate"] == rate_interval(1, 3).model_dump()
    assert by_class["close"] == rate_interval(1, 2).model_dump()
    assert by_class["plan_response"] == rate_interval(1, 1).model_dump()

    # Production versus candidate, with the failed run in the candidate's "none" column.
    assert body["confusion"]["escalate"] == {"escalate": 1, "plan_response": 0, "close": 1, "none": 1}
    assert body["confusion"]["close"] == {"escalate": 1, "plan_response": 0, "close": 1, "none": 0}
    assert body["confusion"]["plan_response"]["plan_response"] == 1

    # The cases that matter, the potential new miss first.
    assert [c["alert_id"] for c in body["potential_misses"]["items"]] == [miss]
    assert body["potential_misses"]["items"][0]["severity"] == "critical"
    assert [c["alert_id"] for c in body["new_escalations"]["items"]] == [more]
    differs = body["plan_differences"]["items"]
    assert [c["alert_id"] for c in differs] == [plan]
    assert differs[0]["production_actions"] == ["block_ip:203.0.113.7"]
    assert differs[0]["candidate_actions"] == ["block_ip:203.0.113.7", "isolate_host:ws-1"]

    # Cost and latency per alert: production 0.004 USD and 1000 ms, the candidate 0.001 USD and 200 ms.
    assert body["cost_usd"] == {"production_mean": 0.004, "candidate_mean": 0.001, "delta": -0.003}
    assert body["latency_ms"] == {"production_mean": 1000, "candidate_mean": 200, "delta": -800}
    assert body["tokens"]["delta"] == -1500
    assert body["candidate"] == "local-llama" and body["report_id"] == report_id

    # The read is audited in the platform admin's home tenant.
    audit = await api.repos.audit.list(TENANT_A, action="platform.shadow_report_viewed")
    assert audit.items and audit.items[0].details["report_id"] == report_id


async def test_shadow_report_reads_only_the_named_tenant_and_needs_a_platform_admin(api: ApiHarness) -> None:
    alert_id = await produced(api, TENANT_B, "high", "escalate")
    report_id = await ShadowReplay(
        cast(ShadowRunner, FixedCandidate({alert_id: shadow("close")})), api.repos, candidate="cand"
    ).run(TENANT_B, [alert_id])
    path = f"/api/v1/platform/shadow/reports/{report_id}"
    platform = await api.login_headers(TENANT_A, "admin", email="platform@a.example.com", platform_admin=True)
    # Another tenant has no such report: 404, never tenant B's rows.
    assert (await api.client.get(path, params={"tenant_id": TENANT_A}, headers=platform)).status_code == 404
    malformed = await api.client.get(
        "/api/v1/platform/shadow/reports/shr_nope", params={"tenant_id": TENANT_B}, headers=platform
    )
    assert malformed.status_code == 422
    for headers in (
        await api.login_headers(TENANT_B, "admin"),
        await api.login_headers(TENANT_A, "analyst", platform_admin=True),
        await api.key_headers(TENANT_B, ["read", "write"]),
    ):
        assert (await api.client.get(path, params={"tenant_id": TENANT_B}, headers=headers)).status_code == 403
    assert (await api.client.get(path, params={"tenant_id": TENANT_B})).status_code == 401
