"""Human review and response end to end: grouping, one decision for both runs, approvals, webhook delivery.

Two related alerts -> one escalation -> one analyst decision resumes both
runs -> admin approval -> the SOAR webhook is called exactly once per
approved action, even though every approval message is delivered twice.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Callable, Dict, List
from uuid import UUID, uuid4

import httpx
import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.services.connectors import WebhookConnector, WebhookTarget, verify_signature
from lg_sotf.services.connectors.webhook import IDEMPOTENCY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import ResponseSettings
from tests.integration.db._support import TENANT_A
from tests.integration.e2e.conftest import Stack, eventually, running

pytestmark = pytest.mark.integration

SECRET = b"e2e-webhook-secret-0123456789abcdef"
SOAR_URL = "https://soar.example.com/hooks/lgsotf"


def related_event(n: int) -> Dict[str, Any]:
    return {
        "source_alert_id": f"c2-related-{n}",
        "title": "Possible C2 beacon from workstation",
        "severity": "medium",
        "occurred_at": "2024-03-05T10:05:00Z",
        "entities": {
            "ips": ["185.220.101.44", "10.0.0.5"],
            "hosts": ["ws-042"],
            "users": ["jdoe"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "processes": ["powershell.exe"],
        },
    }


class Soar:
    """The tenant's SOAR endpoint: verifies signatures and records deliveries."""

    def __init__(self) -> None:
        self.deliveries: List[Dict[str, Any]] = []
        self.bad_signatures = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        headers = request.headers
        if not verify_signature(SECRET, headers[TIMESTAMP_HEADER], request.content, headers[SIGNATURE_HEADER]):
            self.bad_signatures += 1
            return httpx.Response(401)
        body = json.loads(request.content)
        self.deliveries.append({"key": headers[IDEMPOTENCY_HEADER], "action": body["action"], "alert": body["alert"]})
        return httpx.Response(200, json={"status": "succeeded", "reference": f"case-{len(self.deliveries)}"})


async def _resolve(host: str, port: int) -> List[str]:
    return ["93.184.216.34"]


async def _engine(stack: Stack, soar: Soar) -> WorkflowEngine:
    webhook = WebhookConnector(
        WebhookTarget(url=SOAR_URL, secret=SECRET),
        policy=DestinationPolicy(require_https=True),
        target_kinds={"block_ip": "ip", "isolate_host": "host", "create_ticket": "alert"},
        transport=httpx.MockTransport(soar),
        resolver=_resolve,
    )
    engine = await WorkflowEngine.create(
        settings=stack.settings,
        db=stack.db,
        redis=stack.redis,
        events=stack.events,
        connectors={"webhook": webhook},
        checkpoint_pool_size=4,
    )
    stack.engines.append(engine)
    return engine


async def _runs_are(stack: Stack, alert_ids: List[str], status: str) -> bool:
    return all([await stack.run_status(TENANT_A, a) == status for a in alert_ids])


async def test_grouped_review_and_webhook_response(stack_factory: Callable[..., Stack], repos: Repositories) -> None:
    stack = stack_factory()
    stack.settings = stack.settings.model_copy(update={"response": ResponseSettings(dry_run=False)})
    await repos.tenants.update_settings(TENANT_A, {"response": {"connector": "webhook"}})
    analyst = (await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id
    admin = (await repos.users.create(TENANT_A, f"admin-{uuid4().hex[:8]}@example.com", "admin")).id
    review = ReviewService(repos, stack.settings, stack.events)
    soar = Soar()

    first = await stack.ingest(TENANT_A, "api", [related_event(1)])
    second = await stack.ingest(TENANT_A, "api", [related_event(2)])
    alert_ids = [first.inserted[0].alert_id, second.inserted[0].alert_id]
    worker = stack.worker(await _engine(stack, soar))

    async with running(worker):
        # Both alerts are escalated; the second one joins the first one's escalation.
        await stack.dispatch(TENANT_A, first)
        await eventually(lambda: _runs_are(stack, alert_ids[:1], "waiting_human"))
        await stack.dispatch(TENANT_A, second)
        await eventually(lambda: _runs_are(stack, alert_ids, "waiting_human"))
        escalations = (await repos.escalations.list(TENANT_A, limit=10)).items
        assert len(escalations) == 1
        esc = escalations[0]
        assert esc.alert_id == alert_ids[0] and esc.related_alert_ids == [alert_ids[1]]
        for alert_id in alert_ids:
            assert (await repos.alerts.get(TENANT_A, alert_id)).summary["escalation_id"] == esc.id

        # One decision, recorded once, resumes both runs.
        claimed = await review.claim(TENANT_A, esc.id, analyst, esc.version)
        resumes = await review.decide(
            TENANT_A, esc.id, analyst, "analyst", "true_positive", "same beacon on ws-042", [], claimed.version
        )
        assert [r.alert_id for r in resumes] == alert_ids
        for alert_id, payload in resumes:
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)
        await eventually(lambda: _runs_are(stack, alert_ids, "waiting_approval"))
        assert (await repos.escalations.get(TENANT_A, esc.id)).status == "decided"

        awaiting: Dict[str, List[str]] = {}
        for alert_id in alert_ids:
            ledger = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
            awaiting[alert_id] = [str(a.id) for a in ledger if a.status == "awaiting_approval"]
            blocked = {(a.action_type, a.target): a for a in ledger if a.status == "blocked"}
            assert blocked[("block_ip", "10.0.0.5")].blocked_reason == "non_public_ip"
            assert awaiting[alert_id]

        # Approve everything pending (high risk needs the admin); deliver every approval message twice.
        approvals = await review.approve_actions(
            TENANT_A, [i for ids in awaiting.values() for i in ids], admin, "admin"
        )
        assert sorted(r.alert_id for r in approvals) == sorted(alert_ids)
        for alert_id, payload in approvals:
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)
        await eventually(lambda: _runs_are(stack, alert_ids, "completed"))
        await eventually(stack.stream_empty)

    approved_ids = sorted(i for ids in awaiting.values() for i in ids)
    calls = Counter(d["key"] for d in soar.deliveries)
    assert soar.bad_signatures == 0
    assert sorted(calls) == approved_ids and set(calls.values()) == {1}
    for alert_id in alert_ids:
        alert = await repos.alerts.get(TENANT_A, alert_id)
        assert (alert.status, alert.disposition) == ("closed", "malicious")
        assert alert.summary["analyst_decision"] == "true_positive"
        for action in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items:
            if str(action.id) in awaiting[alert_id]:
                assert action.status == "succeeded" and action.connector == "webhook"
                assert action.approved_by == str(admin) and action.result is not None
                assert action.result["http_status"] == 200 and action.result["response"]["status"] == "succeeded"
            else:
                assert action.status == "blocked"
    assert {d["alert"]["id"] for d in soar.deliveries} == set(alert_ids)
    assert (await repos.audit.verify_chain(TENANT_A)).ok
    feedback = await repos.feedback.get_for_escalation(TENANT_A, esc.id)
    assert feedback is not None and feedback.decision == "true_positive"


async def test_partial_approval_keeps_the_run_waiting_until_the_rest_is_decided(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    analyst = (await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id
    review = ReviewService(repos, stack.settings, stack.events)
    result = await stack.ingest(TENANT_A, "api", [related_event(3)])
    alert_id = result.inserted[0].alert_id
    await stack.dispatch(TENANT_A, result)
    worker = stack.worker(await stack.engine())

    async with running(worker):
        await eventually(lambda: _runs_are(stack, [alert_id], "waiting_human"))
        esc = await repos.escalations.get_active_for_alert(TENANT_A, alert_id)
        assert esc is not None
        for rid, payload in await review.decide(TENANT_A, esc.id, analyst, "analyst", "true_positive", None, [], esc.version):
            await stack.queue.enqueue_resume(TENANT_A, rid, payload)
        await eventually(lambda: _runs_are(stack, [alert_id], "waiting_approval"))
        ledger = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
        low_medium = [str(a.id) for a in ledger if a.status == "awaiting_approval" and a.risk_level in ("low", "medium")]
        others = [str(a.id) for a in ledger if a.status == "awaiting_approval" and str(a.id) not in low_medium]
        assert low_medium and others

        # Approve one action only: it runs, the others stay pending and the run waits again.
        for rid, payload in await review.approve_actions(TENANT_A, low_medium[:1], analyst, "analyst"):
            await stack.queue.enqueue_resume(TENANT_A, rid, payload)
        await eventually(lambda: _action_is(repos, low_medium[0], "dry_run"))
        await eventually(lambda: _runs_are(stack, [alert_id], "waiting_approval"))
        for action_id in low_medium[1:] + others:
            assert (await repos.actions.get(TENANT_A, UUID(action_id))).status == "awaiting_approval"

        # Explicitly reject the remaining ones: the run finishes.
        for rid, payload in await review.reject_actions(TENANT_A, others[:1], analyst, "analyst", reject_remaining=True):
            await stack.queue.enqueue_resume(TENANT_A, rid, payload)
        await eventually(lambda: _runs_are(stack, [alert_id], "completed"))

    statuses = {str(a.id): a.status for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    assert statuses[low_medium[0]] == "dry_run"
    assert all(statuses[i] == "rejected" for i in low_medium[1:] + others)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "malicious")


async def _action_is(repos: Repositories, action_id: str, status: str) -> bool:
    return (await repos.actions.get(TENANT_A, UUID(action_id))).status == status
