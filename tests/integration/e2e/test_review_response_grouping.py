"""Grouped escalations end to end: what a decision on the reviewed alert does to the attached alerts.

Regression tests for the review findings RR-1 (a benign group decision closed
an unrelated attached alert and taught the verdict cache its fingerprint) and
RR-2 (a type-only admin pre-approval was applied to an attached alert's
targets). Real worker, Postgres checkpoints, Redis queue and the fake LLM.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List
from uuid import UUID, uuid4

import pytest

from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import Alert, Repositories
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.services.review import ReviewService
from tests.integration.db._support import TENANT_A
from tests.integration.e2e._support import Stack, eventually, running

pytestmark = pytest.mark.integration

GROUP_BY_HOST_AND_USER = {"review": {"grouping": {"indicator_types": ["ip", "domain", "url", "hash", "host", "user"]}}}


def event(source_alert_id: str, title: str, severity: str, **entities: List[str]) -> Dict[str, Any]:
    return {
        "source_alert_id": source_alert_id,
        "title": title,
        "severity": severity,
        "occurred_at": "2024-03-05T10:05:00Z",
        "entities": entities,
    }


async def _status_is(stack: Stack, alert_id: str, *statuses: str) -> bool:
    return await stack.run_status(TENANT_A, alert_id) in statuses


async def _learned(verdicts: VerdictCache, alert: Alert) -> List[Dict[str, Any]]:
    """The analyst-benign decisions the verdict cache holds for the alert's verdict key."""
    return list((await verdicts.get(TENANT_A, verdict_key_of(alert)) or {}).get("decisions", []))


async def _user(repos: Repositories, role: str) -> UUID:
    return (await repos.users.create(TENANT_A, f"{role}-{uuid4().hex[:8]}@example.com", role)).id


async def test_benign_group_decision_does_not_close_or_learn_a_different_attached_alert(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    await repos.tenants.update_settings(TENANT_A, GROUP_BY_HOST_AND_USER)
    analyst = await _user(repos, "analyst")
    review = ReviewService(repos, stack.settings, stack.events)
    verdicts = VerdictCache(stack.redis, stack.settings.redis.key_prefix)

    noisy = event("n1", "Possible C2 beacon from workstation", "medium", hosts=["ws-042"], ips=["185.220.101.44"],
                  processes=["c:\\program files\\agent\\agent.exe"])
    threat = event("m1", "Possible C2 beacon to rare domain", "high", hosts=["ws-042"], ips=["45.9.148.3"])
    r1 = await stack.ingest(TENANT_A, "api", [noisy])
    r2 = await stack.ingest(TENANT_A, "api", [threat])
    a1, a2 = r1.inserted[0].alert_id, r2.inserted[0].alert_id
    worker = stack.worker(await stack.engine())

    async with running(worker):
        await stack.dispatch(TENANT_A, r1)
        await eventually(lambda: _status_is(stack, a1, "waiting_human"))
        await stack.dispatch(TENANT_A, r2)
        await eventually(lambda: _status_is(stack, a2, "waiting_human"))
        group = await repos.escalations.get_active_for_alert(TENANT_A, a1)
        assert group is not None and group.related_alert_ids == [a2]
        alert1, alert2 = await repos.alerts.get(TENANT_A, a1), await repos.alerts.get(TENANT_A, a2)
        assert alert1.fingerprint != alert2.fingerprint

        result = await review.decide(TENANT_A, group.id, analyst, "analyst", "false_positive", "noisy beacon", [], group.version)
        assert result.own_review_alert_ids == [a2]
        for alert_id, payload in result:
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)

        # The reviewed alert closes benign; the attached one waits again, on an escalation of its own.
        await eventually(lambda: _status_is(stack, a1, "completed"))

        async def detached() -> bool:
            own = await repos.escalations.get_active_for_alert(TENANT_A, a2)
            return own is not None and await _status_is(stack, a2, "waiting_human")

        await eventually(detached)
        own = await repos.escalations.get_active_for_alert(TENANT_A, a2)
        assert own is not None and own.id != group.id
        assert own.summary["detached_from"] == group.id and own.summary["own_review_reason"] == "different_fingerprint"
        alert2 = await repos.alerts.get(TENANT_A, a2)
        assert alert2.status == "waiting_human" and alert2.disposition is None
        assert alert2.summary["escalation_id"] == own.id and alert2.summary["detached_from"] == group.id
        closed1 = await repos.alerts.get(TENANT_A, a1)
        assert (closed1.status, closed1.disposition) == ("closed", "benign")

        # Only the reviewed alert's verdict key is learned as benign.
        assert len(await _learned(verdicts, alert1)) == 1
        assert await _learned(verdicts, alert2) == []

        # A recurrence of the attached alert's detection is investigated, not closed at the gate.
        r3 = await stack.ingest(TENANT_A, "api", [{**threat, "source_alert_id": "m2"}])
        a3 = r3.inserted[0].alert_id
        assert (await repos.alerts.get(TENANT_A, a3)).fingerprint == alert2.fingerprint
        await stack.dispatch(TENANT_A, r3)
        await eventually(lambda: stack.all_settled(TENANT_A, [a3]))
        recurrence = await repos.alerts.get(TENANT_A, a3)
        assert recurrence.status in ("waiting_human", "waiting_approval")
        assert recurrence.disposition != "benign" and recurrence.summary.get("suppressed_by") is None

        # The analyst decides the detached alert on its own escalation: that run continues with that decision.
        own = await repos.escalations.get(TENANT_A, own.id)
        decided = await review.decide(TENANT_A, own.id, analyst, "analyst", "true_positive", "real beacon", [], own.version)
        assert decided[0].alert_id == a2
        for alert_id, payload in decided:
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)
        await eventually(lambda: _status_is(stack, a2, "waiting_approval", "completed"))
        await eventually(stack.stream_empty)

    timeline = [(e.event_type, e.data) for e in (await repos.alert_events.list_for_alert(TENANT_A, a2, limit=100)).items]
    assert ("escalation.detached", {"escalation_id": own.id, "detached_from": group.id,
                                    "group_decision": "false_positive", "reason": "different_fingerprint"}) in timeline
    decisions = [d for kind, d in timeline if kind == "analyst.decision"]
    assert {"decision": "true_positive", "escalation_id": own.id} in decisions
    assert await _learned(verdicts, alert2) == []
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_admin_preapproval_covers_only_the_reviewed_alerts_targets(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    await repos.tenants.update_settings(TENANT_A, GROUP_BY_HOST_AND_USER)
    admin = await _user(repos, "admin")
    review = ReviewService(repos, stack.settings, stack.events)

    r1 = await stack.ingest(
        TENANT_A, "api", [event("p1", "Mimikatz credential dump on workstation", "medium", hosts=["ws-042"], users=["jdoe"])]
    )
    r2 = await stack.ingest(TENANT_A, "api", [event("p2", "Unusual login", "medium", hosts=["srv-db-prod"], users=["jdoe"])])
    a1, a2 = r1.inserted[0].alert_id, r2.inserted[0].alert_id
    worker = stack.worker(await stack.engine())

    async with running(worker):
        await stack.dispatch(TENANT_A, r1)
        await eventually(lambda: _status_is(stack, a1, "waiting_human"))
        await stack.dispatch(TENANT_A, r2)
        await eventually(lambda: _status_is(stack, a2, "waiting_human"))
        group = await repos.escalations.get_active_for_alert(TENANT_A, a1)
        assert group is not None and group.related_alert_ids == [a2]

        result = await review.decide(TENANT_A, group.id, admin, "admin", "true_positive", "", ["isolate_host"], group.version)
        assert dict(result) == {
            a1: {**dict(result)[a1], "approved_actions": ["isolate_host:ws-042"]},
            a2: {**dict(result)[a2], "approved_actions": []},
        }
        for alert_id, payload in result:
            await stack.queue.enqueue_resume(TENANT_A, alert_id, payload)
        for alert_id in (a1, a2):
            await eventually(lambda alert_id=alert_id: _status_is(stack, alert_id, "waiting_approval", "completed"))
        await eventually(stack.stream_empty)

    parent_ledger = {(a.action_type, a.target): a for a in (await repos.actions.list(TENANT_A, alert_id=a1, limit=50)).items}
    isolate = parent_ledger[("isolate_host", "ws-042")]
    assert isolate.approved_by == str(admin) and isolate.status == "dry_run"

    attached_ledger = (await repos.actions.list(TENANT_A, alert_id=a2, limit=50)).items
    assert attached_ledger, "the attached alert is planned as a confirmed case"
    assert all(a.approved_by != str(admin) for a in attached_ledger)
    contained = [a for a in attached_ledger if a.target == "srv-db-prod" and a.action_type == "isolate_host"]
    assert len(contained) == 1 and contained[0].status == "awaiting_approval" and contained[0].approved_by is None
    # The attached alert's containment is never treated as analyst-confirmed evidence.
    summary = (await repos.alerts.get(TENANT_A, a2)).summary
    assert summary["response"]["evidence"] != "analyst"
