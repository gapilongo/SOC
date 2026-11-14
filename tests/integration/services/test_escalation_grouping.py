"""Escalation grouping against Postgres: attach related alerts, idempotency, window, tenant isolation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.db import locks
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.services.escalation import EscalationService, EscalationTicket
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.services._support import add_alert, sight
from tests.unit.services.fakes import FakeEvents

pytestmark = pytest.mark.integration


def service(repos: Repositories, make_settings: Callable[..., Settings], events: Any = None) -> EscalationService:
    return EscalationService(repos, events, make_settings())


async def escalate(svc: EscalationService, tenant: str, alert_id: str, **kw: Any) -> EscalationTicket:
    args: Dict[str, Any] = dict(severity="high", confidence=50, threat_score=40, reason="grey zone", reason_code="grey_zone")
    args.update(kw)
    return await svc.open_or_attach(tenant, alert_id, **args)


async def test_related_alert_is_attached_not_escalated_again(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    events = FakeEvents()
    svc = service(repos, make_settings, events)
    first = await add_alert(repos, TENANT_A, fingerprint="fp-1")
    second = await add_alert(repos, TENANT_A, fingerprint="fp-2")
    unrelated = await add_alert(repos, TENANT_A, fingerprint="fp-3")
    await sight(repos, TENANT_A, first, [("ip", "185.220.101.44"), ("host", "ws-042")])
    await sight(repos, TENANT_A, second, [("ip", "185.220.101.44")])
    await sight(repos, TENANT_A, unrelated, [("ip", "8.8.8.8")])

    parent = await escalate(svc, TENANT_A, first, threat_score=30)
    child = await escalate(svc, TENANT_A, second, threat_score=95, severity="critical", confidence=20)
    other = await escalate(svc, TENANT_A, unrelated)

    assert parent.created and not parent.attached
    assert child.attached and not child.created and child.id == parent.id
    assert other.created and other.id != parent.id
    esc = await repos.escalations.get(TENANT_A, parent.id)
    assert esc.related_alert_ids == [second] and esc.status == "open"
    # The parent took over the more urgent attached alert's priority, level and deadline.
    assert esc.priority >= child.priority and esc.level == "L3"
    assert esc.sla_deadline is not None and parent.sla_deadline is not None and esc.sla_deadline <= parent.sla_deadline
    assert esc.version == 2 and esc.summary["attached_count"] == 1
    assert await repos.escalations.get_active_for_alert(TENANT_A, second) is None
    assert EscalationService.alerts_to_resume(esc) == [first, second]

    # Idempotent: the escalate node running again for either alert changes nothing.
    again_child = await escalate(svc, TENANT_A, second)
    again_parent = await escalate(svc, TENANT_A, first)
    assert (again_child.id, again_child.attached) == (parent.id, True)
    assert (again_parent.id, again_parent.created) == (parent.id, False)
    assert (await repos.escalations.get(TENANT_A, parent.id)).related_alert_ids == [second]

    audits = [e.action for e in (await repos.audit.list(TENANT_A, resource_id=parent.id)).items]
    assert sorted(audits) == ["escalation.alert_attached", "escalation.created"]
    attached_events = [e for e in events.events if e["type"] == "escalation.updated"]
    assert {e["alert_id"] for e in attached_events} == {first, second}
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_fingerprint_groups_without_shared_indicators(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    svc = service(repos, make_settings)
    a = await add_alert(repos, TENANT_A, fingerprint="same")
    b = await add_alert(repos, TENANT_A, fingerprint="same")
    first = await escalate(svc, TENANT_A, a)
    second = await escalate(svc, TENANT_A, b, fingerprint="same")
    assert second.attached and second.id == first.id


async def test_process_names_alone_do_not_group(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    svc = service(repos, make_settings)
    a = await add_alert(repos, TENANT_A)
    b = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, a, [("process", "powershell.exe")])
    await sight(repos, TENANT_A, b, [("process", "powershell.exe")])
    first = await escalate(svc, TENANT_A, a)
    second = await escalate(svc, TENANT_A, b)
    assert second.created and second.id != first.id


async def test_grouping_respects_window_tenant_policy_and_tenants(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    svc = service(repos, make_settings)
    old = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, old, [("ip", "185.220.101.44")])
    past = datetime.now(UTC) - timedelta(hours=3)
    parent = await escalate(svc, TENANT_A, old, now=past)
    fresh = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, fresh, [("ip", "185.220.101.44")])
    async with repos.db.tenant_tx(TENANT_A) as conn:
        await conn.execute("UPDATE escalations SET created_at = $2 WHERE id = $1", parent.id, past)
    outside = await escalate(svc, TENANT_A, fresh)
    assert outside.created and outside.id != parent.id

    # Same indicator in tenant B never joins tenant A's escalation.
    b_alert = await add_alert(repos, TENANT_B)
    await sight(repos, TENANT_B, b_alert, [("ip", "185.220.101.44")])
    b_ticket = await escalate(svc, TENANT_B, b_alert)
    assert b_ticket.created and b_ticket.id not in (parent.id, outside.id)

    # A tenant can switch grouping off.
    await repos.tenants.update_settings(TENANT_A, {"review": {"grouping": {"enabled": False}}})
    third = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, third, [("ip", "185.220.101.44")])
    assert (await escalate(svc, TENANT_A, third)).created


async def test_tenant_sla_and_level_policy(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    await repos.tenants.update_settings(
        TENANT_A, {"review": {"sla_minutes": {"L1": 5}, "min_level": {"low": "L1"}, "level_thresholds": {"L2": 3}}}
    )
    svc = service(repos, make_settings)
    now = datetime.now(UTC)
    low = await add_alert(repos, TENANT_A, severity="low")
    ticket = await escalate(svc, TENANT_A, low, severity="low", threat_score=10, confidence=60, now=now)
    assert ticket.level == "L1" and ticket.sla_deadline == now + timedelta(minutes=5)
    mid = await add_alert(repos, TENANT_A, severity="medium")
    ticket = await escalate(svc, TENANT_A, mid, severity="medium", threat_score=30, confidence=60, now=now)
    assert ticket.level == "L2"


async def test_max_attached_opens_a_new_escalation(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    await repos.tenants.update_settings(TENANT_A, {"review": {"grouping": {"max_attached": 1}}})
    svc = service(repos, make_settings)
    ids: List[str] = []
    for _ in range(3):
        alert_id = await add_alert(repos, TENANT_A)
        await sight(repos, TENANT_A, alert_id, [("domain", "evil.example.net")])
        ids.append(alert_id)
    tickets = [await escalate(svc, TENANT_A, a) for a in ids]
    assert tickets[1].attached and tickets[1].id == tickets[0].id
    assert tickets[2].created and tickets[2].id != tickets[0].id


async def test_concurrent_related_alerts_end_in_one_escalation(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    svc = service(repos, make_settings)
    ids = []
    for _ in range(4):
        alert_id = await add_alert(repos, TENANT_A)
        await sight(repos, TENANT_A, alert_id, [("hash", "44d88612fea8a8f36de82e1278abb02f")])
        ids.append(alert_id)
    tickets = await asyncio.gather(*(escalate(svc, TENANT_A, a) for a in ids))
    assert len({t.id for t in tickets}) == 1
    assert sum(t.created for t in tickets) == 1 and sum(t.attached for t in tickets) == 3
    esc = await repos.escalations.get(TENANT_A, tickets[0].id)
    assert sorted(EscalationService.alerts_to_resume(esc)) == sorted(ids)


async def test_shared_host_or_user_alone_groups_only_when_the_tenant_opts_in(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    """RR-1: a busy workstation or account links unrelated detections, so host/user grouping is opt-in."""
    svc = service(repos, make_settings)
    a = await add_alert(repos, TENANT_A)
    b = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, a, [("host", "ws-042"), ("user", "jdoe"), ("ip", "185.220.101.44")])
    await sight(repos, TENANT_A, b, [("host", "ws-042"), ("user", "jdoe"), ("ip", "45.9.148.3")])
    first = await escalate(svc, TENANT_A, a)
    second = await escalate(svc, TENANT_A, b)
    assert second.created and second.id != first.id

    await repos.tenants.update_settings(
        TENANT_A, {"review": {"grouping": {"indicator_types": ["ip", "domain", "url", "hash", "host"]}}}
    )
    c = await add_alert(repos, TENANT_A)
    await sight(repos, TENANT_A, c, [("host", "ws-042")])
    third = await escalate(svc, TENANT_A, c)
    assert third.attached and third.id == first.id


async def test_invalid_grouping_indicator_types_fall_back_to_the_defaults(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    await repos.tenants.update_settings(TENANT_A, {"review": {"grouping": {"indicator_types": ["host", "bogus"]}}})
    svc = service(repos, make_settings)
    policy = await svc.policy(TENANT_A)
    assert policy.grouping.indicator_types == ("ip", "domain", "url", "hash")


SVCHOST = "c:\\windows\\system32\\svchost.exe"


async def _grouped(
    repos: Repositories, svc: EscalationService, *, parent_fp: str, child_fp: str, parent_sev: str, child_sev: str,
    child_process: str = SVCHOST,
) -> tuple[str, str, str]:
    parent = await add_alert(repos, TENANT_A, fingerprint=parent_fp, severity=parent_sev,
                             entities={"processes": [SVCHOST]})
    child = await add_alert(repos, TENANT_A, fingerprint=child_fp, severity=child_sev,
                            entities={"processes": [child_process]})
    for alert_id in (parent, child):
        await sight(repos, TENANT_A, alert_id, [("ip", "185.220.101.44")])
    p = await escalate(svc, TENANT_A, parent, severity=parent_sev)
    c = await escalate(svc, TENANT_A, child, severity=child_sev)
    assert c.attached and c.id == p.id
    return p.id, parent, child


@pytest.mark.parametrize(
    ("decision", "child_fp", "child_sev", "child_process", "reason"),
    [
        ("false_positive", "fp-parent", "medium", SVCHOST, None),
        ("benign_positive", "fp-parent", "low", SVCHOST, None),
        ("false_positive", "fp-other", "medium", SVCHOST, "different_fingerprint"),
        # Same fingerprint (rule and entities), another process: not the activity the analyst reviewed.
        ("false_positive", "fp-parent", "medium", "c:\\windows\\psexesvc.exe", "different_fingerprint"),
        ("false_positive", "fp-parent", "high", SVCHOST, "higher_severity"),
        ("true_positive", "fp-other", "critical", SVCHOST, None),
        ("needs_more_info", "fp-other", "critical", SVCHOST, None),
    ],
)
async def test_decision_scope_of_attached_alerts(
    repos: Repositories,
    make_settings: Callable[..., Settings],
    decision: str,
    child_fp: str,
    child_sev: str,
    child_process: str,
    reason: str | None,
) -> None:
    svc = service(repos, make_settings)
    esc_id, parent, child = await _grouped(
        repos, svc, parent_fp="fp-parent", child_fp=child_fp, parent_sev="medium", child_sev=child_sev,
        child_process=child_process,
    )
    parent_key = verdict_key_of(await repos.alerts.get(TENANT_A, parent))
    child_key = verdict_key_of(await repos.alerts.get(TENANT_A, child))
    own = await svc.decision_scope(TENANT_A, parent, esc_id, decision=decision, verdict_key=parent_key, severity="medium")
    assert (own.inherited, own.own_review_reason, own.parent_alert_id) == (False, None, parent)
    scope = await svc.decision_scope(TENANT_A, child, esc_id, decision=decision, verdict_key=child_key, severity=child_sev)
    assert scope.inherited and scope.parent_alert_id == parent and scope.escalation.id == esc_id
    assert scope.own_review_reason == reason


async def test_open_detached_gives_the_alert_its_own_escalation_idempotently(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    events = FakeEvents()
    svc = service(repos, make_settings, events)
    esc_id, parent, child = await _grouped(
        repos, svc, parent_fp="fp-a", child_fp="fp-b", parent_sev="medium", child_sev="high"
    )
    analyst = (await repos.users.create(TENANT_A, "detach-analyst@example.com", "analyst")).id
    group = await repos.escalations.decide(
        TENANT_A, esc_id, decision="false_positive", decided_by=analyst, expected_version=2
    )
    kw: Dict[str, Any] = dict(
        reason_code="different_fingerprint", decision="false_positive", severity="high", confidence=40, threat_score=70,
        summary={"title": "Possible C2 beacon to rare domain"},
    )
    ticket = await svc.open_detached(TENANT_A, child, group, **kw)
    assert ticket.created and ticket.id != esc_id
    own = await repos.escalations.get(TENANT_A, ticket.id)
    assert own.alert_id == child and own.status == "open" and own.related_alert_ids == []
    assert own.summary["detached_from"] == esc_id and own.summary["parent_alert_id"] == parent
    assert own.summary["own_review_reason"] == "different_fingerprint" and own.summary["title"]
    assert "needs its own decision" in own.reason and own.sla_deadline is not None
    assert [e for e in events.events if e["type"] == "escalation.created" and e["alert_id"] == child]

    # The node runs again on every resume: same escalation, even after it was decided.
    again = await svc.open_detached(TENANT_A, child, group, **kw)
    assert (again.id, again.created) == (ticket.id, False)
    await repos.escalations.decide(TENANT_A, ticket.id, decision="true_positive", decided_by=analyst, expected_version=1)
    after = await svc.open_detached(TENANT_A, child, group, **kw)
    assert (after.id, after.created) == (ticket.id, False)
    audits = [e.action for e in (await repos.audit.list(TENANT_A, resource_id=ticket.id)).items]
    assert audits == ["escalation.detached"]
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_indicator_lookups_run_outside_the_grouping_lock(
    repos: Repositories, make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """PERF-9: the per-tenant grouping lock is held only for the parent lookup and attach/create."""
    svc = service(repos, make_settings)
    first = await add_alert(repos, TENANT_A, fingerprint="fp-l1")
    second = await add_alert(repos, TENANT_A, fingerprint="fp-l2")
    await sight(repos, TENANT_A, first, [("ip", "185.220.101.45")])
    await sight(repos, TENANT_A, second, [("ip", "185.220.101.45")])
    held: List[int] = []
    real = repos.indicators.related_alerts

    async def spy(*args: Any, **kwargs: Any) -> Any:
        async with repos.db.system_tx(readonly=True) as conn:
            held.append(
                await conn.fetchval(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = $1 AND granted",
                    locks.ESCALATION_GROUP,
                )
            )
        return await real(*args, **kwargs)

    monkeypatch.setattr(repos.indicators, "related_alerts", spy)
    parent = await escalate(svc, TENANT_A, first)
    child = await escalate(svc, TENANT_A, second)
    assert child.attached and child.id == parent.id
    assert held and held == [0] * len(held)


async def test_compliance_records_of_an_attached_alert_include_the_deciding_escalation(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    from lg_sotf.compliance.evidence import build_evidence_pack
    from lg_sotf.compliance.nis2 import load_case

    svc = service(repos, make_settings)
    first = await add_alert(repos, TENANT_A, fingerprint="fp-ev-1")
    second = await add_alert(repos, TENANT_A, fingerprint="fp-ev-2")
    await sight(repos, TENANT_A, first, [("ip", "185.220.101.45")])
    await sight(repos, TENANT_A, second, [("ip", "185.220.101.45")])
    parent = await escalate(svc, TENANT_A, first)
    child = await escalate(svc, TENANT_A, second)
    assert child.attached and child.id == parent.id

    # The repository only widens the match when asked.
    assert (await repos.escalations.list(TENANT_A, alert_id=second)).items == []
    attached = await repos.escalations.list(TENANT_A, alert_id=second, include_attached=True)
    assert [e.id for e in attached.items] == [parent.id]

    pack = await build_evidence_pack(repos, make_settings(), TENANT_A, second, generated_by={"type": "test"})
    assert [e["id"] for e in pack["escalations"]] == [parent.id]
    assert second in pack["correlation"]["escalation_related_alert_ids"]
    case = await load_case(repos, TENANT_A, second)
    assert [e.id for e in case.escalations] == [parent.id]
