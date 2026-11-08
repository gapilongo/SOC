"""ReviewService against Postgres: claim/decide locking, resumes for grouped alerts, role vs risk, approvals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, Tuple
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.errors import Conflict, InvalidTransition, NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.response import ResponseService
from lg_sotf.services.review import ReviewDenied, ReviewError, ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.services._support import add_alert, sight
from tests.unit.services.fakes import FakeEvents

pytestmark = pytest.mark.integration


async def user(repos: Repositories, role: str, tenant: str = TENANT_A) -> UUID:
    return (await repos.users.create(tenant, f"{role}-{uuid4().hex[:8]}@example.com", role)).id


PARENT_ENTITIES = {"ips": ["185.220.101.44"], "hosts": ["ws-042"], "users": ["jdoe"]}
ATTACHED_ENTITIES = {"ips": ["185.220.101.44"], "hosts": ["srv-db-prod"], "users": ["jdoe"]}


async def grouped_escalation(
    repos: Repositories, settings: Settings, *, parent_fp: str | None = None, attached_fp: str | None = None,
    attached_severity: str = "high",
) -> Tuple[str, str, str]:
    """Two related alerts in one escalation: (escalation id, parent alert, attached alert)."""
    svc = EscalationService(repos, None, settings)
    first = await add_alert(repos, TENANT_A, fingerprint=parent_fp, entities=PARENT_ENTITIES)
    second = await add_alert(repos, TENANT_A, fingerprint=attached_fp, severity=attached_severity, entities=ATTACHED_ENTITIES)
    for alert_id in (first, second):
        await sight(repos, TENANT_A, alert_id, [("ip", "185.220.101.44")])
    kw: Dict[str, Any] = dict(severity="high", confidence=50, threat_score=40, reason="grey zone")
    parent = await svc.open_or_attach(TENANT_A, first, **kw)
    child = await svc.open_or_attach(TENANT_A, second, **kw)
    assert child.attached and child.id == parent.id
    return parent.id, first, second


async def test_claim_uses_optimistic_locking_and_respects_other_claims(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    events = FakeEvents()
    review = ReviewService(repos, settings, events)
    esc_id, first, second = await grouped_escalation(repos, settings)
    alice, bob, boss, viewer = [await user(repos, r) for r in ("analyst", "analyst", "admin", "viewer")]

    current = await repos.escalations.get(TENANT_A, esc_id)
    with pytest.raises(ReviewDenied):
        await review.claim(TENANT_A, esc_id, viewer, current.version, role="viewer")
    claimed = await review.claim(TENANT_A, esc_id, alice, current.version)
    assert claimed.status == "claimed" and claimed.assigned_to == alice and claimed.version == current.version + 1
    with pytest.raises(Conflict):
        await review.claim(TENANT_A, esc_id, alice, current.version)  # stale version
    with pytest.raises(ReviewDenied):
        await review.claim(TENANT_A, esc_id, bob, claimed.version)  # claimed by alice
    taken = await review.claim(TENANT_A, esc_id, boss, claimed.version, role="admin")
    assert taken.assigned_to == boss
    audits = [e.action for e in (await repos.audit.list(TENANT_A, resource_id=esc_id)).items]
    assert "escalation.claimed" in audits and "escalation.reassigned" in audits
    claim_events = [e for e in events.events if e["type"] == "escalation.updated"]
    assert {e["alert_id"] for e in claim_events} == {first, second}
    with pytest.raises(ReviewError):
        await review.claim(TENANT_A, esc_id, "not-a-uuid", taken.version)


async def test_decision_resumes_every_grouped_alert(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    esc_id, first, second = await grouped_escalation(repos, settings)
    analyst = await user(repos, "analyst")
    esc = await repos.escalations.get(TENANT_A, esc_id)

    with pytest.raises(Conflict):
        await review.decide(TENANT_A, esc_id, analyst, "analyst", "true_positive", "", [], esc.version - 1)
    with pytest.raises(ReviewDenied):
        await review.decide(TENANT_A, esc_id, analyst, "analyst", "true_positive", "", ["isolate_host"], esc.version)
    with pytest.raises(ReviewError):
        await review.decide(TENANT_A, esc_id, analyst, "analyst", "false_positive", "", ["block_ip"], esc.version)
    with pytest.raises(ReviewError):
        await review.decide(TENANT_A, esc_id, analyst, "analyst", "maybe", "", [], esc.version)
    with pytest.raises(ReviewDenied):
        await review.decide(TENANT_A, esc_id, analyst, "viewer", "true_positive", "", [], esc.version)

    result = await review.decide(
        TENANT_A, esc_id, analyst, "analyst", "true_positive", "confirmed on host", ["block_ip"], esc.version,
        feedback={"triage_correct": True, "confidence": 90},
    )
    assert [r.alert_id for r in result] == [first, second]
    for alert_id, payload in result:
        assert payload == {
            "type": "analyst_decision", "escalation_id": esc_id, "decision": "true_positive",
            # Resolved against the reviewed alert's targets; attached alerts get no pre-approvals.
            "approved_actions": ["block_ip:185.220.101.44"] if alert_id == first else [],
            "decided_by": str(analyst), "notes": "confirmed on host", "approver_role": "analyst",
        }
    assert result.approved_actions == ["block_ip:185.220.101.44"] and result.own_review_alert_ids == []
    decided = await repos.escalations.get(TENANT_A, esc_id)
    assert decided.status == "decided" and decided.decided_by == analyst
    assert decided.approved_actions == ["block_ip:185.220.101.44"]
    feedback = await repos.feedback.get_for_escalation(TENANT_A, esc_id)
    assert feedback is not None and feedback.id == result.feedback_id
    assert feedback.triage_correct is True and feedback.confidence == 90 and feedback.review_duration_s is not None
    assert result.suppression_suggestion_id is None
    # A second decision on the same escalation is refused (no longer active).
    with pytest.raises(InvalidTransition):
        await review.decide(TENANT_A, esc_id, analyst, "analyst", "false_positive", "", [], decided.version)
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_false_positive_creates_a_disabled_suppression_suggestion(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings)
    alert_id = await add_alert(repos, TENANT_A, fingerprint="fp-noisy-scanner", title="Nightly scanner", severity="medium")
    ticket = await EscalationService(repos, None, settings).open_or_attach(
        TENANT_A, alert_id, severity="medium", confidence=50, threat_score=20, reason="review"
    )
    analyst = await user(repos, "analyst")
    result = await review.decide(TENANT_A, ticket.id, analyst, "analyst", "false_positive", "scanner", [], ticket.version)
    rule = await repos.suppressions.get(TENANT_A, result.suppression_suggestion_id or "")
    assert rule.enabled is False and rule.match == {
        "fingerprint": "fp-noisy-scanner",
        "source_id": "api",
        "severity": {"in": ["info", "low", "medium"]},
    }
    # LLM-W6-05: once enabled, the suggestion never suppresses a more severe alert of that detection.
    from lg_sotf.domain.suppression import alert_match_view, first_matching_rule

    enabled = await repos.suppressions.update(TENANT_A, rule.id, enabled=True)
    for severity, expected in (("medium", True), ("low", True), ("high", False), ("critical", False)):
        view = alert_match_view(
            title="Nightly scanner", severity=severity, category=None, source_id="api",
            source_alert_id="x", fingerprint="fp-noisy-scanner", normalized={},
        )
        assert (first_matching_rule([enabled], view) is not None) is expected, severity
    await repos.suppressions.update(TENANT_A, rule.id, enabled=False)
    assert rule.source_feedback_id == result.feedback_id and rule.created_by == analyst
    assert rule.expires_at is not None
    assert await repos.suppressions.list_active(TENANT_A) == []

    # Tenants can switch suggestions off.
    await repos.tenants.update_settings(TENANT_A, {"review": {"suggest_suppressions": False}})
    other = await add_alert(repos, TENANT_A)
    t2 = await EscalationService(repos, None, settings).open_or_attach(
        TENANT_A, other, severity="medium", confidence=50, threat_score=20, reason="review"
    )
    r2 = await review.decide(TENANT_A, t2.id, analyst, "analyst", "false_positive", None, [], t2.version)
    assert r2.suppression_suggestion_id is None


TARGETS = {
    "block_ip": "185.220.101.44",
    "block_domain": "evil.example.net",
    "isolate_host": "ws-042",
    "disable_user": "jdoe",
    "create_ticket": "alert:x",
}


async def pending_actions(repos: Repositories, settings: Settings, alert_id: str, risks: Dict[str, str]) -> Dict[str, str]:
    # The alert's run is still live (an approval for an ended run goes to the scheduler instead).
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    ids = {}
    for action_type, risk in risks.items():
        action, _ = await repos.actions.propose(
            TENANT_A, alert_id, action_type, TARGETS[action_type], risk, status="awaiting_approval"
        )
        ids[action_type] = str(action.id)
    return ids


async def test_role_versus_risk_on_approvals(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    alert_id = await add_alert(repos, TENANT_A)
    ids = await pending_actions(
        repos, settings, alert_id, {"block_ip": "medium", "isolate_host": "high", "disable_user": "critical", "create_ticket": "low"}
    )
    analyst, admin = await user(repos, "analyst"), await user(repos, "admin")

    with pytest.raises(ReviewDenied):
        await review.approve_actions(TENANT_A, [ids["isolate_host"]], analyst, "analyst")
    with pytest.raises(ReviewDenied):  # all or nothing: the medium one is not approved either
        await review.approve_actions(TENANT_A, [ids["block_ip"], ids["disable_user"]], admin, "admin")
    assert (await repos.actions.get(TENANT_A, UUID(ids["block_ip"]))).status == "awaiting_approval"
    with pytest.raises(ReviewDenied):
        await review.approve_actions(TENANT_A, [ids["create_ticket"]], analyst, "viewer")

    requests = await review.approve_actions(TENANT_A, [ids["block_ip"]], analyst, "analyst")
    assert requests == [(alert_id, {"type": "approval", "approved_action_ids": [ids["block_ip"]], "rejected_action_ids": [],
                                    "decided_by": str(analyst), "reject_remaining": False})]
    approved = await repos.actions.get(TENANT_A, UUID(ids["block_ip"]))
    assert approved.status == "approved" and approved.approved_by == str(analyst)
    # Partial approval: the others are still pending.
    for name in ("isolate_host", "disable_user", "create_ticket"):
        assert (await repos.actions.get(TENANT_A, UUID(ids[name]))).status == "awaiting_approval"
    # Re-approving is idempotent.
    assert (await review.approve_actions(TENANT_A, [ids["block_ip"]], analyst, "analyst"))[0].payload["approved_action_ids"] == [ids["block_ip"]]

    await review.approve_actions(TENANT_A, [ids["isolate_host"]], admin, "admin")
    assert (await repos.actions.get(TENANT_A, UUID(ids["isolate_host"]))).status == "approved"

    # Critical is approvable by an admin once the tenant policy stops disabling it.
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"critical": "approval"}})
    with pytest.raises(ReviewDenied):
        await review.approve_actions(TENANT_A, [ids["disable_user"]], analyst, "analyst")
    await review.approve_actions(TENANT_A, [ids["disable_user"]], admin, "admin")
    assert (await repos.actions.get(TENANT_A, UUID(ids["disable_user"]))).status == "approved"

    with pytest.raises(NotFound):
        await review.approve_actions(TENANT_A, [str(uuid4())], admin, "admin")
    with pytest.raises(NotFound):  # another tenant's action is invisible
        await review.approve_actions(TENANT_B, [ids["create_ticket"]], admin, "admin")
    with pytest.raises(ReviewError):
        await review.approve_actions(TENANT_A, ["nope"], admin, "admin")
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def test_reject_and_reject_remaining(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    alert_id = await add_alert(repos, TENANT_A)
    ids = await pending_actions(repos, settings, alert_id, {"block_ip": "medium", "block_domain": "medium", "create_ticket": "low", "isolate_host": "high"})
    analyst = await user(repos, "analyst")

    rejected = await review.reject_actions(TENANT_A, [ids["isolate_host"]], analyst, "analyst")
    assert rejected[0].payload["rejected_action_ids"] == [ids["isolate_host"]]
    row = await repos.actions.get(TENANT_A, UUID(ids["isolate_host"]))
    assert row.status == "rejected" and row.blocked_reason == "rejected_by_reviewer"
    assert (await repos.actions.get(TENANT_A, UUID(ids["block_ip"]))).status == "awaiting_approval"

    requests = await review.approve_actions(TENANT_A, [ids["block_ip"]], analyst, "analyst", reject_remaining=True)
    payload = requests[0].payload
    assert payload["reject_remaining"] is True and payload["approved_action_ids"] == [ids["block_ip"]]
    assert sorted(payload["rejected_action_ids"]) == sorted([ids["block_domain"], ids["create_ticket"]])
    statuses = {n: (await repos.actions.get(TENANT_A, UUID(i))).status for n, i in ids.items()}
    assert statuses == {"block_ip": "approved", "block_domain": "rejected", "create_ticket": "rejected", "isolate_host": "rejected"}
    with pytest.raises(InvalidTransition):
        await review.approve_actions(TENANT_A, [ids["block_domain"]], analyst, "analyst")


async def test_review_payloads_drive_the_node_semantics(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    """The node applies a ReviewService payload as a no-op for already-decided actions and keeps the rest pending."""
    settings = make_settings()
    responses = ResponseService(repos, settings)
    review = ReviewService(repos, settings, responses=responses)
    alert_id = await add_alert(repos, TENANT_A)
    ids = await pending_actions(repos, settings, alert_id, {"block_ip": "medium", "block_domain": "medium"})
    analyst = await user(repos, "analyst")
    (request,) = await review.approve_actions(TENANT_A, [ids["block_ip"]], analyst, "analyst")
    pending = list(ids.values())
    outcome = await responses.apply_approval(
        TENANT_A, alert_id, pending_ids=pending, approved_ids=request.payload["approved_action_ids"],
        rejected_ids=request.payload["rejected_action_ids"], decided_by=request.payload["decided_by"],
        reject_remaining=request.payload["reject_remaining"],
    )
    assert outcome == {ids["block_ip"]: "approved"}
    assert set(await responses.awaiting(TENANT_A, alert_id, pending)) == {ids["block_ip"], ids["block_domain"]}
    executed = await responses.execute(TENANT_A, alert_id, pending)
    assert executed == {ids["block_ip"]: "dry_run", ids["block_domain"]: "awaiting_approval"}
    assert await responses.awaiting(TENANT_A, alert_id, pending) == [ids["block_domain"]]


async def test_type_only_preapproval_never_reaches_attached_alerts(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    """RR-2: an admin approving "isolate_host" for ws-042 must not approve isolating srv-db-prod."""
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    esc_id, first, second = await grouped_escalation(repos, settings)
    admin = await user(repos, "admin")
    esc = await repos.escalations.get(TENANT_A, esc_id)
    result = await review.decide(
        TENANT_A, esc_id, admin, "admin", "true_positive", None,
        ["isolate_host", "create_ticket", "block_domain", "block_ip:45.9.148.3"], esc.version,
    )
    payloads = dict(result)
    assert payloads[first]["approved_actions"] == [
        "isolate_host:ws-042", f"create_ticket:alert:{first}", "block_ip:45.9.148.3"
    ]  # no domain on the alert: nothing to pre-approve for block_domain
    assert payloads[second]["approved_actions"] == []
    assert not any("srv-db-prod" in entry for entry in result.approved_actions)
    audit = [e for e in (await repos.audit.list(TENANT_A, resource_id=esc_id)).items if e.action == "escalation.decided"]
    assert audit[0].details["approved_actions"] == result.approved_actions


async def test_malformed_preapprovals_are_refused(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings)
    esc_id, _, _ = await grouped_escalation(repos, settings)
    analyst = await user(repos, "analyst")
    version = (await repos.escalations.get(TENANT_A, esc_id)).version
    for entries in (["block_ip:"], ["block_ip:" + "1" * 300], ["nuke_everything"]):
        with pytest.raises(ReviewError):
            await review.decide(TENANT_A, esc_id, analyst, "analyst", "true_positive", None, entries, version)
    assert (await repos.escalations.get(TENANT_A, esc_id)).status == "open"


@pytest.mark.parametrize(
    ("attached_fp", "attached_severity", "own_review"),
    [("fp-same", "high", False), ("fp-same", "critical", True), ("fp-other", "high", True)],
)
async def test_benign_decision_reports_attached_alerts_needing_their_own_review(
    repos: Repositories, make_settings: Callable[..., Settings], attached_fp: str, attached_severity: str, own_review: bool
) -> None:
    settings = make_settings()
    review = ReviewService(repos, settings)
    esc_id, _, second = await grouped_escalation(
        repos, settings, parent_fp="fp-same", attached_fp=attached_fp, attached_severity=attached_severity
    )
    analyst = await user(repos, "analyst")
    version = (await repos.escalations.get(TENANT_A, esc_id)).version
    result = await review.decide(TENANT_A, esc_id, analyst, "analyst", "false_positive", "noise", [], version)
    assert result.own_review_alert_ids == ([second] if own_review else [])
    # Both runs are still resumed: the workflow applies the decision scope (and detaches) per alert.
    assert [r.alert_id for r in result][1] == second


async def test_orphaned_executing_actions_are_failed(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    """RR-4: an action left 'executing' by a run that was dead-lettered is settled, a live run's is not."""
    settings = make_settings()
    responses = ResponseService(repos, settings)
    dead, alive = await add_alert(repos, TENANT_A), await add_alert(repos, TENANT_A)
    stuck = {}
    for alert_id in (dead, alive):
        await repos.runs.upsert_queued(TENANT_A, alert_id)
        action, _ = await repos.actions.propose(TENANT_A, alert_id, "block_ip", "185.220.101.44", "medium", status="approved")
        # Started before the grace period (the execution budget plus a minute), so no call can still be running.
        stuck[alert_id] = await repos.actions.transition(
            TENANT_A, action.id, "executing", connector="webhook", now=datetime.now(UTC) - timedelta(minutes=10)
        )
    await repos.runs.dead_letter(TENANT_A, dead, "poison")

    assert await responses.fail_orphaned_executing(TENANT_A) == 1
    failed = await repos.actions.get(TENANT_A, stuck[dead].id)
    assert failed.status == "failed" and failed.result is not None and failed.result["error"] == "orphaned_execution"
    assert (await repos.actions.get(TENANT_A, stuck[alive].id)).status == "executing"
    assert await responses.fail_orphaned_executing() == 0  # all tenants (scheduler): nothing left
    audits = [e.action for e in (await repos.audit.list(TENANT_A, resource_id=str(stuck[dead].id))).items]
    assert audits == ["response_action.failed"]


async def test_expired_escalations_take_a_late_decision_once(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    """The SLA sweep expires an L3 escalation but the run still waits on it: the decision must be recordable."""
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    svc = EscalationService(repos, None, settings)
    kw: Dict[str, Any] = dict(severity="critical", confidence=50, threat_score=90, reason="grey zone")
    expired_id = (await svc.open_or_attach(TENANT_A, await add_alert(repos, TENANT_A), **kw)).id
    cancelled_id = (await svc.open_or_attach(TENANT_A, await add_alert(repos, TENANT_A), **kw)).id
    expired = await repos.escalations.expire(TENANT_A, expired_id)
    await repos.escalations.cancel(TENANT_A, cancelled_id)
    analyst = await user(repos, "analyst")

    with pytest.raises(Conflict):
        await review.decide(TENANT_A, expired_id, analyst, "analyst", "true_positive", None, [], expired.version + 1)
    with pytest.raises(NotFound):
        await review.decide(TENANT_B, expired_id, analyst, "analyst", "true_positive", None, [], expired.version)
    result = await review.decide(TENANT_A, expired_id, analyst, "analyst", "true_positive", "late", [], expired.version)
    esc = result.escalation
    assert (esc.status, esc.decision, esc.decided_by, esc.version) == ("decided", "true_positive", analyst, expired.version + 1)
    assert [r.payload["escalation_id"] for r in result] == [expired_id]
    with pytest.raises(InvalidTransition):
        await review.decide(TENANT_A, expired_id, analyst, "analyst", "false_positive", None, [], esc.version)
    cancelled = await repos.escalations.get(TENANT_A, cancelled_id)
    with pytest.raises(InvalidTransition):
        await review.decide(TENANT_A, cancelled_id, analyst, "analyst", "false_positive", None, [], cancelled.version)
    audits = [e for e in (await repos.audit.list(TENANT_A, resource_id=expired_id)).items if e.action == "escalation.decided"]
    assert [a.details["after_sla_expiry"] for a in audits] == [True]
    assert await repos.feedback.get_for_escalation(TENANT_A, expired_id) is not None


async def test_an_expired_escalation_can_be_claimed_and_keeps_its_missed_sla(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    """Overdue work needs an owner: claiming an SLA-expired escalation assigns it and leaves it ``expired``."""
    settings = make_settings()
    review = ReviewService(repos, settings, FakeEvents())
    svc = EscalationService(repos, None, settings)
    kw: Dict[str, Any] = dict(severity="critical", confidence=50, threat_score=90, reason="grey zone")
    esc_id = (await svc.open_or_attach(TENANT_A, await add_alert(repos, TENANT_A), **kw)).id
    expired = await repos.escalations.expire(TENANT_A, esc_id)
    alice, bob, boss = [await user(repos, r) for r in ("analyst", "analyst", "admin")]

    claimed = await review.claim(TENANT_A, esc_id, alice, expired.version)
    assert (claimed.status, claimed.assigned_to, claimed.version) == ("expired", alice, expired.version + 1)
    assert claimed.claimed_at is not None
    # The SLA sweep only looks at active escalations: it does not pick the claimed expired one up again.
    breached = await repos.escalations.find_sla_breached_all_tenants(now=datetime.now(UTC) + timedelta(days=365))
    assert esc_id not in {e.id for e in breached}
    [audit] = [e for e in (await repos.audit.list(TENANT_A, resource_id=esc_id)).items if e.action == "escalation.claimed"]
    assert audit.details["after_sla_expiry"] is True
    # Alice now holds it: another analyst may neither take it over nor decide it; an admin may.
    with pytest.raises(ReviewDenied):
        await review.claim(TENANT_A, esc_id, bob, claimed.version)
    with pytest.raises(ReviewDenied):
        await review.decide(TENANT_A, esc_id, bob, "analyst", "false_positive", None, [], claimed.version)
    taken = await review.claim(TENANT_A, esc_id, boss, claimed.version, role="admin")
    assert (taken.status, taken.assigned_to) == ("expired", boss)
    decided = (await review.decide(TENANT_A, esc_id, boss, "admin", "false_positive", None, [], taken.version)).escalation
    # Claiming a decided escalation is a state error, whatever version the caller had: never a version race.
    for version in (decided.version, decided.version - 1):
        with pytest.raises(InvalidTransition):
            await review.claim(TENANT_A, esc_id, alice, version)
