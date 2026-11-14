"""Decision policy v3 safety net (FIX-3, AI-E3.15): a threat a model judged links the alerts the models closed
alone, and one a person confirmed reopens them.

Through the real workflow and database. The model-judged paths of the engine
(an escalation a model judged a threat, a response plan and a malicious close
with no analyst behind them) link the tenant's model-closed alerts that share
a host, user or IP and closed in the previous 24 hours: they are attached to
the threat's open case, audited ``alert.linked`` and otherwise untouched. An
analyst's ``true_positive`` reopens them, the ones linked earlier included,
audited ``alert.reopened``. Both are idempotent, tenant-scoped and counted
when they fail. A reopened alert never closes on the models' word again.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core import retro_reopen
from lg_sotf.core.graph import initial_state
from lg_sotf.core.retro_reopen import (
    LINK_ACTION,
    REOPEN_ACTION,
    link_related_model_closes,
    reopen_counted,
    reopen_related_model_closes,
)
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.domain import closure
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.observability.metrics import RETRO_LINKED, RETRO_REOPEN_FAILURES, RETRO_REOPENED
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import analyst, decide, suspicious_alert, threat_alert

pytestmark = pytest.mark.integration

ACTOR = Actor("system", "test")


async def model_closed(repos: Repositories, entities: Dict[str, List[str]], tenant_id: str = TENANT_A,
                       closed_at: datetime | None = None) -> str:
    """An alert the models closed alone (``model_closed``, close reason ``ai_closed:audit_required``)."""
    alert_id = await make_alert(repos, tenant_id, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(tenant_id, alert_id, status, now=closed_at)
    await repos.alerts.update(tenant_id, alert_id, disposition="benign",
                              summary={"close_reason": closure.MODEL_CLOSE_REASON})
    return alert_id


async def reopened(repos: Repositories, alert_id: str, mode: str, tenant_id: str = TENANT_A) -> bool:
    """Folded into an open case (``waiting_human``, no new run) or, without one, queued for its own review run."""
    alert = await repos.alerts.get(tenant_id, alert_id)
    marker = alert.summary.get("reopened") or {}
    status = "waiting_human" if mode == "folded" else "queued"
    return (alert.status, marker.get("reason"), marker.get("mode"), alert.disposition) == (
        status, "related_threat", mode, None)


async def linked(repos: Repositories, alert_id: str, threat: str, case: Optional[str]) -> bool:
    """Linked to the threat and its case, and otherwise exactly as the models closed it: closed, benign, still
    marked for audit, not reopened, no run."""
    alert = await repos.alerts.get(TENANT_A, alert_id)
    links = [(link["threat_alert_id"], link["escalation_id"]) for link in alert.summary.get("linked") or []]
    with pytest.raises(NotFound):  # these alerts were closed without a run in this file: linking starts none
        await repos.runs.get(TENANT_A, alert_id)
    return (alert.status, alert.disposition, alert.summary["close_reason"], alert.summary.get("reopened"), links) == (
        "closed", "benign", closure.MODEL_CLOSE_REASON, None, [(threat, case)])


async def audited(repos: Repositories, action: str) -> List[str]:
    return sorted(e.resource_id for e in (await repos.audit.list(TENANT_A, action=action)).items)


async def test_an_escalation_the_models_only_found_suspicious_reopens_nothing(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """FIX-4: the fast tier's ``suspicious`` with an inconclusive deep verdict is a doubt, not a threat. It does
    not block a model close (policy v3), so it does not touch one either: the alert goes to an analyst, and only
    the analyst's ``true_positive`` reopens the related closes."""
    same_host = await model_closed(repos, {"hosts": ["ws-042"]})
    doubt = await suspicious_alert(repos)
    outcome = await engine.run(TENANT_A, doubt)
    assert outcome.status == "waiting_human"
    summary = (await repos.alerts.get(TENANT_A, doubt)).summary
    assert summary["triage"]["threat_assessment"] == "suspicious"
    assert (summary.get("analysis") or {}).get("verdict") != "malicious"
    assert not retro_reopen.judged_threat(summary["triage"], summary.get("analysis") or {})
    closed = await repos.alerts.get(TENANT_A, same_host)
    assert (closed.status, closed.summary.get("reopened"), closed.summary.get("linked")) == ("closed", None, None)


async def test_an_escalation_a_model_judged_a_threat_links_related_model_closes_and_reopens_nothing(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """AI-E3.15: a model's judgement is not a confirmation. The related model closes are shown in the threat's
    case and stay closed; the analyst's ``true_positive`` on that case reopens them."""
    same_host = await model_closed(repos, {"hosts": ["ws-042"]})
    same_user = await model_closed(repos, {"users": ["jdoe"]})
    same_ip = await model_closed(repos, {"ips": ["185.220.101.44"]})
    related = sorted([same_host, same_user, same_ip])
    unrelated = await model_closed(repos, {"hosts": ["db-01"]})
    stale = await model_closed(repos, {"hosts": ["ws-042"]}, closed_at=datetime.now(UTC) - timedelta(hours=25))
    other_tenant = await model_closed(repos, {"hosts": ["ws-042"]}, tenant_id=TENANT_B)

    threat = await threat_alert(repos)
    before = RETRO_LINKED.labels(path="escalation")._value.get()
    outcome = await engine.run(TENANT_A, threat)
    assert outcome.status == "waiting_human"
    stored = await repos.alerts.get(TENANT_A, threat)
    assert retro_reopen.judged_threat(stored.summary["triage"], stored.summary.get("analysis") or {})

    case = outcome.interrupt["escalation_id"]
    for alert_id in related:
        assert await linked(repos, alert_id, threat, case), alert_id
        assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is None  # no case of its own
    for alert_id, tenant in ((unrelated, TENANT_A), (stale, TENANT_A), (other_tenant, TENANT_B)):
        alert = await repos.alerts.get(tenant, alert_id)
        assert (alert.status, alert.disposition, alert.summary.get("linked")) == ("closed", "benign", None), alert_id
    assert sorted((await repos.escalations.get(TENANT_A, case)).related_alert_ids) == related  # the analyst sees them
    assert sorted(stored.summary["linked_alert_ids"]) == related
    assert await audited(repos, LINK_ACTION) == related and await audited(repos, REOPEN_ACTION) == []
    entry = (await repos.audit.list(TENANT_A, action=LINK_ACTION)).items[0]
    assert (entry.details["reason"], entry.details["threat_alert_id"], entry.details["escalation_id"]) == (
        "related_threat", threat, case)
    events = (await repos.alert_events.list_for_alert(TENANT_A, same_host)).items
    assert [e.event_type for e in events if e.event_type in (LINK_ACTION, REOPEN_ACTION)] == [LINK_ACTION]
    assert RETRO_LINKED.labels(path="escalation")._value.get() == before + 3

    # Idempotent: linking again for the same threat and case changes and audits nothing.
    assert await link_related_model_closes(repos, TENANT_A, stored, actor=ACTOR, escalation_id=case) == []
    assert await audited(repos, LINK_ACTION) == related

    # The analyst confirms the threat: the run's response plan reopens what was linked (the case is decided, so
    # each one is queued for its own review). What was never linked (unrelated, too old) stays closed.
    planned = await decide(engine, repos, threat, case, "true_positive", await analyst(repos))
    assert planned.status == "waiting_approval"
    for alert_id in related:
        assert await reopened(repos, alert_id, "requeued"), alert_id
    assert await audited(repos, REOPEN_ACTION) == related
    for alert_id in (unrelated, stale):
        assert (await repos.alerts.get(TENANT_A, alert_id)).status == "closed"

    # Should a reopened alert run again, it never closes on the models' word.
    state = initial_state(TENANT_A, await repos.alerts.get(TENANT_A, same_host))
    assert state["alert"]["reopened"] == {"reason": "related_threat"}
    assert "reopened" in closure.model_close_blockers(state, tier=closure.MODEL_CLOSE_TIER)


async def test_a_response_plan_and_a_malicious_close_on_the_models_word_link_and_reopen_nothing(
    engine_factory: Any, engine_settings: Settings, repos: Repositories
) -> None:
    """AI-E3.15: the workflow proposes a response and closes the alert malicious with no analyst behind either.
    The related model close is linked (there is no case to show it in) and stays closed."""
    settings = engine_settings.model_copy(update={"routing": {**dict(engine_settings.routing or {}), "response_threshold": 0}})
    engine = await engine_factory(settings=settings)
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    closed_alert = await model_closed(repos, {"ips": ["185.220.101.44"]})
    threat = await make_alert(repos, TENANT_A, title="Unusual outbound traffic volume", severity="medium",
                              normalized={"entities": {"ips": ["185.220.101.44"]}})

    outcome = await engine.run(TENANT_A, threat)

    stored = await repos.alerts.get(TENANT_A, threat)
    assert stored.summary["response"]["threat_type"]  # a response was planned
    assert outcome.status == "completed" and stored.summary["close_reason"] == "policy:response"
    assert stored.summary.get("analyst_decision") is None and stored.summary["linked_alert_ids"] == [closed_alert]
    assert await linked(repos, closed_alert, threat, None)
    assert await audited(repos, LINK_ACTION) == [closed_alert] and await audited(repos, REOPEN_ACTION) == []


async def test_an_analysts_true_positive_reopens_at_the_response_plan_and_at_the_malicious_close(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """After the analyst's ``true_positive`` the plan_response path and the malicious-close path each reopen what
    closed since the previous one: a person stands behind the threat."""
    threat = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, threat)
    assert first.status == "waiting_human"

    before_plan = await model_closed(repos, {"hosts": ["ws-042"]})
    second = await decide(engine, repos, threat, first.interrupt["escalation_id"], "true_positive", user_id)
    assert second.status == "waiting_approval"
    assert await reopened(repos, before_plan, "requeued")  # plan_response: the case is decided, nothing to fold into

    before_close = await model_closed(repos, {"users": ["jdoe"]})
    done = await engine.resume(
        TENANT_A, threat,
        {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": user_id,
         "reject_remaining": True},
    )
    assert done.status == "completed"
    assert (await repos.alerts.get(TENANT_A, threat)).disposition == "malicious"
    assert await reopened(repos, before_close, "requeued")  # the malicious close
    assert await audited(repos, LINK_ACTION) == []


async def test_a_confirmed_threat_reopens_what_was_linked_earlier_however_long_ago(repos: Repositories) -> None:
    """AI-E3.15: an analyst may confirm days after the link. The alerts linked to the threat, and those linked
    into its case by another alert of that case, reopen although they left the 24-hour window."""
    by_threat = await model_closed(repos, {"hosts": ["ws-042"]})
    threat = await repos.alerts.get(TENANT_A, await suspicious_alert(repos))
    assert await link_related_model_closes(repos, TENANT_A, threat, actor=ACTOR) == [by_threat]  # no case yet
    later = datetime.now(UTC) + timedelta(days=3)
    # Control: by its entities alone the alert is out of reach by then (``threat`` was read before the link).
    assert await reopen_related_model_closes(repos, TENANT_A, threat, actor=ACTOR, now=later) == []
    threat = await repos.alerts.get(TENANT_A, threat.id)
    assert await reopen_related_model_closes(repos, TENANT_A, threat, actor=ACTOR, now=later) == [by_threat]
    assert await reopened(repos, by_threat, "requeued")

    # A grouped case: the parent alert shares nothing with the model close, an attached alert linked it.
    in_case = await model_closed(repos, {"hosts": ["db-01"]})
    parent = await repos.alerts.get(TENANT_A, await make_alert(repos, TENANT_A, title="Beacon", severity="medium"))
    case, _ = await repos.escalations.create_or_attach(
        TENANT_A, parent.id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    attached = await repos.alerts.get(
        TENANT_A, await make_alert(repos, TENANT_A, title="Lateral movement", normalized={"entities": {"hosts": ["db-01"]}})
    )
    assert await link_related_model_closes(repos, TENANT_A, attached, actor=ACTOR, escalation_id=case.id) == [in_case]
    assert await reopen_related_model_closes(
        repos, TENANT_A, parent, actor=ACTOR, escalation_id=case.id, now=later
    ) == [in_case]
    assert await reopened(repos, in_case, "folded")  # the case is still open: folded into it, where it already was
    assert (await repos.escalations.get(TENANT_A, case.id)).related_alert_ids == [in_case]


async def test_a_later_case_of_the_threat_shows_what_it_linked_before(repos: Repositories) -> None:
    """AI-E3.15: the threat linked at its response plan, before it had a case. When its case opens, even after the
    alert left the 24-hour window, the alert is shown there: one link per threat, linked again only for a new case.
    An alert the retention purge removed since is skipped, by the link and by the reopen."""
    closed_alert = await model_closed(repos, {"hosts": ["ws-042"]})
    threat = await repos.alerts.get(TENANT_A, await suspicious_alert(repos))
    assert await link_related_model_closes(repos, TENANT_A, threat, actor=ACTOR) == [closed_alert]
    assert await linked(repos, closed_alert, threat.id, None)
    await repos.alerts.update(TENANT_A, threat.id, summary={"linked_alert_ids": ["purged-since", closed_alert]})
    case, _ = await repos.escalations.create_or_attach(
        TENANT_A, threat.id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    later = datetime.now(UTC) + timedelta(days=3)

    for expected in ([closed_alert], []):  # the second call finds it linked to this threat and case already
        assert await link_related_model_closes(
            repos, TENANT_A, threat, actor=ACTOR, escalation_id=case.id, now=later
        ) == expected
    assert await linked(repos, closed_alert, threat.id, case.id)
    assert (await repos.escalations.get(TENANT_A, case.id)).related_alert_ids == [closed_alert]
    assert await audited(repos, LINK_ACTION) == [closed_alert, closed_alert]  # without a case, then into the case

    threat = await repos.alerts.get(TENANT_A, threat.id)
    assert await reopen_related_model_closes(
        repos, TENANT_A, threat, actor=ACTOR, escalation_id=case.id, now=later
    ) == [closed_alert]


async def test_a_benign_decision_on_the_case_leaves_a_linked_alert_closed_by_the_models(
    engine: WorkflowEngine, repos: Repositories, redis_client: Any
) -> None:
    """AI-E3.15: the analyst judged the threat alert, not the linked one. The linked alert stays closed by the
    models and marked for audit; it is not analyst-confirmed benign and teaches the verdict cache nothing."""
    linked_alert = await model_closed(repos, {"hosts": ["ws-042"], "processes": ["dpkg"]})  # its own verdict key
    threat = await threat_alert(repos)
    outcome = await engine.run(TENANT_A, threat)
    case = outcome.interrupt["escalation_id"]
    assert await linked(repos, linked_alert, threat, case)
    user_id = await analyst(repos)

    done = await decide(engine, repos, threat, case, "false_positive", user_id)
    assert done.alert_status == "closed"
    # Should the decision's resume message reach the linked alert all the same, it changes nothing.
    await engine.resume(TENANT_A, linked_alert, {"type": "analyst_decision", "escalation_id": case,
                                                 "decision": "false_positive", "approved_actions": [],
                                                 "decided_by": user_id, "notes": ""})

    assert await linked(repos, linked_alert, threat, case)
    alert = await repos.alerts.get(TENANT_A, linked_alert)
    assert alert.summary.get("analyst_decision") is None
    keys = engine.node_deps.verdicts
    learned = await redis_client.exists(keys.key(TENANT_A, str(verdict_key_of(await repos.alerts.get(TENANT_A, threat)))))
    assert learned == 1  # the control: the decided alert's key is cached
    assert verdict_key_of(alert) and await redis_client.exists(keys.key(TENANT_A, str(verdict_key_of(alert)))) == 0
    assert await audited(repos, "alert.folded_settled") == [] and await audited(repos, REOPEN_ACTION) == []


async def test_a_benign_escalation_reopens_nothing(engine: WorkflowEngine, repos: Repositories) -> None:
    closed_alert = await model_closed(repos, {"hosts": ["build-7"]})
    quiet = await make_alert(repos, TENANT_A, title="Authorized approved expected patch healthcheck",
                             severity="low", normalized={"entities": {"hosts": ["build-7"]}})
    await engine.run(TENANT_A, quiet)
    alert = await repos.alerts.get(TENANT_A, closed_alert)
    assert (alert.status, alert.disposition, alert.summary.get("linked")) == ("closed", "benign", None)


@pytest.mark.parametrize("confirmed", [True, False])
async def test_a_reopen_or_link_failure_is_counted_not_swallowed(
    repos: Repositories, monkeypatch: pytest.MonkeyPatch, confirmed: bool
) -> None:
    await model_closed(repos, {"hosts": ["ws-042"]})
    threat = await repos.alerts.get(TENANT_A, await suspicious_alert(repos))

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database went away")

    monkeypatch.setattr(repos.alerts, "model_closed_sharing_entities", broken)
    before = RETRO_REOPEN_FAILURES.labels(path="workflow")._value.get()
    assert await reopen_counted(repos, TENANT_A, threat, actor=ACTOR, path="workflow", confirmed=confirmed) == []
    assert RETRO_REOPEN_FAILURES.labels(path="workflow")._value.get() == before + 1


async def test_the_safety_net_counts_a_link_and_a_reopen_apart(repos: Repositories) -> None:
    closed_alert = await model_closed(repos, {"hosts": ["ws-042"]})
    threat = await repos.alerts.get(TENANT_A, await suspicious_alert(repos))
    counters = [RETRO_LINKED.labels(path="workflow"), RETRO_REOPENED.labels(path="workflow")]
    before = [c._value.get() for c in counters]
    assert await reopen_counted(repos, TENANT_A, threat, actor=ACTOR, path="workflow", confirmed=False) == []
    assert [c._value.get() for c in counters] == [before[0] + 1, before[1]]
    assert await reopen_counted(repos, TENANT_A, threat, actor=ACTOR, path="workflow", confirmed=True) == [closed_alert]
    assert [c._value.get() for c in counters] == [before[0] + 1, before[1] + 1]
