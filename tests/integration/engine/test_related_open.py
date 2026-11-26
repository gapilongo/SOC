"""Related threats and a model-led close (AI-E3.16, #435), through the real workflow and database.

The fake model calls an alert whose text is full of benign words benign at both
tiers, so at the tier ``auto_full_audit`` it closes on the models' word
(``tests/integration/engine/test_model_closure.py``). Here the tenant's
database also holds another alert on the same host or user
(``lg_sotf.domain.related``).

* **Held.** The close is withheld when the other alert is hold grade (high or
  critical and judged a threat by a model, or confirmed by a person; never
  for a response that only waits for an approval) and open, for up to seven days; also while a high
  or critical alert on the same host is being processed. The held alert goes
  through the ordinary escalation path.
* **Linked forward.** A low or medium threat only a model stands behind holds
  nothing: the alert closes and is linked to that threat's case at once.
* **Reopened.** The other order of arrival: the alert closes first, then a
  related alert reaches hold grade and reopens it into its case.
* **Neither.** A doubt, a failed or stale alert, another host and user, a
  queued alert, another tenant.
* **Unchecked.** A read that fails, or too many open threats to compare:
  the alert goes to an analyst and the run goes on.

The last tests replay the demo's attack chain (``scripts/demo/alerts.json``)
with a model that calls the beacon benign for looking like test data, as the
real model did in #435, in both orders of processing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List
from uuid import UUID

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core import nodes, retro_reopen
from lg_sotf.core.retro_reopen import related_open, reopen_counted
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.llm import fake
from lg_sotf.services.blind_audit import BlindAuditService
from lg_sotf.services.escalation import EscalationService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._related import (
    BEACON,
    HOST,
    MODEL_CLOSE,
    NOTHING,
    USER,
    decided,
    links,
    other,
    persuaded,
    routine,
    seed_demo,
    store_chain,
    tier_on,
)
from tests.integration.engine._support import analyst, decide, threat_alert

pytestmark = pytest.mark.integration

# ------------------------------------------------------------------ held


@pytest.mark.parametrize(
    ("status", "state", "shared"),
    [
        # High or critical, and a model judged it a threat.
        ("waiting_human", {"verdict": "malicious"}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "likely_threat"}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "confirmed_threat", "severity": "critical"}, {"users": [USER]}),
        ("processing", {"assessment": "likely_threat"}, {"users": [USER]}),
        ("queued", {"verdict": "malicious"}, {"hosts": [HOST]}),  # requeued with a verdict a model already gave
        # The same host and user under another spelling (short name, FQDN with a trailing dot, domain prefix, UPN).
        ("waiting_human", {"verdict": "malicious"}, {"hosts": ["WS-FIN-0142.corp.example.com."]}),
        ("waiting_human", {"verdict": "malicious"}, {"users": ["CORP\\JSmith"]}),
        ("waiting_human", {"verdict": "malicious"}, {"users": ["jsmith@corp.example.com"]}),
        # It holds for as long as it is open, up to seven days from its ingestion.
        ("waiting_human", {"verdict": "malicious", "ingested_at": datetime.now(UTC) - timedelta(days=6)}, {"hosts": [HOST]}),
        # Waiting for a response approval and hold grade for its own reason: high and judged a threat by a model.
        ("waiting_approval", {"verdict": "malicious", "planned": True}, {"hosts": [HOST]}),
        # Confirmed by a person: an analyst's true positive on its case, although the models called it benign;
        # also for 24 hours after that decision closed it.
        ("processing", {"true_positive": True, "severity": "medium", "verdict": "benign"}, {"hosts": [HOST]}),
        ("waiting_approval", {"true_positive": True, "severity": "low"}, {"users": [USER]}),
        ("closed", {"true_positive": True, "severity": "medium"}, {"hosts": [HOST]}),
    ],
)
async def test_a_hold_grade_threat_on_the_same_host_or_user_holds_the_close(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any], shared: Dict[str, List[str]]
) -> None:
    """The threat is there before the close and is a strong enough signal: the alert the models call benign goes
    to a person, through the ordinary escalation path, with the reason."""
    await tier_on(repos)
    threat = await other(repos, status, hosts=shared.get("hosts", ["dc-01"]), users=shared.get("users", ()), **state)
    alert_id = await routine(repos, "held", severity="high", users=[USER, "root"])

    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("waiting_human", None)
    assert alert.summary["analysis"]["verdict"] == "benign" and alert.summary["triage"]["threat_assessment"] == "benign"
    assert alert.summary["related_open"] == {"threats": [threat], "in_progress": [], "model_only": []}
    event = await decided(repos, alert_id)
    assert (event["route"], event["code"], event["autonomy_tier"]) == ("escalate", "related_open_threat", "auto_full_audit")
    assert "related open threat on the same host" in event["reason"]
    assert event["related_open_threats"] == [threat] and event["related_in_progress"] == []
    escalation = await repos.escalations.get(TENANT_A, alert.summary["escalation_id"])
    assert escalation.alert_id == alert_id and alert.summary["escalation_attached"] is False
    assert escalation.summary["routing"]["code"] == "related_open_threat"
    assert "related open threat on the same host" in escalation.reason


@pytest.mark.parametrize("severity", ["high", "critical"])
async def test_a_serious_alert_being_processed_on_the_same_host_holds_the_close(
    engine: WorkflowEngine, repos: Repositories, severity: str
) -> None:
    """The same moment: nothing is decided yet about a high or critical alert on the host, so the models do not
    close this one before it is."""
    await tier_on(repos)
    running = await other(repos, "processing", severity=severity, hosts=["WS-FIN-0142.corp.example.com"], idle_minutes=14)
    alert_id = await routine(repos, "same-moment")

    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.summary["related_open"] == {"threats": [], "in_progress": [running], "model_only": []}
    event = await decided(repos, alert_id)
    assert event["code"] == "related_in_progress" and "still being processed" in event["reason"]
    assert event["related_in_progress"] == [running]
    assert (await repos.escalations.get(TENANT_A, alert.summary["escalation_id"])).priority >= 1


async def test_a_held_alert_takes_the_ordinary_escalation_path(engine: WorkflowEngine, repos: Repositories) -> None:
    """Review of #442, findings 1 and 5: no custom join. An alert held by a threat with an open case is another
    detection, so the ordinary grouping gives it an escalation of its own; a decision on the threat's case does
    not touch it, and a true positive there does not turn it into a confirmed threat."""
    await tier_on(repos)
    threat = await threat_alert(repos)  # high, on ws-042; the fast tier calls it likely_threat and it is escalated
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]

    held_id = await routine(repos, "held-by-a-case", hosts=["ws-042"])
    waiting = await engine.run(TENANT_A, held_id)
    held = await repos.alerts.get(TENANT_A, held_id)
    own = await repos.escalations.get_active_for_alert(TENANT_A, held_id)
    assert waiting.status == "waiting_human" and (await decided(repos, held_id))["code"] == "related_open_threat"
    assert own is not None and own.id != case and waiting.interrupt["escalation_id"] == own.id
    assert held.summary["related_open"]["threats"] == [threat] and held.summary["escalation_attached"] is False
    assert held_id not in (await repos.escalations.get(TENANT_A, case)).related_alert_ids

    await decide(engine, repos, threat, case, "true_positive", await analyst(repos))
    after = await repos.alerts.get(TENANT_A, held_id)
    assert (after.status, after.disposition) == ("waiting_human", None)
    assert "response" not in after.summary and "analyst_decision" not in after.summary
    assert (await repos.escalations.get(TENANT_A, own.id)).status == "open"


async def test_a_blind_audit_malicious_label_holds_the_close_while_its_case_is_open(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    """Confirmed by a person: an analyst labelled an AI-closed alert malicious in a blind audit. That alert stays
    closed until the escalation the label opened is decided; meanwhile it holds closes on its host."""
    await tier_on(repos)
    labelled = await make_alert(repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": {"hosts": [HOST]}})
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(TENANT_A, labelled, status)
    await repos.alerts.update(TENANT_A, labelled, disposition="benign", summary={"close_reason": "ai_closed:audit_required"})
    closed_at = (await repos.alerts.get(TENANT_A, labelled)).closed_at
    assert closed_at is not None
    await repos.blind_audit.create_run(
        TENANT_A, since=closed_at - timedelta(minutes=1), until=datetime.now(UTC), seed=1, sample_rate=None,
        min_sample=0, fixed_size=1, frame_size=1, items=[(labelled, 1, "benign")], trigger="api", created_by="t",
    )
    [item] = (await repos.blind_audit.list_items(TENANT_A)).items
    user = await analyst(repos)
    result = await BlindAuditService(repos, EscalationService(repos, None, engine_settings)).label(
        TENANT_A, item.id, "malicious", notes="beacon", actor=Actor("user", user), user_id=UUID(user)
    )
    assert result.escalation is not None and (await repos.alerts.get(TENANT_A, labelled)).status == "closed"

    alert_id = await routine(repos, "after-the-label")
    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.summary["related_open"] == {"threats": [labelled], "in_progress": [], "model_only": []}
    assert (await decided(repos, alert_id))["code"] == "related_open_threat"


# ------------------------------------------------------------------ linked forward


@pytest.mark.parametrize(
    ("status", "state", "shared"),
    [
        # Low or medium, and only a model stands behind it: the dev run's "web server 400 errors" and "sshd brute force".
        ("waiting_human", {"verdict": "malicious", "severity": "medium", "case": True}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "confirmed_threat", "severity": "low", "case": True}, {"users": ["CORP\\jsmith"]}),
        ("waiting_human", {"assessment": "likely_threat", "severity": "info"}, {"hosts": [HOST]}),  # no case yet
        ("processing", {"assessment": "likely_threat", "severity": "medium"}, {"users": [USER]}),
        # A response plan that ended with an analyst, not with an approval request, and no model verdict of a threat.
        ("waiting_human", {"planned": True, "assessment": "suspicious", "verdict": "inconclusive", "case": True},
         {"hosts": [HOST]}),
        # A response that waits for an approval is still only the model's word, at any severity: the dev run's
        # "Multiple web server 400 error codes", "New user added to the system" and "Integrity checksum changed".
        ("waiting_approval", {"severity": "low", "planned": True}, {"hosts": [HOST]}),
        ("waiting_approval", {"verdict": "inconclusive", "severity": "medium", "planned": True}, {"users": [USER]}),
        ("waiting_approval", {"verdict": "malicious", "severity": "medium", "planned": True}, {"hosts": [HOST]}),
        ("waiting_approval", {"verdict": "inconclusive", "planned": True}, {"hosts": [HOST]}),  # high, not judged a threat
    ],
)
async def test_a_threat_only_a_model_stands_behind_links_the_close_to_its_case(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any], shared: Dict[str, List[str]]
) -> None:
    """A model's own low or medium alarm holds nothing: the alert closes as today and is linked to that alert's
    case at once, with the mechanics of the safety net (``alert.linked``, ``linked``, ``linked_alert_ids``)."""
    await tier_on(repos)
    threat = await other(repos, status, hosts=shared.get("hosts", ["dc-01"]), users=shared.get("users", ()), **state)
    case = (await repos.alerts.get(TENANT_A, threat)).summary.get("escalation_id")
    assert (case is not None) == bool(state.get("case"))
    alert_id = await routine(repos, "linked", users=[USER, "root"])

    assert (await engine.run(TENANT_A, alert_id)).status == "completed"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition, alert.summary["close_reason"]) == MODEL_CLOSE
    assert alert.summary["related_open"] == {"threats": [], "in_progress": [], "model_only": [threat]}
    event = await decided(repos, alert_id)
    assert event["code"] == "model_closed" and event["related_model_only"] == [threat]
    assert links(alert) == [(threat, case)] and alert.summary.get("reopened") is None
    assert (await repos.alerts.get(TENANT_A, threat)).summary["linked_alert_ids"] == [alert_id]
    audited = [e.resource_id for e in (await repos.audit.list(TENANT_A, action="alert.linked")).items]
    assert audited == [alert_id]
    if case is not None:
        assert alert_id in (await repos.escalations.get(TENANT_A, case)).related_alert_ids


async def test_a_forward_link_reopens_when_the_threat_is_confirmed(engine: WorkflowEngine, repos: Repositories) -> None:
    """The existing confirmation rules apply to a forward link: here the path an analyst's true positive takes."""
    await tier_on(repos)
    threat = await other(repos, "waiting_human", severity="medium", verdict="malicious", case=True)
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    alert_id = await routine(repos, "linked-then-confirmed")
    assert (await engine.run(TENANT_A, alert_id)).status == "completed"
    assert links(await repos.alerts.get(TENANT_A, alert_id)) == [(threat, case)]

    reopened = await reopen_counted(repos, TENANT_A, await repos.alerts.get(TENANT_A, threat),
                                    actor=Actor("system", "test"), path="api", confirmed=True, escalation_id=case)
    assert list(reopened) == [alert_id]
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition, alert.summary["reopened"]["mode"]) == ("waiting_human", None, "folded")


# ------------------------------------------------------------------ the other order: the close comes first


async def test_a_threat_that_reaches_hold_grade_after_the_close_reopens_it_into_its_case(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """Review of #442, finding 3: the backward net is symmetric with the forward hold. An alert closes on the
    models' word while nothing is open; a high alert a model judges a threat follows on the same host (spelled as
    an FQDN) and reopens it into its case. A medium one only links, as #423 decided."""
    await tier_on(repos)
    first = await routine(repos, "before-a-serious-threat", hosts=["WS-042.corp.example.com"])
    assert (await engine.run(TENANT_A, first)).status == "completed"
    assert (await decided(repos, first))["code"] == "model_closed"

    threat = await threat_alert(repos)  # high, on ws-042; the fast tier calls it likely_threat and it is escalated
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    reopened = await repos.alerts.get(TENANT_A, first)
    assert (reopened.status, reopened.disposition, reopened.summary["escalation_id"]) == ("waiting_human", None, case)
    assert reopened.summary["reopened"]["mode"] == "folded" and reopened.summary["reopened"]["threat_alert_id"] == threat
    assert first in (await repos.escalations.get(TENANT_A, case)).related_alert_ids
    assert [e.resource_id for e in (await repos.audit.list(TENANT_A, action="alert.reopened")).items] == [first]

    second = await routine(repos, "before-a-model-only-threat", hosts=["db-07"])
    assert (await engine.run(TENANT_A, second)).status == "completed"
    lesser = await threat_alert(repos, severity="medium", normalized={"entities": {"hosts": ["db-07.corp.example.com"]}})
    assert (await engine.run(TENANT_A, lesser)).status == "waiting_human"
    linked = await repos.alerts.get(TENANT_A, second)
    assert (linked.status, linked.disposition, linked.summary["close_reason"]) == MODEL_CLOSE
    assert [threat_id for threat_id, _ in links(linked)] == [lesser] and linked.summary.get("reopened") is None


# ------------------------------------------------------------------ neither


@pytest.mark.parametrize(
    ("status", "state"),
    [
        ("waiting_human", {"assessment": "suspicious", "verdict": "inconclusive"}),  # a doubt, not a threat (#352)
        ("waiting_human", {"assessment": "benign", "verdict": "benign"}),  # with a person for another reason
        ("closed", {"verdict": "malicious"}),  # closed without a person's confirmation
        ("failed", {"verdict": "malicious"}),  # a failed alert never holds
        ("failed", {"severity": "critical"}),
        ("waiting_human", {"verdict": "malicious", "ingested_at": datetime.now(UTC) - timedelta(days=8)}),  # too old
        ("waiting_human", {"verdict": "malicious", "severity": "medium",
                           "ingested_at": datetime.now(UTC) - timedelta(hours=25)}),  # a link reaches back 24 hours
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["mgarcia"]}),  # nothing shared
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["root"]}),  # every host has a root
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["NT AUTHORITY\\SYSTEM"]}),
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "ips": ["192.0.2.142"]}),  # only an IP
        ("queued", {"severity": "critical"}),  # not looked at yet: if it reaches hold grade, it reopens the close
        ("new", {"severity": "critical"}),
        ("processing", {"severity": "medium"}),  # in progress, but not high or critical
        ("processing", {"severity": "critical", "hosts": ["dc-01"], "users": [USER]}),  # in progress on another host
        ("processing", {"severity": "critical", "idle_minutes": 16}),  # a stuck run stops holding after 15 minutes
    ],
)
async def test_what_is_not_a_related_threat_neither_holds_nor_links(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any]
) -> None:
    await tier_on(repos)
    await other(repos, status, **state)
    alert_id = await routine(repos, "closes", users=[USER, "root", "NT AUTHORITY\\SYSTEM"], ips=["192.0.2.142"])

    assert (await engine.run(TENANT_A, alert_id)).status == "completed"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition, alert.summary["close_reason"]) == MODEL_CLOSE
    assert alert.summary["related_open"] == NOTHING and links(alert) == []
    assert (await decided(repos, alert_id))["code"] == "model_closed"


async def test_another_tenants_threat_never_holds_or_links_a_close(engine: WorkflowEngine, repos: Repositories) -> None:
    """Tenancy: the same host and user names in another tenant are another customer's estate."""
    await tier_on(repos)
    await tier_on(repos, TENANT_B)
    theirs = await other(repos, "waiting_human", tenant_id=TENANT_B, users=[USER], verdict="malicious")
    await other(repos, "processing", tenant_id=TENANT_B, severity="critical")
    await other(repos, "waiting_human", tenant_id=TENANT_B, severity="low", verdict="malicious", case=True)

    ours = await routine(repos, "ours", users=[USER])
    assert (await engine.run(TENANT_A, ours)).status == "completed"
    mine = await repos.alerts.get(TENANT_A, ours)
    assert mine.summary["related_open"] == NOTHING and links(mine) == []
    assert await related_open(repos, TENANT_A, ours) == NOTHING
    now = datetime.now(UTC)
    found = await repos.alerts.related_candidates(
        TENANT_A, exclude_alert_id=ours, open_since=now - timedelta(days=7), closed_since=now - timedelta(hours=24),
        threat_assessments=["likely_threat", "confirmed_threat"], limit=100,
    )
    assert found == []

    # The fixture does hold a close where it belongs: in the tenant that owns the threat.
    same_names = await routine(repos, "theirs", tenant_id=TENANT_B, users=[USER])
    assert (await engine.run(TENANT_B, same_names)).status == "waiting_human"
    held = await repos.alerts.get(TENANT_B, same_names)
    assert held.summary["related_open"]["threats"] == [theirs]
    assert (await decided(repos, same_names, TENANT_B))["code"] == "related_open_threat"


async def test_with_the_tier_off_nothing_is_read_or_kept(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unused(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("with the tier off no model-led close is possible: nothing to check")

    monkeypatch.setattr(nodes, "related_open_counted", unused)
    await other(repos, "waiting_human", verdict="malicious")
    alert_id = await routine(repos, "tier-off")
    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"
    assert "related_open" not in (await repos.alerts.get(TENANT_A, alert_id)).summary
    event = await decided(repos, alert_id)
    assert event["code"] == "false_positive_review" and "related_open_threats" not in event


# ------------------------------------------------------------------ unchecked


async def test_a_failed_read_of_the_related_alerts_escalates_and_never_fails_the_run(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #442, finding 6: fail closed without failing the run. The alert the models call benign goes to
    an analyst with ``related_unchecked``; a threat on the same broken read is escalated as a threat."""
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database read failed")

    await tier_on(repos)
    monkeypatch.setattr(type(repos.alerts), "related_candidates", broken)
    alert_id = await routine(repos, "unreadable")
    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("waiting_human", None)
    assert alert.summary["related_open"] == {"unchecked": "read_failed"}
    event = await decided(repos, alert_id)
    assert event["code"] == "related_unchecked" and event["related_unchecked"] == "read_failed"
    assert "could not be checked" in event["reason"]

    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    assert await repos.escalations.get_active_for_alert(TENANT_A, threat) is not None


async def test_more_open_threats_than_one_decision_compares_is_unchecked(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the candidate limit the check is not complete: it fails closed, on whatever host the threats are."""
    await tier_on(repos)
    monkeypatch.setattr(retro_reopen, "MAX_RELATED_CANDIDATES", 2)
    for n in range(3):
        await other(repos, "waiting_human", verdict="malicious", hosts=[f"srv-{n}"])
    alert_id = await routine(repos, "crowded")
    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.summary["related_open"] == {"unchecked": "too_many_candidates"}
    assert (await decided(repos, alert_id))["code"] == "related_unchecked"


# ------------------------------------------------------------------ the demo's attack chain (scripts/demo/alerts.json)

async def test_no_alert_of_the_demo_attack_chain_closes_without_a_person(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#435 on the demo's own data: Word starts PowerShell, the LSASS dump, the beacon, PsExec, all on WS-FIN-0142,
    at the tier auto_full_audit. A model calls the beacon benign because it looks like test data. Without the
    stored-state check the beacon closes; with it, the open threats on the host send it to a person."""
    seed = seed_demo()
    monkeypatch.setattr(fake, "analyse_text", persuaded(fake.analyse_text))
    for tenant_id in (TENANT_A, TENANT_B):
        await tier_on(repos, tenant_id)

    # Control (the behaviour before AI-E3.16): nothing reads the related alerts, and the beacon closes after the
    # two steps before it.
    async def unchecked(*args: Any, **kwargs: Any) -> Dict[str, List[str]]:
        return {"threats": [], "in_progress": [], "model_only": []}

    before = await store_chain(repos, seed, TENANT_B)
    with monkeypatch.context() as patched:
        patched.setattr(nodes, "related_open_counted", unchecked)
        for step in ("demo-edr-001", "demo-edr-002", BEACON):
            await engine.run(TENANT_B, before[step])
    closed = await repos.alerts.get(TENANT_B, before[BEACON])
    assert (closed.status, closed.disposition, closed.summary["close_reason"]) == MODEL_CLOSE
    assert seed.closed_without_a_person(closed.model_dump(mode="json"))

    chain = await store_chain(repos, seed, TENANT_A)
    for alert_id in chain.values():
        await engine.run(TENANT_A, alert_id)
    alerts = {step: await repos.alerts.get(TENANT_A, alert_id) for step, alert_id in chain.items()}
    beacon = alerts[BEACON]
    assert beacon.summary["analysis"]["verdict"] == "benign" and beacon.summary["analysis"]["threat_score"] <= 10
    assert beacon.status == "waiting_human" and beacon.disposition is None
    assert (await decided(repos, chain[BEACON]))["code"] == "related_open_threat"
    # Held by the steps before it that are open threats on the host (the LSASS dump, which the fake model calls one).
    held_by = set(beacon.summary["related_open"]["threats"])
    assert chain["demo-edr-002"] in held_by and held_by <= {chain["demo-edr-001"], chain["demo-edr-002"]}
    for step, alert in alerts.items():
        assert alert.status in ("waiting_human", "waiting_approval"), (step, alert.status)
        assert not seed.closed_without_a_person(alert.model_dump(mode="json")), step


async def test_the_beacon_decided_before_the_rest_of_the_chain_is_reopened_by_it(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #442, finding 3, the other order on the demo chain: the beacon is decided while the LSASS dump is
    still queued, so nothing holds it and it closes on the models' word. The dump is critical and judged a threat:
    when it is processed it reopens the beacon. No step of the chain ends closed without a person."""
    seed = seed_demo()
    monkeypatch.setattr(fake, "analyse_text", persuaded(fake.analyse_text))
    await tier_on(repos)
    chain = await store_chain(repos, seed, TENANT_A)
    for step, alert_id in chain.items():
        if step != BEACON:
            await repos.alerts.update_status(TENANT_A, alert_id, "queued")

    assert (await engine.run(TENANT_A, chain[BEACON])).status == "completed"
    first = await repos.alerts.get(TENANT_A, chain[BEACON])
    assert (first.status, first.disposition, first.summary["close_reason"]) == MODEL_CLOSE
    assert first.summary["related_open"] == NOTHING

    await engine.run(TENANT_A, chain["demo-edr-002"])  # the LSASS dump: critical, a model judges it a threat
    beacon = await repos.alerts.get(TENANT_A, chain[BEACON])
    assert beacon.status in ("queued", "waiting_human") and beacon.disposition is None
    assert beacon.summary["reopened"]["threat_alert_id"] == chain["demo-edr-002"]
    assert beacon.summary["close_reason"] == "reopened:related_threat"
    assert [e.resource_id for e in (await repos.audit.list(TENANT_A, action="alert.reopened")).items] == [chain[BEACON]]
    assert not seed.closed_without_a_person(beacon.model_dump(mode="json"))

    for step in ("demo-edr-001", "demo-edr-003"):
        await engine.run(TENANT_A, chain[step])
    for step, alert_id in chain.items():
        alert = await repos.alerts.get(TENANT_A, alert_id)
        assert not seed.closed_without_a_person(alert.model_dump(mode="json")), (step, alert.status)
