"""Open threats on the same host or user and a model-led close (AI-E3.16, #435), through the real workflow and
database.

The fake model calls an alert whose text is full of benign words benign at both
tiers, so at the tier ``auto_full_audit`` it closes on the models' word
(``tests/integration/engine/test_model_closure.py``). Here the tenant's
database also holds another alert on the same host or user.

* **Held.** The close is withheld when the other alert is open and waits for
  a response approval, is high or critical and judged a threat by a model, or
  was confirmed by a person; also while a high or critical alert on the same
  host is being processed. The held alert joins the threat's open case.
* **Linked forward.** A low or medium threat only a model stands behind holds
  nothing: the alert closes and is linked to that threat's case at once.
* **Neither.** A doubt, a closed or old alert, another host and user, a queued
  alert, another tenant.

The last test replays the demo's attack chain (``scripts/demo/alerts.json``)
with a model that calls the beacon benign for looking like test data, as the
real model did in #435.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core import nodes
from lg_sotf.core.retro_reopen import related_open, reopen_counted
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.llm import fake
from lg_sotf.services.blind_audit import BlindAuditService
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import analyst, decide, threat_alert

pytestmark = pytest.mark.integration

ROUTINE = "Authorized approved expected patch healthcheck, allowlisted and sanctioned"
HOST, USER = "ws-fin-0142", "jsmith"
NOTHING = {"threats": [], "in_progress": [], "model_only": []}
MODEL_CLOSE = ("closed", "benign", "ai_closed:audit_required")
REPO = Path(__file__).resolve().parents[3]
# How the workflow brings an alert to each status (lg_sotf.db.repos.alerts.ALERT_TRANSITIONS).
PATHS: Dict[str, Sequence[str]] = {
    "new": (),
    "queued": ("queued",),
    "processing": ("queued", "processing"),
    "waiting_human": ("queued", "processing", "waiting_human"),
    "waiting_approval": ("queued", "processing", "waiting_approval"),
    "closed": ("queued", "processing", "closed"),
    "failed": ("queued", "failed"),
}


async def tier_on(repos: Repositories, tenant_id: str = TENANT_A) -> None:
    await repos.tenants.update_settings(tenant_id, {"ai_closure": {"tier": "auto_full_audit"}})


async def routine(
    repos: Repositories, name: str, *, tenant_id: str = TENANT_A, severity: str = "low",
    hosts: Sequence[str] = (HOST,), users: Sequence[str] = (), ips: Sequence[str] = (),
) -> str:
    """An alert both tiers of the fake model call benign, with no approved benign evidence: only the models close it."""
    fields: Dict[str, Any] = {
        "title": ROUTINE, "rule_name": "60106: Windows logon success", "description": ROUTINE,
        "entities": {"hosts": list(hosts), "users": list(users), "ips": list(ips)},
        "mitre": {"tactics": ["Initial Access"], "techniques": ["T1078"]},
    }
    return await make_alert(
        repos, tenant_id, source_alert_id=f"e316-{name}", title=ROUTINE, severity=severity, normalized=fields
    )


async def other(
    repos: Repositories, status: str, *, tenant_id: str = TENANT_A, severity: str = "high",
    hosts: Sequence[str] = (HOST,), users: Sequence[str] = (), ips: Sequence[str] = (),
    assessment: Optional[str] = None, verdict: Optional[str] = None, planned: bool = False, case: bool = False,
    true_positive: bool = False, ingested_at: Optional[datetime] = None,
) -> str:
    """Another stored alert of the tenant, at ``status``, with what the workflow would have kept about it: the
    models' assessments, a response plan (``planned``), an open case of its own (``case``), or an analyst's
    ``true_positive`` on its case (``true_positive``)."""
    alert_id = await make_alert(
        repos, tenant_id, title="Credential dumping from LSASS", severity=severity, ingested_at=ingested_at,
        normalized={"entities": {"hosts": list(hosts), "users": list(users), "ips": list(ips)}},
    )
    for step in PATHS[status]:
        await repos.alerts.update_status(tenant_id, alert_id, step)
    summary: Dict[str, Any] = {}
    if assessment is not None:
        summary["triage"] = {"threat_assessment": assessment}
    if verdict is not None:
        summary["analysis"] = {"verdict": verdict}
    if planned:  # what the plan_response node keeps when the response policy applied
        summary["response"] = {"threat_type": "credential_theft", "evidence": "llm_only", "awaiting": 1}
    if case or true_positive:
        escalation, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="a model judged it a threat")
        summary["escalation_id"] = escalation.id
        if true_positive:
            await repos.escalations.decide(
                tenant_id, escalation.id, decision="true_positive", decided_by=UUID(await analyst(repos, tenant_id)),
                expected_version=escalation.version,
            )
    if summary:
        await repos.alerts.update(tenant_id, alert_id, summary=summary)  # type: ignore[arg-type]
    return alert_id


async def decided(repos: Repositories, alert_id: str, tenant_id: str = TENANT_A) -> Dict[str, Any]:
    events = (await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=100)).items
    (event,) = [e for e in events if e.node == "decide"]
    return dict(event.data)


def links(alert: Any) -> List[tuple]:  # type: ignore[type-arg]
    return [(link["threat_alert_id"], link["escalation_id"]) for link in alert.summary.get("linked") or []]


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
        ("failed", {"verdict": "malicious"}, {"hosts": [HOST]}),
        # Waiting for a response approval, at any severity and whatever the models said.
        ("waiting_approval", {"severity": "low"}, {"hosts": [HOST]}),
        ("waiting_approval", {"verdict": "inconclusive", "severity": "medium"}, {"users": [USER]}),
        # Confirmed by a person: an analyst's true positive on its case, although the models called it benign.
        ("processing", {"true_positive": True, "severity": "medium", "verdict": "benign"}, {"hosts": [HOST]}),
        ("waiting_approval", {"true_positive": True, "severity": "low"}, {"users": [USER]}),
    ],
)
async def test_a_serious_open_threat_on_the_same_host_or_user_holds_the_close(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any], shared: Dict[str, List[str]]
) -> None:
    """The threat is there before the close and is a strong enough signal: the alert the models call benign goes
    to a person. These holders have no open case to join, so the alert gets its own, which names the holder."""
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
    assert f"held by alert {threat}, which has no open case to join" in escalation.reason
    assert escalation.summary["correlated_alert_ids"][0] == threat


@pytest.mark.parametrize("severity", ["high", "critical"])
async def test_a_serious_alert_being_processed_on_the_same_host_holds_the_close(
    engine: WorkflowEngine, repos: Repositories, severity: str
) -> None:
    """The same moment: nothing is decided yet about a high or critical alert on the host, so the models do not
    close this one before it is."""
    await tier_on(repos)
    running = await other(repos, "processing", severity=severity)
    alert_id = await routine(repos, "same-moment")

    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.summary["related_open"] == {"threats": [], "in_progress": [running], "model_only": []}
    event = await decided(repos, alert_id)
    assert event["code"] == "related_in_progress" and "still being processed" in event["reason"]
    assert event["related_in_progress"] == [running]


async def test_a_held_alert_joins_the_threats_case_and_the_case_decision_settles_it(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both orders of arrival around one threat with an open case. The alert that closed before the threat is
    linked by the safety net (unchanged). The alert that comes after it is held and joins the threat's case: one
    case for the analyst, no escalation of its own. A false-positive decision on the case closes it benign,
    without detaching it and without teaching the verdict cache a detection nobody reviewed."""
    learned: List[str] = []
    learn = VerdictCache.put_analyst_benign

    async def recording(self: VerdictCache, *args: Any, **kwargs: Any) -> Any:
        learned.append(kwargs["alert_id"])
        return await learn(self, *args, **kwargs)

    monkeypatch.setattr(VerdictCache, "put_analyst_benign", recording)
    await tier_on(repos)
    first = await routine(repos, "before-the-threat", hosts=["ws-042"])
    assert (await engine.run(TENANT_A, first)).status == "completed"
    assert (await decided(repos, first))["code"] == "model_closed"

    threat = await threat_alert(repos)  # high, on ws-042; the fast tier calls it likely_threat and it is escalated
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    closed = await repos.alerts.get(TENANT_A, first)
    assert (closed.status, closed.disposition, closed.summary.get("reopened")) == ("closed", "benign", None)
    assert links(closed) == [(threat, case)]

    second = await routine(repos, "after-the-threat", hosts=["ws-042"])
    waiting = await engine.run(TENANT_A, second)
    assert waiting.status == "waiting_human" and waiting.interrupt["escalation_id"] == case
    assert (await decided(repos, second))["code"] == "related_open_threat"
    held = await repos.alerts.get(TENANT_A, second)
    assert held.summary["related_open"]["threats"] == [threat]
    assert (held.status, held.summary["escalation_id"], held.summary["escalation_attached"]) == (
        "waiting_human", case, True)
    assert held.summary["held_by"] == [threat]
    grown = await repos.escalations.get(TENANT_A, case)
    assert second in grown.related_alert_ids
    assert await repos.escalations.get_active_for_alert(TENANT_A, second) is None  # no queue item of its own
    # What the API tells the analyst: a benign decision leaves no attached alert for a review of its own (another
    # detection attached by grouping would be listed here; the held alert closes with the case).
    async with repos.db.tenant_tx(TENANT_A) as conn:
        assert await ReviewService(repos, engine_settings)._own_review(TENANT_A, grown, "false_positive", conn) == []

    user = await analyst(repos)
    await decide(engine, repos, threat, case, "false_positive", user)
    payload = {"type": "analyst_decision", "escalation_id": case, "decision": "false_positive", "approved_actions": [],
               "decided_by": user, "notes": ""}
    assert (await engine.resume(TENANT_A, second, payload)).status == "completed"
    settled = await repos.alerts.get(TENANT_A, second)
    assert (settled.status, settled.disposition, settled.summary["close_reason"]) == (
        "closed", "benign", "analyst:false_positive")
    assert settled.summary["analyst_decision"] == "false_positive" and "detached_from" not in settled.summary
    assert await repos.escalations.get_active_for_alert(TENANT_A, second) is None
    assert learned == [threat]
    # The alert that was only linked stays closed by the models, due for audit.
    assert (await repos.alerts.get(TENANT_A, first)).summary["close_reason"] == "ai_closed:audit_required"


async def test_a_true_positive_on_the_case_reaches_the_held_alert(engine: WorkflowEngine, repos: Repositories) -> None:
    """The held alert inherits the case's true positive like any attached alert: it never ends as a benign close."""
    await tier_on(repos)
    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    alert_id = await routine(repos, "held-then-confirmed", hosts=["ws-042"])
    assert (await engine.run(TENANT_A, alert_id)).interrupt["escalation_id"] == case

    user = await analyst(repos)
    await decide(engine, repos, threat, case, "true_positive", user)
    payload = {"type": "analyst_decision", "escalation_id": case, "decision": "true_positive", "approved_actions": [],
               "decided_by": user, "notes": ""}
    await engine.resume(TENANT_A, alert_id, payload)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition != "benign" and alert.summary.get("close_reason") != "ai_closed:audit_required"
    assert alert.status in ("closed", "waiting_approval", "waiting_human")
    assert alert.status != "closed" or alert.summary["close_reason"] == "analyst:true_positive"


async def test_a_blind_audit_malicious_label_holds_the_close_while_its_case_is_open(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    """Confirmed by a person: an analyst labelled an AI-closed alert malicious in a blind audit. That alert stays
    closed until the escalation the label opened is decided; meanwhile it holds closes on its host, and the held
    alert joins that escalation."""
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
    waiting = await engine.run(TENANT_A, alert_id)
    assert waiting.status == "waiting_human" and waiting.interrupt["escalation_id"] == result.escalation.id
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.summary["related_open"] == {"threats": [labelled], "in_progress": [], "model_only": []}
    assert (await decided(repos, alert_id))["code"] == "related_open_threat"


# ------------------------------------------------------------------ linked forward


@pytest.mark.parametrize(
    ("status", "state", "shared"),
    [
        # Low or medium, and only a model stands behind it: the dev run's "web server 400 errors" and "sshd brute force".
        ("waiting_human", {"verdict": "malicious", "severity": "medium", "case": True}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "confirmed_threat", "severity": "low", "case": True}, {"users": [USER]}),
        ("waiting_human", {"assessment": "likely_threat", "severity": "info"}, {"hosts": [HOST]}),  # no case yet
        ("processing", {"assessment": "likely_threat", "severity": "medium"}, {"users": [USER]}),
        # A response plan that ended with an analyst, not with an approval request, and no model verdict of a threat.
        ("waiting_human", {"planned": True, "assessment": "suspicious", "verdict": "inconclusive", "case": True},
         {"hosts": [HOST]}),
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


# ------------------------------------------------------------------ neither


@pytest.mark.parametrize(
    ("status", "state"),
    [
        ("waiting_human", {"assessment": "suspicious", "verdict": "inconclusive"}),  # a doubt, not a threat (#352)
        ("waiting_human", {"assessment": "benign", "verdict": "benign"}),  # with a person for another reason
        ("closed", {"verdict": "malicious"}),  # not open any more
        ("waiting_human", {"verdict": "malicious", "ingested_at": datetime.now(UTC) - timedelta(hours=25)}),
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["mgarcia"]}),  # nothing shared
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["root"]}),  # every host has a root
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "users": ["NT AUTHORITY\\SYSTEM"]}),
        ("waiting_human", {"verdict": "malicious", "hosts": ["dc-01"], "ips": ["192.0.2.142"]}),  # only an IP
        ("queued", {"severity": "critical"}),  # not looked at yet: if it becomes a threat, it arrives after the close
        ("new", {"severity": "critical"}),
        ("processing", {"severity": "medium"}),  # in progress, but not high or critical
        ("processing", {"severity": "critical", "hosts": ["dc-01"], "users": [USER]}),  # in progress on another host
    ],
)
async def test_what_is_not_an_open_threat_neither_holds_nor_links(
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
    found = await repos.alerts.open_threats_sharing_entities(
        TENANT_A, hosts=[HOST], users=[USER], since=datetime.now(UTC) - timedelta(hours=24),
        exclude_alert_id=ours, threat_assessments=["likely_threat", "confirmed_threat"],
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

    monkeypatch.setattr(nodes, "related_open", unused)
    await other(repos, "waiting_human", verdict="malicious")
    alert_id = await routine(repos, "tier-off")
    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"
    assert "related_open" not in (await repos.alerts.get(TENANT_A, alert_id)).summary
    event = await decided(repos, alert_id)
    assert event["code"] == "false_positive_review" and "related_open_threats" not in event


async def test_a_failed_read_of_the_related_alerts_never_closes(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: when the stored state cannot be read the run fails (and is retried by the worker); the alert
    is not closed on the models' word."""
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database read failed")

    await tier_on(repos)
    monkeypatch.setattr(type(repos.alerts), "open_threats_sharing_entities", broken)
    alert_id = await routine(repos, "unreadable")
    with pytest.raises(RuntimeError, match="database read failed"):
        await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status == "failed" and alert.disposition is None


# ------------------------------------------------------------------ the demo's attack chain (scripts/demo/alerts.json)

BEACON = "demo-net-001"


def _seed_demo() -> Any:
    spec = importlib.util.spec_from_file_location("seed_demo", REPO / "scripts" / "demo" / "seed_demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _store_chain(repos: Repositories, seed: Any, tenant_id: str) -> Dict[str, str]:
    """The four alerts of the chain, normalised as the canonical ingest endpoint does, in the demo's order."""
    by_source = {a["source_alert_id"]: a for a in json.loads(seed.DEFAULT_ALERTS.read_text(encoding="utf-8"))["alerts"]}
    ctx = NormalizeContext("demo", "canonical", {}, now=datetime.now(UTC))
    ids: Dict[str, str] = {}
    for step in seed.ATTACK_CHAIN:
        raw = by_source[step]
        normalized = json.loads(get_normalizer("canonical").normalize(raw, ctx).model_dump_json())
        assert "ws-fin-0142.corp.example.com" in normalized["entities"]["hosts"]
        assert normalized["severity"] in ("high", "critical")  # so each step that is judged a threat holds the others
        ids[step] = await make_alert(
            repos, tenant_id, source_id="demo", source_alert_id=f"{step}-qs1", title=normalized["title"],
            severity=normalized["severity"], category=normalized["category"], raw=raw, normalized=normalized,
        )
    return ids


def _persuaded(real: Any) -> Any:
    """The fake model, except that it reads the beacon as the real model did in #435: threat score 10, benign,
    with the test-looking names as its false-positive reasons."""
    def analyse(text: str) -> Any:
        if "cdn-sync.updates-cloud.test" not in text.lower():
            return real(text)
        reasons = ("reserved .test domain", "documentation address ranges", "example.com host naming",
                   "vendor is Demo NDR", "regular interval can be synthetic traffic")
        return fake.Signals(threat_score=10, confidence=90, malicious=(), benign=reasons)

    return analyse


async def test_no_alert_of_the_demo_attack_chain_closes_without_a_person(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#435 on the demo's own data: Word starts PowerShell, the LSASS dump, the beacon, PsExec, all on WS-FIN-0142,
    at the tier auto_full_audit. A model calls the beacon benign because it looks like test data. Without the
    stored-state check the beacon closes; with it, the open threats on the host send it to a person."""
    seed = _seed_demo()
    monkeypatch.setattr(fake, "analyse_text", _persuaded(fake.analyse_text))
    for tenant_id in (TENANT_A, TENANT_B):
        await tier_on(repos, tenant_id)

    # Control (the behaviour before AI-E3.16): nothing reads the related alerts, and the beacon closes.
    async def unchecked(*args: Any, **kwargs: Any) -> Dict[str, List[str]]:
        return {"threats": [], "in_progress": [], "model_only": []}

    before = await _store_chain(repos, seed, TENANT_B)
    with monkeypatch.context() as patched:
        patched.setattr(nodes, "related_open", unchecked)
        for alert_id in before.values():
            await engine.run(TENANT_B, alert_id)
    closed = await repos.alerts.get(TENANT_B, before[BEACON])
    assert (closed.status, closed.disposition, closed.summary["close_reason"]) == MODEL_CLOSE
    assert seed.closed_without_a_person(closed.model_dump(mode="json"))

    chain = await _store_chain(repos, seed, TENANT_A)
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
