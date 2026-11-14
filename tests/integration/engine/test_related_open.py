"""A related open threat holds a model-led close back (AI-E3.16, #435), through the real workflow and database.

The fake model calls an alert whose text is full of benign words benign at both
tiers, so at the tier ``auto_full_audit`` it closes on the models' word
(``tests/integration/engine/test_model_closure.py``). Here the tenant's
database also holds another alert on the same host or user. Each order of
arrival is covered: the threat is open before the close (held), it is being
processed at that moment (held when it is high or critical and on the same
host), it is only queued or arrives later (not held: the safety net links
the close when it becomes a threat). Another tenant's threat never counts.

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

import pytest

from lg_sotf.core import nodes
from lg_sotf.core.retro_reopen import related_open
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.llm import fake
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import threat_alert

pytestmark = pytest.mark.integration

ROUTINE = "Authorized approved expected patch healthcheck, allowlisted and sanctioned"
HOST, USER = "ws-fin-0142", "jsmith"
NOTHING = {"threats": [], "in_progress": []}
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
    assessment: Optional[str] = None, verdict: Optional[str] = None, planned: bool = False,
    ingested_at: Optional[datetime] = None,
) -> str:
    """Another stored alert of the tenant, at ``status``, with the model assessments the workflow would have kept."""
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
    if summary:
        await repos.alerts.update(tenant_id, alert_id, summary=summary)  # type: ignore[arg-type]
    return alert_id


async def decided(repos: Repositories, alert_id: str, tenant_id: str = TENANT_A) -> Dict[str, Any]:
    events = (await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=100)).items
    (event,) = [e for e in events if e.node == "decide"]
    return dict(event.data)


@pytest.mark.parametrize(
    ("status", "state", "shared"),
    [
        ("waiting_human", {"verdict": "malicious"}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "likely_threat"}, {"hosts": [HOST]}),
        ("waiting_human", {"assessment": "confirmed_threat", "severity": "low"}, {"users": [USER]}),
        ("waiting_approval", {}, {"hosts": [HOST]}),  # a response waits for approval: no assessment needed
        ("waiting_approval", {"verdict": "inconclusive", "severity": "medium"}, {"users": [USER]}),
        # The response policy applied and the plan ended with an analyst (response_review), whatever the verdict.
        ("waiting_human", {"planned": True, "assessment": "suspicious", "verdict": "inconclusive"}, {"hosts": [HOST]}),
        ("processing", {"assessment": "likely_threat", "severity": "medium"}, {"users": [USER]}),
        ("queued", {"verdict": "malicious"}, {"hosts": [HOST]}),  # requeued with a verdict a model already gave
        ("failed", {"verdict": "malicious"}, {"hosts": [HOST]}),
    ],
)
async def test_an_open_threat_on_the_same_host_or_user_holds_the_close(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any], shared: Dict[str, List[str]]
) -> None:
    """The threat is there before the close: the alert the models call benign goes to a person, with the reason."""
    await tier_on(repos)
    threat = await other(repos, status, hosts=shared.get("hosts", ["dc-01"]), users=shared.get("users", ()), **state)
    alert_id = await routine(repos, "held", severity="high", users=[USER, "root"])

    assert (await engine.run(TENANT_A, alert_id)).status == "waiting_human"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("waiting_human", None)
    assert alert.summary["analysis"]["verdict"] == "benign" and alert.summary["triage"]["threat_assessment"] == "benign"
    assert alert.summary["related_open"] == {"threats": [threat], "in_progress": []}
    event = await decided(repos, alert_id)
    assert (event["route"], event["code"], event["autonomy_tier"]) == ("escalate", "related_open_threat", "auto_full_audit")
    assert "related open threat on the same host" in event["reason"]
    assert event["related_open_threats"] == [threat] and event["related_in_progress"] == []
    escalation = await repos.escalations.get(TENANT_A, alert.summary["escalation_id"])
    assert escalation.summary["routing"]["code"] == "related_open_threat"
    assert "related open threat on the same host" in escalation.reason


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
async def test_what_is_not_an_open_threat_holds_nothing(
    engine: WorkflowEngine, repos: Repositories, status: str, state: Dict[str, Any]
) -> None:
    await tier_on(repos)
    await other(repos, status, **state)
    alert_id = await routine(repos, "closes", users=[USER, "root", "NT AUTHORITY\\SYSTEM"], ips=["192.0.2.142"])

    assert (await engine.run(TENANT_A, alert_id)).status == "completed"

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition, alert.summary["close_reason"]) == (
        "closed", "benign", "ai_closed:audit_required")
    assert alert.summary["related_open"] == NOTHING
    assert (await decided(repos, alert_id))["code"] == "model_closed"


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
    assert alert.summary["related_open"] == {"threats": [], "in_progress": [running]}
    event = await decided(repos, alert_id)
    assert event["code"] == "related_in_progress" and "still being processed" in event["reason"]
    assert event["related_in_progress"] == [running]


async def test_a_threat_that_arrives_after_the_close_is_left_to_the_safety_net(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """The other order of arrival: nothing is open when the alert closes, so it closes; the threat that follows
    links it to its case and leaves it closed (retro-reopen, unchanged). The next alert on the host is held."""
    await tier_on(repos)
    first = await routine(repos, "before-the-threat", hosts=["ws-042"])
    assert (await engine.run(TENANT_A, first)).status == "completed"
    assert (await decided(repos, first))["code"] == "model_closed"

    threat = await threat_alert(repos)  # on ws-042; the fast tier calls it likely_threat and it is escalated
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    closed = await repos.alerts.get(TENANT_A, first)
    assert (closed.status, closed.disposition, closed.summary.get("reopened")) == ("closed", "benign", None)
    assert [(link["threat_alert_id"], link["escalation_id"]) for link in closed.summary["linked"]] == [(threat, case)]

    second = await routine(repos, "after-the-threat", hosts=["ws-042"])
    assert (await engine.run(TENANT_A, second)).status == "waiting_human"
    assert (await decided(repos, second))["code"] == "related_open_threat"
    assert (await repos.alerts.get(TENANT_A, second)).summary["related_open"]["threats"] == [threat]


async def test_another_tenants_threat_never_holds_a_close(engine: WorkflowEngine, repos: Repositories) -> None:
    """Tenancy: the same host and user names in another tenant are another customer's estate."""
    await tier_on(repos)
    await tier_on(repos, TENANT_B)
    theirs = await other(repos, "waiting_human", tenant_id=TENANT_B, users=[USER], verdict="malicious")
    await other(repos, "processing", tenant_id=TENANT_B, severity="critical")

    ours = await routine(repos, "ours", users=[USER])
    assert (await engine.run(TENANT_A, ours)).status == "completed"
    assert (await repos.alerts.get(TENANT_A, ours)).summary["related_open"] == NOTHING
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
        return {"threats": [], "in_progress": []}

    before = await _store_chain(repos, seed, TENANT_B)
    with monkeypatch.context() as patched:
        patched.setattr(nodes, "related_open", unchecked)
        for alert_id in before.values():
            await engine.run(TENANT_B, alert_id)
    closed = await repos.alerts.get(TENANT_B, before[BEACON])
    assert (closed.status, closed.disposition, closed.summary["close_reason"]) == (
        "closed", "benign", "ai_closed:audit_required")
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
