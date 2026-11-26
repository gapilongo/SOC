"""The probes of the independent review of PR #442 (AI-E3.16). Each test asserts the safe behaviour.

Kept as the reviewer wrote them, except where a decision taken after the review changes what is safe; each
adaptation is marked ``Adapted``:

* the custom join of a held alert into the holder's case is cut, so the probes no longer expect a held alert to
  wait on the holder's escalation, and no longer resume it with that case's decision;
* an IP address alone, and ``SYSTEM`` without a shared host, relate nothing: those two spellings close;
* the related alerts are read as a bounded candidate set and compared in Python, so the two query probes read
  the new query and expect the check to fail closed past the limit;
* the notes the probes wrote to a scratch file are dropped.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import pytest

from lg_sotf.core import retro_reopen
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos import alerts as alerts_repo
from lg_sotf.llm import fake
from lg_sotf.models.vocabulary import ALERT_STATUSES, HIGH_SEVERITIES
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, new_alert
from tests.integration.engine._related import (
    BEACON,
    HOST,
    decided,
    other,
    persuaded,
    routine,
    seed_demo,
    store_chain,
    tier_on,
)
from tests.integration.engine._support import analyst, decide, threat_alert

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------- 1. entity spelling
@pytest.mark.parametrize(
    ("label", "threat_entities", "alert_entities", "held"),
    [
        ("fqdn-vs-short", {"hosts": ["ws-fin-0142.corp.example.com"]}, {"hosts": ["ws-fin-0142"]}, True),
        ("trailing-dot", {"hosts": ["ws-fin-0142.corp.example.com."]}, {"hosts": ["ws-fin-0142.corp.example.com"]}, True),
        ("domain-backslash-user", {"hosts": ["dc-01"], "users": ["CORP\\jsmith"]}, {"hosts": ["ws-9"], "users": ["jsmith"]}, True),
        ("upn-vs-sam", {"hosts": ["dc-01"], "users": ["jsmith@corp.example.com"]}, {"hosts": ["ws-9"], "users": ["jsmith"]}, True),
        ("user-case", {"hosts": ["dc-01"], "users": ["JSmith"]}, {"hosts": ["ws-9"], "users": ["jsmith"]}, True),
        ("system-same-host", {"hosts": [HOST], "users": ["NT AUTHORITY\\SYSTEM"]}, {"hosts": [HOST], "users": ["NT AUTHORITY\\SYSTEM"]}, True),
        # Adapted (decision B): an IP alone, and a built-in account without a shared host, relate nothing.
        ("ip-only", {"hosts": ["dc-01"], "ips": ["10.1.2.3"]}, {"hosts": [], "ips": ["10.1.2.3"]}, False),
        ("system-no-host", {"hosts": [HOST], "users": ["NT AUTHORITY\\SYSTEM"]}, {"hosts": [], "users": ["NT AUTHORITY\\SYSTEM"]}, False),
    ],
)
async def test_probe_spelling_of_the_same_entity_still_holds(
    engine: WorkflowEngine, repos: Repositories, label: str, threat_entities: Dict[str, List[str]],
    alert_entities: Dict[str, List[str]], held: bool,
) -> None:
    await tier_on(repos)
    await other(repos, "waiting_human", severity="critical", verdict="malicious", case=True,
                hosts=threat_entities.get("hosts", ()), users=threat_entities.get("users", ()),
                ips=threat_entities.get("ips", ()))
    alert_id = await routine(repos, f"sp-{label}", hosts=alert_entities.get("hosts", ()),
                             users=alert_entities.get("users", ()), ips=alert_entities.get("ips", ()))
    await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status == ("waiting_human" if held else "closed"), (label, alert.status, alert.summary.get("close_reason"))


# ---------------------------------------------------------------- 1. closed malicious a minute before
async def test_probe_threat_closed_malicious_a_minute_before(engine: WorkflowEngine, repos: Repositories) -> None:
    await tier_on(repos)
    threat = await other(repos, "closed", severity="critical", verdict="malicious", true_positive=True)
    await repos.alerts.update(TENANT_A, threat, disposition="malicious",
                              summary={"close_reason": "analyst:true_positive", "analyst_decision": "true_positive"})
    alert_id = await routine(repos, "after-confirmed")
    await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status == "waiting_human", (alert.status, alert.summary.get("close_reason"))
    assert alert.summary["related_open"]["threats"] == [threat]


# ---------------------------------------------------------------- 1. order of processing on the demo chain
async def test_probe_beacon_decided_while_the_dump_is_still_queued(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = seed_demo()
    monkeypatch.setattr(fake, "analyse_text", persuaded(fake.analyse_text))
    await tier_on(repos)
    chain = await store_chain(repos, seed, TENANT_A)
    for step, alert_id in chain.items():
        if step != BEACON:
            await repos.alerts.update_status(TENANT_A, alert_id, "queued")
    await engine.run(TENANT_A, chain[BEACON])
    for step, alert_id in chain.items():
        if step != BEACON:
            await engine.run(TENANT_A, alert_id)
    beacon = await repos.alerts.get(TENANT_A, chain[BEACON])
    assert not seed.closed_without_a_person(beacon.model_dump(mode="json"))


# ---------------------------------------------------------------- 3. the held alert and the decision on the holder's case
async def test_probe_false_positive_on_the_holder_closes_the_held_alert_outside_the_audit(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    await tier_on(repos)
    threat = await threat_alert(repos)  # high, ws-042, likely_threat, open case
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    held_id = await routine(repos, "held-other-detection", severity="high", hosts=["ws-042"])
    waiting = await engine.run(TENANT_A, held_id)
    # Adapted (decision A): the held alert is another detection, so it waits on an escalation of its own.
    assert waiting.status == "waiting_human" and waiting.interrupt["escalation_id"] != case
    grown = await repos.escalations.get(TENANT_A, case)
    assert held_id not in grown.related_alert_ids
    async with repos.db.tenant_tx(TENANT_A) as conn:
        assert await ReviewService(repos, engine_settings)._own_review(TENANT_A, grown, "false_positive", conn) == []
    user = await analyst(repos)
    await decide(engine, repos, threat, case, "false_positive", user)
    held = await repos.alerts.get(TENANT_A, held_id)
    now = datetime.now(UTC)
    _, frame = await repos.blind_audit.frame(TENANT_A, now - timedelta(hours=1), now + timedelta(minutes=1), seed=1, limit=100)
    in_frame = held_id in {f.alert_id for f in frame}
    # Safe: either a person reviews this other detection, or it stays an AI close that the blind audit can sample.
    assert held.status != "closed" or held.summary.get("close_reason") == "ai_closed:audit_required" or in_frame, held.summary.get("close_reason")
    assert held.status == "waiting_human" and held.summary.get("analyst_decision") is None


async def test_probe_needs_more_info_on_the_case_does_not_strand_the_held_alert(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    await tier_on(repos)
    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    held_id = await routine(repos, "held-more-info", hosts=["ws-042"])
    # Adapted (decision A): the held alert waits on its own escalation, which the case's decision does not reach.
    assert (await engine.run(TENANT_A, held_id)).interrupt["escalation_id"] != case
    user = await analyst(repos)
    await decide(engine, repos, threat, case, "needs_more_info", user)
    held = await repos.alerts.get(TENANT_A, held_id)
    own = await repos.escalations.get_active_for_alert(TENANT_A, held_id)
    async with repos.db.tenant_tx(TENANT_A) as conn:
        attached = await repos.escalations.find_attached_to(TENANT_A, held_id, conn=conn)
    assert held.status == "closed" or own is not None or attached is not None, "stranded: waiting with no open case"


# ---------------------------------------------------------------- 5. abuse: one holder, many held
async def test_probe_one_case_takes_no_more_held_alerts_than_the_grouping_cap(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    await tier_on(repos)
    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    for n in range(56):
        held = await routine(repos, f"flood-{n}", hosts=["ws-042"])
        assert (await engine.run(TENANT_A, held)).status == "waiting_human"
    grown = await repos.escalations.get(TENANT_A, case)
    assert len(grown.related_alert_ids) <= 50, len(grown.related_alert_ids)


# ---------------------------------------------------------------- 2. the query on a few thousand open alerts
async def _six_thousand_open_threats(repos: Repositories) -> str:
    batch = [
        new_alert(source_alert_id=f"bulk-{n}", title="bulk", severity="high" if n % 7 == 0 else "low",
                  normalized={"entities": {"hosts": [f"h-{n % 400}"], "users": [f"u-{n % 300}"]}})
        for n in range(6000)
    ]
    for start in range(0, len(batch), 500):
        await repos.alerts.insert_many_if_absent(TENANT_A, batch[start:start + 500])
    async with repos.db.tenant_tx(TENANT_A) as conn:
        await conn.execute("UPDATE alerts SET status = 'waiting_human', summary = '{\"analysis\": {\"verdict\": \"malicious\"}}'::jsonb WHERE tenant_id = $1", TENANT_A)
        await conn.execute("ANALYZE alerts")
    return batch[0].id


async def test_probe_explain_on_five_thousand_open_alerts(repos: Repositories) -> None:
    first = await _six_thousand_open_threats(repos)
    # Adapted (decision B): the candidate query, which filters by tenant, state and time and never by entity.
    limit = retro_reopen.MAX_RELATED_CANDIDATES + 1
    args = (TENANT_A, first, [s for s in ALERT_STATUSES if s not in ("closed", "failed")],
            datetime.now(UTC) - timedelta(days=7), ["likely_threat", "confirmed_threat"], sorted(HIGH_SEVERITIES), limit)
    async with repos.db.tenant_tx(TENANT_A) as conn:
        plan = await conn.fetch("EXPLAIN (ANALYZE, BUFFERS) " + alerts_repo._OPEN_CANDIDATES_SQL, *args)
        rows = await conn.fetch(alerts_repo._OPEN_CANDIDATES_SQL, *args)
    assert plan and len(rows) == limit  # bounded: never more than the limit, whatever the backlog


async def test_probe2_query_time_without_explain(repos: Repositories) -> None:
    await _six_thousand_open_threats(repos)
    # Adapted (decision B): past the candidate limit the check is not complete, so it fails closed.
    alert_id = await routine(repos, "among-six-thousand", hosts=["h-3"], users=["u-3"])
    assert await retro_reopen.related_open(repos, TENANT_A, alert_id) == {"unchecked": "too_many_candidates"}


# ---------------------------------------------------------------- second round
async def test_probe2_real_flow_true_positive_closed_then_same_host(engine: WorkflowEngine, repos: Repositories) -> None:
    await tier_on(repos)
    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    user = await analyst(repos)
    await decide(engine, repos, threat, case, "true_positive", user)
    confirmed = await repos.alerts.get(TENANT_A, threat)
    alert_id = await routine(repos, "after-real-tp", hosts=["ws-042"], users=["jdoe"])
    await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status != "closed" or confirmed.status != "closed", "closed on the models' word right after a confirmed threat closed on its host"
    assert (await decided(repos, alert_id))["code"] == "related_open_threat"


async def test_probe2_broken_read_and_a_real_threat(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database read failed")

    await tier_on(repos)
    # Adapted (decision B): the read of the related alerts is now ``related_candidates``.
    monkeypatch.setattr(type(repos.alerts), "related_candidates", broken)
    threat = await threat_alert(repos)
    await engine.run(TENANT_A, threat)
    alert = await repos.alerts.get(TENANT_A, threat)
    assert alert.status == "waiting_human", alert.status
    assert await repos.escalations.get_active_for_alert(TENANT_A, threat) is not None


async def test_probe2_tier_off_chain_with_the_stock_fake_model(engine: WorkflowEngine, repos: Repositories) -> None:
    seed = seed_demo()
    chain = await store_chain(repos, seed, TENANT_A)
    for alert_id in chain.values():
        await engine.run(TENANT_A, alert_id)
    alerts = {step: await repos.alerts.get(TENANT_A, a) for step, a in chain.items()}
    assert not [s for s, a in alerts.items() if seed.closed_without_a_person(a.model_dump(mode="json"))]


async def test_probe3_true_positive_on_the_case_and_the_benign_held_alert(engine: WorkflowEngine, repos: Repositories) -> None:
    await tier_on(repos)
    bystander = await routine(repos, "bystander", hosts=["srv-9"], ips=["10.9.9.9"])  # closes; shares only an IP with the held alert
    assert (await engine.run(TENANT_A, bystander)).status == "completed"
    threat = await threat_alert(repos)
    assert (await engine.run(TENANT_A, threat)).status == "waiting_human"
    case = (await repos.alerts.get(TENANT_A, threat)).summary["escalation_id"]
    held_id = await routine(repos, "held-tp", hosts=["ws-042"], ips=["10.9.9.9"])
    # Adapted (decision A): no join, so the case's true positive never reaches the held alert.
    assert (await engine.run(TENANT_A, held_id)).interrupt["escalation_id"] != case
    user = await analyst(repos)
    await decide(engine, repos, threat, case, "true_positive", user)
    held = await repos.alerts.get(TENANT_A, held_id)
    other_alert = await repos.alerts.get(TENANT_A, bystander)
    # The reviewer's finding 5: the held alert became a confirmed threat with its own response plan, which requeued
    # the bystander. Safe: it is still an alert the models called benign, waiting for a person; nothing else moved.
    assert (held.status, held.disposition) == ("waiting_human", None) and "response" not in held.summary
    assert other_alert.status == "closed" and other_alert.summary.get("reopened") is None
