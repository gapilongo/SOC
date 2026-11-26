"""The investigation harness on corpus_v1 with its telemetry (AI-E3.3): what it adds, and what it must not change.

The corpus alerts run through the real pipeline at the autonomy tier ``auto_full_audit``, with the stand-in
model and the network blocked: once as today (the tenant's switch off), and with the harness on and the
evidence tools answering from the corpus telemetry (``investigation.evidence_backend: event_store``).

The evidence can hold a model-led close and can never buy one (ADR 0014 Amendment 1 point 1, pulled forward
by the review of PR 443): a malicious indicator of the skill that is true over the facts, a benign verdict
with a hard citation finding, or steering text in a fact sends the alert to a person. The stand-in model is a
keyword scorer over everything untrusted it is shown, the evidence included, so its verdict can move with
the evidence. Three runs separate the effects:

* harness on, the stand-in **blind to the evidence** (it still cites the ids): every verdict is today's, so an
  alert ends where it ends today unless an evidence blocker holds it, and nothing closes that did not;
* harness on, the stand-in reading the evidence: an outcome may differ only for an alert whose verdict moved
  or which an evidence blocker holds, and automation closes no more attacks than with the harness off;
* an alert alone on its host has no true indicator: the alert is never its own evidence.

By default a selection of the corpus runs (every family, both labels). ``LG_SOTF_CORPUS_INVESTIGATION_REPORT=path.json``
runs all of it and writes the measurement: how many alerts were investigated, facts per alert, outcomes,
budget use, citation findings, what each blocker held by label, and the closes of the three runs.
"""

from __future__ import annotations

import secrets
from collections import Counter

import pytest

from lg_sotf.agents.investigation.catalog import load_catalog
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.settings import Settings
from tests.integration.eval._investigation import (
    DATASET,
    EVENTS,
    EVIDENCE_CODES,
    ITEM_0351,
    REPORT,
    alone_on_host,
    blind_to_evidence,
    held_by_evidence,
    measurement,
    outcomes,
    own_event_listed,
    records,
    selection,
    verdicts,
    with_harness,
    write_report,
)
from tests.integration.eval._support import NetworkGuard, at_tier, closures

pytestmark = [pytest.mark.integration, pytest.mark.timeout(3600)]

async def test_the_harness_gives_corpus_alerts_facts_and_changes_no_close(
    eval_settings: Settings, monkeypatch: pytest.MonkeyPatch, repos: Repositories
) -> None:
    dataset = at_tier(selection(load_dataset(DATASET)), "auto_full_audit")
    harness_settings = eval_settings.model_copy(update={
        "investigation": eval_settings.investigation.model_copy(update={
            "evidence_backend": "event_store", "event_store_files": [str(DATASET), str(EVENTS)]}),
    })
    net = NetworkGuard(eval_settings)
    net.install(monkeypatch)
    expected = {item.id: item.expected.disposition for item in dataset.items}

    off = await run_evaluation(eval_settings, dataset, tenant_id=f"inv-off-{secrets.token_hex(3)}")
    on = await run_evaluation(harness_settings, with_harness(dataset), tenant_id=f"inv-on-{secrets.token_hex(3)}")
    with monkeypatch.context() as patch:
        blind_to_evidence(patch)
        blind = await run_evaluation(harness_settings, with_harness(dataset), tenant_id=f"inv-blind-{secrets.token_hex(3)}")

    ran = (*off.results, *on.results, *blind.results)
    assert [(r.item_id, r.error) for r in ran if r.status == "error"] == [] and net.attempts == []
    before, after, unseen = await records(repos, off), await records(repos, on), await records(repos, blind)
    assert not any(a.get("investigation") for a in before.values())  # today's path records nothing
    measured = measurement(after)
    assert measurement(unseen)["investigated"] == measured["investigated"]
    # Every alert that reached the deep analysis was investigated, and its host was read (found or found empty).
    assert measured["investigated"] == measured["analysed"] - sum(not a for a in after.values()) > 0
    assert measured["lookup_outcomes"].get("failed", 0) == 0
    assert all(a["investigation"]["steps"][0]["outcome"] in ("success", "empty") for a in after.values() if a.get("investigation"))
    assert measured["citation_findings"].get("unknown_fact", 0) == 0  # the stand-in cites only ids it was shown
    assert measured["budget"]["steps"]["max"] <= 8 and measured["budget"]["usd"]["max"] == 0

    was, now, held_verdicts = outcomes(off), outcomes(on), outcomes(blind)
    # With the verdicts held (the stand-in blind to the evidence), the harness moves an alert only by holding its
    # close: what ended differently was closed by automation today and is with a person for an evidence blocker.
    assert verdicts(unseen) == verdicts(before)
    stopped = sorted(i for i in was if was[i] != held_verdicts[i])
    assert all(was[i][0] == "closed" and held_verdicts[i][2] in EVIDENCE_CODES for i in stopped), stopped
    # With the stand-in reading the evidence, an outcome differs only where the verdict moved or a blocker held.
    moved = sorted(i for i in after if verdicts(before)[i] != verdicts(after)[i])
    changed = sorted(i for i in was if was[i] != now[i])
    assert all(i in moved or now[i][2] in EVIDENCE_CODES for i in changed), changed
    # The evidence never buys a close: no more attacks closed than with the harness off, in either run.
    closes_off, closes_on, closes_blind = closures(off.results), closures(on.results), closures(blind.results)
    assert closes_on["malicious_closed"] <= closes_off["malicious_closed"] >= closes_blind["malicious_closed"]
    assert closes_blind["benign_closed"] <= closes_off["benign_closed"]
    if ITEM_0351 in now:  # the attack the evidence bought a close for, before the review
        assert now[ITEM_0351][0] != "closed" and held_verdicts[ITEM_0351][0] != "closed"
    # The alert is never its own evidence: alone on its host it shows no indicator, and no fact lists its own event.
    skill = load_catalog()[0]
    never_close = list(skill.hypotheses.malicious[0].indicator.any_technique_in)  # type: ignore[union-attr]
    alone = alone_on_host(dataset, after, never_close)
    assert alone["true_indicators"] == []
    tenants = on.info["tenants"]
    facts = {}
    for result in on.results:
        record = after.get(result.item_id, {}).get("investigation")
        if record and result.alert_id:
            ledger = await repos.evidence_facts.list_for_run(tenants.get(result.split) or tenants["*"], result.alert_id, record["run_id"])
            facts[result.item_id] = [dict(entry.fact) for entry in ledger if entry.fact]
    assert own_event_listed(dataset, facts) == []
    first = dataset.items[0]  # the check does find an own event when a fact lists one
    own = {"rule_id": first.alert["rule"]["id"], "at": first.alert["timestamp"].replace("+0000", "000Z")}
    assert own_event_listed(dataset, {first.id: [{"kind": "host_activity", "value": {"events": [own]}}]}) == [first.id]
    if REPORT:
        assert alone["alerts"] > 0 and alone["own_event_would_show"] > 0  # the corpus does hold the case
        report = {
            "dataset": dataset.sha256, "items": len(dataset.items), "tier": "auto_full_audit", "model": "fake (stand-in)",
            "harness": measured, "closes_off": closes_off, "closes_on": closes_on,
            "closes_on_stand_in_blind_to_evidence": closes_blind,
            "held_by_evidence_on": held_by_evidence(on, after),
            "held_by_evidence_blind": held_by_evidence(blind, unseen),
            "closes_stopped_blind": {label: sum(1 for i in stopped if expected[i] == label) for label in ("benign", "malicious")},
            "alone_on_host": alone,
            ITEM_0351: {"off": was.get(ITEM_0351), "on": now.get(ITEM_0351), "blind": held_verdicts.get(ITEM_0351)},
            # Alerts that never reached the deep analysis, by where they ended: the harness runs inside it.
            "not_investigated": dict(Counter(
                f"{now[i][0]}/{now[i][2] or now[i][3] or 'no decision'}" for i in after if not after[i].get("investigation"))),
            "verdict_moved_with_evidence": moved, "outcome_changed": changed,
            "outcome_changes": {i: {"off": was[i], "on": now[i], "verdict_off": before[i].get("verdict"),
                                    "verdict_on": after[i].get("verdict")} for i in changed},
        }
        write_report(REPORT, report)
