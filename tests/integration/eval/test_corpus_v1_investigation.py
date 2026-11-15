"""The investigation harness on corpus_v1 with its telemetry (AI-E3.3): what it adds, and what it must not change.

The corpus alerts run twice through the real pipeline at the autonomy tier ``auto_full_audit``, with the
stand-in model and the network blocked: once as today (the tenant's switch off), once with the harness on
and the evidence tools answering from the corpus telemetry (``investigation.evidence_backend: event_store``).

The closing rule is not touched by the harness, so what automation closes must be the same in both runs,
alert by alert, whenever the deep verdict is the same. The stand-in model is a keyword scorer over
everything untrusted it is shown, the evidence included, so its verdict can move with the evidence (a
command line in a host's activity that holds the word ``update`` reads as benign to it). Two checks
separate the two effects:

* a third run has the harness on and the stand-in **blind to the evidence** (it still cites the ids):
  every alert must then end exactly where it ends today, with the same verdict and score;
* in the run where the stand-in reads the evidence, an outcome may differ only for an alert whose verdict
  moved.

By default a selection of the corpus runs (every family, both labels). ``LG_SOTF_CORPUS_INVESTIGATION_REPORT=path.json``
runs all of it and writes the measurement: how many alerts were investigated, facts per alert, outcomes,
budget use, citation findings and the closes of the three runs.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import Dataset, load_dataset
from lg_sotf.eval.runner import EvalRun, run_evaluation
from lg_sotf.llm import fake
from lg_sotf.llm.prompting import serialize_untrusted
from lg_sotf.settings import Settings
from tests.integration.eval._support import NetworkGuard, at_tier, closures

pytestmark = [pytest.mark.integration, pytest.mark.timeout(3600)]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "corpus_v1.jsonl.gz"
EVENTS = FIXTURES / "corpus_v1_events.jsonl.gz"
REPORT = os.environ.get("LG_SOTF_CORPUS_INVESTIGATION_REPORT")
PER_FAMILY_AND_LABEL = 3


def selection(dataset: Dataset) -> Dataset:
    """The first few items of every family and label (the whole corpus when a report is asked for)."""
    if REPORT:
        return dataset
    seen: Counter[Any] = Counter()
    chosen = []
    for item in dataset.items:
        key = (item.family, item.expected.disposition)
        if seen[key] < PER_FAMILY_AND_LABEL:
            seen[key] += 1
            chosen.append(item)
    return dataclasses.replace(dataset, items=chosen)


def with_harness(dataset: Dataset) -> Dataset:
    """``dataset`` with its evaluation tenants' evidence tools switched on."""
    tenant_settings = dict(dataset.meta.get("tenant_settings") or {})
    tenant_settings["tools"] = {**dict(tenant_settings.get("tools") or {}), "wazuh_indexer": {"enabled": True}}
    return dataclasses.replace(dataset, meta={**dataset.meta, "tenant_settings": tenant_settings})


async def records(repos: Repositories, run: EvalRun) -> Dict[str, Mapping[str, Any]]:
    """Each item's stored analysis (``alerts.summary.analysis``), by item id."""
    tenants = run.info["tenants"]
    out: Dict[str, Mapping[str, Any]] = {}
    for result in run.results:
        if result.alert_id is None:
            continue
        alert = await repos.alerts.get(tenants.get(result.split) or tenants["*"], result.alert_id)
        out[result.item_id] = alert.summary.get("analysis") or {}
    return out


def measurement(analyses: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """What the harness did over a run, from the stored investigation records."""
    found = {item: a["investigation"] for item, a in analyses.items() if a.get("investigation")}
    steps = [step for record in found.values() for step in record["steps"]]
    facts = [record["facts"] for record in found.values()]
    claims = [claim for record in found.values() for claim in record.get("claims") or []]
    used = {kind: [record["budget"][kind]["used"] for record in found.values()] for kind in ("steps", "wall_s", "tokens", "usd")}
    return {
        "analysed": len(analyses),
        "investigated": len(found),
        "status": dict(Counter(record["status"] for record in found.values())),
        "reasons": dict(Counter(str(record["reason"]) for record in found.values())),
        "facts_per_alert": {"mean": round(statistics.fmean(facts), 2) if facts else 0, "median": statistics.median(facts) if facts else 0,
                            "min": min(facts, default=0), "max": max(facts, default=0)},
        "lookup_outcomes": dict(Counter(step["outcome"] for step in steps)),
        "skipped_reasons": dict(Counter(step["reason"] for step in steps if step["outcome"] == "skipped")),
        "incomplete_lookups": sum(step["outcome"] in ("success", "empty") and not step["complete"] for step in steps),
        "budget": {kind: {"mean": round(statistics.fmean(values), 4) if values else 0, "max": max(values, default=0)}
                   for kind, values in used.items()},
        "claims": len(claims),
        "citation_findings": dict(Counter(f["code"] for claim in claims for f in claim["findings"])),
        "indicators": dict(Counter(f"{name}={state}" for record in found.values() for name, state in record["indicators"].items())),
    }


def write_report(path: str, report: Mapping[str, Any]) -> None:
    Path(path).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def outcomes(run: EvalRun) -> Dict[str, Any]:
    return {r.item_id: (r.status, r.disposition, r.decision_code, r.close_reason) for r in run.results}


def verdicts(analyses: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    return {item: (a.get("verdict"), a.get("threat_score")) for item, a in analyses.items()}


def blind_to_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stand-in scores a prompt without its evidence block: its verdict is then the one it gives today."""
    scored = fake.untrusted_text

    def without_evidence(messages: Any) -> str:
        return _strip(scored(messages))

    monkeypatch.setattr(fake, "untrusted_text", without_evidence)


def _strip(text: str) -> str:
    """``text`` (the prompt's data blocks, one JSON document a line) without the ``evidence`` member of a block.
    A block without one is left byte for byte as it was."""
    kept: List[str] = []
    for line in text.splitlines():
        try:
            block = json.loads(line)
        except ValueError:
            block = None
        if isinstance(block, dict) and "evidence" in block:
            del block["evidence"]
            line = serialize_untrusted(block)
        kept.append(line)
    return "\n".join(kept)


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

    off = await run_evaluation(eval_settings, dataset, tenant_id=f"inv-off-{secrets.token_hex(3)}")
    on = await run_evaluation(harness_settings, with_harness(dataset), tenant_id=f"inv-on-{secrets.token_hex(3)}")
    with monkeypatch.context() as patch:
        blind_to_evidence(patch)
        blind = await run_evaluation(harness_settings, with_harness(dataset), tenant_id=f"inv-blind-{secrets.token_hex(3)}")

    ran = (*off.results, *on.results, *blind.results)
    assert [(r.item_id, r.error) for r in ran if r.status == "error"] == [] and net.attempts == []
    before, after, unseen = await records(repos, off), await records(repos, on), await records(repos, blind)
    assert not any(a.get("investigation") for a in before.values())  # today's path records nothing
    # The harness ran in the blind run too, and with the verdicts held it changed no alert's outcome at all.
    assert measurement(unseen)["investigated"] == measurement(after)["investigated"]
    assert verdicts(unseen) == verdicts(before) and outcomes(blind) == outcomes(off)
    measured = measurement(after)
    # Every alert that reached the deep analysis was investigated, and got at least its host's activity.
    assert measured["investigated"] == measured["analysed"] - sum(not a for a in after.values()) > 0
    assert measured["lookup_outcomes"].get("failed", 0) == 0 and measured["facts_per_alert"]["min"] >= 1
    assert measured["citation_findings"].get("unknown_fact", 0) == 0  # the stand-in cites only ids it was shown
    assert measured["budget"]["steps"]["max"] <= 8 and measured["budget"]["usd"]["max"] == 0

    # The closing rule is untouched: an alert whose deep verdict did not move ends exactly where it ended.
    moved = sorted(i for i in after if verdicts(before)[i] != verdicts(after)[i])
    was, now = outcomes(off), outcomes(on)
    changed = sorted(i for i in was if was[i] != now[i])
    assert set(changed) <= set(moved), sorted(set(changed) - set(moved))
    if REPORT:
        report = {
            "dataset": dataset.sha256, "items": len(dataset.items), "tier": "auto_full_audit", "model": "fake (stand-in)",
            "harness": measured, "closes_off": closures(off.results), "closes_on": closures(on.results),
            "closes_on_stand_in_blind_to_evidence": closures(blind.results),
            # Alerts that never reached the deep analysis, by where they ended: the harness runs inside it.
            "not_investigated": dict(Counter(
                f"{now[i][0]}/{now[i][2] or now[i][3] or 'no decision'}" for i in after if not after[i].get("investigation"))),
            "verdict_moved_with_evidence": moved, "outcome_changed": changed,
            "outcome_changes": {i: {"off": was[i], "on": now[i], "verdict_off": before[i].get("verdict"),
                                    "verdict_on": after[i].get("verdict")} for i in changed},
        }
        write_report(REPORT, report)
