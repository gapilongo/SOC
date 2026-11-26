"""Shared by the tests of the investigation harness on corpus_v1: the dataset with the harness on, what it
did per item, and the stand-in model made blind to the evidence."""

from __future__ import annotations

import dataclasses
import json
import os
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import Dataset
from lg_sotf.eval.runner import EvalRun
from lg_sotf.llm import fake
from lg_sotf.llm.prompting import serialize_untrusted

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


EVIDENCE_CODES = ("evidence_steering", "evidence_indicator", "evidence_citation")
ITEM_0351 = "cv1-0351"
"""The T1110 attack the stand-in closed once it was shown its host's facts (review of PR 443, the major finding)."""


def held_by_evidence(run: EvalRun, analyses: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """The alerts only the evidence of their investigation kept from a model-led close (the decide code is the
    blocker's): by blocker and label, and for the indicator blocker which indicator held it."""
    by_blocker: Dict[str, Counter[str]] = {code: Counter() for code in EVIDENCE_CODES}
    indicators: Counter[str] = Counter()
    for result in run.results:
        if result.decision_code not in EVIDENCE_CODES:
            continue
        by_blocker[result.decision_code][result.expected] += 1
        blocking = (analyses[result.item_id].get("investigation") or {}).get("blocking") or {}
        if result.decision_code == "evidence_indicator":
            indicators.update(f"{name}/{result.expected}" for name in blocking.get("indicators") or {})
    return {"by_blocker": {code: dict(count) for code, count in by_blocker.items()}, "indicators": dict(indicators)}


def alone_on_host(dataset: Dataset, analyses: Mapping[str, Mapping[str, Any]], techniques: List[str]) -> Dict[str, Any]:
    """The alerts whose host raised nothing else in the hour: the host lookup is empty once the alert's own event
    is left out. ``own_event_would_show`` counts those whose own level or technique would have made an indicator
    true had the alert counted itself; ``true_indicators`` lists any alone alert with a true indicator (none)."""
    alone, loud, shown = [], [], []
    for item in dataset.items:
        record = analyses.get(item.id, {}).get("investigation")
        host = next((s for s in (record or {}).get("steps", []) if s["evidence_id"] == "host"), None)
        if record is None or host is None or host["outcome"] != "empty":
            continue
        alone.append(item.id)
        rule = item.alert.get("rule") or {}
        own = [str(t) for t in (rule.get("mitre") or {}).get("id") or []]
        if int(rule.get("level") or 0) >= 12 or any(t in techniques or t.split(".", 1)[0] in techniques for t in own):
            loud.append(item.id)
        if "true" in record["indicators"].values() or record["blocking"]["indicators"]:
            shown.append(item.id)
    return {"alerts": len(alone), "own_event_would_show": len(loud), "true_indicators": shown}


def own_event_listed(dataset: Dataset, facts: Mapping[str, List[Mapping[str, Any]]]) -> List[str]:
    """Items whose host-activity fact still lists the alert's own event (its rule at its instant): none."""
    listed = []
    for item in dataset.items:
        rule_id, at = str((item.alert.get("rule") or {}).get("id")), str(item.alert.get("timestamp"))[:23]
        for fact in facts.get(item.id, []):
            events = (fact.get("value") or {}).get("events") or []
            if fact.get("kind") == "host_activity" and any(e.get("rule_id") == rule_id and str(e.get("at"))[:23] == at[:23] for e in events):
                listed.append(item.id)
    return listed


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
