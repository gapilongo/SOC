"""Reviewer probe (PR 443): cv1-0351 with the harness off and on, alone or after the corpus items before it.

Kept as the reviewer wrote it. It only printed; the assertions at its end are added (marked), for the
review's decision that the evidence never buys this attack a close.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
from typing import Any

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.settings import Settings
from tests.integration.eval._investigation import DATASET, EVENTS, outcomes, records, with_harness
from tests.integration.eval._support import NetworkGuard, at_tier

pytestmark = [pytest.mark.integration, pytest.mark.timeout(1500)]

ITEM = "cv1-0351"


async def test_probe_cv1_0351(eval_settings: Settings, monkeypatch: pytest.MonkeyPatch, repos: Repositories, capsys: Any) -> None:
    full = load_dataset(DATASET)
    low = int(os.environ.get("PROBE_FROM", "351"))
    chosen = [i for i in full.items if low <= int(i.id.split("-")[1]) <= 351]
    assert chosen, "item not in corpus"
    dataset = at_tier(dataclasses.replace(full, items=chosen), "auto_full_audit")
    harness = eval_settings.model_copy(update={
        "investigation": eval_settings.investigation.model_copy(update={
            "evidence_backend": "event_store", "event_store_files": [str(DATASET), str(EVENTS)]}),
    })
    NetworkGuard(eval_settings).install(monkeypatch)
    off = await run_evaluation(eval_settings, dataset, tenant_id=f"p-off-{secrets.token_hex(3)}")
    on = await run_evaluation(harness, with_harness(dataset), tenant_id=f"p-on-{secrets.token_hex(3)}")
    before, after = await records(repos, off), await records(repos, on)
    record = after[ITEM].get("investigation") or {}
    out = {
        "expected": chosen[-1].expected.disposition, "family": chosen[-1].family, "items": len(chosen),
        "off": outcomes(off)[ITEM], "on": outcomes(on)[ITEM],
        "verdict_off": (before[ITEM].get("verdict"), before[ITEM].get("threat_score")),
        "verdict_on": (after[ITEM].get("verdict"), after[ITEM].get("threat_score")),
        "status": record.get("status"), "steps": [(s["evidence_id"], s["outcome"], s["complete"]) for s in record.get("steps", [])],
        "claims": record.get("claims"), "indicators": record.get("indicators"),
    }
    tenants = on.info["tenants"]
    last = [r for r in on.results if r.item_id == ITEM][0]
    alert = await repos.alerts.get(tenants.get(last.split) or tenants["*"], last.alert_id)
    out["rule_tp"] = (alert.summary.get("triage") or {}).get("rule_tp")
    out["severity"] = alert.severity
    facts = await repos.evidence_facts.list_for_run(alert.tenant_id, alert.id, record.get("run_id") or "")
    out["facts"] = [json.dumps(e.fact, default=str)[:900] for e in facts if e.fact]
    was, now = outcomes(off), outcomes(on)
    out["changed"] = {i: (was[i], now[i], before[i].get("verdict"), after[i].get("verdict")) for i in was if was[i] != now[i]}
    with capsys.disabled():
        print("\nPROBE_0351 " + json.dumps(out, default=str))
    # added: the probe only printed what it found (a T1110 attack the models closed once they were shown the host's
    # facts). The review's decision: with the harness on this attack is held by the evidence, never closed by it.
    assert out["expected"] != "benign" and out["on"][2] != "model_closed" and out["on"][3] is None
    assert out["on"][2] in ("evidence_indicator", "evidence_citation", "evidence_steering") or out["verdict_on"][0] != "benign"
    assert record.get("blocking") is not None
