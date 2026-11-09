"""corpus_v1 (AI-E1.8): 520 labelled Wazuh 4.14 alerts replayed from cassettes through the real pipeline: the CI gate.

Every item is ingested as a Wazuh alert, run through the real graph and
routing policy, and answered from its committed cassette
(``tests/fixtures/eval/cassettes/corpus_v1/*.jsonl.gz``, recorded with the
fake model): no model, no network, no Wazuh lab. The report must pass
``corpus_v1_thresholds.yaml`` with model-led closure off (the default) and
at the autonomy tier ``auto_full_audit`` (FIX-1).

When a prompt or agent change makes the cassettes stale (a replay then fails
with "record it again"), record them again with ``make eval-corpus-cassettes``
(``LG_SOTF_RECORD_CASSETTES=1``). ``LG_SOTF_CORPUS_REPORT=path.json`` also
writes the replay's report (and its Markdown next to it).
"""

from __future__ import annotations

import os
import secrets
import shutil
from pathlib import Path

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.gate import evaluate_gate, load_thresholds
from lg_sotf.eval.report import build_report, render_markdown, write_json
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.llm.cassette import CassetteSet, cassette_name
from lg_sotf.settings import Settings
from tests.integration.eval._support import NetworkGuard, at_tier, block_network_and_model, closures, v3_closures

pytestmark = [pytest.mark.integration, pytest.mark.timeout(1800)]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
DATASET = FIXTURES / "corpus_v1.jsonl.gz"
THRESHOLDS = FIXTURES / "corpus_v1_thresholds.yaml"
CASSETTES = FIXTURES / "cassettes" / "corpus_v1"
RECORD = os.environ.get("LG_SOTF_RECORD_CASSETTES") == "1"
REPORT = os.environ.get("LG_SOTF_CORPUS_REPORT")
FAMILIES = {"sysmon", "windows", "syscheck", "audit", "sshd", "syslog", "web"}


async def test_corpus_v1_replays_offline_and_passes_its_gate(
    eval_settings: Settings, monkeypatch: pytest.MonkeyPatch, repos: Repositories
) -> None:
    dataset = load_dataset(DATASET)
    assert len(dataset.items) >= 500 and set(dataset.families()) == FAMILIES
    if RECORD:
        shutil.rmtree(CASSETTES, ignore_errors=True)
        recording = CassetteSet(CASSETTES, "record", source=f"lg-sotf eval {DATASET.name}",
                                dataset_sha256=dataset.sha256, compress=True)
        recorded = await run_evaluation(eval_settings, dataset, tenant_id=f"rec-cv1-{secrets.token_hex(3)}",
                                        cassettes=recording)
        assert [(r.item_id, r.error) for r in recorded.results if r.status == "error"] == []
    assert {p.name for p in CASSETTES.iterdir()} == {cassette_name(i.id) + ".gz" for i in dataset.items}

    # FIX-3: model-led closure on. Model closes change what later alerts' correlation shows to the model, so the
    # tier-off cassettes no longer answer every call: this run uses the fake model itself, with the network blocked.
    net = NetworkGuard(eval_settings)
    net.install(monkeypatch)
    on = await run_evaluation(eval_settings, at_tier(dataset, "auto_full_audit"),
                              tenant_id=f"play-cv1on-{secrets.token_hex(3)}")
    assert [(r.item_id, r.error) for r in on.results if r.status == "error"] == [] and net.attempts == []
    counts = await v3_closures(repos, on)
    assert counts["forbidden"] == [], counts

    guard = block_network_and_model(eval_settings, monkeypatch)
    replay = await run_evaluation(eval_settings, dataset, tenant_id=f"play-cv1-{secrets.token_hex(3)}",
                                  cassettes=CassetteSet(CASSETTES, "replay"))
    errors = [(r.item_id, r.error) for r in replay.results if r.status == "error"]
    assert not errors, f"stale cassettes, record them again with `make eval-corpus-cassettes`: {errors[:5]}"
    assert guard.attempts == []
    assert replay.info["llm_provider"] == "cassette"

    report = build_report(replay.results, dataset=dataset, run_info=replay.info)
    gate = evaluate_gate(report, load_thresholds(THRESHOLDS))
    if REPORT:
        report["gate"] = gate.as_dict()
        write_json(report, REPORT)
        Path(REPORT).with_suffix(".md").write_text(render_markdown(report, gate.as_dict()), encoding="utf-8")
    assert gate.passed, [v.message for v in gate.violations]
    metrics = report["metrics"]
    assert metrics["scored"] == len(dataset.items) and metrics["errors"] == 0
    assert set(report["families"]) == FAMILIES
    assert closures(replay.results)["benign_model_closed"] == 0  # the tier is off by default
