"""corpus_v1 with the analyst oracle: automation that learns from perfect analysts closes no attack.

With every escalation decided from the ground truth (``lg-sotf eval --oracle
propose|accept``), the mechanisms that learn from analysts (the verdict
cache and, with ``accept``, every suggested suppression rule enabled) closed
four attacks while they matched alerts by fingerprint alone: ``cv1-0113``,
``cv1-0309``, ``cv1-0440`` (malicious services next to benign service
installs on the same host) and ``cv1-0494`` (a web shell's ``ps`` next to
monitoring's). Both now match by verdict key, the cache needs two analyst
decisions, and a confirmed threat disables the rules that match it. Fake
model, real database, Redis, ingestion and workflow.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from lg_sotf.eval.closure import closure_summary
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.report import write_json
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.settings import Settings

pytestmark = [pytest.mark.integration, pytest.mark.timeout(3600)]

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_v1.jsonl.gz"
COLLISIONS = {"cv1-0113", "cv1-0309", "cv1-0440", "cv1-0494"}
REPORT_DIR = os.environ.get("LG_SOTF_ORACLE_REPORT_DIR")


@pytest.mark.parametrize("mode", ["propose", "accept"])
async def test_the_oracle_closes_no_attack_on_corpus_v1(eval_settings: Settings, mode: str) -> None:
    dataset = load_dataset(DATASET)
    run = await run_evaluation(
        eval_settings, dataset, tenant_id=f"oracle-{mode}-{secrets.token_hex(3)}", isolate="none",
        oracle=True, accept_suppressions=mode == "accept",
    )
    assert [(r.item_id, r.error) for r in run.results if r.status == "error"] == []
    summary = closure_summary(run.results)
    if REPORT_DIR:
        write_json({"run": run.info, "closure": summary}, str(Path(REPORT_DIR) / f"oracle-{mode}.json"))
    assert summary["malicious_closed"] == []
    assert summary["headline"]["malicious_auto_close"]["k"] == 0
    closed = {r.item_id for r in run.results if r.auto_closed}
    assert not closed & COLLISIONS
    # The learning still pays: analysts' repeated benign decisions close benign repeats.
    # 4 since FIX-2 (9 before): Wazuh authentication-failure rules outside credential access by ATT&CK (logon
    # failures mapped to T1531, the auth-failure rule groups) are a never-close class now, so they get no verdict key.
    assert summary["headline"]["benign_closure"]["k"] >= 4
