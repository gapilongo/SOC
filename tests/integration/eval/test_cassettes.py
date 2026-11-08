"""Cassettes: a recorded evaluation replays offline with the same verdicts (AI-E1.4).

The acceptance test records a run live (a scripted model that looks a file
hash up, a VirusTotal key answered by a mock transport), then replays it in a
fresh tenant with every outbound connection blocked and the configured model
unusable: same verdict, routing and disposition, zero network calls.

The committed cassettes under ``tests/fixtures/eval/cassettes/`` (fake model)
are replayed the same way and compared with a live fake-model run. When a
prompt or agent change makes them stale, record them again with
``make eval-cassettes`` (``LG_SOTF_RECORD_CASSETTES=1``).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Tuple

import httpx
import pytest

from lg_sotf.agents.registry import AgentSet
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import EvalItem, load_dataset, parse_dataset
from lg_sotf.eval.results import ItemResult
from lg_sotf.eval.runner import EvalRunner, open_engine, run_evaluation
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.llm.cassette import CassetteSet, cassette_name, recording_model_factory
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from tests.integration.eval._support import block_network_and_model

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
COMMITTED = {"synthetic_v1": 12, "phishing_v1": 8}
"""Committed cassette sets: dataset name -> the first N items recorded."""
RECORD = os.environ.get("LG_SOTF_RECORD_CASSETTES") == "1"
SUBSET = ("syn-001", "syn-031", "syn-015", "syn-007", "adv-003")
HASH_ITEM = {
    "id": "it-cassette-hash",
    "source_type": "canonical",
    "alert": {
        "source_alert_id": "it-cassette-hash-1",
        "title": "Suspicious binary executed from a temp directory",
        "severity": "high",
        "description": "Unsigned executable launched by a script host; file hash attached for reputation.",
        "entities": {"hosts": ["ws-17"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"]},
    },
    "expected": {"disposition": "malicious"},
}
# The model's first investigation step looks the hash up; the heuristic fake model would finish instead,
# so the replay can only reach the same verdict from the cassette.
LOOKUP = {
    "thought": "check the file hash", "threat_score": 60, "certainty": 40, "verdict": "inconclusive",
    "conclusion": "reputation needed", "recommended_actions": [], "action": "lookup", "target": "i1",
}
COMPARED = ("status", "predicted", "route", "disposition", "escalated", "decision_code", "severity", "review")


def vt_transport(calls: List[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        stats = {"malicious": 41, "suspicious": 2, "harmless": 0, "undetected": 20}
        body = {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -80, "tags": ["peexe"]}}}
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


@pytest.fixture
def settings(eval_settings: Settings) -> Settings:
    """The evaluation settings plus an install VirusTotal key shared with every tenant."""
    vt = {"api_key": "test-only-vt", "share_with_tenants": True, "requests_per_minute": 0}
    return eval_settings.model_copy(update={"tools": {**eval_settings.tools, "virustotal": vt}})


def items() -> List[EvalItem]:
    dataset = load_dataset(FIXTURES / "synthetic_v1.jsonl")
    return [parse_dataset(json.dumps(HASH_ITEM)).items[0], *(i for i in dataset.items if i.id in SUBSET)]


async def run_items(
    tenant: str, engine: WorkflowEngine, db: Database, repos: Repositories, settings: Settings, cassettes: CassetteSet
) -> Dict[str, ItemResult]:
    await repos.tenants.create(tenant, f"Evaluation {tenant}")
    ingestion = IngestionService(db, settings)
    try:
        runner = EvalRunner(
            tenant_id=tenant, repos=repos, ingestion=ingestion, engine=engine,
            run_timeout_s=settings.worker.run_timeout_s, cassettes=cassettes,
        )
        return {r.item_id: r for r in await runner.run(items())}
    finally:
        await ingestion.close()
        await engine.close()


def written(directory: Path, item_id: str) -> Tuple[List[str], List[str]]:
    """The cassette files in ``directory`` and the lines of one item's cassette."""
    names = sorted(p.name for p in directory.iterdir())
    return names, (directory / cassette_name(item_id)).read_text().splitlines()


def outcomes(results: Any) -> Dict[str, Tuple[Any, ...]]:
    return {r.item_id: tuple(getattr(r, name) for name in COMPARED) for r in results}


async def test_a_recorded_run_replays_offline_with_identical_outcomes(
    settings: Settings, db: Database, repos: Repositories, redis_client: Any, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vt_calls: List[str] = []
    enrichment = EnrichmentService.from_settings(settings, transport=vt_transport(vt_calls))
    scripted = ScriptedChatModel(model_name="fake-scripted", script={"InvestigationStep": [LOOKUP]})
    agents = AgentSet.build(
        settings, model_factory=recording_model_factory(lambda tier, s: scripted), enrichment=enrichment
    )
    engine = await WorkflowEngine.create(
        settings=settings, db=db, redis=redis_client, events=None, agents=agents, checkpoint_pool_size=3
    )
    recorded = await run_items("eval-cas-rec", engine, db, repos, settings, CassetteSet(tmp_path, "record"))
    assert all(r.status != "error" for r in recorded.values()), [(r.item_id, r.error) for r in recorded.values()]
    assert vt_calls, "the live run looks the hash up"
    names, lines = written(tmp_path, "it-cassette-hash")
    assert names == sorted(cassette_name(item_id) for item_id in recorded)
    tools = [json.loads(line).get("tool") for line in lines[1:]]
    assert "reputation" in tools and "history" in tools and "test-only-vt" not in "".join(lines)

    # Replay in a fresh tenant: every outbound connection blocked, the configured model unusable.
    guard = block_network_and_model(settings, monkeypatch)
    replay_engine = await open_engine(settings, db, redis_client, 1, cassettes=CassetteSet(tmp_path, "replay"))
    replayed = await run_items("eval-cas-play", replay_engine, db, repos, settings, CassetteSet(tmp_path, "replay"))

    assert guard.attempts == []
    assert outcomes(replayed.values()) == outcomes(recorded.values())
    for item_id, result in replayed.items():
        assert (result.llm_calls, result.total_tokens) == (recorded[item_id].llm_calls, recorded[item_id].total_tokens)
    # The guard is live: a lookup the replay had made would have been caught.
    with pytest.raises(httpx.ConnectError):
        async with httpx.AsyncClient() as client:
            await client.get("https://www.virustotal.com/api/v3/files/x")
    assert guard.attempts == ["http www.virustotal.com"]


async def test_a_missing_cassette_fails_the_item_instead_of_calling_out(
    settings: Settings, db: Database, repos: Repositories, redis_client: Any, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = block_network_and_model(settings, monkeypatch)
    engine = await open_engine(settings, db, redis_client, 1, cassettes=CassetteSet(tmp_path, "replay"))
    results = await run_items("eval-cas-miss", engine, db, repos, settings, CassetteSet(tmp_path, "replay"))
    malicious = results["syn-001"]
    assert malicious.status == "error" and "no cassette file" in (malicious.error or "")
    assert guard.attempts == []


@pytest.mark.parametrize("name", sorted(COMMITTED))
async def test_the_committed_cassettes_replay_offline_like_a_live_run(
    name: str, eval_settings: Settings, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    dataset = load_dataset(FIXTURES / f"{name}.jsonl").select(limit=COMMITTED[name])
    directory = FIXTURES / "cassettes" / name
    if RECORD:
        shutil.rmtree(directory, ignore_errors=True)
        recording = CassetteSet(directory, "record", source=f"lg-sotf eval {name}.jsonl", dataset_sha256=dataset.sha256)
        recorded = await run_evaluation(eval_settings, dataset, tenant_id=f"rec-{name[:9]}", cassettes=recording)
        assert all(r.status != "error" for r in recorded.results), [r.error for r in recorded.results]
    live = await run_evaluation(eval_settings, dataset, tenant_id=f"live-{name[:9]}")

    guard = block_network_and_model(eval_settings, monkeypatch)
    replay = await run_evaluation(
        eval_settings, dataset, tenant_id=f"play-{name[:9]}", cassettes=CassetteSet(directory, "replay")
    )
    errors = [(r.item_id, r.error) for r in replay.results if r.status == "error"]
    assert not errors, f"stale cassettes, record them again with `make eval-cassettes`: {errors}"
    assert guard.attempts == []
    assert outcomes(replay.results) == outcomes(live.results)
    assert replay.info["llm_provider"] == "cassette" and replay.info["cassettes"]["mode"] == "replay"
