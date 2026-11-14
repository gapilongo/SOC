"""Security review of PR #315 (AI-E1.5b): how a broken candidate is reported; where alert data goes; Redis untouched.

Adopted from the review with F2 and F3 flipped: a candidate that cannot reach its model, or whose model
answers are unusable, must not look healthy in the report.
"""

from __future__ import annotations

import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest
import redis.asyncio as aioredis

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.runtime.shadow_replay import ShadowRunOptions, run_shadow_replay
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.engine._support import suspicious_alert

pytestmark = pytest.mark.integration

LLM = "  fast: {model: m, max_retries: 0, timeout_s: 5}\n  deep: {model: m, max_retries: 0, timeout_s: 5}\n"


async def _decided(engine: WorkflowEngine, repos: Repositories) -> Tuple[str, str]:
    benign = await make_alert(
        repos, TENANT_A, title="Scheduled backup maintenance test job", severity="low",
        normalized={"rule_name": "scheduled-backup-maintenance-test", "entities": {"hosts": ["backup-01"]}},
    )
    suspicious = await suspicious_alert(repos)
    await engine.run(TENANT_A, benign)
    await engine.run(TENANT_A, suspicious)
    return benign, suspicious


async def test_unreachable_candidate_cannot_score_full_agreement(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, redis_client: aioredis.Redis,
    tmp_path: Path,
) -> None:
    _, suspicious = await _decided(engine, repos)
    keys_before = sorted(await redis_client.keys("*"))
    path = tmp_path / "broken.yaml"  # nothing listens on port 9
    path.write_text("name: broken\nllm:\n  provider: openai_compatible\n  base_url: http://127.0.0.1:9/v1\n" + LLM)
    report = await run_shadow_replay(
        _allow_local_candidates(engine_settings),
        ShadowRunOptions(tenant_id=TENANT_A, candidate=path, window=timedelta(days=1)),
    )
    # The escalated alert has no usable candidate verdict: it counts against the candidate and is listed.
    assert report.candidate_failed + report.candidate_degraded >= 1
    assert report.agreement.n == 2 and report.agreement.rate is not None and report.agreement.rate <= 0.5
    assert not report.enough_data
    assert any("production escalated or responded to" in w for w in report.data_warnings)
    assert suspicious in {c.alert_id for c in report.candidate_failures.items}
    assert report.potential_misses.count == 0
    # Production's Redis is untouched by the replay (sound).
    assert sorted(await redis_client.keys("*")) == keys_before


def _allow_local_candidates(settings: Settings) -> Settings:
    """The candidates here are local test servers: on the candidate LLM host allow-list (AI-E1.5c, F6)."""
    security = settings.security.model_copy(update={"shadow_candidate_llm_hosts": ["127.0.0.1"]})
    return settings.model_copy(update={"security": security})


class _GarbageLLM(BaseHTTPRequestHandler):
    bodies: List[str] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        _GarbageLLM.bodies.append(self.rfile.read(length).decode("utf-8", "replace"))
        _GarbageLLM.bodies.append("AUTH=" + str(self.headers.get("Authorization")))
        body = json.dumps({
            "id": "x", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "I cannot comply, here is prose not JSON"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return None


@pytest.fixture
def garbage_llm() -> Iterator[str]:
    _GarbageLLM.bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GarbageLLM)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


async def test_candidate_whose_model_output_is_unusable_is_reported_as_degraded(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, tmp_path: Path, garbage_llm: str,
) -> None:
    _, suspicious = await _decided(engine, repos)
    path = tmp_path / "garbage.yaml"
    path.write_text(f"name: garbage\nllm:\n  provider: openai_compatible\n  base_url: {garbage_llm}\n" + LLM)
    report = await run_shadow_replay(
        _allow_local_candidates(engine_settings),
        ShadowRunOptions(tenant_id=TENANT_A, candidate=path, window=timedelta(days=1)),
    )
    assert _GarbageLLM.bodies, "the candidate endpoint was called"
    # The model never produced a usable answer: the rules decided, and the report says so.
    rows = {r.alert_id: r for r in await repos.shadow_verdicts.list_for_report(TENANT_A, report.report_id)}
    assert rows[suspicious].cand_degraded > 0
    assert report.candidate_degraded >= 1 and report.compared <= 1
    assert report.agreement.rate is not None and report.agreement.rate <= 0.5 and not report.enough_data
    failure = next(c for c in report.candidate_failures.items if c.alert_id == suspicious)
    assert failure.candidate_degraded > 0 and failure.candidate_error is None
    # Tenant alert content reached the candidate's endpoint (expected for a model evaluation), but no
    # production key did: a self-hosted candidate on another endpoint sends none.
    assert any("suspicious" in b.lower() or "powershell" in b.lower() for b in _GarbageLLM.bodies)
    assert {b for b in _GarbageLLM.bodies if b.startswith("AUTH=")} == {"AUTH=Bearer no-key"}
