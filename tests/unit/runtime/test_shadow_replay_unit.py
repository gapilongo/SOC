"""``lg-sotf shadow-run`` (AI-E1.5b): the shadow-role gate, the window, the candidate profile, the candidate verdict."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.core.shadow import ShadowOutcome
from lg_sotf.core.shadow_replay import candidate_verdict, new_report_id
from lg_sotf.db.repos.shadow_verdicts import REPORT_ID, check_report_id, production_verdict
from lg_sotf.errors import OperationError
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.runtime.shadow_replay import NO_SHADOW_ROLE_FLAG, check_shadow_gate, load_candidate, parse_window
from lg_sotf.security.shadow import ShadowEffect, ShadowRun, note_llm_shortfall, shadow_scope
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit


@pytest.fixture
def env(settings_env: Any) -> Any:
    return settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL="postgresql://nobody:x@127.0.0.1:1/none_test",
    )


# ------------------------------------------------------------------ gate


def test_the_gate_refuses_without_the_shadow_role_or_the_dev_flag() -> None:
    with pytest.raises(OperationError, match="AI-E1.5c") as refused:
        check_shadow_gate(Settings(environment="development"), acknowledged=False)
    assert NO_SHADOW_ROLE_FLAG in str(refused.value)
    check_shadow_gate(Settings(environment="test"), acknowledged=True)


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_the_dev_flag_is_refused_in_production_config(environment: str) -> None:
    with pytest.raises(OperationError, match="not available in staging or production"):
        check_shadow_gate(Settings(environment=environment), acknowledged=True)  # type: ignore[arg-type]


def test_cli_refuses_before_touching_anything(env: Any, tmp_path: Path) -> None:
    profile = tmp_path / "cand.yaml"
    profile.write_text("name: cand\n")
    result = CliRunner().invoke(cli, ["shadow-run", "--tenant", "tenant-a", "--candidate", str(profile)])
    assert result.exit_code != 0
    assert "shadow database role" in result.output and "database unavailable" not in result.output


def test_cli_validates_the_window_before_touching_anything(env: Any, tmp_path: Path) -> None:
    profile = tmp_path / "cand.yaml"
    profile.write_text("name: cand\n")
    result = CliRunner().invoke(
        cli, ["shadow-run", "--tenant", "tenant-a", "--candidate", str(profile), "--window", "3w", NO_SHADOW_ROLE_FLAG]
    )
    assert result.exit_code != 0 and "--window" in result.output


# ---------------------------------------------------------------- inputs


def test_window_accepts_hours_and_days_up_to_90_days() -> None:
    assert parse_window("24h") == timedelta(hours=24)
    assert parse_window(" 7d ") == timedelta(days=7)
    assert parse_window("90d") == timedelta(days=90)
    for bad in ("0d", "91d", "7", "1w", "-1d", "7d;"):
        with pytest.raises(OperationError):
            parse_window(bad)


def test_candidate_profile_overrides_only_llm_and_agents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "local-model.yaml"
    path.write_text("llm:\n  fast:\n    model: candidate-fast-model\nagents:\n  triage:\n    llm_enabled: false\n")
    base = Settings(environment="test", llm={"provider": "fake"}, routing={"response_threshold": 70})
    label, candidate = load_candidate(base, path)
    assert label == "local-model"
    assert candidate.llm.fast.model == "candidate-fast-model"
    assert candidate.llm.provider == "fake" and candidate.llm.deep.model == base.llm.deep.model
    assert candidate.agents["triage"] == {"llm_enabled": False}
    assert candidate.routing == base.routing and candidate.database == base.database


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("routing:\n  response_threshold: 0\n", "only these keys"),
        ("- a\n", "only these keys"),
        ("name: 'bad|name'\n", "candidate name"),
        ("llm: [1]\n", "mappings"),
        ("llm:\n  provider: nope\n", "llm section is invalid"),
        ("llm: {unclosed\n", "not valid YAML"),
    ],
)
def test_candidate_profile_is_validated(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "cand.yaml"
    path.write_text(text)
    with pytest.raises(OperationError, match=message):
        load_candidate(Settings(environment="test"), path)


def test_production_api_key_never_follows_the_candidate_to_another_endpoint(tmp_path: Path) -> None:
    production = Settings(environment="test", llm={"provider": "anthropic", "api_key": "test-only-production-key"})
    path = tmp_path / "cand.yaml"
    path.write_text("llm:\n  provider: openai\n")
    with pytest.raises(OperationError, match="set its own llm.api_key"):
        load_candidate(production, path)
    path.write_text("llm:\n  provider: openai_compatible\n  base_url: http://llm.internal:8000/v1\n")
    _, local = load_candidate(production, path)
    assert local.llm.api_key is None
    path.write_text("llm:\n  provider: openai\n  api_key: test-only-candidate-key\n")
    _, own = load_candidate(production, path)
    assert own.llm.api_key is not None and own.llm.api_key.get_secret_value() == "test-only-candidate-key"
    path.write_text("llm:\n  fast: {model: claude-sonnet-4-5}\n")  # same provider and endpoint: the key stays
    _, same = load_candidate(production, path)
    assert same.llm.api_key == production.llm.api_key


def test_missing_or_huge_profile_is_refused(tmp_path: Path) -> None:
    with pytest.raises(OperationError, match="cannot read"):
        load_candidate(Settings(environment="test"), tmp_path / "missing.yaml")
    huge = tmp_path / "huge.yaml"
    huge.write_text("name: x\n" + "#" * 70_000)
    with pytest.raises(OperationError, match="64 KiB"):
        load_candidate(Settings(environment="test"), huge)


# -------------------------------------------------------------- verdicts


def _step(ms: int) -> NewTraceStep:
    from datetime import UTC, datetime

    return NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash="0" * 64, outcome="success",
                        latency_ms=ms, started_at=datetime.now(UTC))


def outcome(state: dict, effects: tuple = (), trace: tuple = ()) -> ShadowOutcome:  # type: ignore[type-arg]
    return ShadowOutcome(run_id="shadow/x", state=state, interrupt=None, effects=effects, trace=trace,
                         llm_calls=2, llm_tokens=1200, llm_cost_usd=Decimal("0.0042"))


def test_candidate_verdict_reads_the_routing_decision_plan_and_usage() -> None:
    plan = ShadowEffect(3, "response_plan", "ResponseService.plan", "sunk",
                        {"threat_type": "c2", "actions": ["isolate_host:ws-1", "block_ip:203.0.113.7"]})
    v = candidate_verdict(outcome(
        {"decision": {"route": "plan_response", "disposition": "malicious"}, "confidence": 91},
        effects=(ShadowEffect(0, "alert", "AlertsRepo.update", "sunk", {}), plan),
        trace=(_step(300), _step(450)),
    ))
    assert (v.route, v.disposition, v.confidence) == ("plan_response", "malicious", 91.0)
    assert v.actions == ("block_ip:203.0.113.7", "isolate_host:ws-1")
    assert (v.tokens, v.cost_usd, v.latency_ms) == (1200, Decimal("0.0042"), 750)


def test_unusable_or_refused_model_answers_make_the_verdict_degraded() -> None:
    run = ShadowRun("shadow/count")
    note_llm_shortfall("unusable")  # live: nothing to count, nothing raised
    with shadow_scope(run):
        for kind in ("skipped", "unusable", "unusable", "refused"):
            note_llm_shortfall(kind)  # type: ignore[arg-type]
    assert (run.llm_skipped, run.llm_unusable, run.llm_refused) == (1, 2, 1)
    degraded = ShadowOutcome(run_id="shadow/x", state={"decision": {"route": "escalate"}}, interrupt=None, effects=(),
                             trace=(), llm_skipped=1, llm_unusable=2, llm_refused=1)
    assert candidate_verdict(degraded).degraded == 3  # a deliberate skip (rules decisive) is not degradation


def test_candidate_verdict_without_a_decision() -> None:
    suppressed = candidate_verdict(outcome({"gate": {"suppressed": True}, "disposition": "benign"}))
    assert (suppressed.route, suppressed.disposition) == ("close", "benign")
    triage_closed = candidate_verdict(outcome({"disposition": "benign", "confidence": 12}))
    assert triage_closed.route == "close"
    unfinished = candidate_verdict(outcome({"decision": {"route": "made-up"}, "confidence": "high"}))
    assert (unfinished.route, unfinished.confidence) == (None, None)


def test_production_verdict_reads_stored_values_defensively() -> None:
    decided = production_verdict({
        "decision": {"route": "escalate", "disposition": None}, "status": "closed", "disposition": "benign",
        "confidence": 55.0, "actions": ["block_ip:203.0.113.7"], "latency_ms": 1200,
        "llm_usage": {"total_tokens": 900, "cost_usd": 0.0031},
    })
    assert (decided.route, decided.disposition, decided.tokens, decided.cost_usd) == (
        "escalate", None, 900, Decimal("0.0031")
    )
    closed = production_verdict({"decision": None, "status": "closed", "disposition": "benign",
                                 "llm_usage": {"total_tokens": -5, "cost_usd": "NaN"}})
    assert (closed.route, closed.disposition, closed.tokens, closed.cost_usd) == ("close", "benign", 0, Decimal(0))
    pending = production_verdict({"decision": "garbage", "status": "waiting_human", "llm_usage": [1]})
    assert pending.route is None and pending.tokens == 0


def test_report_ids() -> None:
    assert REPORT_ID.fullmatch(new_report_id())
    assert new_report_id() != new_report_id()
    with pytest.raises(ValueError, match="shr_"):
        check_report_id("shr_../../etc")
