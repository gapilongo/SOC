"""Security review of PR #315 (AI-E1.5b): candidate profile, API key, gate, report statistics.

Adopted from the review with F1, F2 and F5a flipped to assert the safe behaviour. F4 (the gate trusts the
``environment`` setting) is deferred to AI-E1.5c and documented; its test pins today's behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from lg_sotf.domain.shadow_agreement import Comparison, Verdict, build_report
from lg_sotf.errors import OperationError
from lg_sotf.llm.client import clear_model_cache, get_chat_model
from lg_sotf.runtime.shadow_replay import check_shadow_gate, load_candidate
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit

SECRET = "process-secret-jwt-0123456789abcdef0123456789"


# ---------------------------------------------------------------- F1: ${VAR} in a candidate profile


def test_candidate_profile_cannot_route_a_process_secret_to_its_own_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LG_SOTF_AUTH__JWT_SECRET", SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-production-key")
    path = tmp_path / "vendor-tuned.yaml"
    path.write_text(
        "llm:\n"
        "  provider: openai_compatible\n"
        "  base_url: https://llm.vendor.example/v1\n"
        "  api_key: ${LG_SOTF_AUTH__JWT_SECRET}\n"
    )
    production = Settings(environment="development", llm={"provider": "anthropic"})
    assert production.llm.api_key is not None  # from ANTHROPIC_API_KEY
    # Refused: only CANDIDATE_ variables may be named, so the JWT signing secret cannot become a bearer token.
    with pytest.raises(OperationError, match="CANDIDATE_"):
        load_candidate(production, path)
    # The production key, named explicitly, is refused for the same reason...
    path.write_text(
        "llm:\n  provider: anthropic\n  base_url: https://llm.vendor.example\n  api_key: ${ANTHROPIC_API_KEY}\n"
    )
    with pytest.raises(OperationError, match="CANDIDATE_"):
        load_candidate(production, path)
    # ...and copied into a CANDIDATE_ variable (or pasted literally) it is refused by value.
    monkeypatch.setenv("CANDIDATE_API_KEY", "sk-ant-production-key")
    path.write_text(
        "llm:\n  provider: anthropic\n  base_url: https://llm.vendor.example\n  api_key: ${CANDIDATE_API_KEY}\n"
    )
    with pytest.raises(OperationError, match="production's key"):
        load_candidate(production, path)
    path.write_text("llm:\n  provider: openai\n  api_key: sk-ant-production-key\n")
    with pytest.raises(OperationError, match="production's key"):
        load_candidate(production, path)
    # And no secret in the URL path: ${...} is never expanded in base_url (or anywhere but llm.api_key).
    path.write_text(
        "llm:\n  provider: openai_compatible\n  base_url: https://llm.vendor.example/v1/${LG_SOTF_AUTH__JWT_SECRET}\n"
    )
    with pytest.raises(OperationError, match="only in llm.api_key"):
        load_candidate(production, path)
    path.write_text("name: x\nagents:\n  triage:\n    note: ${CANDIDATE_API_KEY}\n")
    with pytest.raises(OperationError, match="only in llm.api_key"):
        load_candidate(production, path)


def test_candidate_key_comes_from_a_candidate_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-production-key")
    monkeypatch.setenv("CANDIDATE_VENDOR_KEY", "test-only-candidate-key")
    production = Settings(environment="development", llm={"provider": "anthropic"})
    path = tmp_path / "cand.yaml"
    path.write_text("llm:\n  provider: openai\n  api_key: ${CANDIDATE_VENDOR_KEY}\n")
    _, cand = load_candidate(production, path)
    assert cand.llm.api_key is not None and cand.llm.api_key.get_secret_value() == "test-only-candidate-key"
    path.write_text("llm:\n  provider: openai\n  api_key: prefix-${CANDIDATE_VENDOR_KEY}\n")
    with pytest.raises(OperationError, match="CANDIDATE_"):
        load_candidate(production, path)


# ---------------------------------------------------------------- sound: no implicit production key


@pytest.mark.parametrize("env_key", ["OPENAI_API_KEY", "LG_SOTF_LLM__API_KEY"])
def test_self_hosted_candidate_never_falls_back_to_an_env_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_key: str
) -> None:
    monkeypatch.setenv(env_key, "sk-production-key")
    production = Settings(environment="development", llm={"provider": "openai"})
    assert production.llm.api_key is not None
    path = tmp_path / "cand.yaml"
    path.write_text("llm:\n  provider: openai_compatible\n  base_url: https://evil.example/v1\n")
    _, cand = load_candidate(production, path)
    clear_model_cache()
    model = get_chat_model("fast", cand)
    assert model.openai_api_key.get_secret_value() == "no-key"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "text",
    [
        "llm:\n  base_url: https://evil.example/v1\n",
        "llm:\n  provider: gemini\n",
        # An unset CANDIDATE_ variable is no key at all.
        "llm:\n  provider: openai\n  base_url: https://evil.example/v1\n  api_key: ${CANDIDATE_UNSET_VAR_XYZ}\n",
    ],
)
def test_cloud_candidate_on_another_endpoint_needs_its_own_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-production-key")
    monkeypatch.setenv("GOOGLE_API_KEY", "g-production-key")
    monkeypatch.delenv("CANDIDATE_UNSET_VAR_XYZ", raising=False)
    production = Settings(environment="development", llm={"provider": "openai"})
    path = tmp_path / "cand.yaml"
    path.write_text(text)
    with pytest.raises(OperationError, match="set its own llm.api_key"):
        load_candidate(production, path)


# ---------------------------------------------------------------- F4 (deferred to AI-E1.5c, documented)


def test_gate_is_open_when_no_environment_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LG_SOTF_ENVIRONMENT", "LG_SOTF_ENV"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.environment == "development"
    check_shadow_gate(settings, acknowledged=True)  # passes: only the default says this is not production


# ---------------------------------------------------------------- F2: failures count against the candidate


def _row(i: int, prod: Optional[str], cand: Optional[str], severity: str = "medium", error: Optional[str] = None,
         degraded: int = 0) -> Comparison:
    return Comparison(alert_id=f"a{i:03d}", severity=severity, production=Verdict(route=prod),
                      candidate=Verdict(route=cand, error=error, degraded=degraded))


def test_a_candidate_that_fails_on_every_escalation_cannot_score_full_agreement() -> None:
    rows = [_row(i, "close", "close", "low") for i in range(30)]
    rows += [_row(100 + i, "escalate", None, "critical", error="TimeoutError") for i in range(30)]
    r = build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="c")
    # Failures are disagreements: 30 of 60, and the report says it is not enough to judge on.
    assert r.agreement.rate == 0.5 and r.agreement.n == 60
    assert not r.enough_data
    assert any("failed on 30 alert(s) production escalated" in w for w in r.data_warnings)
    assert any("30 of 60 candidate runs failed" in w for w in r.data_warnings)
    # The usable-only figure is shown beside the headline, never instead of it.
    assert r.agreement_usable.rate == 1.0 and r.agreement_usable.n == 30
    escalate = next(c for c in r.by_class if c.production_route == "escalate")
    assert escalate.agreement.n == 30 and escalate.agreement.rate == 0.0
    assert r.candidate_failed == 30
    # The 30 critical alerts the candidate could not decide are listed, most severe first.
    assert r.candidate_failures.count == 30
    assert all(c.alert_id.startswith("a1") and c.candidate_error == "TimeoutError" for c in r.candidate_failures.items)
    assert r.confusion["escalate"]["none"] == 30


def test_a_degraded_run_is_a_failure_not_a_verdict() -> None:
    rows = [_row(i, "escalate", "escalate", "high", degraded=2) for i in range(3)]
    r = build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="c")
    assert (r.compared, r.candidate_degraded, r.candidate_failed) == (0, 3, 0)
    assert r.agreement.rate == 0.0 and not r.enough_data
    assert r.candidate_failures.count == 3 and r.candidate_failures.items[0].candidate_degraded == 2


def test_failure_rate_above_the_threshold_is_not_enough_data() -> None:
    rows = [_row(i, "close", "close", "low") for i in range(95)]
    rows += [_row(200 + i, "close", None, "low", error="TimeoutError") for i in range(5)]
    assert build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="c").enough_data  # 5% is ok
    rows.append(_row(300, "close", None, "low", error="TimeoutError"))
    r = build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="c")
    assert not r.enough_data and r.data_warnings == ["6 of 101 candidate runs failed or fell back to rules (more than 5%)"]


# ---------------------------------------------------------------- F5a: escalate <-> plan_response


def test_escalate_to_plan_response_disagreements_are_listed_next_to_the_misses() -> None:
    rows = [_row(i, "escalate", "plan_response", "low") for i in range(5)]
    rows += [_row(50, "plan_response", "escalate", "critical")]
    r = build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="c")
    assert r.agreement.rate == 0.0
    assert r.routing_differences.count == 6
    # A human was wanted and the candidate would act automatically: those come first, whatever the severity.
    assert [c.production_route for c in r.routing_differences.items] == ["escalate"] * 5 + ["plan_response"]
    assert r.potential_misses.count == r.new_escalations.count == r.plan_differences.count == 0
