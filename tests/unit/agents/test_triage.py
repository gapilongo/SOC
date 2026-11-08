"""Triage: field-specific rules, LLM only in the ambiguous band, refusal/invalid/budget fall back to rules."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest

import lg_sotf.agents.base as agent_base
from lg_sotf.agents.triage.base import (
    TriageAgent,
    decisive_reason,
    evidence_words,
    llm_band,
    priority_for,
    rule_confidence,
    rule_indicators,
)
from lg_sotf.llm.errors import LLMBudgetExceeded
from lg_sotf.llm.fake import Invalid, Refuse, Truncate
from lg_sotf.observability.metrics import REGISTRY
from lg_sotf.settings import Settings
from tests.unit.agents._support import (
    AMBIGUOUS,
    ASSESSMENT,
    BENIGN,
    MALICIOUS,
    ctx,
    factory,
    fake_repos,
    scripted,
)


def metric(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, {"mode": "live", **labels}) or 0.0


def test_rule_scoring() -> None:
    assert rule_confidence(BENIGN) == 0
    assert rule_confidence(MALICIOUS) == 100
    fp, tp = rule_indicators(BENIGN)
    assert {"test_detected", "scheduled_detected", "maintenance_detected", "backup_detected"} <= set(fp)
    fp, tp = rule_indicators(MALICIOUS)
    assert {"malware_detected", "suspicious_port", "file_hash_present"} <= set(tp)


def test_tp_evidence_comes_from_specific_fields_not_the_whole_alert() -> None:
    """A keyword in an arbitrary key, value or nested raw field is not evidence; command lines are."""
    noise = {
        "title": "Outbound connection",
        "severity": "medium",
        "source_id": "fw-prod",
        "malware_scan_result": "clean",
        "raw": {"note": "no malware or backdoor here", "http_user_agent": "exploit-kit/1.0"},
        "entities": {"users": ["trojan.horse@example.com"]},
    }
    assert rule_indicators(noise)[1] == []
    assert rule_confidence(noise) == 60
    cmd = {**noise, "raw": {"command_line": "C:\\tools\\mimikatz.exe sekurlsa::logonpasswords"}}
    assert "mimikatz_detected" in rule_indicators(cmd)[1]
    mitre = {**noise, "mitre": {"tactics": ["Persistence"], "techniques": ["T1053"]}}
    assert "persistence_detected" in rule_indicators(mitre)[1]
    # Whole words only: "antimalware" is not "malware"; plural forms count.
    assert "malware" not in evidence_words({"title": "antimalware service restarted"})
    assert "credential_detected" in rule_indicators({"title": "Credentials dumped", "severity": "low"})[1]


def test_priority_scale() -> None:
    assert priority_for("critical", 95) == 10
    assert priority_for("info", 10) == 1
    assert 1 <= priority_for("unknown", 60) <= 10


def test_llm_band_follows_routing_thresholds() -> None:
    assert llm_band({}) == (10, 80)
    assert llm_band({"triage_close_max_confidence": 5, "response_threshold": 90}) == (5, 90)
    assert llm_band({"triage_llm_min": 20, "triage_llm_max": 70}) == (20, 70)
    assert decisive_reason("medium", 50, [], [], {}) is None
    assert decisive_reason("critical", 85, [], ["x"], {}) is not None
    assert decisive_reason("low", 0, ["test_detected", "backup_detected"], [], {}) is not None
    # Rules alone would close it (FP majority at low confidence): decisive even inside the band.
    assert decisive_reason("low", 15, ["a", "b", "c"], [], {}) is not None
    assert decisive_reason("high", 15, ["a", "b", "c"], [], {}) is None


@pytest.mark.parametrize("alert", [BENIGN, MALICIOUS])
async def test_decisive_rule_outcomes_skip_the_llm(make_settings: Callable[..., Settings], alert: dict) -> None:
    settings = make_settings()
    model = scripted()
    before = metric("lgsotf_llm_skipped_total", agent="triage", reason="rules_decisive")
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), alert)
    assert model.calls == []
    assert not result.llm_used and result.llm_skipped == "rules_decisive"
    assert result.confidence == result.rule_confidence
    assert metric("lgsotf_llm_skipped_total", agent="triage", reason="rules_decisive") == before + 1


async def test_ambiguous_alert_calls_the_llm_once_and_blends(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    model = scripted(TriageAssessment=[ASSESSMENT])
    repos = fake_repos()
    c = ctx(settings, repos=repos)
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(c, AMBIGUOUS)
    assert len(model.calls) == 1 and model.calls[0].schema == "TriageAssessment"
    assert result.llm_used and result.rule_confidence == 60
    assert result.confidence == round(60 * 0.6 + 90 * 0.4)
    assert result.llm_tp == ["beaconing interval"] and result.threat_assessment == "likely_threat"
    usage = repos.alerts.rows[("t1", "a1")].summary["llm_usage"]
    assert usage["calls"] == 1 and usage["by_agent"]["triage"]["calls"] == 1
    assert usage["input_tokens"] > 0 and usage["output_tokens"] > 0 and usage["total_tokens"] > 0


async def test_always_consult_llm_turns_gating_off(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(agents={"triage": {"always_consult_llm": True}})
    model = scripted()
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), BENIGN)
    assert len(model.calls) == 1 and result.llm_used


async def test_refusal_falls_back_to_rules_and_is_marked(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    c = ctx(settings, repos=repos)
    model = scripted(TriageAssessment=[Refuse("cyber")])
    before = metric("lgsotf_llm_refusals_total", agent="triage", category="cyber")
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(c, AMBIGUOUS)
    assert not result.llm_used and result.confidence == result.rule_confidence
    assert result.llm_refusal == {"reason": "model_refused", "category": "cyber", "agent": "triage"}
    assert result.digest()["llm_refusal"]["reason"] == "model_refused"
    assert c.refusals == [{"agent": "triage", "category": "cyber"}]
    assert metric("lgsotf_llm_refusals_total", agent="triage", category="cyber") == before + 1
    summary = repos.alerts.rows[("t1", "a1")].summary
    assert summary["llm_refusals"] == [{"agent": "triage", "category": "cyber"}]
    assert summary["llm_usage"]["refusals"] == 1
    assert any("declined" in n for n in result.notes)


@pytest.mark.parametrize("item", [Invalid(), Truncate()])
async def test_unusable_output_falls_back_to_rules(make_settings: Callable[..., Settings], item: Any) -> None:
    settings = make_settings()
    model = scripted(TriageAssessment=[item])
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), AMBIGUOUS)
    assert len(model.calls) == 1
    assert not result.llm_used and result.confidence == result.rule_confidence == 60
    assert result.llm_skipped == "LLMOutputError" and "llm_refusal" not in result.digest()
    assert result.notes


class ExhaustedBudget:
    async def check_and_reserve(self, tenant_id: str, estimate: int, *, limit: Any = None) -> Any:
        raise LLMBudgetExceeded(tenant_id, limit=1, used=1, requested=estimate)


async def test_budget_exhaustion_is_remembered_and_flagged_in_summary(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    c = ctx(settings, repos=repos, budget=ExhaustedBudget())  # type: ignore[arg-type]
    model = scripted()
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(c, AMBIGUOUS)
    assert c.llm_budget_exceeded and model.calls == []
    assert result.llm_skipped == "budget_exceeded" and result.confidence == result.rule_confidence
    summary = repos.alerts.rows[("t1", "a1")].summary
    assert summary["llm_budget_exceeded"] is True
    assert summary["llm_usage"]["budget_exceeded"] == 1 and summary["llm_usage"]["calls"] == 0


async def test_budget_already_exceeded_skips_without_writing(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    model = scripted()
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(
        ctx(settings, repos=repos, llm_budget_exceeded=True), AMBIGUOUS
    )
    assert model.calls == [] and result.llm_skipped == "budget_exceeded"
    assert repos.alerts.updates == []


async def test_transport_errors_propagate(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down(*args: Any, **kwargs: Any) -> Any:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(agent_base, "ainvoke_structured", down)
    settings = make_settings()
    with pytest.raises(httpx.ConnectError):
        await TriageAgent(settings=settings).run(ctx(settings), AMBIGUOUS)


async def test_llm_disabled_uses_rules(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(llm={"enabled": False})
    result = await TriageAgent(settings=settings).run(ctx(settings), AMBIGUOUS)
    assert not result.llm_used and result.llm_skipped == "disabled"


async def test_no_llm_call_means_no_summary_write(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    await TriageAgent(settings=settings, model_factory=factory(scripted())).run(ctx(settings, repos=repos), BENIGN)
    assert repos.alerts.updates == []


def test_agent_is_stateless_singleton(make_settings: Callable[..., Settings]) -> None:
    agent = TriageAgent(settings=make_settings(agents={"triage": {"llm_weight": 0.5}}))
    assert agent.llm_weight == 0.5
    with pytest.raises(ValueError):
        TriageAgent(settings=make_settings(agents={"triage": {"llm_weight": 2}}))


# ------------------------------------------------ attacker-writable keywords never make triage decisive

KEYWORDS_IN_COMMAND_LINE = {
    "title": "Process execution",
    "severity": "medium",
    "source_id": "edr-prod",
    "occurred_at": "2026-09-01T10:00:00Z",
    "entities": {"hosts": ["dc-01"], "command_lines": ["cmd /c echo malware backdoor exploit"]},
}
CONFIRMED = {**ASSESSMENT, "threat_likelihood": 100, "threat_assessment": "confirmed_threat"}


def test_trusted_score_ignores_attacker_writable_fields() -> None:
    from lg_sotf.agents.triage.base import trusted_rule_confidence

    assert rule_confidence(KEYWORDS_IN_COMMAND_LINE) == 100
    assert trusted_rule_confidence(KEYWORDS_IN_COMMAND_LINE) == 60
    assert trusted_rule_confidence(MALICIOUS) == rule_confidence(MALICIOUS) == 100
    assert decisive_reason("medium", 100, [], ["malware_detected"], {}, trusted=60) is None
    assert decisive_reason("medium", 100, [], ["malware_detected"], {}, trusted=85) is not None


@pytest.mark.parametrize("answer", [CONFIRMED, Invalid()], ids=["model-agrees", "model-unusable"])
async def test_keywords_in_a_command_line_consult_the_model_and_stay_below_the_combo_level(
    make_settings: Callable[..., Settings], answer: Any
) -> None:
    """Keywords an attacker writes can raise the score, but never skip the model or reach response_combo_confidence."""
    from lg_sotf.domain import routing
    from lg_sotf.domain.routing import RoutingThresholds

    settings = make_settings()
    model = scripted(TriageAssessment=[answer])
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), KEYWORDS_IN_COMMAND_LINE)
    assert len(model.calls) == 1 and result.llm_skipped != "rules_decisive"
    assert result.rule_score == 100 and result.trusted_score == 60
    t = RoutingThresholds()
    assert result.confidence == t.response_combo_confidence - 1
    assert result.rule_confidence == t.response_threshold - 1
    # An unsure analysis (threat 60) no longer meets the combo rule on the strength of those keywords.
    state = {
        "severity": "medium",
        "confidence": result.confidence,
        "triage": result.digest(),
        "analysis": {"threat_score": 60, "rule_threat_score": 60, "verdict": "inconclusive"},
    }
    assert routing.decide(state, t).route == "escalate"


async def test_trusted_decisive_rules_skip_the_model_but_never_reach_the_combo_level(
    make_settings: Callable[..., Settings],
) -> None:
    settings = make_settings()
    model = scripted()
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), MALICIOUS)
    assert model.calls == [] and result.llm_skipped == "rules_decisive"
    assert (result.rule_score, result.trusted_score, result.confidence, result.rule_confidence) == (100, 100, 79, 79)
    assert result.priority == 10  # urgency still reflects the full rule score


def test_confidence_bounds() -> None:
    from lg_sotf.agents.triage.base import confidence_bounds
    from lg_sotf.domain.routing import RoutingThresholds

    t = RoutingThresholds()
    assert confidence_bounds(t, model_consulted=True, trusted=60, rules_close=False, refused=False) == (21, 79)
    assert confidence_bounds(t, model_consulted=True, trusted=85, rules_close=False, refused=False) == (21, 100)
    assert confidence_bounds(t, model_consulted=True, trusted=60, rules_close=True, refused=False) == (0, 79)
    assert confidence_bounds(t, model_consulted=False, trusted=95, rules_close=False, refused=False) == (0, 79)
    assert confidence_bounds(t, model_consulted=False, trusted=15, rules_close=False, refused=True) == (30, 79)
    custom = RoutingThresholds(triage_fp_majority_max_confidence=35, response_combo_confidence=90)
    assert confidence_bounds(custom, model_consulted=True, trusted=60, rules_close=False, refused=False) == (36, 89)


async def test_a_persuaded_model_cannot_pull_an_alert_into_the_triage_close_region(
    make_settings: Callable[..., Settings],
) -> None:
    from lg_sotf.domain import routing
    from lg_sotf.domain.routing import RoutingThresholds

    settings = make_settings()
    alert = {"title": "Scheduled task created", "severity": "low", "source_id": "sysmon", "occurred_at": "2026-09-01T10:00:00Z"}
    benign = {**ASSESSMENT, "threat_likelihood": 0, "false_positive_indicators": ["a", "b", "c", "d"], "true_positive_indicators": []}
    result = await TriageAgent(settings=settings, model_factory=factory(scripted(TriageAssessment=[benign]))).run(ctx(settings), alert)
    assert result.llm_used and result.rule_fp == ["scheduled_detected"]
    t = RoutingThresholds()
    assert result.confidence == 21  # blended 12, held above the close thresholds and human_review_min
    state = {"severity": "low", "confidence": result.confidence, "triage": result.digest(), "correlation": {"score": 0}}
    assert routing.route_after_triage(state, t) == "correlation"
    assert routing.route_after_correlation(state, t) == "analysis"


async def test_refused_ambiguous_alert_is_never_closed_automatically(make_settings: Callable[..., Settings]) -> None:
    """Routing sees a grey-zone confidence and a refusal marker: triage, correlation and decide all keep it open."""
    from lg_sotf.domain import routing
    from lg_sotf.domain.routing import RoutingThresholds

    settings = make_settings()
    alert = {"title": "Maintenance window login", "severity": "low", "source_id": "splunk-prod",
             "occurred_at": "2026-09-01T10:00:00Z", "entities": {"users": ["bob"]}}
    assert rule_confidence(alert) == 15
    model = scripted(TriageAssessment=[Refuse("cyber")])
    result = await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings), alert)
    assert len(model.calls) == 1 and result.llm_refusal is not None
    t = RoutingThresholds()
    assert result.confidence == t.correlation_grey_zone_min and result.rule_score == 15
    state: dict = {"severity": "low", "confidence": result.confidence, "triage": result.digest()}
    assert routing.route_after_triage(state, t) == "correlation"
    state["correlation"] = {"score": 0, "related_count": 0, "burst": False}
    assert routing.route_after_correlation(state, t) == "analysis"
    # Even if routing skipped analysis, decide would keep the grey-zone confidence open.
    assert routing.decide(state, t).route == "escalate"
