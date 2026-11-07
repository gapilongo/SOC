"""Analysis result assembly and the prompt block, as pure functions (no model, no providers)."""

from __future__ import annotations

from typing import Any, Dict

from lg_sotf.agents.analysis.base import (
    REFUSAL_CONCLUSION,
    UPSTREAM_REFUSAL_CONCLUSION,
    AnalysisVerdict,
    _assemble_result,
    _prompt_block,
    rule_actions,
    rule_conclusion,
)
from lg_sotf.agents.analysis.react import MAX_ACTIONS, Candidate
from lg_sotf.agents.base import LLMResult

RULE_SCORE = 72
UPSTREAM = {"reason": "model_refused", "category": "cyber", "agent": "triage"}


def _common() -> Dict[str, Any]:
    return {
        "rule_threat_score": RULE_SCORE,
        "rule_verdict": "malicious",
        "rule_corroborated": False,
        "rule_evidence": [],
        "corroborated_targets": [],
        "threat_indicators": ["suspicious_port_usage"],
        "tool_steps": 0,
        "llm_calls": 1,
        "stop_reason": "no_candidates",
        "observations": [],
        "history": [],
        "reasoning": [],
        "notes": ["triage: note"],
    }


def _verdict(**overrides: Any) -> AnalysisVerdict:
    fields: Dict[str, Any] = {
        "threat_score": 40,
        "certainty": 80,
        "verdict": "benign",
        "conclusion": "Routine admin activity.",
        "recommended_actions": ["Confirm with the user", "Block the IP"],
    }
    return AnalysisVerdict(**{**fields, **overrides})


def test_the_model_assessment_wins_and_merges_rule_actions() -> None:
    common = _common()
    result = _assemble_result(_verdict(), None, None, RULE_SCORE, common, agent="analysis")
    assert (result.threat_score, result.certainty, result.verdict) == (40, 80, "benign")
    assert result.conclusion == "Routine admin activity." and result.llm_used and result.llm_refusal is None
    # Model actions first, then the rule actions for the higher of the two scores, without duplicates.
    expected = list(dict.fromkeys(["Confirm with the user", "Block the IP", *rule_actions(RULE_SCORE)]))
    assert result.recommended_actions == expected[:MAX_ACTIONS]
    assert result.rule_threat_score == RULE_SCORE and result.notes == ["triage: note"]
    assert common == _common()


def test_an_upstream_refusal_keeps_the_assessment_but_leaves_the_verdict_to_a_human() -> None:
    common = _common()
    result = _assemble_result(_verdict(), None, UPSTREAM, RULE_SCORE, common, agent="analysis")
    assert result.llm_used and result.threat_score == 40 and result.verdict == "inconclusive"
    assert result.conclusion == f"{UPSTREAM_REFUSAL_CONCLUSION} Routine admin activity."
    assert result.llm_refusal == UPSTREAM
    assert result.notes == ["triage: note", "analysis: an earlier model call was refused; verdict left to an analyst"]
    assert common == _common(), "the shared fields are not modified"


def test_a_refusal_falls_back_to_the_rules_with_an_inconclusive_verdict() -> None:
    refusal: LLMResult[Any] = LLMResult(skipped="refusal", refusal_category="cyber")
    result = _assemble_result(None, refusal, UPSTREAM, RULE_SCORE, _common(), agent="analysis")
    assert (result.threat_score, result.certainty, result.verdict) == (RULE_SCORE, 0, "inconclusive")
    assert result.conclusion == f"{REFUSAL_CONCLUSION} {rule_conclusion(RULE_SCORE)}"
    assert result.recommended_actions == rule_actions(RULE_SCORE) and not result.llm_used
    # This agent's own refusal is reported, not the earlier one.
    assert result.llm_refusal == {"reason": "model_refused", "category": "cyber", "agent": "analysis"}


def test_without_a_model_call_an_upstream_refusal_still_needs_a_human() -> None:
    result = _assemble_result(None, None, UPSTREAM, RULE_SCORE, _common(), agent="analysis")
    assert result.verdict == "inconclusive" and result.certainty == 0 and result.llm_refusal == UPSTREAM


def test_without_a_model_the_rules_decide() -> None:
    result = _assemble_result(None, None, None, RULE_SCORE, _common(), agent="analysis")
    assert (result.threat_score, result.certainty) == (RULE_SCORE, 50)
    assert result.verdict == "malicious" and result.conclusion == rule_conclusion(RULE_SCORE)
    assert result.recommended_actions == rule_actions(RULE_SCORE)
    assert not result.llm_used and result.llm_refusal is None


def test_prompt_block_carries_only_present_background_fields_and_clips_the_analyst_request() -> None:
    alert = {"title": "Possible C2 beacon", "severity": "high"}
    block = _prompt_block(
        alert,
        {"confidence": 70, "rule_fp": None, "ignored": 1},
        {"score": 3, "burst": False},
        rule_indicators=["suspicious_port_usage"],
        rule_score=RULE_SCORE,
        history=[{"kind": "ip", "value": "198.51.100.7"}],
        candidates={"i1": Candidate("i1", "ip", "198.51.100.7", ["virustotal"])},
        analyst_notes="x" * 1_500,
    )
    assert block == {
        "alert": alert,
        "background": {
            "triage": {"confidence": 70},
            "correlation": {"score": 3, "burst": False},
            "rule_threat_indicators": ["suspicious_port_usage"],
            "rule_threat_score": RULE_SCORE,
        },
        "history": [{"kind": "ip", "value": "198.51.100.7"}],
        "candidates": {"i1": {"kind": "ip", "value": "198.51.100.7", "providers": ["virustotal"]}},
        "analyst_request": "x" * 1_000,
    }
    without_notes = _prompt_block(
        alert, {}, {}, rule_indicators=[], rule_score=0, history=[], candidates={}, analyst_notes=None
    )
    assert "analyst_request" not in without_notes and without_notes["background"]["triage"] == {}
