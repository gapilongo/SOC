"""Deterministic fake chat model."""

from __future__ import annotations

import enum
import json
from typing import List, Literal, Optional

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from lg_sotf.llm.fake import FakeChatModel, analyse_text, untrusted_text
from lg_sotf.llm.prompting import build_messages
from lg_sotf.settings import Settings

_S = Settings(_env_file=None, environment="test", llm={"provider": "fake"})


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Indicator(BaseModel):
    type: Literal["ip", "domain", "hash"]
    value: str = Field(max_length=64)


class Verdict(BaseModel):
    disposition: Literal["malicious", "benign", "inconclusive"]
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    threat_probability: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(gt=0, lt=10)
    is_false_positive: bool
    escalate: bool
    reasoning: str = Field(min_length=10, max_length=120)
    malicious_indicators: List[str] = Field(default_factory=list, max_length=2)
    iocs: List[Indicator] = Field(default_factory=list)
    recommended_action: Optional[str] = None


def _msgs(alert: dict) -> list:  # type: ignore[type-arg]
    return build_messages("Watch for malware and ransomware.", "Assess.", alert, settings=_S)


def test_is_a_real_chat_model() -> None:
    assert isinstance(FakeChatModel(), BaseChatModel)


def test_heuristics() -> None:
    bad = analyse_text("mimikatz dumped lsass then a cobalt strike beacon called the c2 server; severity: critical")
    good = analyse_text("scheduled backup by known update agent, benign test")
    neutral = analyse_text("user logged in")
    assert bad.threat_score > 90 and bad.band == "high" and bad.confidence > 80
    assert good.threat_score < 10 and good.band == "low"
    assert neutral.threat_score == 50 and neutral.confidence == 45 and neutral.band == "mid"
    assert "mimikatz" in bad.malicious and "backup" in good.benign
    assert analyse_text("latest unknown attest") == neutral


def test_only_alert_data_is_scored() -> None:
    msgs = _msgs({"title": "user logged in"})
    assert "malware" not in untrusted_text(msgs)
    assert analyse_text(untrusted_text(msgs)).threat_score == 50
    assert untrusted_text([HumanMessage("plain ransomware text")]) == "plain ransomware text"


async def test_structured_output_is_schema_valid_and_tracks_signals() -> None:
    model = FakeChatModel()
    structured = model.with_structured_output(Verdict)
    bad = await structured.ainvoke(_msgs({"title": "Ransomware and mimikatz with C2 beacon", "severity": "critical"}))
    good = await structured.ainvoke(_msgs({"title": "Scheduled backup test by known benign update job", "severity": "low"}))
    assert isinstance(bad, Verdict) and isinstance(good, Verdict)
    assert bad.disposition == "malicious" and good.disposition == "benign"
    assert bad.severity in (Severity.HIGH, Severity.CRITICAL) and good.severity == Severity.LOW
    assert bad.confidence > 70 and 0.0 <= bad.threat_probability <= 1.0 and 0 < bad.risk_score < 10
    assert bad.threat_probability > good.threat_probability
    assert bad.escalate and not bad.is_false_positive
    assert good.is_false_positive and not good.escalate
    assert len(bad.malicious_indicators) <= 2
    assert bad.recommended_action == "escalate for analyst review"
    assert good.recommended_action == "close as benign"


async def test_deterministic() -> None:
    structured = FakeChatModel().with_structured_output(Verdict)
    msgs = _msgs({"title": "beacon to c2"})
    assert (await structured.ainvoke(msgs)) == (await structured.ainvoke(msgs))
    assert structured.invoke(msgs) == await structured.ainvoke(msgs)


async def test_include_raw_has_usage_and_stop_reason() -> None:
    out = await FakeChatModel(model_name="fake-deep").with_structured_output(Verdict, include_raw=True).ainvoke(
        _msgs({"title": "malware"})
    )
    assert out["parsing_error"] is None
    raw = out["raw"]
    assert isinstance(raw, AIMessage)
    assert raw.response_metadata["stop_reason"] == "end_turn"
    assert raw.response_metadata["model_name"] == "fake-deep"
    assert raw.usage_metadata is not None and raw.usage_metadata["input_tokens"] > 0
    assert Verdict.model_validate_json(str(raw.content)) == out["parsed"]


async def test_impossible_schema_reported_as_parsing_error() -> None:
    class Impossible(BaseModel):
        choice: Literal["a"]
        n: int = Field(ge=5, le=1)

    out = await FakeChatModel().with_structured_output(Impossible, include_raw=True).ainvoke([HumanMessage("x")])
    assert out["parsed"] is None and out["parsing_error"] is not None


def test_plain_invoke_returns_json_with_usage() -> None:
    msg = FakeChatModel().invoke([SystemMessage("s"), HumanMessage("<alert_data>{\"t\":\"mimikatz\"}</alert_data>")])
    payload = json.loads(str(msg.content))
    assert payload["verdict"] == "malicious" or payload["threat_score"] > 50
    assert payload["malicious_signals"] == ["mimikatz"]
    assert msg.usage_metadata is not None


def test_non_pydantic_schema_rejected() -> None:
    with pytest.raises(NotImplementedError):
        FakeChatModel().with_structured_output({"type": "object"})


def test_bind_tools_is_accepted() -> None:
    model = FakeChatModel()
    assert model.bind_tools([]) is model
