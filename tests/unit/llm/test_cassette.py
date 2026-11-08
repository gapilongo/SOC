"""Cassettes: what is recorded, how it is replayed, and that a miss never turns into a live call."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, List, Literal, Tuple

import pytest
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from lg_sotf.llm.cassette import (
    Cassette,
    CassetteChatModel,
    CassetteError,
    CassetteMiss,
    CassetteSet,
    cassette_name,
    llm_key,
    recording_model_factory,
    replay_model_factory,
)
from lg_sotf.llm.client import PROVIDER_KEY, STRUCTURED_KEY
from lg_sotf.llm.errors import LLMOutputError, LLMRefusal
from lg_sotf.llm.fake import FakeChatModel, Refuse, ScriptedChatModel
from lg_sotf.llm.structured import ainvoke_structured
from lg_sotf.llm.trace import TraceRecorder, observe, tool_input_hash, use_tape
from lg_sotf.llm.usage import UsageTally
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentResult


class Verdict(BaseModel):
    disposition: Literal["malicious", "benign", "inconclusive"]
    confidence: int = Field(ge=0, le=100)
    reasoning: str


class Heuristic(BaseModel):
    """The shape :class:`FakeChatModel` answers in JSON text."""

    threat_score: int
    verdict: str


def _fake_token() -> str:
    return "test-only-" + "q9Vw3" * 8


def _messages(alert_id: str = "7b209fb2-ddec-47cc-8e57-2c36200c80ed", at: str = "2026-11-07T23:59:41+00:00") -> List[BaseMessage]:
    return [SystemMessage("rules"), HumanMessage(f'<alert_data>{{"id": "{alert_id}", "seen": "{at}", "t": "mimikatz"}}</alert_data>')]


def _recorder() -> Cassette:
    return CassetteSet(Path("unused"), "record").open("it-1", "sha-1")


def _replayer(recorded: Cassette, mode: Any = "replay") -> Cassette:
    return Cassette.loads(recorded.dumps(), mode)


async def _call(model: Any, settings: Settings, tally: UsageTally, schema: Any = Verdict) -> Tuple[Any, TraceRecorder]:
    trace = TraceRecorder()
    value = await ainvoke_structured(
        model, schema, _messages(), agent="triage", tier="fast", settings=settings, tally=tally, trace=trace
    )
    return value, trace


def test_llm_key_ignores_alert_ids_and_timestamps_but_not_content() -> None:
    assert llm_key(_messages()) == llm_key(_messages("0d4f1a2b-0000-4000-8000-000000000001", "2027-01-02 03:04"))
    assert llm_key(_messages()) != llm_key([SystemMessage("rules"), HumanMessage("other")])
    # A secret is redacted before hashing, so a replayed observation with the redacted value still matches.
    assert llm_key([HumanMessage(f"api_key={_fake_token()}")]) == llm_key([HumanMessage(f"api_key={_fake_token()}z")])


def test_a_cassette_round_trips_with_sorted_keys_and_redacted_observations() -> None:
    cassette = _recorder()
    token = _fake_token()
    request = {"value": "203.0.113.9", "kind": "ip"}
    cassette.record_tool("reputation", request, tool_input_hash("reputation", request), {"api_key": token, "n": 1})
    text = cassette.dumps()
    assert token not in text
    lines = text.splitlines()
    assert json.loads(lines[0])["cassette"] == 2 and json.loads(lines[0])["item_id"] == "it-1"
    assert lines[1] == json.dumps(json.loads(lines[1]), sort_keys=True, separators=(",", ":"))
    again = Cassette.loads(text, "record")
    assert again.dumps() == text
    with pytest.raises(CassetteError):
        Cassette.loads('{"cassette": 1}\n', "replay")  # version 1 used the field name key
    with pytest.raises(CassetteError):
        Cassette.loads("not json", "replay")


def test_tool_replay_follows_the_recording_order_and_misses_loudly() -> None:
    cassette = _recorder()
    key = tool_input_hash("history", {"kind": "ip", "value": "10.0.0.1"})
    cassette.record_tool("history", {"kind": "ip", "value": "10.0.0.1"}, key, {"n": 1})
    cassette.record_tool("history", {"kind": "ip", "value": "10.0.0.1"}, key, {"n": 2})
    replay = _replayer(cassette)
    assert [replay.replay_tool("history", key) for _ in range(3)] == [{"n": 1}, {"n": 2}, {"n": 2}]
    with pytest.raises(CassetteMiss, match="record it again"):
        replay.replay_tool("history", "0" * 64)
    replay.problem = "no cassette file"
    with pytest.raises(CassetteMiss, match="no cassette file"):
        replay.replay_tool("history", key)


async def test_trace_tool_replays_without_running_the_lookup_and_still_adds_a_step() -> None:
    calls: List[str] = []

    async def lookup() -> EnrichmentResult:
        calls.append("live")
        return EnrichmentResult.ok("history", "ip", "suspicious", {"prior_alerts": 3})

    request = {"kind": "ip", "value": "10.0.0.1"}
    restore: Callable[[Any], EnrichmentResult] = lambda row: EnrichmentResult.from_dict("ip", row)  # noqa: E731
    recording, trace = _recorder(), TraceRecorder()
    with use_tape(recording):
        live = await trace.tool("analysis", "history", request, lookup(), EnrichmentResult.as_dict, restore)
    replay, replay_trace = _replayer(recording), TraceRecorder()
    with use_tape(replay):
        again = await replay_trace.tool("analysis", "history", request, lookup(), EnrichmentResult.as_dict, restore)
        with pytest.raises(LookupError, match="cannot be replayed"):
            await replay_trace.tool("analysis", "history", request, lookup(), EnrichmentResult.as_dict)
    assert calls == ["live"] and again == live
    assert replay_trace.steps[0].input_hash == trace.steps[0].input_hash
    assert replay_trace.steps[0].output_hash == trace.steps[0].output_hash
    assert replay_trace.steps[1].outcome == "error"


async def test_observe_records_and_replays_without_a_trace_step() -> None:
    async def providers() -> dict[str, list[str]]:
        return {"hash": ["virustotal"]}

    recording = _recorder()
    with use_tape(recording):
        assert await observe("enrichment_providers", {}, providers(), dict, dict) == {"hash": ["virustotal"]}

    async def unreachable() -> dict[str, list[str]]:
        raise AssertionError("the replay must not run the call")

    with use_tape(_replayer(recording, "replay-tools")):
        assert await observe("enrichment_providers", {}, unreachable(), dict, dict) == {"hash": ["virustotal"]}
    assert await observe("enrichment_providers", {}, providers(), dict, dict) == {"hash": ["virustotal"]}


async def test_model_calls_replay_value_usage_and_trace_from_the_cassette(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    scripted = ScriptedChatModel(model_name="fake-scripted", script={"Verdict": [{"disposition": "benign", "confidence": 9, "reasoning": "r"}]})
    recording = _recorder()
    live_tally = UsageTally()
    with use_tape(recording):
        live, live_trace = await _call(recording_model_factory(lambda tier, s: scripted)("fast", settings), settings, live_tally)
    assert recording.models["fast"] == {"provider": "fake", "model": "fake-scripted", "structured_output": None}

    replay = _replayer(recording)
    tally = UsageTally()
    with use_tape(replay):
        model = replay_model_factory("fast", settings)
        value, trace = await _call(model, settings, tally)
    assert value == live
    assert tally.by_agent["triage"].input_tokens == live_tally.by_agent["triage"].input_tokens > 0
    assert trace.steps[0].output_hash == live_trace.steps[0].output_hash
    assert trace.steps[0].provider == "cassette" and trace.steps[0].model == "fake-scripted"
    with pytest.raises(CassetteMiss):
        replay_model_factory("fast", settings)  # outside a replaying cassette


async def test_refusals_and_invalid_replies_replay_as_the_same_errors(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    recording = _recorder()
    refusing = ScriptedChatModel(script={"Verdict": [Refuse("cyber")]})
    with use_tape(recording), pytest.raises(LLMRefusal):
        await _call(refusing, settings, UsageTally())
    # The JSON text path with a repair attempt: the fake model's JSON is not a Verdict, twice.
    json_text = FakeChatModel(model_name="local-json", metadata={PROVIDER_KEY: "ollama", STRUCTURED_KEY: "json_schema"})
    recording.note_model("deep", json_text)
    with use_tape(recording), pytest.raises(LLMOutputError):
        await _call(json_text, settings, UsageTally())
    kinds = [(e["outcome"], "reply" in e) for e in recording.entries]
    assert kinds == [("refusal", True), ("invalid_output", True), ("invalid_output", True)]
    assert recording.entries[0]["refusal_category"] == "cyber"

    replay = _replayer(recording)
    with use_tape(replay):
        with pytest.raises(LLMRefusal) as refused:
            await _call(replay_model_factory("fast", settings), settings, UsageTally())
        assert refused.value.category == "cyber"
        with pytest.raises(LLMOutputError):
            _, _ = await _call(replay_model_factory("deep", settings), settings, UsageTally())


async def test_the_json_text_path_replays_its_reply_text(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    json_text = FakeChatModel(model_name="local-json", metadata={PROVIDER_KEY: "ollama", STRUCTURED_KEY: "json_mode"})
    recording = _recorder()
    with use_tape(recording):
        live, _ = await _call(recording_model_factory(lambda tier, s: json_text)("deep", settings), settings, UsageTally(), Heuristic)
    with use_tape(_replayer(recording)):
        model = replay_model_factory("deep", settings)
        assert isinstance(model, CassetteChatModel) and model.metadata is not None
        assert (model.metadata[PROVIDER_KEY], model.metadata[STRUCTURED_KEY]) == ("cassette", "json_mode")
        value, trace = await _call(model, settings, UsageTally(), Heuristic)
    assert value == live and trace.steps[0].model == "local/local-json"


def test_a_cassette_set_writes_and_reads_one_file_per_item(tmp_path: Path) -> None:
    recorder = CassetteSet(tmp_path, "record", dataset_sha256="d" * 64)
    cassette = recorder.open("syn:001", "sha-a")
    recorder.save(cassette)
    assert cassette_name("syn:001") == "syn_001.jsonl" and (tmp_path / "syn_001.jsonl").is_file()
    replay = CassetteSet(tmp_path, "replay")
    assert replay.open("syn:001", "sha-a").problem is None
    assert "changed since it was recorded" in (replay.open("syn:001", "sha-b").problem or "")
    assert "records item" in (replay.open("syn_001", "sha-a").problem or "")
    assert "no cassette file" in (replay.open("syn-404", "sha-a").problem or "")
    (tmp_path / "bad.jsonl").write_text("[]\n")
    assert "unreadable" in (replay.open("bad", "sha-a").problem or "")
    replay.save(replay.open("syn:001", "sha-a"))  # a replay never writes
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bad.jsonl", "syn_001.jsonl"]


def test_enrichment_results_survive_the_round_trip() -> None:
    result = EnrichmentResult("virustotal", "hash", "rate_limited", "unknown", {}, "busy", 12.34, cached=True)
    assert EnrichmentResult.from_dict("hash", result.as_dict()) == EnrichmentResult(
        "virustotal", "hash", "rate_limited", "unknown", {}, "busy", 12.3, cached=True
    )
    ok = EnrichmentResult.ok("history", "ip", "suspicious", {"prior_alerts": 3})
    assert EnrichmentResult.from_dict("ip", ok.as_dict()) == ok
