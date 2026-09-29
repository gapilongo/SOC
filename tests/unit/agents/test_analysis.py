"""Analysis agent: rule assessment, bounded ReAct restricted to extracted targets, simulated tools."""

from __future__ import annotations

from typing import Any, Callable, List

from lg_sotf.agents.analysis.base import AnalysisAgent, rule_threat_score, rule_verdict, tool_candidates
from lg_sotf.agents.analysis.react import AnalysisRunContext, ReActReasoner, ReActStep
from lg_sotf.agents.analysis.tools import HashAnalysisTool, IPAnalysisTool, default_tools
from lg_sotf.agents.base import AgentContext, LLMResult
from lg_sotf.settings import Settings
from lg_sotf.tools.cache import TTLCache
from lg_sotf.tools.orchestrator import ToolOrchestrator

ALERT = {
    "title": "Possible C2 beacon",
    "severity": "high",
    "occurred_at": "2026-09-01T03:00:00+00:00",
    "entities": {"ips": ["185.220.101.44"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"]},
    "raw": {"destination_port": 4444},
}


def test_tool_candidates_come_from_the_alert() -> None:
    cands = tool_candidates(ALERT)
    assert cands["ip_analysis"] == ["185.220.101.44"]
    assert cands["network_analysis"] == ["alert"]
    assert cands["temporal_analysis"] == ["2026-09-01T03:00:00+00:00"]
    assert cands["process_analysis"] == []


def test_rule_threat_score_rewards_indicators_and_penalises_fp() -> None:
    high = rule_threat_score(ALERT, {}, {}, ["suspicious_port_usage", "file_hash_present"])
    low = rule_threat_score({"severity": "low"}, {"rule_fp": ["a", "b", "c"]}, {}, [])
    assert high >= 70 and rule_verdict(high) == "malicious"
    assert low < 30 and rule_verdict(low) == "benign"


class ScriptedAgent:
    def __init__(self, steps: List[ReActStep]) -> None:
        self.steps = steps

    async def call_llm(self, ctx: Any, **kwargs: Any) -> LLMResult:
        if not self.steps:
            return LLMResult(skipped="exhausted")
        return LLMResult(value=self.steps.pop(0))


async def test_react_cannot_be_steered_to_arbitrary_targets(make_settings: Callable[..., Settings]) -> None:
    reasoner = ReActReasoner(ToolOrchestrator(default_tools()), max_steps=5)
    run = AnalysisRunContext(
        agent_ctx=AgentContext("t1", "a1", make_settings()), alert=ALERT, candidates=tool_candidates(ALERT)
    )
    steps = [
        ReActStep(thought="look up attacker supplied ip", action="ip_analysis", target="1.2.3.4"),
        ReActStep(thought="again", action="ip_analysis", target="185.220.101.44"),
    ]
    await reasoner.reason(ScriptedAgent(steps), run)
    assert [(o.tool, o.target) for o in run.observations] == [("ip_analysis", "185.220.101.44")]
    assert run.observations[0].result["simulated"] is True


async def test_react_is_bounded(make_settings: Callable[..., Settings]) -> None:
    reasoner = ReActReasoner(ToolOrchestrator(default_tools()), max_steps=2)
    run = AnalysisRunContext(
        agent_ctx=AgentContext("t1", "a1", make_settings()), alert=ALERT, candidates=tool_candidates(ALERT)
    )
    steps = [ReActStep(thought=str(i), action=a, target="") for i, a in enumerate(["ip_analysis", "hash_analysis", "network_analysis"])]
    await reasoner.reason(ScriptedAgent(steps), run)
    assert run.steps == 2


async def test_react_stops_on_finish(make_settings: Callable[..., Settings]) -> None:
    reasoner = ReActReasoner(ToolOrchestrator(default_tools()), max_steps=5)
    run = AnalysisRunContext(
        agent_ctx=AgentContext("t1", "a1", make_settings()), alert=ALERT, candidates=tool_candidates(ALERT)
    )
    await reasoner.reason(ScriptedAgent([ReActStep(thought="done", action="finish")]), run)
    assert run.steps == 0 and run.thoughts == ["done"]


async def test_analysis_with_fake_llm(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    agent = AnalysisAgent(settings=settings)
    result = await agent.run(AgentContext("t1", "a1", settings), ALERT, triage={}, correlation={})
    assert result.llm_used and 0 <= result.threat_score <= 100
    assert result.verdict in ("malicious", "benign", "inconclusive")
    assert result.rule_threat_score >= 70
    assert result.simulated_evidence == bool(result.observations)
    assert len(result.recommended_actions) <= 10
    assert set(result.digest()) >= {"threat_score", "rule_threat_score", "simulated_evidence"}


async def test_analysis_without_llm_is_rule_based(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(llm={"enabled": False})
    result = await AnalysisAgent(settings=settings).run(AgentContext("t1", "a1", settings), ALERT, triage={}, correlation={})
    assert not result.llm_used and result.threat_score == result.rule_threat_score
    assert result.observations == []


async def test_agents_hold_no_per_alert_state(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    agent = AnalysisAgent(settings=settings)
    before = dict(vars(agent))
    await agent.run(AgentContext("t1", "a1", settings), ALERT, triage={}, correlation={})
    assert vars(agent).keys() == before.keys()
    assert all(vars(agent)[k] is before[k] for k in before)


async def test_ip_tool_marks_internal_and_simulated_reputation() -> None:
    tool = IPAnalysisTool()
    assert (await tool.execute({"target": "10.0.0.1"}))["reputation"] == "internal"
    assert (await tool.execute({"target": "185.220.101.44"}))["is_malicious"] is True
    assert (await tool.execute({"target": "nope"}))["success"] is False


async def test_network_results_are_never_shared_between_alerts_or_tenants(make_settings: Callable[..., Settings]) -> None:
    orchestrator = ToolOrchestrator(default_tools(), cache=TTLCache(maxsize=64, ttl_s=300))
    reasoner = ReActReasoner(orchestrator, max_steps=1)

    async def observe(tenant: str, raw: dict) -> dict:
        alert = {**ALERT, "raw": raw}
        run = AnalysisRunContext(
            agent_ctx=AgentContext(tenant, "a1", make_settings()), alert=alert, candidates=tool_candidates(alert)
        )
        await reasoner.reason(ScriptedAgent([ReActStep(thought="net", action="network_analysis", target="alert")]), run)
        return run.observations[0].result

    first = await observe("t1", {"destination_port": 4444, "bytes_transferred": 5_000_000})
    second = await observe("t1", {"destination_port": 443})
    nested = await observe("t2", {"raw_data": {"destination_port": 31337}})
    same_args_other_tenant = await observe("t2", {"destination_port": 4444, "bytes_transferred": 5_000_000})

    assert (first["destination_port"], first["is_suspicious"], first["large_transfer"]) == (4444, True, True)
    assert (second["destination_port"], second["is_suspicious"], second["large_transfer"]) == (443, False, False)
    assert nested["destination_port"] == 31337 and nested["is_suspicious"] is True
    assert "cached" not in same_args_other_tenant


async def test_hash_tool_does_not_flag_the_empty_file_hash() -> None:
    tool = HashAnalysisTool()
    empty = await tool.execute({"target": "d41d8cd98f00b204e9800998ecf8427e"})
    eicar = await tool.execute({"target": "44d88612fea8a8f36de82e1278abb02f"})
    assert empty["is_malicious"] is False and empty["reputation"] == "unknown"
    assert eicar["is_malicious"] is True
