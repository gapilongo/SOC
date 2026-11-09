"""Correlation: bounded indicators, hashed values, burst detection, one LLM call over real related-alert digests."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Callable

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.correlation.base import MAX_DIGESTS, MAX_RELATED, CorrelationAgent, frequency_level
from lg_sotf.domain.indicators import extract_indicators, is_public_ip
from lg_sotf.llm.fake import Refuse
from lg_sotf.settings import Settings
from tests.unit.agents._support import NOW, Related, StoredAlert, factory, fake_repos, scripted, texts

HASH_ALERT = {
    "title": "Dropper executed",
    "severity": "high",
    "entities": {"hashes": ["d41d8cd98f00b204e9800998ecf8427e"]},
    "raw": {"command_line": "secret-bearing raw event must not reach the correlation prompt"},
}


def test_indicator_extraction_is_bounded_and_validated() -> None:
    alert = {
        "entities": {"ips": ["10.0.0.1", "not-an-ip", "10.0.0.1"], "domains": ["evil.example.com", "-bad-"]},
        "raw": {"src_ip": "8.8.8.8", "url": "javascript:alert(1)", "md5": "d41d8cd98f00b204e9800998ecf8427e"},
    }
    kinds = [(i.type, i.value) for i in extract_indicators(alert)]
    assert ("ip", "10.0.0.1") in kinds and ("ip", "8.8.8.8") in kinds and ("domain", "evil.example.com") in kinds
    assert all(v != "not-an-ip" and v != "-bad-" and not v.startswith("javascript") for _, v in kinds)
    assert kinds.count(("ip", "10.0.0.1")) == 1
    assert is_public_ip("8.8.8.8") and not is_public_ip("10.0.0.1")


async def test_no_related_alerts_skips_the_llm(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    model = scripted()
    ctx = AgentContext("t1", "a1", settings, repos=repos)
    result = await CorrelationAgent(settings=settings, model_factory=factory(model)).run(
        ctx, {"entities": {"ips": ["8.8.8.8"]}}, base_confidence=40, now=NOW
    )
    assert (result.score, result.related_count, result.llm_used, result.confidence) == (0, 0, False, 40)
    assert result.llm_skipped == "no_related_alerts" and model.calls == []
    (itype, value_hash, display, seen_at), = repos.indicators.sightings
    assert itype == "ip" and value_hash != "8.8.8.8" and len(value_hash) == 64 and display == "8.8.8.8"
    assert seen_at == NOW


async def test_one_llm_call_with_the_related_alert_digests(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    stored = [
        StoredAlert(
            id=f"r{i}",
            title=f"Dropper seen on host-{i}",
            severity="high",
            disposition="malicious" if i == 0 else ("benign" if i == 1 else None),
            status="closed" if i < 2 else "waiting_human",
            normalized={"mitre": {"techniques": ["T1204", "T1059"]}, "raw": {"secret": "never in prompt"}},
        )
        for i in range(12)
    ]
    related = [Related(f"r{i}", 2, NOW - timedelta(minutes=1)) for i in range(12)]
    repos = fake_repos(alerts=stored, related=related)
    model = scripted(
        CorrelationAssessment=[
            {"campaign_likelihood": 80, "attack_campaign_indicators": ["same dropper hash"], "reasoning": "r"}
        ]
    )
    agent = CorrelationAgent(settings=settings, model_factory=factory(model), config={"max_correlations": 20})
    ctx = AgentContext("t1", "a1", settings, repos=repos)
    result = await agent.run(ctx, HASH_ALERT, base_confidence=40, now=NOW)

    assert len(model.calls) == 1 and result.llm_used and result.burst
    assert result.related_count == 12 and result.campaign_indicators == ["same dropper hash"]
    # FIX-1 review: counted over every related alert (12), not only the MAX_DIGESTS shown to the model.
    assert result.related_dispositions == {"malicious": 1, "benign": 1, "undecided": 10}
    assert (result.related_open_reviews, result.related_threats) == (10, 0)
    human = texts(model.calls[0].messages)[1]
    payload = json.loads(human.split("<alert_data>\n", 1)[1].rsplit("\n</alert_data>", 1)[0])
    digests = payload["related_alerts"]
    assert len(digests) == MAX_DIGESTS
    assert digests[0] == {
        "ref": "r1",
        "title": "Dropper seen on host-0",
        "severity": "high",
        "category": None,
        "status": "closed",
        "disposition": "malicious",
        "verdict": None,
        "occurred_at": NOW.isoformat(),
        "shared_indicators": 2,
        "mitre_techniques": ["T1204", "T1059"],
    }
    assert payload["correlation"]["related_alerts"] == 12 and payload["correlation"]["burst"] is True
    assert "raw" not in payload["alert"] and "never in prompt" not in human
    assert "secret-bearing" not in human
    assert "r0" not in human  # alert ids are replaced by refs
    _, kwargs = repos.indicators.queries[0]
    assert kwargs["since"] == NOW - agent.window and kwargs["exclude_alert_id"] == "a1"
    assert repos.alerts.rows[("t1", "a1")].summary["llm_usage"]["by_agent"]["correlation"]["calls"] == 1


async def test_related_alerts_removed_since_sighting_are_skipped(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos(alerts=[StoredAlert(id="kept")], related=[Related("gone", 1, NOW), Related("kept", 1, NOW)])
    model = scripted()
    ctx = AgentContext("t1", "a1", settings, repos=repos)
    result = await CorrelationAgent(settings=settings, model_factory=factory(model)).run(
        ctx, HASH_ALERT, base_confidence=40, now=NOW
    )
    assert result.related_count == 2 and len(model.calls) == 1
    human = texts(model.calls[0].messages)[1]
    assert human.count('"ref":') == 1


async def test_refusal_keeps_the_rule_score_and_marks_the_digest(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    related = [Related(f"r{i}", 1, NOW - timedelta(minutes=30)) for i in range(2)]
    repos = fake_repos(alerts=[StoredAlert(id="r0"), StoredAlert(id="r1")], related=related)
    model = scripted(CorrelationAssessment=[Refuse(None)])
    ctx = AgentContext("t1", "a1", settings, repos=repos)
    agent = CorrelationAgent(settings=settings, model_factory=factory(model))
    result = await agent.run(ctx, HASH_ALERT, base_confidence=40, now=NOW)
    assert not result.llm_used and result.score == agent._rule_score(related, extract_indicators(HASH_ALERT), False)
    assert result.digest()["llm_refusal"] == {"reason": "model_refused", "category": None, "agent": "correlation"}


async def test_refusal_holds_a_low_confidence_in_the_grey_zone(make_settings: Callable[..., Settings]) -> None:
    """A refused alert must reach analysis and an analyst, not the low-confidence shortcut to an automatic close."""
    from lg_sotf.domain import routing
    from lg_sotf.domain.routing import RoutingThresholds

    settings = make_settings()
    t = RoutingThresholds()
    related = [Related("r0", 1, NOW - timedelta(minutes=50))]
    repos = fake_repos(alerts=[StoredAlert(id="r0")], related=related)
    refused = await CorrelationAgent(settings=settings, model_factory=factory(scripted(CorrelationAssessment=[Refuse("cyber")]))).run(
        AgentContext("t1", "a1", settings, repos=repos), HASH_ALERT, base_confidence=2, now=NOW
    )
    assert refused.confidence == t.correlation_grey_zone_min and refused.llm_refusal is not None
    state = {"severity": "low", "confidence": refused.confidence, "correlation": refused.digest()}
    assert routing.route_after_correlation(state, t) == "analysis"
    answered = await CorrelationAgent(settings=settings).run(
        AgentContext("t1", "a1", settings, repos=fake_repos(alerts=[StoredAlert(id="r0")], related=related)),
        HASH_ALERT,
        base_confidence=2,
        now=NOW,
    )
    assert answered.confidence < t.human_review_min


async def test_burst_and_frequency_come_from_sightings(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    related = [Related(f"r{i}", 2, NOW - timedelta(minutes=1)) for i in range(6)]
    ctx = AgentContext("t1", "a1", settings, repos=fake_repos(related=related))
    agent = CorrelationAgent(settings=settings)
    result = await agent.run(ctx, {"entities": {"hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}}, base_confidence=40, now=NOW)
    assert result.burst and result.related_count == 6 and result.llm_used
    assert result.related_alert_ids == [f"r{i}" for i in range(6)]
    assert result.score > 0


async def test_model_closed_and_threat_judged_related_alerts_are_counted_beyond_the_digests(
    make_settings: Callable[..., Settings],
) -> None:
    """FIX-1 review (F3, observation 4): a related alert the models closed alone is shown and counted as
    ai_closed_unaudited, never benign; one a model judged a threat counts even past the MAX_DIGESTS shown."""
    settings = make_settings()
    ai_closed = {"close_reason": "ai_closed:audit_required", "verdict": "benign"}
    stored = [StoredAlert(id="r0", disposition="benign", summary=ai_closed)]
    stored += [StoredAlert(id=f"r{i}", disposition="benign", summary={"close_reason": "analyst:false_positive"})
               for i in range(1, MAX_RELATED - 1)]
    stored.append(StoredAlert(id=f"r{MAX_RELATED - 1}", status="processing",
                              summary={"triage": {"threat_assessment": "suspicious"}}))
    related = [Related(a.id, 1, NOW - timedelta(minutes=30)) for a in stored]
    model = scripted()
    agent = CorrelationAgent(settings=settings, model_factory=factory(model), config={"max_correlations": MAX_RELATED})
    ctx = AgentContext("t1", "a1", settings, repos=fake_repos(alerts=stored, related=related))
    result = await agent.run(ctx, HASH_ALERT, base_confidence=40, now=NOW)
    assert result.related_dispositions == {"ai_closed_unaudited": 1, "benign": MAX_RELATED - 2, "undecided": 1}
    assert (result.related_threats, result.related_open_reviews) == (1, 0)
    payload = json.loads(texts(model.calls[0].messages)[1].split("<alert_data>\n", 1)[1].rsplit("\n</alert_data>", 1)[0])
    shown = payload["related_alerts"]
    assert len(shown) == MAX_DIGESTS and (shown[0]["disposition"], shown[0]["verdict"]) == ("ai_closed_unaudited", None)
    assert result.digest()["related_threats"] == 1


async def test_correlation_is_evidence_and_never_raises_the_confidence(make_settings: Callable[..., Settings]) -> None:
    """FIX-1: a burst of strongly related alerts is in the digest, but routing's confidence is triage's."""
    settings = make_settings()
    related = [Related(f"r{i}", 3, NOW - timedelta(minutes=1)) for i in range(MAX_RELATED)]
    agent = CorrelationAgent(settings=settings, config={"max_correlations": MAX_RELATED})
    result = await agent.run(
        AgentContext("t1", "a1", settings, repos=fake_repos(related=related)), HASH_ALERT, base_confidence=55, now=NOW
    )
    assert result.burst and result.related_count == MAX_RELATED and result.score >= 85
    assert result.confidence == 55 and result.digest()["confidence"] == 55


def test_frequency_levels() -> None:
    assert [frequency_level(x) for x in (1, 6, 21, 51)] == ["low", "medium", "high", "critical"]
