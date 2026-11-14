"""The gate node: which suppression rules and cached verdicts may close an alert before triage (#343)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import fakeredis.aioredis
import pytest

from lg_sotf.core.nodes import WorkflowNodes
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.domain.suppression import fingerprint_suggestion

FP = "f" * 64
VK = "a" * 64


def _rule(rule_id: str, match: Dict[str, Any], feedback: Optional[str] = None) -> Any:
    return SimpleNamespace(id=rule_id, name=rule_id, match=match, source_feedback_id=feedback)


SUGGESTION = {"fingerprint": FP, "source_id": "s", "severity": {"in": ["info", "low", "medium"]}}


class Suppressions:
    def __init__(self, rules: List[Any]) -> None:
        self.rules, self.hits = rules, []  # type: ignore[var-annotated]

    async def list_active(self, tenant_id: str) -> List[Any]:
        return self.rules

    async def record_hit(self, tenant_id: str, rule_id: str) -> None:
        self.hits.append(rule_id)


def _nodes(rules: List[Any], cache: Optional[VerdictCache] = None) -> WorkflowNodes:
    wn = WorkflowNodes.__new__(WorkflowNodes)
    wn.deps = SimpleNamespace(  # type: ignore[assignment]
        repos=SimpleNamespace(suppressions=Suppressions(rules)),
        verdicts=cache or VerdictCache(fakeredis.aioredis.FakeRedis(), "pfx"),
    )
    return wn


def _state(flags: Optional[List[str]] = None, severity: str = "medium") -> Dict[str, Any]:
    alert = {"title": "New service", "source_id": "s", "source_alert_id": "x", "flags": flags or [],
             "entities": {"hosts": ["srv-app-02"]}}
    return {"tenant_id": "t1", "alert_id": "a1", "severity": severity, "fingerprint": FP, "verdict_key": VK,
            "alert": alert}


def test_fingerprint_suggestions_are_recognised() -> None:
    assert fingerprint_suggestion(_rule("r", SUGGESTION))  # a bulk proposal's shape
    assert fingerprint_suggestion(_rule("r", {"fingerprint": FP, "title": "x"}, feedback="fb-1"))  # from a false positive
    assert not fingerprint_suggestion(_rule("r", {"fingerprint": FP, "title": "Nightly scanner"}))  # an admin's rule
    assert not fingerprint_suggestion(_rule("r", {"verdict_key": VK, "source_id": "s", "severity": "low"}, "fb"))
    assert not fingerprint_suggestion(_rule("r", {}))
    assert not fingerprint_suggestion(SimpleNamespace(id="r"))


async def test_a_fingerprint_suggestion_never_closes_even_enabled_again_by_an_admin() -> None:
    """N2: migration 0016 disabled them; an admin who enables one again gets no effect from it at the gate."""
    gate = _nodes([_rule("old", SUGGESTION, feedback="fb-1"), _rule("bulk", SUGGESTION)])
    out = await gate.gate(_state())
    assert out["gate"] == {"suppressed": False}
    assert gate.deps.repos.suppressions.hits == []  # type: ignore[attr-defined]


async def test_rules_on_the_verdict_key_and_admin_rules_still_apply() -> None:
    gate = _nodes([_rule("old", SUGGESTION, "fb-1"), _rule("vk", {"verdict_key": VK, "severity": {"in": ["medium"]}})])
    out = await gate.gate(_state())
    assert out["gate"]["suppressed_by"]["rule_id"] == "vk"
    admin = _nodes([_rule("admin", {"fingerprint": FP, "title": "New service"})])
    assert (await admin.gate(_state()))["gate"]["suppressed_by"]["rule_id"] == "admin"


@pytest.mark.parametrize("rules", [[{"verdict_key": VK}], [{"entities.hosts": "srv-app-02"}]])
async def test_a_model_normalised_alert_skips_rules_and_the_cache(rules: List[Dict[str, Any]]) -> None:
    """L1: its fields are a model's reading of attacker-shaped text."""
    cache = VerdictCache(fakeredis.aioredis.FakeRedis(), "pfx")
    for n in (1, 2):
        await cache.put_analyst_benign("t1", VK, decision="false_positive", alert_id=f"b{n}", escalation_id=None,
                                       decided_by=f"analyst-{n}", severity="medium")
    gate = _nodes([_rule(f"r{i}", m) for i, m in enumerate(rules)], cache)
    assert (await gate.gate(_state(flags=["llm_normalized"])))["gate"] == {"suppressed": False}
    assert (await gate.gate(_state()))["gate"]["suppressed"] is True
