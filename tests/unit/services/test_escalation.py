"""EscalationService policy: level, priority, SLA and grouping settings (grouping itself: integration tests)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Callable, Optional

import pytest

from lg_sotf.services.escalation import (
    DEFAULT_KEY_INDICATOR_TYPES,
    EscalationService,
    ReviewPolicy,
    _place,
    _Placement,
    compute_level,
    compute_priority,
    max_level,
    own_review_reason,
    resolve_review_policy,
)
from lg_sotf.settings import Settings


def test_priority_and_level() -> None:
    low = compute_priority(severity="low", threat_score=20, confidence=60, correlations_count=0, reason_code="false_positive_review")
    high = compute_priority(severity="critical", threat_score=90, confidence=20, correlations_count=12, reason_code="high_risk")
    assert low == 1 and high == 10
    assert compute_level(priority=10, threat_score=10, severity="low", reason_code="x") == "L3"
    assert compute_level(priority=8, threat_score=10, severity="low", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=85, severity="low", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=20, severity="critical", reason_code="x") == "L2"
    assert compute_level(priority=3, threat_score=20, severity="low", reason_code="grey_zone") == "L1"
    assert compute_level(priority=5, threat_score=20, severity="low", reason_code="x", l2_threshold=5) == "L2"
    assert max_level("L1", "L3", "L2") == "L3"


def test_install_defaults(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(agents={"human_loop": {"sla_minutes": {"L1": 15}, "escalation_threshold": 60}})
    policy = resolve_review_policy({}, settings)
    assert policy.sla_minutes == {"L1": 15, "L2": 60, "L3": 120}
    assert policy.grouping.enabled and policy.grouping.window_minutes == 60
    assert policy.grouping.indicator_types == DEFAULT_KEY_INDICATOR_TYPES and "process" not in DEFAULT_KEY_INDICATOR_TYPES
    service = EscalationService(None, None, settings)  # type: ignore[arg-type]
    assert service.sla_minutes("L1") == 15 and service.sla_minutes("L3") == 120


def test_tenant_overrides_merge_over_install(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(agents={"human_loop": {"sla_minutes": {"L1": 15}}})
    tenant = {
        "review": {
            "sla_minutes": {"L2": 20},
            "level_thresholds": {"L2": 6},
            "min_level": {"critical": "L3"},
            "grouping": {"window_minutes": 10, "by_fingerprint": False},
            "suggest_suppressions": False,
        }
    }
    policy = resolve_review_policy(tenant, settings)
    assert policy.sla_minutes == {"L1": 15, "L2": 20, "L3": 120}
    assert policy.grouping.window_minutes == 10 and not policy.grouping.by_fingerprint and policy.grouping.by_indicators
    assert not policy.suggest_suppressions
    assert policy.level_for(priority=6, threat_score=10, severity="low", reason_code="x") == "L2"
    assert policy.level_for(priority=1, threat_score=10, severity="critical", reason_code="x") == "L3"


def test_invalid_tenant_policy_falls_back_to_install(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(agents={"human_loop": {"sla_minutes": {"L1": 15}}})
    for bad in ({"sla_minutes": {"L9": 5}}, {"sla_minutes": {"L1": 0}}, {"grouping": {"window_minutes": -1}},
                {"level_thresholds": {"L1": 3}}, {"min_level": {"high": "L7"}}):
        policy = resolve_review_policy({"review": bad}, settings)
        assert policy.sla_minutes["L1"] == 15 and policy.grouping.window_minutes == 60
    assert resolve_review_policy({"review": "nonsense"}, settings).sla_minutes["L1"] == 15


def test_default_grouping_ignores_hosts_and_users() -> None:
    assert DEFAULT_KEY_INDICATOR_TYPES == ("ip", "domain", "url", "hash")


@pytest.mark.parametrize(
    ("decision", "parent", "attached", "reason"),
    [
        ("false_positive", ("fp", "high"), ("fp", "high"), None),
        ("benign_positive", ("fp", "high"), ("fp", "medium"), None),
        ("false_positive", ("fp", "medium"), ("fp", "high"), "higher_severity"),
        ("false_positive", ("fp", "high"), ("other", "low"), "different_fingerprint"),
        ("false_positive", ("fp", "high"), (None, "low"), "different_fingerprint"),
        ("false_positive", ("", "high"), ("", "low"), "different_fingerprint"),
        ("false_positive", ("fp", "high"), ("fp", "bogus"), "higher_severity"),
        ("true_positive", ("fp", "low"), ("other", "critical"), None),
        ("needs_more_info", ("fp", "low"), ("other", "critical"), None),
    ],
)
def test_own_review_reason(
    decision: str, parent: tuple, attached: tuple, reason: Optional[str]
) -> None:
    got = own_review_reason(
        decision, parent_fingerprint=parent[0], parent_severity=parent[1], fingerprint=attached[0], severity=attached[1]
    )
    assert got == reason


def test_place_matches_priority_level_and_sla() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy = ReviewPolicy(sla_minutes={"L1": 30, "L2": 45, "L3": 90})
    low = _place(policy, "low", 20, 60, 0, "false_positive_review", now)
    assert low == _Placement(priority=1, level="L1", sla_deadline=now + timedelta(minutes=30))
    high = _place(policy, "critical", 90, 20, 12, "high_risk", now)
    assert high == _Placement(priority=10, level="L3", sla_deadline=now + timedelta(minutes=90))
    # The correlation count raises the priority (5 or more: +1, 10 or more: +2).
    assert [_place(policy, "medium", 50, 60, n, "grey_zone", now).priority for n in (0, 5, 10)] == [6, 7, 8]
    assert _place(policy, "medium", 50, 60, 10, "grey_zone", now).level == "L2"


def test_place_follows_the_tenant_thresholds_and_minimum_levels() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy = ReviewPolicy(level_thresholds={"L2": 6, "L3": 9}, min_level={"high": "L3"})
    assert _place(policy, "medium", 50, 60, 0, "grey_zone", now).level == "L2"
    assert _place(policy, "high", 10, 60, 0, "group_review", now).level == "L3"
    assert _place(policy, "low", 10, 60, 0, "group_review", now).sla_deadline == now + timedelta(
        minutes=policy.sla_minutes["L1"]
    )
