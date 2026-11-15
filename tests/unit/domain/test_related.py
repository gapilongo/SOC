"""Which alerts relate, and which related alert is a strong enough signal (AI-E3.16, review of #442)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.domain.related import (
    RelatedFacts,
    classify,
    hold_grade,
    host_key,
    model_judged_threat,
    related_digest,
    relation_keys,
    user_key,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
MINE = {"hosts": ["ws-fin-0142"], "users": ["jsmith"]}


@pytest.mark.parametrize(
    ("spelling", "key"),
    [
        ("ws-fin-0142", "ws-fin-0142"),
        ("WS-FIN-0142.corp.example.com", "ws-fin-0142"),
        ("ws-fin-0142.corp.example.com.", "ws-fin-0142"),
        ("  Ws-Fin-0142  ", "ws-fin-0142"),
        ("192.0.2.142", "192.0.2.142"),  # an IP literal used as a host name is kept whole, never cut at a dot
        ("2001:DB8::1", "2001:db8::1"),
        ("", None), (".", None), (None, None), (42, None),
    ],
)
def test_a_host_relates_by_its_lower_case_short_name(spelling: Any, key: Optional[str]) -> None:
    assert host_key(spelling) == key


@pytest.mark.parametrize(
    ("spelling", "key"),
    [
        ("jsmith", "jsmith"), ("JSmith", "jsmith"), ("CORP\\jsmith", "jsmith"), ("jsmith@corp.example.com", "jsmith"),
        ("CORP\\JSmith@corp.example.com", "jsmith"), (" jsmith ", "jsmith"), ("svc-backup@example.com", "svc-backup"),
        # The accounts every host has of its own relate nothing.
        ("root", None), ("SYSTEM", None), ("NT AUTHORITY\\SYSTEM", None), ("Local Service", None),
        ("NT AUTHORITY\\NETWORK SERVICE", None), ("root@db-01", None),
        ("", None), (None, None), (["jsmith"], None),
    ],
)
def test_a_user_relates_by_the_bare_account_name(spelling: Any, key: Optional[str]) -> None:
    assert user_key(spelling) == key


def test_relation_keys_are_hosts_and_users_and_never_ips() -> None:
    entities = {"hosts": ["WS-FIN-0142.corp.example.com", "dc-01"], "users": ["CORP\\jsmith", "SYSTEM"],
                "ips": ["192.0.2.142"], "domains": ["cdn-sync.updates-cloud.test"]}
    assert relation_keys(entities) == {"host:ws-fin-0142", "host:dc-01", "user:jsmith"}
    assert relation_keys({"ips": ["192.0.2.142"]}) == frozenset()
    assert relation_keys({"users": ["NT AUTHORITY\\SYSTEM", "root"]}) == frozenset()
    for unreadable in (None, [], "ws-fin-0142", {"hosts": "ws-fin-0142"}, {"hosts": [None, 7]}):
        assert relation_keys(unreadable) == frozenset()


@pytest.mark.parametrize(
    ("severity", "assessment", "verdict", "awaiting", "confirmed", "grade"),
    [
        ("high", "likely_threat", None, False, False, True),
        ("critical", "benign", "malicious", False, False, True),
        ("high", "suspicious", "inconclusive", False, False, False),  # a doubt is not a threat (#352)
        ("medium", "confirmed_threat", "malicious", False, False, False),  # only a model, below high: it links
        ("low", "likely_threat", None, False, False, False),
        ("low", "benign", "benign", True, False, True),  # a response waits for an approval, at any severity
        ("info", "benign", "benign", False, True, True),  # a person confirmed it
        ("high", None, None, False, False, False),
        (None, "likely_threat", "malicious", False, False, False),
    ],
)
def test_hold_grade_is_one_predicate(
    severity: Any, assessment: Any, verdict: Any, awaiting: bool, confirmed: bool, grade: bool
) -> None:
    assert hold_grade(severity=severity, threat_assessment=assessment, verdict=verdict, awaiting_approval=awaiting,
                      confirmed=confirmed) is grade
    assert model_judged_threat("suspicious", "inconclusive") is False
    assert model_judged_threat("likely_threat", None) and model_judged_threat(None, "malicious")


def facts(**changes: Any) -> RelatedFacts:
    values: Dict[str, Any] = {
        "id": "a-1", "status": "waiting_human", "severity": "high", "entities": {"hosts": ["WS-FIN-0142.corp.example.com"]},
        "threat_assessment": None, "verdict": "malicious", "planned": False, "confirmed": False,
        "ingested_at": NOW - timedelta(hours=1), "changed_at": NOW - timedelta(minutes=1),
    }
    values.update(changes)
    return RelatedFacts(**values)


@pytest.mark.parametrize(
    ("changes", "role"),
    [
        ({}, "hold"),
        ({"entities": {"users": ["CORP\\JSmith"]}}, "hold"),
        ({"ingested_at": NOW - timedelta(days=6, hours=23)}, "hold"),  # open: it holds for as long as it is open ...
        ({"ingested_at": NOW - timedelta(days=7, minutes=1)}, None),  # ... up to seven days from its ingestion
        ({"status": "waiting_approval", "severity": "low", "verdict": "benign"}, "hold"),
        ({"status": "processing", "severity": "medium", "verdict": "benign", "confirmed": True}, "hold"),
        ({"status": "queued"}, "hold"),  # requeued with a verdict a model already gave
        ({"status": "failed"}, None),  # a failed alert never holds
        ({"status": "failed", "confirmed": True}, None),
        ({"entities": {"hosts": ["dc-01"], "users": ["mgarcia"]}}, None),  # nothing shared
        ({"entities": {"hosts": ["dc-01"], "users": ["root", "NT AUTHORITY\\SYSTEM"], "ips": ["192.0.2.142"]}}, None),
        # Closed: only with a person's confirmation (the reader hands in the recent ones).
        ({"status": "closed", "confirmed": True, "verdict": "benign", "severity": "low"}, "hold"),
        ({"status": "closed"}, None),
        # A high or critical alert in progress on a shared host, while it changed in the last 15 minutes.
        ({"status": "processing", "verdict": None}, "in_progress"),
        ({"status": "processing", "verdict": None, "severity": "critical", "changed_at": NOW - timedelta(minutes=14)},
         "in_progress"),
        ({"status": "processing", "verdict": None, "changed_at": NOW - timedelta(minutes=16)}, None),  # a stuck run
        ({"status": "processing", "verdict": None, "severity": "medium"}, None),
        ({"status": "processing", "verdict": None, "entities": {"hosts": ["dc-01"], "users": ["jsmith"]}}, None),
        # Only a model stands behind it, below high: it links, for 24 hours.
        ({"severity": "medium"}, "model_only"),
        ({"severity": "low", "verdict": None, "threat_assessment": "confirmed_threat"}, "model_only"),
        ({"verdict": "inconclusive", "threat_assessment": "suspicious", "planned": True}, "model_only"),
        ({"severity": "medium", "ingested_at": NOW - timedelta(hours=25)}, None),
        ({"verdict": "inconclusive", "threat_assessment": "suspicious"}, None),
        ({"verdict": "benign", "threat_assessment": "benign"}, None),
    ],
)
def test_the_role_of_a_related_alert_for_a_close(changes: Dict[str, Any], role: Optional[str]) -> None:
    assert classify(facts(**changes), relation_keys(MINE), NOW) == role


def test_the_digest_lists_the_related_alerts_by_role_and_is_bounded() -> None:
    others: List[RelatedFacts] = [
        facts(id="hold-1"), facts(id="unrelated", entities={"hosts": ["dc-01"]}),
        facts(id="busy", status="processing", verdict=None), facts(id="link-1", severity="medium"),
        *[facts(id=f"hold-{n}") for n in range(2, 15)],
    ]
    digest = related_digest(MINE, others, NOW)
    assert digest == {"threats": ["hold-1", *[f"hold-{n}" for n in range(2, 11)]], "in_progress": ["busy"],
                      "model_only": ["link-1"]}
    # An alert with no host and no user of its own relates to nothing.
    assert related_digest({"ips": ["192.0.2.142"]}, others, NOW) == {"threats": [], "in_progress": [], "model_only": []}
