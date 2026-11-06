"""Bulk triage, the response preview helpers, the shared plan context and per-item error descriptions."""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

import pytest

from lg_sotf.api.errors import describe_error
from lg_sotf.db.errors import Conflict, DatabaseUnavailable, InvalidTransition, NotFound
from lg_sotf.services import triage
from lg_sotf.services.plan_context import corroborated_targets, plan_context, threat_texts
from lg_sotf.services.response_preview import _outcome, _role_lock
from lg_sotf.services.review import ReviewDenied, ReviewError

pytestmark = pytest.mark.unit


class FakeReview:
    """Answers each escalation id with a value, or raises the exception mapped to it."""

    def __init__(self, behaviour: dict[str, Any]) -> None:
        self.behaviour = behaviour
        self.calls: List[Tuple[str, Any]] = []

    def _answer(self, escalation_id: str) -> Any:
        value = self.behaviour[escalation_id]
        if isinstance(value, BaseException):
            raise value
        return value

    async def claim(self, tenant_id: str, escalation_id: str, user: Any, version: int, *, role: str) -> Any:
        self.calls.append(("claim", (escalation_id, version, role)))
        return self._answer(escalation_id)

    async def decide(self, tenant_id: str, escalation_id: str, user: Any, role: str, decision: str,
                     notes: Optional[str], approved: List[str], version: int, **kwargs: Any) -> Any:
        self.calls.append(("decide", (escalation_id, decision, notes, approved, version, kwargs)))
        return self._answer(escalation_id)


class Decided:
    def __init__(self, escalation: str) -> None:
        self.escalation = escalation


async def test_bulk_claim_reports_each_item_in_order() -> None:
    review = FakeReview({"a": "A", "b": Conflict("version moved"), "c": "C", "d": NotFound("escalation", "d")})
    out = await triage.bulk_claim(review, "t1", [("a", 1), ("b", 2), ("c", 3), ("d", 4)], user="u", role="analyst")  # type: ignore[arg-type]
    assert [(o.escalation_id, o.escalation, type(o.error).__name__ if o.error else None) for o in out] == [
        ("a", "A", None), ("b", None, "Conflict"), ("c", "C", None), ("d", None, "NotFound"),
    ]
    assert [c[1] for c in review.calls] == [("a", 1, "analyst"), ("b", 2, "analyst"), ("c", 3, "analyst"), ("d", 4, "analyst")]


async def test_an_unexpected_error_stops_the_batch() -> None:
    review = FakeReview({"a": "A", "b": DatabaseUnavailable("down"), "c": "C"})
    with pytest.raises(DatabaseUnavailable):
        await triage.bulk_claim(review, "t1", [("a", 1), ("b", 1), ("c", 1)], user="u", role="analyst")  # type: ignore[arg-type]
    assert [c[1][0] for c in review.calls] == ["a", "b"]


async def test_bulk_close_records_one_benign_decision_with_the_same_note() -> None:
    review = FakeReview({"a": Decided("A"), "b": ReviewDenied("claimed by another analyst")})
    out = await triage.bulk_close(
        review, "t1", [("a", 0), ("b", 5)], user="u", role="analyst", decision="benign_positive", notes="known",  # type: ignore[arg-type]
        suggest_suppression=False,
    )
    assert out[0].escalation == "A" and out[0].decision is not None and isinstance(out[1].error, ReviewDenied)
    assert review.calls[0][1] == ("a", "benign_positive", "known", [], 0, {"suggest_suppression": False})


@pytest.mark.parametrize(
    ("ids", "decision"),
    [([], "false_positive"), ([f"e{i}" for i in range(triage.MAX_BULK + 1)], "false_positive"),
     (["a", "a"], "false_positive"), (["a"], "true_positive")],
)
async def test_bulk_batches_are_bounded_distinct_and_benign(ids: List[str], decision: str) -> None:
    review = FakeReview({})
    with pytest.raises(ReviewError):
        await triage.bulk_close(review, "t1", [(i, 0) for i in ids], user="u", role="analyst", decision=decision, notes="n")  # type: ignore[arg-type]
    assert review.calls == []


def test_rule_names_say_what_the_proposal_covers() -> None:
    assert triage._rule_name(["Unusual sign-in", "Unusual sign-in"], 2) == "Proposed from 2 benign escalation(s): Unusual sign-in"
    assert triage._rule_name(["A", "B", "A"], 3) == "Proposed from 3 benign escalations of 2 detections"
    assert len(triage._rule_name(["x" * 500], 1)) == triage.MAX_RULE_NAME_CHARS


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (NotFound("escalation", "e1"), (404, "not_found")),
        (Conflict("stale"), (409, "conflict")),
        (InvalidTransition("escalation", "e1", "decided", "claimed"), (409, "invalid_transition")),
        (ReviewDenied("no"), (403, "forbidden")),
        (ReviewError("bad"), (400, "invalid_request")),
    ],
)
def test_items_are_described_like_the_single_endpoint_answers(exc: Exception, expected: Tuple[int, str]) -> None:
    described = describe_error(exc)
    assert described is not None and described[:2] == expected and described[2]


def test_errors_without_a_simple_handler_are_not_described() -> None:
    assert describe_error(DatabaseUnavailable("down")) is None
    assert describe_error(ValueError("internal detail")) is None


def test_preview_outcomes_and_role_locks() -> None:
    assert _outcome(True, "auto") == "blocked"
    assert _outcome(False, "auto") == "automatic"
    assert _outcome(False, "approval") == "awaiting_approval"
    assert _role_lock("medium", "approval") is None
    assert _role_lock("high", "approval") == "admin"
    assert _role_lock("low", "disabled") == "disabled"


def test_plan_context_reads_the_alert_and_its_digests() -> None:
    alert = {
        "title": "Ransomware beacon",
        "category": "malware",
        "entities": {"hosts": ["ws-042", 7], "ips": ["185.220.101.44"]},
        "mitre": {"tactics": ["command-and-control"], "techniques": [1071]},
        "raw": {},
    }
    analysis = {
        "conclusion": "C2 beacon.",
        "recommended_actions": ["isolate host"],
        "corroborated_targets": [["ip", "185.220.101.44"], ["bad"]],
    }
    ctx = plan_context(alert, severity="high", evidence="analyst", analysis=analysis, triage={"threat_categories": ["c2"]})
    assert (ctx.severity, ctx.evidence, ctx.title, ctx.category) == ("high", "analyst", "Ransomware beacon", "malware")
    assert ctx.hosts == ["ws-042"] and ctx.recommended_actions == ["isolate host"]
    assert ctx.threat_texts == ["C2 beacon.", "c2", "command-and-control", "1071"]
    assert ctx.corroborated_targets == frozenset({("ip", "185.220.101.44")})
    assert ctx.approved_actions == [] and ctx.approved_by is None
    assert corroborated_targets({}) is None
    assert threat_texts({}, {}, {}) == [""]
