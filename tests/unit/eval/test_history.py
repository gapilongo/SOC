"""Backtest helpers (lg_sotf.eval.history) and the ``--from-history`` option checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, List

import pytest
from click.testing import CliRunner

from lg_sotf.db.repos import Alert
from lg_sotf.db.repos.indicators import IndicatorsRepo, RelatedAlert
from lg_sotf.eval.command import EvalCommandError, EvalOptions, execute
from lg_sotf.eval.history import (
    PointInTimeIndicatorsRepo,
    ReadOnlyDatabase,
    Replay,
    ReplayWriteBlocked,
    as_of,
    classify,
    item_id_for,
)
from lg_sotf.eval.results import ItemResult
from lg_sotf.settings import Settings

T0 = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _alert(**kwargs: Any) -> Alert:
    base = dict(
        tenant_id="t", id="a1", source_id="s", source_alert_id="x", fingerprint="f", title="t", severity="low",
        category=None, status="closed", disposition="benign", confidence=None, threat_score=None, priority=None,
        assigned_to=None, occurred_at=T0, ingested_at=T0, updated_at=T0, closed_at=T0 + timedelta(hours=1),
        summary={"analyst_decision": "false_positive"}, case_key=None, raw={}, normalized={},
    )
    base.update(kwargs)
    return Alert(**base)


def _result() -> ItemResult:
    return ItemResult(item_id="a", split="history", tags=[], source_type="canonical", expected="malicious", status="error")


def test_as_of_hides_outcomes_after_the_cutoff() -> None:
    alert = _alert()
    assert as_of(alert, T0 + timedelta(hours=2)) is alert
    hidden = as_of(alert, T0 + timedelta(minutes=30))
    assert (hidden.status, hidden.disposition, hidden.closed_at, hidden.summary) == ("processing", None, None, {})
    still_open = as_of(_alert(status="waiting_human", closed_at=None, disposition=None), T0 + timedelta(days=9))
    assert still_open.summary == {} and still_open.status == "processing"


def test_classify_uses_the_harness_prediction_semantics() -> None:
    usage = {"calls": 3, "input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cost_usd": 0.25}
    closed = _result()
    classify(closed, Replay(state={}, route="close", usage=usage))
    assert (closed.status, closed.predicted, closed.disposition, closed.close_reason) == (
        "closed", "benign", "benign", "triage:false_positive"
    )
    assert (closed.llm_calls, closed.total_tokens, closed.cost_usd) == (3, 15, 0.25)
    policy = _result()
    classify(policy, Replay(state={"decision": {"route": "close", "disposition": "benign", "code": "c"}}, route="close"))
    assert policy.close_reason == "policy:close" and policy.decision_code == "c"
    respond = _result()
    classify(respond, Replay(state={"decision": {"route": "plan_response", "code": "high_risk"}}, route="plan_response"))
    assert (respond.status, respond.predicted, respond.approval_requested) == ("waiting_approval", "malicious", True)
    escalated = _result()
    classify(escalated, Replay(state={"analysis": {"verdict": "benign"}, "decision": {"route": "escalate"}},
                               route="escalate"))
    assert (escalated.status, escalated.predicted, escalated.escalated) == ("waiting_human", "benign", True)
    refused = _result()
    classify(refused, Replay(state={"triage": {"llm_refusal": {"reason": "model_refused"}}}, route="escalate"))
    assert refused.predicted == "inconclusive" and refused.model_refused is True


def test_item_ids_are_valid_dataset_names() -> None:
    assert item_id_for("3e032650-2ed7-48c9-91f5-134bfe091f16") == "3e032650-2ed7-48c9-91f5-134bfe091f16"
    odd = item_id_for("weird id/with spaces")
    assert odd.startswith("h-") and len(odd) == 34 and odd == item_id_for("weird id/with spaces")


async def test_point_in_time_indicators_shift_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[dict] = []

    async def fake_related(self: Any, tenant_id: str, indicators: Any, **kwargs: Any) -> List[RelatedAlert]:
        calls.append(kwargs)
        return [RelatedAlert(alert_id="r", shared_indicator_count=1, last_seen=T0 - timedelta(minutes=10))]

    monkeypatch.setattr(IndicatorsRepo, "related_alerts", fake_related)
    offset = timedelta(days=30)
    repo = PointInTimeIndicatorsRepo(object(), cutoff=T0, offset=offset)
    wall_now = T0 + offset
    related = await repo.related_alerts("t", [("ip", "h")], since=wall_now - timedelta(hours=1), limit=5)
    assert calls[0]["since"] == T0 - timedelta(hours=1) and calls[0]["until"] == T0 and calls[0]["limit"] == 5
    # Seen 10 minutes before the cutoff reads as 10 minutes before "now".
    assert related[0].last_seen == wall_now - timedelta(minutes=10)
    await repo.related_alerts("t", [("ip", "h")], since=wall_now, until=wall_now + timedelta(days=1))
    assert calls[1]["until"] == T0
    assert await repo.add_sightings("t", "a", [("ip", "h", "d", T0)]) == 0


async def test_read_only_database_refuses_system_transactions() -> None:
    ro = ReadOnlyDatabase(object())  # type: ignore[arg-type]
    with pytest.raises(ReplayWriteBlocked):
        async with ro.system_tx():
            pass


@pytest.mark.parametrize(
    ("options", "message"),
    [
        (EvalOptions(dataset="x.jsonl", report="r.json", tenant_id="t", from_history=True), "do not pass --dataset"),
        (EvalOptions(dataset="", report="r.json", from_history=True), "needs --tenant"),
        (EvalOptions(dataset="", report="r.json", tenant_id="t", from_history=True, splits=("a",)), "--split"),
        (EvalOptions(dataset="", report="r.json", tenant_id="t", from_history=True, days=400), "--days"),
    ],
)
def test_from_history_option_errors(options: EvalOptions, message: str) -> None:
    with pytest.raises(EvalCommandError, match=message):
        execute(Settings(_env_file=None, environment="test"), options)


def test_from_history_validate_only(tmp_path: Any) -> None:
    lines: List[str] = []
    options = EvalOptions(
        dataset="", report=str(tmp_path / "r.json"), tenant_id="acme", from_history=True, days=7, validate_only=True
    )
    assert execute(Settings(_env_file=None, environment="test"), options, echo=lines.append) == 0
    assert lines == ["history backtest options ok: tenant acme, last 7 days, at most 500 alerts"]


def test_cli_requires_a_dataset_or_from_history() -> None:
    from lg_sotf.cli import cli

    result = CliRunner().invoke(cli, ["eval", "--report", "r.json"])
    assert result.exit_code == 2 and "--dataset" in result.output
    too_many = CliRunner().invoke(cli, ["eval", "--from-history", "--tenant", "t", "--limit", "10001"])
    assert too_many.exit_code == 2 and "10000" in too_many.output
    bad_days = CliRunner().invoke(cli, ["eval", "--from-history", "--tenant", "t", "--days", "0"])
    assert bad_days.exit_code == 2
