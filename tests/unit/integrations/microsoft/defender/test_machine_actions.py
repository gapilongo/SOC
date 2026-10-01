"""Machine actions: parsing (both update-time spellings), listing wire bytes, ours by marker, verification mapping."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.integrations.microsoft.defender import DEFENDER_ISOLATION
from lg_sotf.integrations.microsoft.defender._common import ms_id, parse_time
from lg_sotf.integrations.microsoft.defender.machine_actions import (
    latest,
    list_actions,
    ours,
    parse_action,
    verification_from,
)
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from tests.fixtures.microsoft import make_context
from tests.unit.integrations.microsoft.defender._support import FakeDefender


def entity(**fields: object) -> dict:  # type: ignore[type-arg]
    return {"id": str(uuid.uuid4()), "type": "Isolate", "status": "Pending", "machineId": "m1",
            "requestorComment": "LG-SOTF action x: t", "creationDateTimeUtc": "2026-09-30T08:00:00.1234567Z", **fields}


@pytest.mark.parametrize("name", ["lastUpdateDateTimeUtc", "lastUpdateTimeUtc"])
def test_both_update_time_spellings_are_parsed(name: str) -> None:
    action = parse_action(entity(**{name: "2026-09-30T09:15:02.7654321Z"}))
    assert action is not None
    assert action.last_update == datetime(2026, 9, 30, 9, 15, 2, 765432, tzinfo=UTC)
    assert action.created == datetime(2026, 9, 30, 8, 0, 0, 123456, tzinfo=UTC)
    assert action.when == action.last_update


def test_unusable_entities_are_skipped() -> None:
    assert parse_action({"type": "Isolate"}) is None
    assert parse_action(entity(id="../x")) is None
    assert parse_action("not an object") is None
    assert parse_time("yesterday") is None and parse_time(None) is None
    with pytest.raises(MicrosoftApiError):
        ms_id("a/b", "machine id")
    with pytest.raises(MicrosoftApiError):
        ms_id(True, "indicator id")
    assert ms_id(1234, "indicator id") == "1234"


@pytest.mark.parametrize(
    ("status", "state"),
    [("Pending", "pending"), ("InProgress", "pending"), ("Succeeded", "verified"), ("Failed", "failed"),
     ("TimeOut", "failed"), ("Cancelled", "failed")],
)
def test_verification_from(status: str, state: str) -> None:
    action = parse_action(entity(status=status))
    assert action is not None
    result = verification_from(action)
    assert result.state == state and result.detail["status"] == status


def test_ours_and_latest() -> None:
    mine = parse_action(entity(requestorComment="LG-SOTF action abc: rollback"))
    other = parse_action(entity(requestorComment="isolated by the analyst", status="Succeeded",
                                lastUpdateTimeUtc="2026-09-30T10:00:00Z"))
    older = parse_action(entity(status="Succeeded", lastUpdateTimeUtc="2026-09-29T10:00:00Z"))
    assert mine is not None and other is not None and older is not None
    assert ours([mine, other], "LG-SOTF action abc") == [mine] and ours([mine], "") == []
    assert latest([older, other, mine], lambda a: a.succeeded) == other
    assert latest([mine], lambda a: a.succeeded) is None


async def test_list_uses_and_only_and_sorts_by_creation() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    newer = defender.action(mid, "Isolate", "Succeeded", age=timedelta(hours=1))
    older = defender.action(mid, "Isolate", "Failed", age=timedelta(days=1))
    defender.action(mid, "Unisolate", "Succeeded")
    defender.action("another-machine", "Isolate", "Succeeded")
    ctx, _ = make_context(defender.fake, DEFENDER_ISOLATION, read_only=True)
    listed = await list_actions(ctx, mid, "Isolate")
    assert [a.id for a in listed] == [older, newer]
    (request,) = defender.fake.api_requests()
    assert request.url.query.decode("ascii") == (
        f"$filter=machineId%20eq%20%27{mid}%27%20and%20type%20eq%20%27Isolate%27&$top=50"
    )
