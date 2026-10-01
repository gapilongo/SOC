"""mail.remediate restore_message: the rollback of a purge moves each removed item back to its folder."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Tuple

import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_REMEDIATE
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange, FakeMessage
from tests.unit.integrations.microsoft.mail._scenario import (
    ALICE,
    BOB,
    context,
    executed,
    mail_world,
    message_id,
    phish_alert,
    purge_action,
)


async def purged(
    *, mode: str = "soft_delete", recoverable_by_id: bool = True
) -> Tuple[FakeMicrosoft, FakeExchange, ResponseAction, Dict[str, FakeMessage], str]:
    """A purge of one message from ALICE's Inbox and BOB's "Projects" folder, as the ledger holds it."""
    fake, exchange = mail_world(recoverable_by_id=recoverable_by_id)
    mid = message_id()
    exchange.mailbox(BOB).add_folder("Projects")
    copies = {ALICE: exchange.mailbox(ALICE).add(mid), BOB: exchange.mailbox(BOB).add(mid, folder="Projects")}
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, options={"mode": mode}, alert=phish_alert(mid, (ALICE, BOB), reporter=None))
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert result.status == "succeeded", result.detail
    return fake, exchange, executed(action, result), copies, mid


def rollback_of(original: ResponseAction, **fields: Any) -> ResponseAction:
    return make_action(
        "restore_message", original.target, rollback_of=original.id, execution_owner="scheduler",
        params={"rollback": {"of": str(original.id), "reason": "false positive", "requested_by": "user:x"}},
        **fields,
    )


async def restore(fake: FakeMicrosoft, original: ResponseAction, action: ResponseAction, **options: Any) -> Any:
    run = context(fake, MAIL_REMEDIATE, action, options=options, original=original)
    run.result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    return run


def moves(fake: FakeMicrosoft, since: int = 0) -> list[Dict[str, Any]]:
    return [
        {"path": r.url.path, **json.loads(r.content)}
        for r in fake.writes()[since:]
        if r.url.path.endswith("/move")
    ]


@pytest.mark.parametrize("recoverable_by_id", [True, False])
async def test_restore_moves_each_item_back_to_its_folder(recoverable_by_id: bool) -> None:
    fake, exchange, original, copies, _ = await purged(recoverable_by_id=recoverable_by_id)
    before = len(fake.writes())
    action = rollback_of(original)
    run = await restore(fake, original, action)
    result = run.result
    assert result.status == "succeeded", result.detail
    assert result.detail["summary"] == "restored the message in 2 of 2 mailboxes" and result.detail["restored"] == 2
    assert exchange.mailbox(ALICE).where(copies[ALICE]) == "inbox"
    assert exchange.mailbox(BOB).where(copies[BOB]) == "Projects"
    projects = exchange.mailbox(BOB).folders["Projects"]
    assert sorted(m["destinationId"] for m in moves(fake, before)) == sorted(["inbox", projects])
    ref = result.external_ref
    assert ref["reversible"] is False and ref["restores"] == str(original.id) and ref["mode"] == "soft_delete"
    steps = {s["mailbox"]: s for s in ref["steps"]}
    assert steps[ALICE]["items"] == [{"id": copies[ALICE].id, "folder": exchange.mailbox(ALICE).folders["inbox"]}]
    assert result.verify is not None and result.verify.state == "verified"
    if not recoverable_by_id:  # found again by Message-ID in Recoverable Items
        lookups = [p for m, p in exchange.log if m == "GET" and p.endswith("/recoverableitemsdeletions/messages")]
        assert len(lookups) == 2


async def test_restore_after_a_move_to_deleted_items() -> None:
    fake, exchange, original, copies, _ = await purged(mode="move_to_deleted_items")
    assert exchange.mailbox(ALICE).where(copies[ALICE]) == "deleteditems"
    run = await restore(fake, original, rollback_of(original), mode="soft_delete")  # the purge's mode wins
    assert run.result.status == "succeeded" and run.result.external_ref["mode"] == "move_to_deleted_items"
    assert exchange.mailbox(ALICE).where(copies[ALICE]) == "inbox"
    assert exchange.mailbox(BOB).where(copies[BOB]) == "Projects"


async def test_a_folder_that_no_longer_exists_falls_back_to_the_inbox() -> None:
    fake, exchange, original, copies, _ = await purged()
    box = exchange.mailbox(BOB)
    del box.folders["Projects"]  # the user deleted the folder since
    before = len(fake.writes())
    run = await restore(fake, original, rollback_of(original))
    assert run.result.status == "succeeded"
    assert exchange.mailbox(BOB).where(copies[BOB]) == "inbox"
    bob_moves = [m["destinationId"] for m in moves(fake, before) if f"/users/{BOB}/" in m["path"]]
    assert bob_moves[-1] == "inbox" and len(bob_moves) == 2


async def test_error_item_not_found_on_the_move_also_falls_back() -> None:
    fake, exchange, original, copies, _ = await purged()
    exchange.fail("POST", rf"/v1\.0/users/{BOB}/messages/.+/move", graph_error(400, "ErrorItemNotFound"))
    run = await restore(fake, original, rollback_of(original))
    assert run.result.status == "succeeded" and exchange.mailbox(BOB).where(copies[BOB]) == "inbox"


async def test_nothing_left_to_restore_is_rollback_not_needed() -> None:
    fake, exchange, original, copies, _ = await purged()
    for address, message in copies.items():
        exchange.mailbox(address).messages.pop(message.id)  # purged by retention
    run = await restore(fake, original, rollback_of(original))
    result = run.result
    assert result.status == "succeeded" and result.detail["changed"] is False
    assert result.detail["error"] == "rollback_not_needed" and result.verify is None
    assert {s["status"] for s in result.external_ref["steps"]} == {"not_found"}
    assert moves(fake) == []


async def test_after_the_window_nothing_found_is_rollback_window_expired() -> None:
    fake, exchange, original, copies, _ = await purged()
    for address, message in copies.items():
        exchange.mailbox(address).messages.pop(message.id)
    expired = {**(original.external_ref or {}), "rollback_until": (datetime.now(UTC) - timedelta(days=1)).isoformat()}
    old = original.model_copy(update={"external_ref": expired})
    run = await restore(fake, old, rollback_of(old))
    assert run.result.status == "failed" and run.result.detail["error"] == "rollback_window_expired"


async def test_items_already_back_in_place_are_not_moved() -> None:
    fake, exchange, original, copies, _ = await purged()
    for address, message in copies.items():
        box = exchange.mailbox(address)
        box.messages[message.id].folder = box.folders["inbox" if address == ALICE else "Projects"]
    before = len(fake.writes())
    run = await restore(fake, original, rollback_of(original))
    assert run.result.status == "succeeded" and run.result.detail["already"] is True
    assert run.result.detail["changed"] is False and moves(fake, before) == []


async def test_an_interrupted_restore_does_not_move_twice() -> None:
    fake, exchange, original, copies, mid = await purged()
    box = exchange.mailbox(ALICE)
    box.messages[copies[ALICE].id].folder = box.folders["inbox"]  # the first run's move was applied ...
    interrupted = {  # ... but the crash came before it was recorded
        "mode": "soft_delete", "internet_message_id": mid, "restores": str(original.id),
        "steps": [
            {"mailbox": ALICE, "status": "pending", "items": [{"id": copies[ALICE].id, "folder": "inbox"}]},
            {"mailbox": BOB, "status": "pending"},
        ],
    }
    before = len(fake.writes())
    run = await restore(fake, original, rollback_of(original, external_ref=interrupted))
    result = run.result
    assert result.status == "succeeded" and result.detail["counts"]["done"] == 2
    assert [m["path"] for m in moves(fake, before)] == [f"/v1.0/users/{BOB}/messages/{copies[BOB].id}/move"]


async def test_a_partial_purge_is_restored_where_it_changed_something() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    alice = exchange.mailbox(ALICE).add(mid)
    bob = exchange.mailbox(BOB).add(mid)
    exchange.fail("DELETE", rf"/v1\.0/users/{BOB}/messages/.+", graph_error(503, "ServiceUnavailable"), times=None)
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid, (ALICE, BOB), reporter=None))
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert result.status == "failed" and result.detail["error"] == "partial"
    assert {s["mailbox"]: s["status"] for s in result.external_ref["steps"]} == {ALICE: "done", BOB: "failed"}
    original = executed(action, result)
    back = await restore(fake, original, rollback_of(original))
    steps = {s["mailbox"]: s for s in back.result.external_ref["steps"]}
    assert steps[ALICE]["status"] == "done" and steps[BOB] == {"mailbox": BOB, "status": "skipped",
                                                               "reason": "already_in_place"}
    assert exchange.mailbox(ALICE).where(alice) == "inbox" and exchange.mailbox(BOB).where(bob) == "inbox"


async def test_restore_needs_the_purge_it_rolls_back() -> None:
    fake, exchange = mail_world()
    action = make_action("restore_message", message_id())
    run = await restore(fake, None, action)  # type: ignore[arg-type]
    assert run.result.status == "failed" and run.result.detail["error"] == "invalid_target"
    assert fake.requests == []


async def test_restore_proof_waits_then_verifies() -> None:
    fake, exchange, original, copies, _ = await purged()
    action = rollback_of(original)
    run = context(fake, MAIL_REMEDIATE, action, original=original)

    def unavailable_after_the_move(request: Any) -> None:  # the proof's read of ALICE's item fails
        if request.url.path.startswith(f"/v1.0/users/{ALICE}/") and request.url.path.endswith("/move"):
            exchange.fail("GET", rf"/v1\.0/users/{ALICE}/messages/[^/]+", graph_error(503, "ServiceUnavailable"),
                          times=3)

    exchange.on_write = unavailable_after_the_move
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    plan = result.verify
    assert result.status == "succeeded" and plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (60.0, 900.0) and plan.detail["proven"] == [BOB]
    row = executed(action, result, verification="pending", verification_detail=dict(plan.detail))
    verdict = await MAIL_REMEDIATE.handler(context(fake, MAIL_REMEDIATE, row, read_only=True).ctx).verify(row)
    assert verdict.state == "verified" and verdict.detail == {"mailboxes": 2}


async def test_restore_verification_waits_while_an_item_is_elsewhere() -> None:
    fake, exchange, original, copies, _ = await purged()
    action = rollback_of(original)
    run = await restore(fake, original, action)
    box = exchange.mailbox(ALICE)
    box.messages[copies[ALICE].id].folder = box.folders["junkemail"]
    row = executed(action, run.result, verification="pending", verification_detail={})
    verdict = await MAIL_REMEDIATE.handler(context(fake, MAIL_REMEDIATE, row, read_only=True).ctx).verify(row)
    assert verdict.state == "pending" and verdict.detail["unproven"] == [ALICE]
