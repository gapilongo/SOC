"""mail.remediate and recipient addresses that are not the user principal name (aliases, hybrid SMTP addresses).

Graph addresses a mailbox only by its owner's object id or UPN: an alias
answers 404 exactly like an address nobody has. The purge must find the
owner before it concludes ``mailbox_not_found``, and keep addressing the
mailbox by the owner's id afterwards (re-runs, proof, restore).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Tuple

import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.alert_view import AlertView
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_REMEDIATE
from lg_sotf.services.connectors.base import ConnectorResult
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action
from tests.unit.integrations.microsoft.mail._scenario import (
    Run,
    context,
    executed,
    mail_world,
    message_id,
    phish_alert,
    purge_action,
)

JANE = "jane@corp.contoso.example"  # the user principal name
JANE_SMTP = "jane@contoso.example"  # her primary SMTP address (hybrid tenant)
INFO = "info@contoso.example"  # a proxy address of hers
GHOST = "ghost@partner.example"


async def purge(
    fake: FakeMicrosoft, action: ResponseAction, alert: AlertView, **options: Any
) -> Tuple[ConnectorResult, Run]:
    run = context(fake, MAIL_REMEDIATE, action, options=options, alert=alert)
    return await MAIL_REMEDIATE.handler(run.ctx).execute(action), run


async def test_a_proxy_address_is_resolved_to_its_mailbox_before_mailbox_not_found() -> None:
    fake, exchange = mail_world()
    box = exchange.alias(JANE, INFO, mail=JANE_SMTP)
    mid = message_id()
    copy = box.add(mid)
    result, run = await purge(fake, purge_action(mid), phish_alert(mid, (INFO, GHOST), reporter=None))
    assert result.status == "succeeded", result.detail
    assert result.detail["removed"] == 1 and exchange.mailbox(JANE).where(copy) == "recoverableitemsdeletions"
    steps = {s["mailbox"]: s for s in result.external_ref["steps"]}
    assert steps[INFO]["status"] == "done" and steps[INFO]["user_id"] == box.id
    assert steps[GHOST] == {"mailbox": GHOST, "status": "mailbox_not_found"}
    # The write went to the owner's object id, never to the alias.
    assert [r.url.path for r in fake.writes()] == [f"/v1.0/users/{box.id}/messages/{copy.id}"]
    lookups = [r.url.params["$filter"] for r in fake.api_requests() if r.url.path == "/v1.0/users"]
    assert f"mail eq '{INFO}'" in lookups and f"proxyAddresses/any(x:x eq 'smtp:{INFO}')" in lookups
    assert result.verify is not None and result.verify.state == "verified"


async def test_message_trace_smtp_addresses_of_a_hybrid_tenant_are_found() -> None:
    fake, exchange = mail_world()
    box = exchange.alias(JANE, mail=JANE_SMTP)
    mid = message_id()
    copy = box.add(mid)
    exchange.trace(mid, JANE_SMTP)
    alert = phish_alert(mid, (), reporter=None, received_at=datetime.now(UTC) - timedelta(hours=2))
    result, _ = await purge(fake, purge_action(mid), alert, recipient_source="message_trace")
    assert result.status == "succeeded" and result.detail["removed"] == 1
    assert exchange.mailbox(JANE).where(copy) == "recoverableitemsdeletions"


async def test_the_proof_the_verification_and_the_restore_use_the_recorded_owner() -> None:
    fake, exchange = mail_world()
    box = exchange.alias(JANE, INFO)
    mid = message_id()
    copy = box.add(mid)
    action = purge_action(mid)
    result, _ = await purge(fake, action, phish_alert(mid, (INFO,), reporter=None))
    assert result.detail["removed"] == 1
    original = executed(action, result)
    check = context(fake, MAIL_REMEDIATE, original, read_only=True)
    assert (await MAIL_REMEDIATE.handler(check.ctx).verify(original)).state == "verified"
    rollback = make_action("restore_message", mid, rollback_of=original.id, execution_owner="scheduler")
    run = context(fake, MAIL_REMEDIATE, rollback, original=original)
    restored = await MAIL_REMEDIATE.handler(run.ctx).execute(rollback)
    assert restored.status == "succeeded", restored.detail
    assert exchange.mailbox(JANE).where(copy) == "inbox"
    assert all(f"/v1.0/users/{box.id}/" in r.url.path for r in fake.writes())
    # The restore's own steps keep the owner, so its proof (inline and later) reads the right mailbox.
    assert restored.verify is not None and restored.verify.state == "verified"
    assert [s.get("user_id") for s in (restored.external_ref or {})["steps"]] == [box.id]
    done = executed(rollback, restored)
    recheck = context(fake, MAIL_REMEDIATE, done, original=original, read_only=True)
    assert (await MAIL_REMEDIATE.handler(recheck.ctx).verify(done)).state == "verified"


async def test_a_rerun_addresses_the_mailbox_by_the_recorded_owner() -> None:
    fake, exchange = mail_world()
    box = exchange.alias(JANE, INFO)
    mid = message_id()
    box.add(mid)
    exchange.fail("DELETE", r"/v1\.0/users/[^/]+/messages/[^/]+", graph_error(429, "TooManyRequests",
                                                                             headers={"Retry-After": "600"}))
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid, (INFO,), reporter=None))
    with pytest.raises(MicrosoftApiError):  # throttling stops the run (the framework defers it)
        await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    (step,) = run.store["steps"]
    assert step["status"] == "pending" and step["user_id"] == box.id and step["items"]
    lookups_before = len([r for r in fake.api_requests() if r.url.path == "/v1.0/users"])
    rerun = action.model_copy(update={"status": "executing", "external_ref": dict(run.store)})
    again = context(fake, MAIL_REMEDIATE, rerun, alert=phish_alert(mid, (INFO,), reporter=None))
    result = await MAIL_REMEDIATE.handler(again.ctx).execute(rerun)
    assert result.status == "succeeded", result.detail
    assert len([r for r in fake.api_requests() if r.url.path == "/v1.0/users"]) == lookups_before


async def test_two_owners_of_one_address_fail_that_mailbox() -> None:
    fake, exchange = mail_world()
    exchange.alias(JANE, INFO)
    exchange.alias("john@corp.contoso.example", INFO)
    mid = message_id()
    result, _ = await purge(fake, purge_action(mid), phish_alert(mid, (INFO,), reporter=None))
    assert result.status == "failed" and result.detail["error"] == "ambiguous_target"
    assert fake.writes() == []


async def test_without_user_read_all_an_alias_mailbox_fails_instead_of_counting_as_missing() -> None:
    fake, exchange = mail_world()
    box = exchange.alias(JANE, INFO)
    mid = message_id()
    box.add(mid)
    exchange.fail("GET", r"/v1\.0/users", graph_error(403, "Authorization_RequestDenied"), times=None)
    result, _ = await purge(fake, purge_action(mid), phish_alert(mid, (INFO,), reporter=None))
    # Never "nothing to remove": the mailbox could not be searched.
    assert result.status == "failed" and result.detail["error"] == "permission_denied"
    assert "User.Read.All" in result.detail["hint"] and fake.writes() == []
