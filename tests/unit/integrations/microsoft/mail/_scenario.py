"""Scenario helpers of the mail capability tests: a reported phish, its alert view, ledger rows and handler runs."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.integrations.microsoft.alert_view import AlertView
from lg_sotf.integrations.microsoft.capability import CapabilitySpec, HandlerContext
from tests.fixtures.microsoft import FakeMicrosoft, default_alert, make_action, make_context
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange

SENDER = "billing@attacker.example"
SUBJECT = "Invoice overdue"
ALICE = "alice@contoso.example"
BOB = "bob@contoso.example"
CAROL = "carol@contoso.example"
SOC = "soc@contoso.example"


def message_id() -> str:
    """A fresh Internet Message-ID (angle brackets included, as Graph stores it)."""
    return f"<{uuid.uuid4().hex}@mail.attacker.example>"


def phish_alert(
    mid: str,
    recipients: Sequence[str] = (ALICE, BOB),
    *,
    reporter: Optional[str] = ALICE,
    received_at: Optional[datetime] = None,
    subject: str = SUBJECT,
    disposition: str = "malicious",
    ingested_at: Optional[datetime] = None,
) -> AlertView:
    received = received_at or datetime.now(UTC) - timedelta(hours=2)
    email = {
        "message_id": mid, "from": SENDER, "subject": subject, "recipients": tuple(recipients),
        "reporter": reporter, "received_at": received.isoformat(),
    }
    return default_alert(email=MappingProxyType(email), received_at=received, disposition=disposition,
                         ingested_at=ingested_at)


def purge_action(mid: str, *, sender: Optional[str] = SENDER, **fields: Any) -> ResponseAction:
    match: Dict[str, Any] = {"internet_message_id": mid, "subject": SUBJECT}
    if sender is not None:
        match["sender"] = sender
    return make_action("purge_message", mid, params={"match": match, "playbook": "phishing"}, **fields)


def executed(action: ResponseAction, result: ConnectorResult, **fields: Any) -> ResponseAction:
    """The row as the ledger holds it after ``result`` (for a rollback, a re-check or a re-run)."""
    status = {"deferred": "executing"}.get(result.status, result.status)
    values = {"status": status, "result": result.detail, "external_ref": result.external_ref, **fields}
    return action.model_copy(update=values)


@dataclass
class Run:
    """One handler call and what it left behind."""

    ctx: HandlerContext
    store: Dict[str, Any]
    result: Any = None
    checkpoints: List[Dict[str, Any]] = field(default_factory=list)


def mail_world(*, recoverable_by_id: bool = True) -> tuple[FakeMicrosoft, FakeExchange]:
    fake = FakeMicrosoft()
    return fake, FakeExchange(fake, recoverable_by_id=recoverable_by_id)


def context(
    fake: FakeMicrosoft,
    spec: CapabilitySpec,
    action: ResponseAction,
    *,
    options: Mapping[str, Any] = MappingProxyType({}),
    alert: Optional[AlertView] = None,
    original: Optional[ResponseAction] = None,
    read_only: bool = False,
    deadline_s: float = 30.0,
) -> Run:
    """A context whose checkpoints are also recorded one by one (``Run.checkpoints``)."""
    ctx, store = make_context(fake, spec, options=options, action=action, alert=alert, original=original,
                              read_only=read_only, deadline_s=deadline_s)
    run = Run(ctx=ctx, store=store)
    inner = ctx.checkpoint

    async def checkpoint(patch: Mapping[str, Any]) -> None:
        await inner(patch)
        run.checkpoints.append(dict(patch))

    ctx.checkpoint = checkpoint
    return run


__all__ = [
    "ALICE", "BOB", "CAROL", "SENDER", "SOC", "SUBJECT", "Run", "context", "executed", "mail_world", "message_id",
    "phish_alert", "purge_action",
]
