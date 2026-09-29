"""The connector contract: how an approved ledger action reaches an external system.

A connector executes exactly one :class:`~lg_sotf.db.repos.ResponseAction`
and reports what happened as a :class:`ConnectorResult`; the response
service writes that outcome to the ledger. Connectors never touch the ledger
themselves.

Idempotency: the ledger guarantees that one worker at a time runs a given
action, but an interrupted execution (worker crash between the external call
and the ledger write) is run again. Every connector must therefore be
idempotent per action id: calling :meth:`Connector.execute` twice for the same
action must not perform the external change twice (the webhook connector
sends the action id as ``Idempotency-Key`` so the receiver can deduplicate).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

ConnectorStatus = Literal["succeeded", "failed", "dry_run"]


class ConnectorConfigError(ValueError):
    """A connector cannot be built from the tenant/install configuration (message is safe to store)."""


@dataclass(frozen=True)
class ConnectorResult:
    """Outcome of one execution. ``detail`` is stored in ``response_actions.result``: keep it small, no secrets."""

    status: ConnectorStatus
    detail: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Connector(Protocol):
    """Executes one approved ledger action. Implementations must be idempotent per action id."""

    name: str

    async def execute(self, action: ResponseAction) -> ConnectorResult: ...


class MisconfiguredConnector:
    """Stands in for a connector whose configuration is invalid: every execution fails with the reason.

    Used so that a broken tenant configuration fails the affected actions
    visibly on the ledger instead of failing the whole workflow run (or,
    worse, silently falling back to another connector).
    """

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason[:300]

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        return ConnectorResult("failed", {"error": "connector_misconfigured", "reason": self.reason})
