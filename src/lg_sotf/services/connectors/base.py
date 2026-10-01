"""The connector contract: how an approved ledger action reaches an external system.

A connector executes exactly one :class:`~lg_sotf.db.repos.ResponseAction`
and reports what happened as a :class:`ConnectorResult`; the response
service writes that outcome to the ledger. Connectors never change a ledger
row's status themselves (a stateful connector only checkpoints its progress
into the executing row's ``external_ref``).

Idempotency: the ledger guarantees that one worker at a time runs a given
action, but an interrupted execution (worker crash between the external call
and the ledger write) is run again. Every connector must therefore be
idempotent per action id: calling :meth:`Connector.execute` twice for the same
action must not perform the external change twice (the webhook connector
sends the action id as ``Idempotency-Key`` so the receiver can deduplicate).

Stateful connectors (the direct Microsoft connector) may also answer
``deferred``: the call could not finish now (throttled, or a write whose
outcome is unknown) and must be run again later. The row stays
``executing`` and the scheduler owns it from then on. Such connectors can
also be a :class:`Verifier`: after ``succeeded`` they prove the change by
reading it back (``ConnectorResult.verify`` schedules that).

:data:`call_deadline` carries the absolute deadline (``loop.time()``) of the
current connector call, set by the response service around
:meth:`Connector.execute`; connectors that do several requests per call read
it with :func:`current_deadline` so they finish before the caller gives up.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Literal, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

ConnectorStatus = Literal["succeeded", "failed", "dry_run", "deferred"]
VerificationState = Literal["pending", "verified", "failed", "inconclusive"]
FINAL_VERIFICATION_STATES = ("verified", "failed", "inconclusive")

# The deadline (event loop clock) of the connector call in progress; None outside one.
call_deadline: ContextVar[Optional[float]] = ContextVar("lg_sotf_connector_call_deadline", default=None)


def current_deadline(default_s: float) -> float:
    """The current call's deadline (``loop.time()``), or now + ``default_s`` outside a response-service call."""
    loop = asyncio.get_running_loop()
    value = call_deadline.get()
    return value if value is not None else loop.time() + default_s


class ConnectorConfigError(ValueError):
    """A connector cannot be built from the tenant/install configuration (message is safe to store)."""


class LedgerUnavailable(RuntimeError):
    """The ledger could not be read or written during a stateful connector call (raised from the database error).

    Never recorded as the action's outcome: the external change may already
    have happened, and a checkpoint or the alert read failing says nothing
    about it. The response service lets it propagate, so the row stays
    ``executing`` and the workflow node's retry or the scheduler's lease runs
    it again (the handler reconciles from its checkpoints).
    """


@dataclass(frozen=True)
class VerifyPlan:
    """How to prove a ``succeeded`` change (``ConnectorResult.verify``).

    ``state="verified"``: an inline re-read already proved it. ``"pending"``:
    the verification job re-queries after ``first_check_s`` and then with
    backoff until ``max_duration_s`` after execution (capped by
    ``response.verify_max_s``). ``detail`` is the observed state: small, no secrets.
    """

    state: Literal["pending", "verified"] = "pending"
    first_check_s: float = 30.0
    max_duration_s: float = 900.0
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorResult:
    """Outcome of one execution. ``detail`` is stored in ``response_actions.result``: keep it small, no secrets.

    ``external_ref`` (stateful connectors) replaces ``response_actions.external_ref``
    when not ``None``: Microsoft object ids, operation ids and per-target steps,
    ``reversible``/``rollback_until`` for rollback. ``verify`` is honoured with
    ``succeeded`` only, ``retry_after_s`` with ``deferred`` only. The framework
    truncates ``detail`` above 8 KiB.
    """

    status: ConnectorStatus
    detail: Dict[str, Any] = field(default_factory=dict)
    external_ref: Optional[Dict[str, Any]] = None
    verify: Optional[VerifyPlan] = None
    retry_after_s: Optional[float] = None


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of one verification check. ``retry_after_s`` (pending only): the earliest next check."""

    state: VerificationState
    detail: Dict[str, Any] = field(default_factory=dict)
    retry_after_s: Optional[float] = None


@runtime_checkable
class Connector(Protocol):
    """Executes one approved ledger action. Implementations must be idempotent per action id."""

    name: str

    async def execute(self, action: ResponseAction) -> ConnectorResult: ...


@runtime_checkable
class Verifier(Protocol):
    """Re-reads the external state an executed action changed (read-only, idempotent)."""

    name: str

    async def verify(self, action: ResponseAction) -> VerificationResult: ...


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
