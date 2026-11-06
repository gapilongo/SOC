"""Database layer exceptions.

Repositories translate driver errors that carry domain meaning (unique
violations, missing rows, lost optimistic locks) into these types so callers
never need to import asyncpg to handle them.
"""

from __future__ import annotations

from typing import Optional, Tuple, Type

import asyncpg

from lg_sotf.errors import StorageError


class DatabaseError(StorageError):
    """Base class for all errors raised by ``lg_sotf.db``."""


class DatabaseUnavailable(DatabaseError):
    """The database could not be reached or the pool is not open."""


class PoolExhausted(DatabaseUnavailable):
    """No pooled connection became free within the acquire timeout."""


class SystemScopeDenied(DatabaseError, PermissionError):
    """``system_tx`` was used by a role that may not bypass tenant isolation.

    Only members of the schema owner role (migrate, scheduler) can bypass RLS;
    the API/worker runtime role cannot, even by setting ``app.bypass_rls``.
    """


class InvalidTenantId(DatabaseError, ValueError):
    """A tenant id does not match the allowed format."""


class InvalidValue(DatabaseError, ValueError):
    """The database rejected a value (CHECK, NOT NULL, type or range)."""


class NotFound(DatabaseError):
    """The requested row does not exist (or is not visible to this tenant)."""

    def __init__(self, resource: str, key: object) -> None:
        super().__init__(f"{resource} not found: {key}" if key is not None else f"{resource} not found")
        self.resource = resource
        self.key = key


class ReferenceNotFound(NotFound):
    """A write referenced a row (alert, user, escalation, ...) that this tenant does not have."""

    def __init__(self, resource: str, constraint: Optional[str]) -> None:
        super().__init__(resource, None)
        self.constraint = constraint


class Conflict(DatabaseError):
    """A uniqueness or optimistic-locking constraint rejected the write."""


class InvalidTransition(Conflict):
    """A status change is not allowed from the row's current status."""

    def __init__(self, resource: str, key: object, current: str, target: str) -> None:
        super().__init__(f"{resource} {key}: transition {current} -> {target} is not allowed")
        self.resource = resource
        self.key = key
        self.current = current
        self.target = target


class AlreadyInState(InvalidTransition):
    """The row is already in the target status, so this call changed nothing.

    Raised instead of returning success so that, of several concurrent callers
    making the same transition, exactly one observes success.
    """

    def __init__(self, resource: str, key: object, status: str) -> None:
        super().__init__(resource, key, status, status)


class InvalidCursor(DatabaseError, ValueError):
    """A pagination cursor could not be decoded."""


class RunNotClaimable(Conflict):
    """A workflow run cannot be claimed right now.

    ``reason`` is one of:

    * ``"completed"`` / ``"dead_lettered"``: terminal; ack and drop the message.
    * ``"leased"``: another claim holds an unexpired lease; retry later.
    * ``"waiting"``: a ``process`` claim found the run waiting for an analyst
      or approval; ack and drop (the ``resume`` message continues it).
    * ``"not_waiting"``: a ``resume`` claim found the run queued; retry later.
    """

    def __init__(self, tenant_id: str, alert_id: str, reason: str, run: Optional[object] = None) -> None:
        super().__init__(f"run {tenant_id}:{alert_id} not claimable: {reason}")
        self.reason = reason
        self.run = run


class LeaseLost(Conflict):
    """The worker no longer holds the lease on a run it tried to update."""


class RefreshTokenInvalid(DatabaseError):
    """A refresh token is unknown, expired or revoked (without reuse)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"refresh token invalid: {reason}")
        self.reason = reason


class RefreshTokenReuse(Conflict):
    """An already-rotated refresh token was presented again.

    Every refresh token of the user has been revoked (and committed) before
    this is raised.
    """

    def __init__(self, user_id: object, revoked: int) -> None:
        super().__init__(f"refresh token reuse detected; revoked {revoked} tokens")
        self.user_id = user_id
        self.revoked = revoked


# Driver exception tuples, so code outside ``lg_sotf.db`` can catch driver errors without importing asyncpg.

TRANSIENT_DB_ERRORS: Tuple[Type[BaseException], ...] = (
    DatabaseUnavailable,
    asyncpg.PostgresConnectionError,
    asyncpg.ConnectionDoesNotExistError,
    asyncpg.TooManyConnectionsError,
    asyncpg.CannotConnectNowError,
    asyncpg.SerializationError,
    asyncpg.DeadlockDetectedError,
)
"""Errors that a retry of the same work may not hit: a lost or refused connection, a serialization
failure or a deadlock (:func:`lg_sotf.core.retry.is_transient`)."""

STATEMENT_ERRORS: Tuple[Type[BaseException], ...] = (asyncpg.PostgresError,)
"""Any error the server reports for a statement (every SQLSTATE), for best-effort reads that degrade
instead of failing. Code that needs a specific SQLSTATE belongs in a repository."""
