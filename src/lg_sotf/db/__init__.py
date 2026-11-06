"""PostgreSQL system of record: pool, tenancy (RLS), migrations and repositories."""

from lg_sotf.db.errors import (
    AlreadyInState,
    Conflict,
    DatabaseError,
    DatabaseUnavailable,
    InvalidCursor,
    InvalidTenantId,
    InvalidTransition,
    InvalidValue,
    LeaseLost,
    NotFound,
    PoolExhausted,
    ReferenceNotFound,
    RefreshTokenInvalid,
    RefreshTokenReuse,
    RunNotClaimable,
    SystemScopeDenied,
)
from lg_sotf.db.pagination import Page
from lg_sotf.db.pool import Database
from lg_sotf.db.tenancy import (
    DEFAULT_TENANT_ID,
    is_valid_tenant_id,
    parse_thread_id,
    thread_id_for,
    validate_tenant_id,
)
from lg_sotf.db.types import Connection

__all__ = [
    "AlreadyInState",
    "Conflict",
    "Connection",
    "DEFAULT_TENANT_ID",
    "Database",
    "DatabaseError",
    "DatabaseUnavailable",
    "InvalidCursor",
    "InvalidTenantId",
    "InvalidTransition",
    "InvalidValue",
    "LeaseLost",
    "NotFound",
    "Page",
    "PoolExhausted",
    "ReferenceNotFound",
    "RefreshTokenInvalid",
    "RefreshTokenReuse",
    "RunNotClaimable",
    "SystemScopeDenied",
    "is_valid_tenant_id",
    "parse_thread_id",
    "thread_id_for",
    "validate_tenant_id",
]
