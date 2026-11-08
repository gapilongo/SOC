"""API authentication: local users (argon2 + JWT + rotating refresh tokens), OIDC bearer tokens and API keys."""

from lg_sotf.api.auth.deps import ADMIN, ADMIN_USER, ANALYST, ANY, CLAIMER, INGEST, REVIEWER, VIEWER, Access, require
from lg_sotf.api.auth.principal import ROLES, SCOPES, Principal, role_at_least

__all__ = [
    "ADMIN",
    "ADMIN_USER",
    "ANALYST",
    "ANY",
    "CLAIMER",
    "INGEST",
    "REVIEWER",
    "ROLES",
    "SCOPES",
    "VIEWER",
    "Access",
    "Principal",
    "require",
    "role_at_least",
]
