"""API mapping of tenant quota refusals (:mod:`lg_sotf.services.tenancy`)."""

from __future__ import annotations

from lg_sotf.api.errors import ApiError
from lg_sotf.services.tenancy import QuotaExceeded

_WHAT = {"max_sources": "sources", "max_users": "active users"}


def quota_conflict(exc: QuotaExceeded) -> ApiError:
    """``409 quota_exceeded`` for a create that would pass a count quota."""
    what = _WHAT.get(exc.quota, exc.quota)
    return ApiError(
        409,
        "quota_exceeded",
        f"the tenant has reached its limit of {exc.limit} {what}; ask your provider to raise it",
        details=[{"quota": exc.quota, "limit": exc.limit, "used": exc.used}],
    )
