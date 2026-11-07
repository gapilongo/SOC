"""Typed security edge (roadmap T1): roles and scopes are vocabulary ``Literal`` types for mypy only.

``Access``, ``Principal`` and ``role_at_least`` are annotated with ``Role`` and
``Scope``, so mypy checks every literal role and scope at the call sites
(``deps.py``, ``routers/mfa.py``, ``routers/suppressions.py``,
``routers/ws.py``). The annotations add no runtime check: a stored role the
vocabulary does not list still builds a principal, which then ranks below
every role and is refused by every role-gated endpoint, as before.
"""

from __future__ import annotations

from typing import FrozenSet, Optional, get_type_hints

import pytest

from lg_sotf.api.auth import deps
from lg_sotf.api.auth.deps import Access
from lg_sotf.api.auth.principal import Principal, role_at_least
from lg_sotf.api.errors import ApiError
from lg_sotf.models.vocabulary import ROLES, SCOPES, Role, Scope


def test_the_security_edge_is_annotated_with_the_vocabulary() -> None:
    assert get_type_hints(Access)["role"] == Optional[Role]
    assert get_type_hints(Access)["scope"] == Optional[Scope]
    assert get_type_hints(Principal)["role"] == Optional[Role]
    assert get_type_hints(Principal)["scopes"] == FrozenSet[Scope]
    assert get_type_hints(role_at_least)["minimum"] == Role


@pytest.mark.parametrize(
    "name", ["VIEWER", "ANALYST", "REVIEWER", "ADMIN", "ADMIN_USER", "ANY", "PLATFORM_ADMIN", "INGEST"]
)
def test_access_levels_use_vocabulary_values(name: str) -> None:
    access: Access = getattr(deps, name)
    assert access.role is None or access.role in ROLES
    assert access.scope is None or access.scope in SCOPES


def _user(role: str) -> Principal:
    return Principal(
        kind="user",
        tenant_id="t1",
        home_tenant_id="t1",
        auth_method="password",
        role=role,  # type: ignore[arg-type]
    )


def test_an_unknown_stored_role_is_not_rejected_at_construction() -> None:
    """No new runtime rejection: the principal builds and simply ranks below every role."""
    principal = _user("auditor")
    assert principal.role == "auditor"
    assert not any(role_at_least(principal.role, minimum) for minimum in ROLES)
    with pytest.raises(ApiError) as caught:
        deps.VIEWER.check(principal)
    assert caught.value.status_code == 403


@pytest.mark.parametrize(
    ("role", "minimum", "expected"),
    [
        ("viewer", "viewer", True),
        ("viewer", "analyst", False),
        ("admin", "analyst", True),
        (None, "viewer", False),
    ],
)
def test_role_at_least(role: Optional[Role], minimum: Role, expected: bool) -> None:
    assert role_at_least(role, minimum) is expected
