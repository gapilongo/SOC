"""Access tokens and endpoint access rules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

import jwt
import pytest

from lg_sotf.api.auth.deps import ADMIN, ADMIN_USER, ANALYST, ANY, INGEST, REVIEWER, VIEWER, Access
from lg_sotf.api.auth.principal import Principal, role_at_least
from lg_sotf.api.auth.tokens import InvalidToken, TokenService, is_local_token, jwt_secret
from lg_sotf.api.errors import ApiError
from lg_sotf.db.repos import User
from lg_sotf.settings import Settings

SECRET = b"x" * 48


def _user(**overrides: Any) -> User:
    now = datetime.now(UTC)
    values = {
        "id": uuid.uuid4(),
        "tenant_id": "tenant-a",
        "email": "a@example.com",
        "role": "analyst",
        "is_platform_admin": False,
        "is_active": True,
        "failed_logins": 0,
        "locked_until": None,
        "last_login_at": None,
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return User.model_validate(values)


@pytest.fixture
def tokens(make_settings: Callable[..., Settings]) -> TokenService:
    return TokenService(make_settings(auth={"access_token_ttl_s": 600}), secret=SECRET)


def test_access_token_round_trip_carries_contract_claims(tokens: TokenService) -> None:
    user = _user(is_platform_admin=True)
    issued = tokens.issue_access(user)
    claims = tokens.verify_access(issued.token)
    assert claims["sub"] == str(user.id)
    assert claims["tenant"] == "tenant-a"
    assert claims["role"] == "analyst"
    assert claims["pa"] is True
    assert claims["iss"] == "lg-sotf" and claims["aud"] == "lg-sotf-api"
    assert claims["jti"] == issued.jti
    assert claims["exp"] - claims["iat"] == 600
    assert jwt.get_unverified_header(issued.token)["alg"] == "HS256"
    assert is_local_token(issued.token)


def test_a_break_glass_token_is_marked_and_never_outlives_a_normal_one(make_settings: Callable[..., Settings]) -> None:
    short = TokenService(make_settings(auth={"break_glass_ttl_s": 120}), secret=SECRET)
    issued = short.issue_access(_user(), break_glass=True)
    claims = short.verify_access(issued.token)
    assert issued.expires_in == claims["exp"] - claims["iat"] == 120 and claims["auth_method"] == "break_glass"
    assert "auth_method" not in short.verify_access(short.issue_access(_user()).token)
    capped = TokenService(make_settings(auth={"access_token_ttl_s": 300, "break_glass_ttl_s": 900}), secret=SECRET)
    assert capped.issue_access(_user(), break_glass=True).expires_in == 300


def test_expired_tokens_are_rejected(tokens: TokenService) -> None:
    issued = tokens.issue_access(_user(), now=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(InvalidToken):
        tokens.verify_access(issued.token)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(aud="other"),
        lambda c: c.update(iss="other"),
        lambda c: c.update(typ="refresh"),
        lambda c: c.pop("jti"),
        lambda c: c.pop("tenant"),
        lambda c: c.update(sub=""),
    ],
)
def test_tokens_with_wrong_or_missing_claims_are_rejected(tokens: TokenService, mutate: Callable[[dict], Any]) -> None:
    claims = jwt.decode(tokens.issue_access(_user()).token, SECRET, algorithms=["HS256"], audience="lg-sotf-api")
    mutate(claims)
    forged = jwt.encode(claims, SECRET, algorithm="HS256")
    with pytest.raises(InvalidToken):
        tokens.verify_access(forged)


def test_other_secrets_and_algorithms_are_rejected(tokens: TokenService) -> None:
    claims = jwt.decode(tokens.issue_access(_user()).token, SECRET, algorithms=["HS256"], audience="lg-sotf-api")
    with pytest.raises(InvalidToken):
        tokens.verify_access(jwt.encode(claims, b"y" * 48, algorithm="HS256"))
    with pytest.raises(InvalidToken):
        tokens.verify_access(jwt.encode(claims, SECRET + SECRET, algorithm="HS512"))
    with pytest.raises(InvalidToken):
        tokens.verify_access(jwt.encode(claims, None, algorithm="none"))


def test_refresh_tokens_store_only_a_hash(tokens: TokenService) -> None:
    refresh = tokens.new_refresh()
    assert len(refresh.token) >= 40
    assert refresh.token_hash != refresh.token and len(refresh.token_hash) == 64
    assert refresh.token not in repr(refresh)


def test_jwt_secret_rules(make_settings: Callable[..., Settings]) -> None:
    assert len(jwt_secret(make_settings())) >= 32  # development: ephemeral random secret
    assert jwt_secret(make_settings(auth={"jwt_secret": "z" * 40})) == b"z" * 40
    with pytest.raises(RuntimeError):
        jwt_secret(make_settings(environment="production"))


def _principal(kind: str = "user", **overrides: Any) -> Principal:
    values: dict = {"kind": kind, "tenant_id": "t1", "home_tenant_id": "t1", "auth_method": "password"}
    if kind == "user":
        values.update(role="viewer", user_id=uuid.uuid4())
    else:
        values.update(auth_method="api_key", api_key_id=uuid.uuid4(), scopes=frozenset({"read"}))
    values.update(overrides)
    return Principal(**values)


def _allowed(access: Access, principal: Principal) -> bool:
    try:
        access.check(principal)
    except ApiError as exc:
        assert exc.status_code == 403
        return False
    return True


def test_role_hierarchy() -> None:
    assert role_at_least("admin", "analyst") and role_at_least("analyst", "viewer")
    assert not role_at_least("viewer", "analyst") and not role_at_least(None, "viewer")
    assert not role_at_least("superuser", "viewer")


@pytest.mark.parametrize(
    ("access", "viewer", "analyst", "admin"),
    [
        (VIEWER, True, True, True),
        (ANALYST, False, True, True),
        (REVIEWER, False, True, True),
        (ADMIN, False, False, True),
        (INGEST, False, False, False),
        (ANY, True, True, True),
    ],
)
def test_user_roles(access: Access, viewer: bool, analyst: bool, admin: bool) -> None:
    assert _allowed(access, _principal(role="viewer")) is viewer
    assert _allowed(access, _principal(role="analyst")) is analyst
    assert _allowed(access, _principal(role="admin")) is admin


@pytest.mark.parametrize(
    ("access", "read", "write", "ingest"),
    [
        (VIEWER, True, False, False),
        (ANALYST, False, True, False),
        (REVIEWER, False, False, False),
        (ADMIN, False, False, False),
        (ADMIN_USER, False, False, False),
        (INGEST, False, False, True),
        (ANY, True, True, True),
    ],
)
def test_api_key_scopes(access: Access, read: bool, write: bool, ingest: bool) -> None:
    for scope, expected in (("read", read), ("write", write), ("ingest", ingest)):
        assert _allowed(access, _principal("api_key", scopes=frozenset({scope}))) is expected, scope


def test_person_attributed_actions_need_a_user_account() -> None:
    sso_admin = _principal(role="admin", user_id=None, auth_method="oidc", subject="idp-sub")
    assert not _allowed(REVIEWER, sso_admin)
    assert not _allowed(ADMIN_USER, sso_admin)
    assert _allowed(ADMIN, sso_admin)
    assert sso_admin.id == "oidc:idp-sub"
