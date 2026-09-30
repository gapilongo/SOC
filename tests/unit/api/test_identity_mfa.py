"""MFA challenge tokens, the platform-admin MFA default, OIDC role mapping and the tenant security section."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List

import jwt
import pytest
from pydantic import ValidationError

from lg_sotf.api.auth.authenticate import map_oidc_role
from lg_sotf.api.auth.mfa import secret_context, tenant_requires_mfa
from lg_sotf.api.auth.tokens import (
    MFA_ENROLL_TOKEN_TYPE,
    MFA_TOKEN_TYPE,
    InvalidToken,
    TokenService,
    password_fingerprint,
)
from lg_sotf.api.routers.tenant import _security_section
from lg_sotf.db.repos import User
from lg_sotf.settings import AuthSettings, Settings

SECRET = b"x" * 48


def _user(**overrides: Any) -> User:
    now = datetime.now(UTC)
    values = {
        "id": uuid.uuid4(),
        "tenant_id": "tenant-a",
        "email": "a@example.com",
        "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 22 + "$" + "b" * 43,
        "role": "admin",
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
    return TokenService(make_settings(), secret=SECRET)


def test_challenge_token_is_bound_to_user_purpose_and_password(tokens: TokenService) -> None:
    user = _user()
    issued = tokens.issue_mfa_challenge(user, MFA_TOKEN_TYPE)
    claims = tokens.verify_mfa_challenge(issued.token)
    assert claims["sub"] == str(user.id) and claims["tenant"] == "tenant-a"
    assert claims["typ"] == MFA_TOKEN_TYPE
    assert claims["aud"] == "lg-sotf-api:mfa"
    assert claims["pwf"] == password_fingerprint(user.password_hash)
    assert claims["exp"] - claims["iat"] == 300 == issued.expires_in
    assert "role" not in claims and "pa" not in claims
    enroll = tokens.verify_mfa_challenge(tokens.issue_mfa_challenge(user, MFA_ENROLL_TOKEN_TYPE).token)
    assert enroll["typ"] == MFA_ENROLL_TOKEN_TYPE
    assert password_fingerprint("other") != claims["pwf"]
    with pytest.raises(ValueError):
        tokens.issue_mfa_challenge(user, "access")


def test_challenge_token_is_never_an_access_token_and_vice_versa(tokens: TokenService) -> None:
    user = _user()
    challenge = tokens.issue_mfa_challenge(user, MFA_TOKEN_TYPE).token
    with pytest.raises(InvalidToken):
        tokens.verify_access(challenge)
    with pytest.raises(InvalidToken):
        tokens.verify_mfa_challenge(tokens.issue_access(user).token)


def test_challenge_token_expires_and_needs_this_deployment_s_key(tokens: TokenService, make_settings) -> None:
    user = _user()
    old = tokens.issue_mfa_challenge(user, MFA_TOKEN_TYPE, now=datetime.now(UTC) - timedelta(minutes=6))
    with pytest.raises(InvalidToken):
        tokens.verify_mfa_challenge(old.token)
    other = TokenService(make_settings(), secret=b"y" * 48)
    with pytest.raises(InvalidToken):
        other.verify_mfa_challenge(tokens.issue_mfa_challenge(user, MFA_TOKEN_TYPE).token)


def test_forged_challenge_type_is_refused(tokens: TokenService) -> None:
    now = datetime.now(UTC)
    claims = {
        "iss": "lg-sotf",
        "aud": "lg-sotf-api:mfa",
        "sub": str(uuid.uuid4()),
        "tenant": "tenant-a",
        "typ": "access",
        "pwf": "f" * 32,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=1)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    with pytest.raises(InvalidToken):
        tokens.verify_mfa_challenge(jwt.encode(claims, SECRET, algorithm="HS256"))


@pytest.mark.parametrize(
    ("environment", "explicit", "required"),
    [
        ("development", None, False),
        ("test", None, False),
        ("staging", None, True),
        ("production", None, True),
        ("production", False, False),
        ("development", True, True),
    ],
)
def test_platform_admin_mfa_defaults_to_on_outside_development(
    make_settings: Callable[..., Settings], environment: str, explicit: Any, required: bool
) -> None:
    auth = {} if explicit is None else {"require_mfa_for_platform_admins": explicit}
    settings = make_settings(environment=environment, auth=auth)
    assert settings.platform_admin_mfa_required is required


@pytest.mark.parametrize(
    ("role_map", "default", "values", "expected"),
    [
        ({}, None, ["viewer", "analyst"], "analyst"),
        ({}, None, ["SOC-Admins"], None),
        ({}, "viewer", ["SOC-Admins"], "viewer"),
        ({"SOC-Admins": "admin", "SOC-Analysts": "analyst"}, None, ["SOC-Analysts", "SOC-Admins"], "admin"),
        ({"SOC-Analysts": "analyst"}, None, ["admin"], None),
        ({"SOC-Analysts": "analyst"}, "viewer", ["Everyone"], "viewer"),
        ({"SOC-Analysts": "analyst"}, None, [], None),
    ],
)
def test_oidc_role_mapping(role_map: dict, default: Any, values: List[str], expected: Any) -> None:
    auth = AuthSettings(oidc_role_map=role_map, oidc_default_role=default)
    assert map_oidc_role(auth, values) == expected


def test_oidc_role_map_values_are_validated() -> None:
    with pytest.raises(ValidationError):
        AuthSettings(oidc_role_map={"SOC-Admins": "platform_admin"})
    with pytest.raises(ValidationError):
        AuthSettings(oidc_role_map={"": "admin"})
    with pytest.raises(ValidationError):
        AuthSettings(oidc_default_role="root")


def test_tenant_security_section() -> None:
    problems: List[str] = []
    assert _security_section({}, {"require_mfa": True}, problems) == {"require_mfa": True}
    assert _security_section({"require_mfa": True}, {"require_mfa": None}, problems) == {}
    assert problems == []
    _security_section({}, {"require_mfa": "yes"}, problems)
    _security_section({}, {"other": 1}, problems)
    _security_section({}, [], problems)
    assert len(problems) == 3
    assert tenant_requires_mfa({"security": {"require_mfa": True}})
    assert not tenant_requires_mfa({"security": {"require_mfa": "true"}})
    assert not tenant_requires_mfa({})
    assert not tenant_requires_mfa(None)


def test_secret_context_binds_tenant_and_user() -> None:
    uid = uuid.uuid4()
    assert secret_context("tenant-a", uid) == f"mfa:tenant-a:{uid}"
    assert secret_context("tenant-b", uid) != secret_context("tenant-a", uid)
