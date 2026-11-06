"""An audit entry commits with the change it records: when the entry cannot be written, nothing changes.

``failing_audit`` makes ``AuditRepo.append`` raise for the named actions, as a
full disk, a lost connection or a broken chain lock would. The request then
answers 500 and the change it would have made is not there; once the audit
log works again the same request succeeds.
"""

from __future__ import annotations

from typing import Any, Set

import pytest

from lg_sotf.db.repos.audit import AuditRepo
from tests.integration.api.conftest import PASSWORD, TENANT_A, ApiHarness
from tests.integration.api.test_mfa import Clock, challenge, code_now, enroll, verify
from tests.integration.api.test_oidc import IdP, bearer
from tests.integration.api.test_oidc_jit import _jit_api, _token

pytestmark = pytest.mark.integration

API = "/api/v1"


class AuditUnavailable(RuntimeError):
    pass


@pytest.fixture
def failing_audit(monkeypatch: pytest.MonkeyPatch) -> Set[str]:
    """The set of audit actions whose append raises; empty means the audit log works."""
    failing: Set[str] = set()
    original = AuditRepo.append

    async def append(self: AuditRepo, tenant_id: str, actor_type: str, actor_id: Any, action: str, *a: Any, **kw: Any) -> Any:
        if action in failing:
            raise AuditUnavailable(action)
        return await original(self, tenant_id, actor_type, actor_id, action, *a, **kw)

    monkeypatch.setattr(AuditRepo, "append", append)
    return failing


@pytest.fixture
def idp() -> IdP:
    return IdP()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    from lg_sotf.api.auth import mfa as mfa_module

    c = Clock()
    monkeypatch.setattr(mfa_module, "clock", c)
    return c


async def _count(api: ApiHarness, action: str, tenant_id: str = TENANT_A) -> int:
    return len((await api.repos.audit.list(tenant_id, action=action)).items)


# ------------------------------------------------------------------------------- MFA


async def test_mfa_enrollment_is_not_activated_without_its_audit_entry(
    api: ApiHarness, clock: Clock, failing_audit: Set[str]
) -> None:
    user = await api.user(TENANT_A, "analyst", email="enroll-atomic@a.example.com")
    headers = api.auth(user)
    started = await api.client.post(f"{API}/auth/mfa/enroll", json={}, headers=headers)
    secret = started.json()["secret"]
    failing_audit.add("auth.mfa_enrolled")
    failed = await api.client.post(f"{API}/auth/mfa/confirm", json={"code": code_now(secret, clock)}, headers=headers)
    assert failed.status_code == 500
    stored = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert stored is not None and not stored.enabled and stored.pending_secret_ciphertext is not None
    failing_audit.clear()
    retried = await api.client.post(f"{API}/auth/mfa/confirm", json={"code": code_now(secret, clock)}, headers=headers)
    assert retried.status_code == 200, retried.text
    assert await _count(api, "auth.mfa_enrolled") == 1


async def test_mfa_stays_enabled_when_disable_cannot_be_audited(
    api: ApiHarness, clock: Clock, failing_audit: Set[str]
) -> None:
    user = await api.user(TENANT_A, "analyst", email="disable-atomic@a.example.com")
    secret, _ = await enroll(api, user, clock)
    headers = api.auth(user)
    failing_audit.add("auth.mfa_disabled")
    body = {"password": PASSWORD, "code": code_now(secret, clock)}
    assert (await api.client.post(f"{API}/auth/mfa/disable", json=body, headers=headers)).status_code == 500
    stored = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert stored is not None and stored.enabled
    failing_audit.clear()
    clock.tick()
    body = {"password": PASSWORD, "code": code_now(secret, clock)}
    assert (await api.client.post(f"{API}/auth/mfa/disable", json=body, headers=headers)).status_code == 204
    assert await api.repos.user_mfa.get(TENANT_A, user.id) is None
    assert await _count(api, "auth.mfa_disabled") == 1


async def test_recovery_codes_are_kept_when_regeneration_cannot_be_audited(
    api: ApiHarness, clock: Clock, failing_audit: Set[str]
) -> None:
    user = await api.user(TENANT_A, "analyst", email="regen-atomic@a.example.com")
    secret, codes = await enroll(api, user, clock)
    before = await api.repos.user_mfa.get(TENANT_A, user.id)
    failing_audit.add("auth.mfa_recovery_codes_regenerated")
    regenerated = await api.client.post(
        f"{API}/auth/mfa/recovery-codes", json={"code": code_now(secret, clock)}, headers=api.auth(user)
    )
    assert regenerated.status_code == 500
    after = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert before is not None and after is not None
    assert after.recovery_code_hashes == before.recovery_code_hashes
    failing_audit.clear()
    assert (await verify(api, await challenge(api, "regen-atomic@a.example.com"), codes[0])).status_code == 200


async def test_a_recovery_code_is_not_used_up_when_its_use_cannot_be_audited(
    api: ApiHarness, clock: Clock, failing_audit: Set[str]
) -> None:
    user = await api.user(TENANT_A, "viewer", email="recover-atomic@a.example.com")
    _, codes = await enroll(api, user, clock)
    failing_audit.add("auth.mfa_recovery_code_used")
    token = await challenge(api, "recover-atomic@a.example.com")
    assert (await verify(api, token, codes[0])).status_code == 500
    stored = await api.repos.user_mfa.get(TENANT_A, user.id)
    assert stored is not None and stored.recovery_codes_remaining == 10
    failing_audit.clear()
    used = await verify(api, await challenge(api, "recover-atomic@a.example.com"), codes[0])
    assert used.status_code == 200, used.text
    assert used.json()["recovery_codes_remaining"] == 9


async def test_an_sso_role_is_not_synced_without_its_audit_entry(
    make_api: Any, idp: IdP, failing_audit: Set[str]
) -> None:
    api = await _jit_api(make_api, idp)
    assert (await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Viewers"])))).status_code == 200
    user = await api.repos.users.get_by_oidc_subject(TENANT_A, "entra-oid-1")
    assert user is not None and user.role == "viewer"
    failing_audit.add("user.role_synced")
    promoted = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    assert promoted.status_code == 500
    assert (await api.repos.users.get(TENANT_A, user.id)).role == "viewer"
    failing_audit.clear()
    promoted = await api.client.get(f"{API}/auth/me", headers=bearer(_token(idp, ["SOC-Admins"])))
    assert promoted.json()["role"] == "admin"
    assert await _count(api, "user.role_synced") == 1
