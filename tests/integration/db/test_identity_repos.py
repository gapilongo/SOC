"""Tenants, users, refresh tokens and API keys."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lg_sotf.db.errors import Conflict, NotFound, RefreshTokenInvalid, RefreshTokenReuse
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, TENANT_B

pytestmark = pytest.mark.asyncio

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class TestTenants:
    async def test_create_get_and_conflict(self, repos: Repositories) -> None:
        tenant = await repos.tenants.create("acme", "Acme", settings={"autonomy": {"low": "auto"}})
        assert tenant.status == "active" and tenant.settings == {"autonomy": {"low": "auto"}}
        assert (await repos.tenants.get("acme")).name == "Acme"
        with pytest.raises(Conflict):
            await repos.tenants.create("acme", "Again")
        with pytest.raises(NotFound):
            await repos.tenants.get("missing")

    async def test_ensure_is_idempotent(self, repos: Repositories) -> None:
        first = await repos.tenants.ensure("boot", "Boot")
        second = await repos.tenants.ensure("boot", "Other name")
        assert first.id == second.id == "boot" and second.name == "Boot"

    async def test_update_settings_merges_removes_and_replaces(self, repos: Repositories) -> None:
        await repos.tenants.update_settings(TENANT_A, {"a": 1, "b": {"x": 1}})
        t = await repos.tenants.update_settings(TENANT_A, {"b": {"y": 2}, "c": True})
        assert t.settings == {"a": 1, "b": {"y": 2}, "c": True}
        t = await repos.tenants.update_settings(TENANT_A, {"a": None})
        assert t.settings == {"b": {"y": 2}, "c": True}
        t = await repos.tenants.update_settings(TENANT_A, {"z": 1}, replace=True)
        assert t.settings == {"z": 1}
        assert (await repos.tenants.get(TENANT_B)).settings == {}

    async def test_list_all_and_status(self, repos: Repositories) -> None:
        await repos.tenants.set_status(TENANT_B, "suspended")
        assert [t.id for t in await repos.tenants.list_all_tenants()] == [TENANT_A, TENANT_B]
        assert [t.id for t in await repos.tenants.list_all_tenants(status="suspended")] == [TENANT_B]
        with pytest.raises(ValueError):
            await repos.tenants.set_status(TENANT_B, "deleted")


class TestUsers:
    async def test_create_and_lookup_case_insensitive(self, repos: Repositories) -> None:
        user = await repos.users.create(TENANT_A, "  Alice@Example.COM ", "admin", password_hash="h")
        assert user.email == "alice@example.com"
        assert "h" not in repr(user)
        found = await repos.users.get_by_email(TENANT_A, "ALICE@example.com")
        assert found is not None and found.id == user.id
        assert (await repos.users.get(TENANT_A, user.id)).role == "admin"
        with pytest.raises(Conflict):
            await repos.users.create(TENANT_A, "alice@EXAMPLE.com", "viewer")
        other = await repos.users.create(TENANT_B, "alice@example.com", "viewer")
        matches = await repos.users.find_by_email_all_tenants("Alice@example.com")
        assert {(u.tenant_id, u.id) for u in matches} == {(TENANT_A, user.id), (TENANT_B, other.id)}

    async def test_validation(self, repos: Repositories) -> None:
        with pytest.raises(ValueError):
            await repos.users.create(TENANT_A, "not-an-email", "admin")
        with pytest.raises(ValueError):
            await repos.users.create(TENANT_A, "a@b.c", "superuser")
        with pytest.raises(NotFound):
            await repos.users.get(TENANT_A, uuid4())

    async def test_update_list_delete(self, repos: Repositories) -> None:
        a = await repos.users.create(TENANT_A, "a@x.io", "admin")
        b = await repos.users.create(TENANT_A, "b@x.io", "analyst")
        b = await repos.users.update(TENANT_A, b.id, role="admin", is_active=False)
        assert (b.role, b.is_active) == ("admin", False)
        assert [u.email for u in await repos.users.list(TENANT_A)] == ["a@x.io", "b@x.io"]
        assert [u.email for u in await repos.users.list(TENANT_A, include_inactive=False)] == ["a@x.io"]
        assert await repos.users.count_active_admins(TENANT_A) == 1
        assert await repos.users.update(TENANT_A, a.id) == a
        assert await repos.users.delete(TENANT_A, b.id) is True
        assert await repos.users.delete(TENANT_A, b.id) is False
        with pytest.raises(NotFound):
            await repos.users.update(TENANT_A, b.id, role="viewer")

    async def test_lockout_after_max_failures_and_expiry(self, repos: Repositories) -> None:
        user = await repos.users.create(TENANT_A, "l@x.io", "analyst", password_hash="h")
        for i in range(2):
            user = await repos.users.record_login_failure(TENANT_A, user.id, max_attempts=3, lockout_minutes=15, now=T0)
            assert user.failed_logins == i + 1 and user.locked_until is None
        user = await repos.users.record_login_failure(TENANT_A, user.id, max_attempts=3, lockout_minutes=15, now=T0)
        assert user.locked_until == T0 + timedelta(minutes=15)
        assert user.is_locked(T0) and not user.is_locked(T0 + timedelta(minutes=16))
        assert user.failed_logins == 0

        after = T0 + timedelta(minutes=20)
        user = await repos.users.record_login_failure(TENANT_A, user.id, max_attempts=3, lockout_minutes=15, now=after)
        assert user.locked_until is None and user.failed_logins == 1

        user = await repos.users.record_login_success(TENANT_A, user.id, now=after)
        assert user.failed_logins == 0 and user.last_login_at == after

    async def test_password_change_clears_lockout(self, repos: Repositories) -> None:
        user = await repos.users.create(TENANT_A, "p@x.io", "analyst", password_hash="old")
        user = await repos.users.record_login_failure(TENANT_A, user.id, max_attempts=1, lockout_minutes=5)
        assert user.locked_until is not None
        user = await repos.users.update(TENANT_A, user.id, password_hash="new")
        assert user.locked_until is None and user.password_hash == "new"


class TestRefreshTokens:
    async def _user(self, repos: Repositories) -> object:
        return await repos.users.create(TENANT_A, "rt@x.io", "analyst")

    async def test_rotate_links_and_revokes(self, repos: Repositories) -> None:
        user = await self._user(repos)
        old = await repos.refresh_tokens.create(TENANT_A, user.id, sha("t1"), T0 + timedelta(days=14))
        assert sha("t1") not in repr(old)
        assert (await repos.refresh_tokens.get_by_hash_all_tenants(sha("t1"))).tenant_id == TENANT_A
        new = await repos.refresh_tokens.rotate(TENANT_A, sha("t1"), sha("t2"), T0 + timedelta(days=28), now=T0)
        old = await repos.refresh_tokens.get_by_hash(TENANT_A, sha("t1"))
        assert old.revoked_at == T0 and old.replaced_by == new.id
        assert new.is_active(T0) and not old.is_active(T0)

    async def test_reuse_revokes_whole_family(self, repos: Repositories) -> None:
        user = await self._user(repos)
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("t1"), T0 + timedelta(days=14))
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("other-device"), T0 + timedelta(days=14))
        await repos.refresh_tokens.rotate(TENANT_A, sha("t1"), sha("t2"), T0 + timedelta(days=28), now=T0)
        with pytest.raises(RefreshTokenReuse) as info:
            await repos.refresh_tokens.rotate(TENANT_A, sha("t1"), sha("t3"), T0 + timedelta(days=28), now=T0)
        assert info.value.revoked == 2
        for token in ("t1", "t2", "other-device"):
            rt = await repos.refresh_tokens.get_by_hash(TENANT_A, sha(token))
            assert rt.revoked_at is not None
        assert await repos.refresh_tokens.get_by_hash(TENANT_A, sha("t3")) is None

    async def test_invalid_tokens(self, repos: Repositories) -> None:
        user = await self._user(repos)
        with pytest.raises(RefreshTokenInvalid) as info:
            await repos.refresh_tokens.rotate(TENANT_A, sha("nope"), sha("n2"), T0 + timedelta(days=1), now=T0)
        assert info.value.reason == "not_found"
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("exp"), T0 - timedelta(seconds=1))
        with pytest.raises(RefreshTokenInvalid) as info:
            await repos.refresh_tokens.rotate(TENANT_A, sha("exp"), sha("e2"), T0 + timedelta(days=1), now=T0)
        assert info.value.reason == "expired"
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("out"), T0 + timedelta(days=1))
        assert await repos.refresh_tokens.revoke(TENANT_A, sha("out")) is True
        assert await repos.refresh_tokens.revoke(TENANT_A, sha("out")) is False
        with pytest.raises(RefreshTokenInvalid) as info:
            await repos.refresh_tokens.rotate(TENANT_A, sha("out"), sha("o2"), T0 + timedelta(days=1), now=T0)
        assert info.value.reason == "revoked"
        with pytest.raises(RefreshTokenInvalid):
            await repos.refresh_tokens.rotate(TENANT_B, sha("out"), sha("o3"), T0 + timedelta(days=1), now=T0)

    async def test_revoke_lineage_follows_rotations(self, repos: Repositories) -> None:
        # Logout racing a refresh: the presented token was rotated, its replacement must die too.
        user = await self._user(repos)
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("l1"), T0 + timedelta(days=14))
        await repos.refresh_tokens.create(TENANT_A, user.id, sha("other-device"), T0 + timedelta(days=14))
        await repos.refresh_tokens.rotate(TENANT_A, sha("l1"), sha("l2"), T0 + timedelta(days=28), now=T0)
        await repos.refresh_tokens.rotate(TENANT_A, sha("l2"), sha("l3"), T0 + timedelta(days=28), now=T0)
        assert await repos.refresh_tokens.revoke_lineage(TENANT_A, sha("l1")) == 1
        for token in ("l1", "l2", "l3"):
            rt = await repos.refresh_tokens.get_by_hash(TENANT_A, sha(token))
            assert rt.revoked_at is not None
        assert (await repos.refresh_tokens.get_by_hash(TENANT_A, sha("other-device"))).revoked_at is None
        with pytest.raises(RefreshTokenInvalid):
            await repos.refresh_tokens.rotate(TENANT_A, sha("l3"), sha("l4"), T0 + timedelta(days=28), now=T0)
        assert await repos.refresh_tokens.revoke_lineage(TENANT_A, sha("l1")) == 0
        assert await repos.refresh_tokens.revoke_lineage(TENANT_A, sha("unknown")) == 0
        assert await repos.refresh_tokens.revoke_lineage(TENANT_B, sha("other-device")) == 0

    async def test_revoke_all_for_user(self, repos: Repositories) -> None:
        user = await self._user(repos)
        for i in range(3):
            await repos.refresh_tokens.create(TENANT_A, user.id, sha(f"r{i}"), T0 + timedelta(days=1))
        assert await repos.refresh_tokens.revoke_all_for_user(TENANT_A, user.id) == 3
        assert await repos.refresh_tokens.revoke_all_for_user(TENANT_A, user.id) == 0

    async def test_hash_format_enforced(self, repos: Repositories) -> None:
        user = await self._user(repos)
        with pytest.raises(ValueError):
            await repos.refresh_tokens.create(TENANT_A, user.id, "plaintext-token", T0)
        with pytest.raises(ValueError):
            await repos.api_keys.create(TENANT_A, "k", "lgk_x", "A" * 64, ["read"])


class TestApiKeys:
    async def test_lifecycle(self, db: Database, repos: Repositories) -> None:
        key_id = uuid4()
        key = await repos.api_keys.create(
            TENANT_A, "SIEM forwarder", "lgk_1a2b", sha("secret"), ["read", "ingest", "read"], key_id=key_id
        )
        assert key.id == key_id and key.scopes == ["ingest", "read"]
        assert sha("secret") not in repr(key)
        async with db.system_tx() as conn:
            columns = {
                r["column_name"]
                for r in await conn.fetch(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'api_keys'"
                )
            }
        assert "secret" not in columns and "key" not in columns

        assert (await repos.api_keys.get_by_id_all_tenants(key_id)).tenant_id == TENANT_A
        assert await repos.api_keys.get_by_id(TENANT_B, key_id) is None
        assert await repos.api_keys.touch_last_used(TENANT_A, key_id, now=T0) is True
        assert await repos.api_keys.touch_last_used(TENANT_A, key_id, now=T0 + timedelta(seconds=30)) is False
        assert await repos.api_keys.touch_last_used(TENANT_A, key_id, now=T0 + timedelta(seconds=61)) is True

        assert [k.id for k in await repos.api_keys.list(TENANT_A)] == [key_id]
        assert await repos.api_keys.revoke(TENANT_A, key_id) is True
        assert await repos.api_keys.revoke(TENANT_A, key_id) is False
        assert await repos.api_keys.list(TENANT_A) == []
        assert (await repos.api_keys.list(TENANT_A, include_revoked=True))[0].is_revoked

    async def test_scope_and_duplicate_validation(self, repos: Repositories) -> None:
        with pytest.raises(ValueError):
            await repos.api_keys.create(TENANT_A, "k", "lgk_x", sha("s"), ["admin"])
        with pytest.raises(ValueError):
            await repos.api_keys.create(TENANT_A, "k", "lgk_x", sha("s"), [])
        await repos.api_keys.create(TENANT_A, "k", "lgk_x", sha("dup"), ["read"])
        with pytest.raises(Conflict):
            await repos.api_keys.create(TENANT_A, "k2", "lgk_y", sha("dup"), ["read"])
