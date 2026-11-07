"""ARCH-E4.1a: organisations, members and grants under row-level security.

A grant row belongs to the customer tenant that gave it; the organisation it
names can read it from its home tenant and nobody else can see it. Only the
customer writes grants: an organisation cannot create, extend or revoke one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict, List

import asyncpg
import pytest

from lg_sotf.db.errors import InvalidValue, ReferenceNotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories, TenantGrant, User
from tests.integration.db._support import TENANT_A, TENANT_B

pytestmark = pytest.mark.asyncio

ORG_ONE = "mssp-one"
ORG_TWO = "mssp-two"


async def _org(repos: Repositories, org_id: str) -> User:
    await repos.tenants.create(org_id, org_id)
    await repos.organisations.upsert(org_id, org_id.upper())
    staff = await repos.users.create(org_id, f"analyst@{org_id}.test", "admin")
    await repos.organisations.add_member(org_id, staff.id, added_by="test")
    return staff


async def _grant(repos: Repositories, tenant_id: str, org_id: str, role: str = "analyst", **kwargs: object) -> TenantGrant:
    expires_at = kwargs.pop("expires_at", datetime.now(UTC) + timedelta(hours=8))
    return await repos.grants.create(
        tenant_id, org_id, role, reason="on-call cover", created_by="admin@customer", expires_at=expires_at, **kwargs
    )


async def _visible(db: Database, tenant_id: str) -> Dict[str, List[str]]:
    async with db.tenant_tx(tenant_id) as conn:
        grants = await conn.fetch("SELECT tenant_id, organisation_id FROM tenant_grants ORDER BY tenant_id")
        orgs = await conn.fetch("SELECT tenant_id FROM organisations")
        members = await conn.fetch("SELECT tenant_id FROM organisation_members")
    return {
        "grants": [f"{r['tenant_id']}->{r['organisation_id']}" for r in grants],
        "organisations": [r["tenant_id"] for r in orgs],
        "members": [r["tenant_id"] for r in members],
    }


async def test_grant_rows_are_invisible_across_organisations(db: Database, repos: Repositories) -> None:
    await _org(repos, ORG_ONE)
    await _org(repos, ORG_TWO)
    await _grant(repos, TENANT_A, ORG_ONE)
    await _grant(repos, TENANT_B, ORG_TWO)

    assert await _visible(db, ORG_ONE) == {
        "grants": [f"{TENANT_A}->{ORG_ONE}"], "organisations": [ORG_ONE], "members": [ORG_ONE]
    }
    assert await _visible(db, ORG_TWO) == {
        "grants": [f"{TENANT_B}->{ORG_TWO}"], "organisations": [ORG_TWO], "members": [ORG_TWO]
    }
    # The customer sees the grants it gave, never the organisation's own rows.
    assert await _visible(db, TENANT_A) == {"grants": [f"{TENANT_A}->{ORG_ONE}"], "organisations": [], "members": []}
    assert await _visible(db, TENANT_B) == {"grants": [f"{TENANT_B}->{ORG_TWO}"], "organisations": [], "members": []}
    async with db.connection() as conn:
        async with conn.transaction():
            assert await conn.fetchval("SELECT count(*) FROM tenant_grants") == 0
    assert [g.tenant_id for g in await repos.grants.list_for_organisation(ORG_ONE)] == [TENANT_A]
    assert await repos.grants.list_for_tenant(TENANT_A) != []
    assert await repos.grants.list_for_tenant(ORG_ONE) == []


async def test_only_the_customer_writes_its_grants(db: Database, repos: Repositories) -> None:
    await _org(repos, ORG_ONE)
    grant = await _grant(repos, TENANT_A, ORG_ONE)
    later = datetime.now(UTC) + timedelta(days=30)

    # The organisation can read its grant but cannot extend, revoke or forge one.
    async with db.tenant_tx(ORG_ONE) as conn:
        assert await conn.execute("UPDATE tenant_grants SET expires_at = $1", later) == "UPDATE 0"
        assert await conn.execute("UPDATE tenant_grants SET revoked_at = now()") == "UPDATE 0"
        assert await conn.execute("DELETE FROM tenant_grants") == "DELETE 0"
    for tenant_id in (TENANT_A, TENANT_B):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with db.tenant_tx(ORG_ONE) as conn:
                await conn.execute(
                    "INSERT INTO tenant_grants (tenant_id, organisation_id, role, reason, created_by, expires_at) "
                    "VALUES ($1, $2, 'admin', 'self-granted', 'mssp', $3)",
                    tenant_id,
                    ORG_ONE,
                    later,
                )
    # Another customer cannot plant or touch a grant in tenant A.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_B) as conn:
            await conn.execute(
                "INSERT INTO tenant_grants (tenant_id, organisation_id, role, reason, created_by, expires_at) "
                "VALUES ($1, $2, 'admin', 'x', 'b', $3)",
                TENANT_A,
                ORG_ONE,
                later,
            )
    async with db.tenant_tx(TENANT_B) as conn:
        assert await conn.execute("UPDATE tenant_grants SET revoked_at = now()") == "UPDATE 0"
    # Nor can the customer move its grant to another tenant.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute("UPDATE tenant_grants SET tenant_id = $1", TENANT_B)
    assert await repos.grants.revoke(TENANT_B, grant.id, revoked_by="b") is None
    assert (await repos.grants.get(TENANT_A, grant.id)) == grant


async def test_live_grant_lookup(db: Database, repos: Repositories) -> None:
    staff = await _org(repos, ORG_ONE)
    other = await repos.users.create(ORG_ONE, "other@mssp-one.test", "admin")
    outsider = await repos.users.create(ORG_ONE, "not-a-member@mssp-one.test", "admin")
    await repos.organisations.add_member(ORG_ONE, other.id)
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, staff.id) is None

    viewer = await _grant(repos, TENANT_A, ORG_ONE, "viewer")
    personal = await _grant(repos, TENANT_A, ORG_ONE, "admin", user_id=other.id)
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, staff.id) == viewer
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, other.id) == personal  # the stronger grant wins
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, outsider.id) is None
    assert await repos.grants.active_for(ORG_ONE, TENANT_B, staff.id) is None

    revoked = await repos.grants.revoke(TENANT_A, personal.id, revoked_by="admin@customer")
    assert revoked is not None and revoked.revoked_by == "admin@customer" and not revoked.is_active(datetime.now(UTC))
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, other.id) == viewer
    assert await repos.grants.revoke(TENANT_A, personal.id, revoked_by="again") is None

    past = datetime.now(UTC) - timedelta(days=2)
    await _grant(repos, TENANT_B, ORG_ONE, "admin", now=past, expires_at=past + timedelta(hours=1))
    assert await repos.grants.active_for(ORG_ONE, TENANT_B, staff.id) is None

    # Leaving the organisation ends access at once, and takes the member's own grants with it.
    await repos.organisations.remove_member(ORG_ONE, other.id)
    assert await repos.grants.active_for(ORG_ONE, TENANT_A, other.id) is None
    assert await repos.grants.get(TENANT_A, personal.id) is None


async def test_grant_constraints(db: Database, repos: Repositories) -> None:
    staff = await _org(repos, ORG_ONE)
    outsider = await repos.users.create(TENANT_B, "someone@b.test", "admin")
    with pytest.raises(InvalidValue):  # an organisation does not grant itself
        await _grant(repos, ORG_ONE, ORG_ONE)
    with pytest.raises(InvalidValue):  # time-bounded: at most a year
        await _grant(repos, TENANT_A, ORG_ONE, expires_at=datetime.now(UTC) + timedelta(days=400))
    with pytest.raises(InvalidValue):
        await repos.grants.create(
            TENANT_A, ORG_ONE, "viewer", reason="  ", created_by="x", expires_at=datetime.now(UTC) + timedelta(hours=1)
        )
    with pytest.raises(ReferenceNotFound):  # TENANT_B is not an organisation
        await _grant(repos, TENANT_A, TENANT_B)
    with pytest.raises(ReferenceNotFound):  # a personal grant names a member of that organisation
        await _grant(repos, TENANT_A, ORG_ONE, user_id=outsider.id)
    assert (await _grant(repos, TENANT_A, ORG_ONE, user_id=staff.id)).user_id == staff.id
