"""Suppression rules that close matching alerts as benign."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from uuid import UUID

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pagination import Params
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    affected,
    fetch_one,
    require_aware,
    set_clauses,
    to_model,
    to_models,
)


class SuppressionRule(Record):
    id: str
    tenant_id: str
    name: str
    match: Dict[str, Any]
    disposition: str
    created_by: Optional[UUID]
    source_feedback_id: Optional[str]
    expires_at: Optional[datetime]
    hit_count: int
    last_hit_at: Optional[datetime]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    #: The MSSP grant the rule was written under (its expiry is capped at the grant's).
    grant_id: Optional[UUID] = None


def _check_match(match: Mapping[str, Any]) -> Dict[str, Any]:
    value = dict(match)
    if not value:
        raise ValueError("a suppression rule needs at least one match predicate")
    return value


class SuppressionsRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        name: str,
        match: Mapping[str, Any],
        *,
        created_by: Optional[UUID] = None,
        source_feedback_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        enabled: bool = True,
        grant_id: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> SuppressionRule:
        require_aware(expires_at, "expires_at")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO suppression_rules (tenant_id, name, match, created_by, source_feedback_id,
                                               expires_at, enabled, grant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
                """,
                tenant_id,
                name,
                _check_match(match),
                created_by,
                source_feedback_id,
                expires_at,
                enabled,
                grant_id,
            )
        return SuppressionRule.model_validate(dict(row))

    async def get(self, tenant_id: str, rule_id: str, *, conn: Optional[Connection] = None) -> SuppressionRule:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM suppression_rules WHERE tenant_id = $1 AND id = $2", tenant_id, rule_id
            )
        rule = to_model(SuppressionRule, row)
        if rule is None:
            raise NotFound("suppression rule", rule_id)
        return rule

    async def list(
        self, tenant_id: str, *, include_disabled: bool = True, conn: Optional[Connection] = None
    ) -> List[SuppressionRule]:
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM suppression_rules
                WHERE tenant_id = $1 AND ($2 OR enabled)
                ORDER BY created_at DESC, id
                """,
                tenant_id,
                include_disabled,
            )
        return to_models(SuppressionRule, rows)

    async def find_reusable(
        self, tenant_id: str, match: Mapping[str, Any], now: datetime, *, conn: Optional[Connection] = None
    ) -> Optional[SuppressionRule]:
        """The newest unexpired rule (enabled or not) whose ``match`` equals this one, else ``None``."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                SELECT * FROM suppression_rules
                WHERE tenant_id = $1 AND match = $2::jsonb AND (expires_at IS NULL OR expires_at > $3)
                ORDER BY created_at DESC, id
                LIMIT 1
                """,
                tenant_id,
                dict(match),
                now,
            )
        return to_model(SuppressionRule, row)

    async def list_active(
        self, tenant_id: str, *, now: Optional[datetime] = None, conn: Optional[Connection] = None
    ) -> List[SuppressionRule]:
        """Enabled, unexpired rules (what the gate node evaluates).

        A rule written under an MSSP grant counts only while that grant is live
        (revocation also expires it; this is the second line of defence).
        """
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM suppression_rules r
                WHERE r.tenant_id = $1 AND r.enabled
                  AND (r.expires_at IS NULL OR r.expires_at > COALESCE($2::timestamptz, now()))
                  AND (r.grant_id IS NULL OR EXISTS (
                      SELECT 1 FROM tenant_grants g
                      WHERE g.tenant_id = r.tenant_id AND g.id = r.grant_id AND g.revoked_at IS NULL
                        AND g.expires_at > COALESCE($2::timestamptz, now())
                  ))
                ORDER BY r.created_at, r.id
                """,
                tenant_id,
                now,
            )
        return to_models(SuppressionRule, rows)

    async def expire_for_grant(self, tenant_id: str, grant_id: UUID, *, conn: Optional[Connection] = None) -> int:
        """End now every still-live rule written under ``grant_id``; returns how many."""
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE suppression_rules SET expires_at = now()
                WHERE tenant_id = $1 AND grant_id = $2 AND (expires_at IS NULL OR expires_at > now())
                """,
                tenant_id,
                grant_id,
            )
        return affected(status)

    async def update(
        self,
        tenant_id: str,
        rule_id: str,
        *,
        name: str = UNSET,
        match: Mapping[str, Any] = UNSET,
        enabled: bool = UNSET,
        expires_at: Optional[datetime] = UNSET,
        grant_id: Optional[UUID] = UNSET,
        conn: Optional[Connection] = None,
    ) -> SuppressionRule:
        if expires_at not in (UNSET, None):
            require_aware(expires_at, "expires_at")
        params = Params(tenant_id, rule_id)
        sets = set_clauses(
            {
                "name": name,
                "match": _check_match(match) if match is not UNSET else UNSET,
                "enabled": enabled,
                "expires_at": expires_at,
                "grant_id": grant_id,
            },
            params,
        )
        if not sets:
            return await self.get(tenant_id, rule_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"UPDATE suppression_rules SET {', '.join(sets)} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
                *params.values,
            )
        rule = to_model(SuppressionRule, row)
        if rule is None:
            raise NotFound("suppression rule", rule_id)
        return rule

    async def delete(self, tenant_id: str, rule_id: str, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                "DELETE FROM suppression_rules WHERE tenant_id = $1 AND id = $2", tenant_id, rule_id
            )
        return status.endswith(" 1")

    async def record_hit(
        self,
        tenant_id: str,
        rule_id: str,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE suppression_rules
                SET hit_count = hit_count + 1, last_hit_at = COALESCE($3::timestamptz, now())
                WHERE tenant_id = $1 AND id = $2
                """,
                tenant_id,
                rule_id,
                now,
            )
        if not status.endswith(" 1"):
            raise NotFound("suppression rule", rule_id)
