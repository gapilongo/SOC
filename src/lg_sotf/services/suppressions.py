"""Audited suppression-rule changes: create, update, delete, and disabling the rules a threat matches.

Each function runs the change and its audit entry in one ``db.tenant_tx``,
so an audit failure rolls the change back. Rule validation and the
"only admins create active rules" policy are the caller's
(``api.routers.suppressions``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, List, Mapping, Optional
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger, acting_under_grant, written_under_grant
from lg_sotf.db.repos import Repositories, SuppressionRule
from lg_sotf.domain.suppression import matching_rules
from lg_sotf.security.shadow import egress, sink

RESOURCE = "suppression_rule"
MAX_AUDITED_FIELDS = 20


async def create_rule(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    name: str,
    match: Mapping[str, Any],
    created_by: Optional[UUID],
    expires_at: Optional[datetime],
    enabled: bool,
    requested_enabled: bool,
) -> SuppressionRule:
    """Create a rule (audited ``suppression.created`` with the matched field names, never their values)."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        bound = written_under_grant(tenant_id, expires_at)  # under an MSSP grant: expires with the grant
        rule = await repos.suppressions.create(
            tenant_id, name, match, created_by=created_by, enabled=enabled, conn=conn, **bound
        )
        await audit.record(
            tenant_id,
            "suppression.created",
            RESOURCE,
            rule.id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={
                "enabled": rule.enabled,
                "requested_enabled": requested_enabled,
                "fields": sorted(match)[:MAX_AUDITED_FIELDS],
            },
            conn=conn,
        )
    return rule


async def update_rule(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    rule_id: str,
    changes: Mapping[str, Any],
    *,
    fields: Iterable[str],
) -> SuppressionRule:
    """Apply ``changes`` (repository column values); audited ``suppression.updated`` with the field names."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if acting_under_grant(tenant_id):  # a rule changed under an MSSP grant expires with the grant
            current = await repos.suppressions.get(tenant_id, rule_id, conn=conn)
            changes = {**changes, **written_under_grant(tenant_id, changes.get("expires_at", current.expires_at))}
        rule = await repos.suppressions.update(tenant_id, rule_id, **changes, conn=conn)
        await audit.record(
            tenant_id,
            "suppression.updated",
            RESOURCE,
            rule_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"fields": sorted(fields), "enabled": rule.enabled},
            conn=conn,
        )
    return rule


async def delete_rule(repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, rule_id: str) -> bool:
    """Delete a rule (audited ``suppression.deleted``); ``False`` when there is none."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if not await repos.suppressions.delete(tenant_id, rule_id, conn=conn):
            return False
        await audit.record(
            tenant_id,
            "suppression.deleted",
            RESOURCE,
            rule_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={},
            conn=conn,
        )
    return True



@egress("suppression_rule", sink(lambda a: []))
async def disable_rules_matching(
    repos: Repositories, audit: AuditLogger, tenant_id: str, view: Mapping[str, Any], *, actor: Actor, alert_id: str
) -> List[str]:
    """A threat was confirmed on the alert ``view`` shows: disable every active rule that would close it.

    A rule counts when it matches the alert at its own severity or at the
    lowest one (a suggestion bounded to low severities still closes the
    attack's quieter repeats). Each rule is disabled and audited
    ``suppression.revoked`` (with the alert id, never the alert's values) in
    one transaction; returns the rule ids.
    """
    rules = matching_rules(await repos.suppressions.list_active(tenant_id), [view, {**view, "severity": "info"}])
    if not rules:
        return []
    async with repos.db.tenant_tx(tenant_id) as conn:
        for rule in rules:
            await repos.suppressions.update(tenant_id, rule.id, enabled=False, conn=conn)
            await audit.record(
                tenant_id,
                "suppression.revoked",
                RESOURCE,
                rule.id,
                actor_type=actor.type,
                actor_id=actor.id,
                details={"alert_id": alert_id, "reason": "threat_confirmed"},
                conn=conn,
            )
    return [rule.id for rule in rules]
