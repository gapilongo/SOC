"""Break-glass sign-in (SEC6.5): the record that cannot be skipped.

:func:`record_use` writes, in one transaction in the acting account's
tenant, the audit entry ``auth.break_glass_used`` (who, source address,
reason, the session's token id and end) and one outbox row per active
platform admin of the install (operation ``email``; the scheduler mails it
through the install's SMTP). The caller hands out the session only after
this returns, so no break-glass session exists without its audit entry and
its alerts: when either cannot be written, the sign-in fails.

The recipients are read before the session exists, so whoever signs in
cannot take an admin off the list first; the rows belong to no integration,
so no tenant admin can disable or delete their channel.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.repos import Repositories, User
from lg_sotf.db.repos.outbox import NewOutboxEntry, enqueue_on
from lg_sotf.integrations.events import BREAK_GLASS_USED, build_event, clean_text

BREAK_GLASS_FAILED = "auth.break_glass_failed"


async def record_use(
    repos: Repositories, user: User, *, reason: str, client_ip: str, token_id: str, expires_at: datetime
) -> int:
    """Audit a break-glass sign-in as ``user`` and queue the alert to every platform admin; returns how many."""
    admins = await repos.users.platform_admins_all_tenants()
    event_id = uuid.uuid4()
    title = f"{user.email} (tenant {user.tenant_id}) signed in from {client_ip}. Reason: {reason}"
    # The event payload every channel renders; "alert" carries the headline and the severity.
    payload = build_event(
        BREAK_GLASS_USED, user.tenant_id, alert={"title": clean_text(title), "severity": "critical"}, event_id=event_id
    )
    entries = [
        NewOutboxEntry(
            integration_id=None,
            event_id=event_id,
            event_type=BREAK_GLASS_USED,
            operation="email",
            dedupe_key=f"{BREAK_GLASS_USED}:{token_id}:{admin.id}",
            payload={**payload, "recipients": [admin.email]},
        )
        for admin in admins
    ]
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        await AuditLogger(repos).record(
            user.tenant_id,
            BREAK_GLASS_USED,
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={
                "reason": reason,
                "client_ip": client_ip,
                "token_id": token_id,
                "expires_at": expires_at.isoformat(),
                "admins_notified": len(entries),
            },
            conn=conn,
        )
        await enqueue_on(conn, user.tenant_id, entries)
    return len(entries)
