"""Helpers for the break-glass tests (``test_break_glass.py``, ``test_review_413.py``)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, password_hash

URL = "/api/v1/auth/break-glass"
CREDENTIAL = "test-only-" + "sealed-break-glass-credential"
REASON = "IdP outage, incident INC-4711"
SMTP = {"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"}
ROOT = "root@a.example.com"


class Mailbox:
    """An SMTP client that keeps what it is asked to send."""

    sent: List[Any] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        pass

    def __enter__(self) -> Mailbox:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def starttls(self, context: Any) -> None:
        return None

    def send_message(self, message: Any) -> None:
        Mailbox.sent.append(message)


async def enabled(make_api: Callable[..., Any], **overrides: Any) -> ApiHarness:
    """An API with break-glass on, and its platform admins: ``ROOT`` in tenant A, one more in tenant B."""
    auth = {"break_glass_credential_hash": password_hash(CREDENTIAL), "bootstrap_tenant_id": TENANT_A}
    mail = {**SMTP, **overrides.pop("integrations", {})}
    api: ApiHarness = await make_api(auth=auth, integrations=mail, **overrides)
    await api.user(TENANT_A, "admin", email=ROOT, platform_admin=True)
    await api.user(TENANT_B, "analyst", email="second@b.example.com", platform_admin=True)
    await api.user(TENANT_B, "admin", email="left@b.example.com", platform_admin=True, active=False)
    await api.user(TENANT_A, "admin", email="tenant-admin@a.example.com")
    return api


def body(**changes: Any) -> Dict[str, Any]:
    return {"email": ROOT, "credential": CREDENTIAL, "reason": REASON, **changes}


async def alerts(api: ApiHarness, tenant_id: str = TENANT_A) -> List[Any]:
    """The outbox rows mailed to people (no integration) of a tenant, oldest first."""
    async with api.repos.db.tenant_tx(tenant_id) as conn:
        return list(await conn.fetch("SELECT * FROM notification_outbox WHERE integration_id IS NULL ORDER BY created_at"))


async def audited(api: ApiHarness, action: str, tenant_id: str = TENANT_A) -> List[Any]:
    return (await api.repos.audit.list(tenant_id, action=action)).items
