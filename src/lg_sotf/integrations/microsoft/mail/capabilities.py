"""The capability declarations of the Microsoft 365 mail package (``docs/microsoft-mail.md``)."""

from __future__ import annotations

from lg_sotf.integrations.microsoft.capability import ActionSupport, CapabilitySpec, Permission
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS
from lg_sotf.integrations.microsoft.mail.notify import MailNotifyOptions, NotifyHandler
from lg_sotf.integrations.microsoft.mail.remediate import MailRemediateOptions, RemediateHandler

DAY_S = 86_400

MAIL_REMEDIATE = CapabilitySpec(
    key="mail.remediate",
    package="mail",
    api="graph",
    title="Remove reported messages",
    description=(
        "Finds the reported message by its Internet Message-ID in every recipient mailbox (from the alert, or "
        "from Exchange message trace) and soft-deletes it or moves it to Deleted Items. A rollback moves it back "
        "to the folder it was in."
    ),
    actions={
        "purge_message": ActionSupport(
            reversible=True, rollback_window_s=14 * DAY_S,
            note="restorable while Exchange keeps deleted items (14 days by default, at most 30)",
        ),
        "restore_message": ActionSupport(),
    },
    permissions=(
        Permission(
            "graph", "Mail.ReadWrite", "find, remove and restore the reported message in recipient mailboxes",
            exchange_rbac="Application Mail.ReadWrite",
        ),
        Permission(
            "graph", "User.Read.All",
            "find the mailbox of a recipient address that is not the user principal name (an alias or proxy "
            "address, as in hybrid tenants and message trace)",
        ),
        Permission(
            "graph", "ExchangeMessageTrace.Read.All", "find every recipient of the message",
            required=False, when="recipient_source=message_trace",
        ),
    ),
    options=MailRemediateOptions,
    handler=RemediateHandler,
    clouds=ALL_CLOUDS,
    licence="",
    live_confirmation=(
        "Approved purges remove the message from the recipients' mailboxes; users and admins can still recover "
        "it until Exchange's deleted item retention ends."
    ),
)

MAIL_NOTIFY = CapabilitySpec(
    key="mail.notify",
    package="mail",
    api="graph",
    title="Notify reporters",
    description=(
        "Replies from the SOC mailbox to the user who reported an email, with a fixed plain-text update that "
        "depends on the alert's final verdict."
    ),
    actions={"notify_reporter": ActionSupport(note="a sent email cannot be recalled")},
    permissions=(
        Permission("graph", "Mail.Send", "send the reply from the SOC mailbox", exchange_rbac="Application Mail.Send"),
        Permission(
            "graph", "Mail.ReadWrite", "create the draft and find it in Sent Items (idempotency and proof)",
            exchange_rbac="Application Mail.ReadWrite",
        ),
    ),
    options=MailNotifyOptions,
    handler=NotifyHandler,
    clouds=ALL_CLOUDS,
    live_confirmation="Reporters receive an email from the SOC mailbox that cannot be recalled.",
)

__all__ = ["MAIL_NOTIFY", "MAIL_REMEDIATE"]
