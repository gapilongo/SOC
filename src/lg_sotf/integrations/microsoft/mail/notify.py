"""``mail.notify``: tell the user who reported an email what the SOC found, from the SOC mailbox.

``notify_reporter`` (target ``alert:<id>``, ``params.reporter``):

1. The reporter address is validated and its domain must be allowed
   (``recipient_domains``, or the SOC mailbox's own domain when that list
   is empty; exact domains, no subdomains): ``recipient_not_allowed``
   otherwise. With ``require_known_disposition``, an alert whose final
   verdict is ``unknown`` gives ``disposition_unknown``. Nothing is sent in
   either case.
2. Idempotency, in order: the SOC mailbox's Sent Items is searched for a
   message tagged with this action id (a single-value extended property,
   :data:`PROP_ID`); found means it was sent (``already``, ``verified``). A
   draft recorded by an interrupted run (``external_ref.draft_id``) is sent
   if it is still a draft, and otherwise waits for verification. A draft
   left by a run that stopped before recording it is found in Drafts by the
   same tag and adopted. So a re-run never sends twice.
3. Otherwise a draft is created (``POST /users/{soc}/messages``: plain text
   from :mod:`~lg_sotf.integrations.microsoft.mail.templates`, the reporter
   as the only recipient, the tag), recorded, and sent
   (``POST .../messages/{id}/send``, 202: accepted, not delivered).
4. Proof: the tagged message appears in Sent Items (``pending`` first after
   60 s, for up to 30 minutes). A sent email cannot be recalled.

Both roles are needed on the SOC mailbox only: ``Mail.ReadWrite`` (the
draft, the Sent Items search) and ``Mail.Send``; with Exchange RBAC for
Applications, scope them to that mailbox (``Application Mail Full Access``
covers both).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Tuple

from pydantic import Field

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.alert_view import AlertView
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.clouds import Cloud
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.integrations.microsoft.mail import templates
from lg_sotf.integrations.microsoft.mail.mailboxes import (
    FOLDER_DRAFTS,
    FOLDER_SENT,
    Mailbox,
    Refusal,
    item_id,
    mailbox_address,
    probe_get,
)
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult, VerifyPlan

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

# The property set of the tag on every reply (derived, never changed: re-runs and verification find replies by it).
PROPERTY_SET = uuid.uuid5(uuid.NAMESPACE_URL, "https://lg-sotf.invalid/microsoft/mail/notify-reporter")
PROP_ID = f"String {{{PROPERTY_SET}}} Name LGSOTFAction"
FIRST_CHECK_S = 60.0
VERIFY_MAX_S = 1_800.0


class MailNotifyOptions(CapabilityOptions):
    """Options of ``mail.notify`` (docs/microsoft-mail.md)."""

    sender_mailbox: str = Field(
        default="", max_length=320,
        description="The SOC mailbox the reply is sent from (scope Mail.Send and Mail.ReadWrite to it only).",
    )
    recipient_domains: List[str] = Field(
        default_factory=list, max_length=50,
        description="Domains a reporter may be in (exact match). Empty: the sender mailbox's domain only.",
    )
    require_known_disposition: bool = Field(
        default=False, description="Send nothing while the alert has no final verdict (disposition unknown)."
    )

    def problems(self, cloud: Cloud) -> List[str]:
        out: List[str] = []
        try:
            mailbox_address(self.sender_mailbox)
        except odata.InvalidTarget:
            out.append("sender_mailbox must be the email address of the SOC mailbox the reply is sent from")
        for value in self.recipient_domains:
            try:
                odata.domain(value)
            except odata.InvalidTarget:
                out.append(f"recipient_domains: {value[:64]!r} is not a domain name")
        return out


def tag_filter(action_id: Any) -> str:
    """The ``$filter`` finding the message tagged with one action id."""
    return (
        f"singleValueExtendedProperties/any(ep: ep/id eq {odata.odata_string(PROP_ID)}"
        f" and ep/value eq {odata.odata_string(str(action_id))})"
    )


class NotifyHandler:
    """The ``mail.notify`` handler (see the module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx
        options = ctx.options
        self.options = (
            options if isinstance(options, MailNotifyOptions)
            else MailNotifyOptions.model_validate(options.model_dump())
        )

    # ------------------------------------------------------------------ inputs

    def _sender(self) -> str:
        try:
            return mailbox_address(self.options.sender_mailbox)
        except odata.InvalidTarget:
            raise Refusal("invalid_options", "mail.notify has no valid sender_mailbox",
                          hint="set sender_mailbox to the SOC mailbox in the capability options") from None

    def _allowed_domains(self, sender: str) -> FrozenSet[str]:
        if not self.options.recipient_domains:
            return frozenset({sender.rsplit("@", 1)[1]})
        configured = set()
        for value in self.options.recipient_domains:
            try:
                configured.add(odata.domain(value))  # lower-case, IDNA: comparable with a reporter address
            except odata.InvalidTarget:
                continue  # refused when the capability is enabled (problems()); an invalid entry allows nothing
        return frozenset(configured)

    @staticmethod
    def _reporter(action: ResponseAction) -> str:
        value = (action.params or {}).get("reporter")
        if not isinstance(value, str) or not value.strip():
            raise odata.InvalidTarget("invalid_target", "the action names no reporter address (params.reporter)")
        return mailbox_address(value)

    async def _prepare(self, action: ResponseAction) -> Tuple[str, str, AlertView]:
        """``(sender, reporter, alert)`` once every check before sending passed (``Refusal`` otherwise)."""
        sender = self._sender()
        reporter = self._reporter(action)
        if reporter.rsplit("@", 1)[1] not in self._allowed_domains(sender):
            raise Refusal("recipient_not_allowed", "the reporter's domain is not an allowed recipient domain",
                          hint="add the domain to recipient_domains of mail.notify")
        view = await self.ctx.alert()
        if self.options.require_known_disposition and view.disposition == "unknown":
            # Retryable: once the alert is decided, Retry sends the reply.
            raise Refusal("disposition_unknown", "the alert has no final verdict yet; nothing was sent",
                          hint="decide the alert, then retry (or turn off require_known_disposition)",
                          retryable=True)
        return sender, reporter, view

    async def _tagged(self, mailbox: Mailbox, folder: str, action_id: Any, select: str) -> Optional[Dict[str, Any]]:
        found = await mailbox.search(folder, tag_filter(action_id), select)
        return found[0] if found else None

    # ------------------------------------------------------------------ execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        try:
            sender, reporter, view = await self._prepare(action)
        except Refusal as refusal:
            return refusal.result()
        mailbox = Mailbox(self.ctx, sender)
        ref: Dict[str, Any] = {"sender": sender, "reversible": False}
        sent = await self._tagged(mailbox, FOLDER_SENT, action.id, "id,sentDateTime")
        if sent is not None:
            return ConnectorResult(
                "succeeded", {"summary": "the reporter was already notified", "changed": False, "already": True},
                external_ref=ref, verify=VerifyPlan("verified", detail={"sent_at": sent.get("sentDateTime")}),
            )
        draft_id = item_id((action.external_ref or {}).get("draft_id"))
        if draft_id is not None:
            ref["draft_id"] = draft_id
            response = await mailbox.request(
                "GET", f"/messages/{odata.segment(draft_id)}", params={"$select": "id,isDraft"}, not_found_ok=True
            )
            still_draft = response.status != 404 and isinstance(response.body, dict) and response.body.get("isDraft")
            if still_draft is not True:
                return self._accepted(ref, "the notification was sent by an earlier attempt")
        else:
            adopted = await self._tagged(mailbox, FOLDER_DRAFTS, action.id, "id,isDraft")
            draft_id = item_id(adopted.get("id")) if adopted is not None else None
            if draft_id is None:
                draft_id = await self._create_draft(mailbox, action, reporter, view)
            ref["draft_id"] = draft_id
            await self.ctx.checkpoint({"draft_id": draft_id, "sender": sender})
        await mailbox.request("POST", f"/messages/{odata.segment(draft_id)}/send", ok=(202,))
        return self._accepted(ref, "notification sent to the reporter")

    async def _create_draft(self, mailbox: Mailbox, action: ResponseAction, reporter: str, view: AlertView) -> str:
        subject, body = templates.render(view.disposition, view.email.get("subject"))
        response = await mailbox.request(
            "POST",
            "/messages",
            json_body={
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [{"emailAddress": {"address": reporter}}],
                "singleValueExtendedProperties": [{"id": PROP_ID, "value": str(action.id)}],
            },
            ok=(201,),
        )
        created = item_id(response.body.get("id")) if isinstance(response.body, dict) else None
        if created is None:
            raise MicrosoftApiError("bad_request", "Graph created the draft but returned no id", status=response.status,
                                    request_id=response.request_id, retryable=False)
        return created

    @staticmethod
    def _accepted(ref: Dict[str, Any], summary: str) -> ConnectorResult:
        return ConnectorResult(
            "succeeded", {"summary": summary, "changed": True}, external_ref=ref,
            verify=VerifyPlan("pending", first_check_s=FIRST_CHECK_S, max_duration_s=VERIFY_MAX_S,
                              detail={"waiting_for": "sent_items"}),
        )

    # ------------------------------------------------------------------ verify, rehearse, probe

    async def verify(self, action: ResponseAction) -> VerificationResult:
        """The tagged reply is in the SOC mailbox's Sent Items."""
        recorded = (action.external_ref or {}).get("sender")
        sender = mailbox_address(recorded) if isinstance(recorded, str) and recorded else self._sender()
        sent = await self._tagged(Mailbox(self.ctx, sender), FOLDER_SENT, action.id, "id,sentDateTime")
        if sent is not None:
            return VerificationResult("verified", {"sent_at": sent.get("sentDateTime")})
        return VerificationResult("pending", {"waiting_for": "sent_items"})

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        try:
            sender, reporter, view = await self._prepare(action)
        except Refusal as refusal:
            return {"summary": f"would not send: {refusal.summary}", "problem": refusal.error}
        mailbox = Mailbox(self.ctx, sender)
        await mailbox.request("GET", f"/mailFolders/{FOLDER_SENT}", params={"$select": "id"})
        subject, _ = templates.render(view.disposition, view.email.get("subject"))
        return {
            "summary": f"would send the {view.disposition} update from {sender} to {reporter}",
            "would_execute": {"from": sender, "to": reporter, "subject": subject},
        }

    async def probe(self) -> List[ProbeCheck]:
        try:
            sender = self._sender()
        except Refusal:
            return [ProbeCheck("sender mailbox", "skipped", permission="Mail.ReadWrite",
                               detail="set sender_mailbox to test the SOC mailbox")]
        mailbox = Mailbox(self.ctx, sender)
        return [
            await probe_get(self.ctx, "sender mailbox", "Mail.ReadWrite", f"{mailbox.path}/mailFolders/{FOLDER_SENT}",
                            {"$select": "id"}),
            ProbeCheck("send mail", "skipped", permission="Mail.Send",
                       detail="Mail.Send cannot be tested without sending mail; check it with "
                              "Test-ServicePrincipalAuthorization"),
        ]


__all__ = ["PROP_ID", "PROPERTY_SET", "MailNotifyOptions", "NotifyHandler", "tag_filter"]
