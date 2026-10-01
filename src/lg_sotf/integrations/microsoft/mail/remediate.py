"""``mail.remediate``: remove a reported message from every recipient mailbox, and put it back on rollback.

``purge_message`` (target: the Internet Message-ID; ``params.match`` may
name the ``sender``):

1. The Message-ID and the sender are validated. The recipients come from
   the alert (its recipients, plus the reporter with ``include_reporter``)
   or from Exchange message trace; more than ``max_mailboxes`` refuses the
   action (``too_many_recipients``) before any change. The mailboxes are
   recorded as ``pending`` steps first (write-ahead), so a re-run works on
   the same set without asking message trace again.
2. Per mailbox (up to four at a time): find the message
   (``GET /users/{mb}/messages?$filter=internetMessageId eq '<id>'``), keep
   the copies from the expected sender, drop the Sent Items copy (the
   sender's own) and copies already removed; record their handles
   (``{id, folder}``) *before* changing anything; then ``DELETE`` each
   (``soft_delete``: into Recoverable Items, which the user and admins can
   still restore for the retention period, 14 days by default) or move it to
   Deleted Items (``move_to_deleted_items``). A 404 on the write means it is
   already gone.
3. A re-run skips ``done`` mailboxes. A mailbox with recorded handles is
   reconciled: an item Graph no longer finds by its id, or finds in the
   mode's removal folder, is done; any other is acted on again. So an
   interrupted run never deletes or moves the same item twice.
4. Outcome: every mailbox final and none failed is ``succeeded`` (``changed``
   when something was removed; then reversible until
   ``rollback_window_days`` after the first change); some removed and
   others failed or unfinished is ``failed`` with ``error: "partial"``
   (retryable, reversible); nothing removed and failures is ``failed``.
5. Proof: for every removed item, Graph no longer finds it by id or finds
   it in the removal folder (``recoverableitemsdeletions``; for the move
   mode ``deleteditems``, or further along), and its original folder has no
   message with that Message-ID. Proven inline gives ``verified``, otherwise
   the verification job re-checks (``pending``: first after 120 s, for up to
   30 minutes), and a message back in its original folder is ``failed``.

``restore_message`` (the rollback; ``ctx.original`` is the purge): for
every item the purge recorded, find it (by id, else by Message-ID in
Recoverable Items, and Deleted Items for the move mode) and move it back to
the folder it was in, or to the Inbox when that folder no longer exists.
Items already back in place are not moved. Nothing found anywhere is
``succeeded`` with ``error: "rollback_not_needed"`` (``failed`` with
``rollback_window_expired`` once the purge's rollback window has passed).
Proof: each restored item is in its destination folder.

Rehearsal (not live) resolves the recipients and looks the message up in
the first five mailboxes, with GETs only. The probe reads the Inbox of
``probe_mailbox`` and, with message trace, one trace row.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Literal, Mapping, Optional, Set, Tuple

from pydantic import Field

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.clouds import Cloud
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.integrations.microsoft.mail.mailboxes import (
    FOLDER_DELETED,
    FOLDER_INBOX,
    FOLDER_RECOVERABLE,
    FOLDER_SENT,
    TRACE_PATH,
    AmbiguousMailbox,
    Mailbox,
    Refusal,
    StepBook,
    each_mailbox,
    failed,
    failure_summary,
    guarded_step,
    item_id,
    listed,
    mailbox_address,
    mailbox_addresses,
    now_utc,
    probe_get,
    traced_recipients,
)
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult, VerifyPlan

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

log = get_logger(__name__)

Mode = Literal["soft_delete", "move_to_deleted_items"]
MODES: Tuple[Mode, ...] = ("soft_delete", "move_to_deleted_items")
PURGE_FIRST_CHECK_S = 120.0
PURGE_VERIFY_MAX_S = 1_800.0
RESTORE_FIRST_CHECK_S = 60.0
RESTORE_VERIFY_MAX_S = 900.0
REHEARSAL_MAILBOXES = 5
# Proof checks are GETs only: they may start closer to the deadline than a mailbox's changes (MIN_START_S).
MIN_PROOF_START_S = 3.0
VERBS: Mapping[str, str] = {"soft_delete": "soft-deleted", "move_to_deleted_items": "moved to Deleted Items"}
INTENTS: Mapping[str, str] = {"soft_delete": "soft-delete", "move_to_deleted_items": "move to Deleted Items"}
ProofCheck = Callable[[Mailbox, List[Dict[str, str]]], Awaitable[str]]
PERMISSION_HINT = (
    "grant Mail.ReadWrite for these mailboxes through Exchange RBAC for Applications "
    "(Test-ServicePrincipalAuthorization shows the scope); a recipient address that is not the user principal "
    "name also needs User.Read.All to find its mailbox"
)


class MailRemediateOptions(CapabilityOptions):
    """Options of ``mail.remediate`` (docs/microsoft-mail.md)."""

    recipient_source: Literal["alert", "message_trace"] = Field(
        default="alert",
        description="Where the mailboxes to clean come from: the alert's recipients (and reporter), or every "
        "recipient Exchange message trace reports (global cloud only; needs ExchangeMessageTrace.Read.All).",
    )
    mode: Literal["soft_delete", "move_to_deleted_items"] = Field(
        default="soft_delete",
        description="soft_delete removes the message from every folder view (users can still recover it); "
        "move_to_deleted_items leaves it visible in Deleted Items.",
    )
    max_mailboxes: int = Field(
        default=50, ge=1, le=200,
        description="More recipients than this refuses the action before anything is changed.",
    )
    rollback_window_days: int = Field(
        default=14, ge=1, le=30,
        description="How long a purge can be rolled back: match the mailboxes' deleted item retention "
        "(14 days by default, at most 30).",
    )
    include_reporter: bool = Field(
        default=True, description="With recipient_source=alert, also clean the reporter's mailbox."
    )
    probe_mailbox: str = Field(
        default="", max_length=320,
        description="A mailbox inside the Exchange RBAC scope that the connection test reads (Inbox id only).",
    )

    def problems(self, cloud: Cloud) -> List[str]:
        out: List[str] = []
        if self.recipient_source == "message_trace" and cloud != "global":
            out.append("recipient_source=message_trace needs the global cloud (Graph message trace is not "
                       "available in the US Government clouds)")
        if self.probe_mailbox:
            try:
                mailbox_address(self.probe_mailbox)
            except odata.InvalidTarget:
                out.append("probe_mailbox must be an email address")
        return out


def removal_folders(mode: str) -> Tuple[str, ...]:
    """Where a removed item may be found: Recoverable Items, and for the move mode Deleted Items first."""
    return (FOLDER_RECOVERABLE,) if mode == "soft_delete" else (FOLDER_DELETED, FOLDER_RECOVERABLE)


def _mode(value: Any, default: str) -> str:
    return value if value in MODES else default


def _sender_of(message: Mapping[str, Any]) -> str:
    sender = message.get("from")
    email = sender.get("emailAddress") if isinstance(sender, Mapping) else None
    address = email.get("address") if isinstance(email, Mapping) else None
    return address.strip().lower() if isinstance(address, str) else ""


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 'es' if word.endswith('x') else 's'}"


class RemediateHandler:
    """The ``mail.remediate`` handler (see the module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx
        options = ctx.options
        self.options = (
            options if isinstance(options, MailRemediateOptions)
            else MailRemediateOptions.model_validate(options.model_dump())
        )

    # ------------------------------------------------------------------ inputs

    @staticmethod
    def _sender(action: ResponseAction) -> Optional[str]:
        match = (action.params or {}).get("match")
        sender = match.get("sender") if isinstance(match, Mapping) else None
        if sender is None or sender == "":
            return None
        return odata.email_address(sender)

    async def _recipients(self, message_id: str) -> Tuple[List[str], int]:
        if self.options.recipient_source == "message_trace":
            if self.ctx.cloud.name != "global":
                raise Refusal("invalid_options", "message trace is only available in the global cloud",
                              hint="set recipient_source=alert for this cloud")
            view = await self.ctx.alert()
            return mailbox_addresses(await traced_recipients(self.ctx, message_id, view.received_at, view.ingested_at))
        view = await self.ctx.alert()
        candidates: List[Any] = list(view.email.get("recipients") or ())
        if self.options.include_reporter and view.email.get("reporter"):
            candidates.append(view.email.get("reporter"))
        return mailbox_addresses(candidates)

    async def _mailboxes(self, message_id: str) -> Tuple[List[str], int]:
        mailboxes, dropped = await self._recipients(message_id)
        if not mailboxes:
            where = "message trace" if self.options.recipient_source == "message_trace" else "the alert"
            raise Refusal(
                "not_found", f"no recipient mailbox to search: {where} names none", invalid_recipients=dropped,
                hint="check the alert's email section, or use recipient_source=message_trace",
            )
        if len(mailboxes) > self.options.max_mailboxes:
            raise Refusal(
                "too_many_recipients",
                f"{len(mailboxes)} recipient mailboxes exceed max_mailboxes ({self.options.max_mailboxes})",
                count=len(mailboxes), max_mailboxes=self.options.max_mailboxes,
                hint="raise max_mailboxes (at most 200) or remove the message with Microsoft Purview or Defender",
            )
        return mailboxes, dropped

    async def _candidates(
        self, mailbox: Mailbox, message_id: str, sender: Optional[str], mode: str
    ) -> Tuple[str, Optional[str], List[Dict[str, str]]]:
        """``(status, reason, items)`` of a fresh lookup: ``pending`` with the items to remove, or a final status."""
        found = await mailbox.find(message_id)
        if found is None:
            return "mailbox_not_found", None, []
        if not found:
            return "not_found", None, []
        if sender is not None:
            found = [m for m in found if _sender_of(m) == sender]
            if not found:
                return "skipped", "sender_mismatch", []
        sent = await mailbox.folder_id(FOLDER_SENT)
        found = [m for m in found if sent is None or m.get("parentFolderId") != sent]
        if not found:
            return "skipped", "sent_items", []
        removed = {await mailbox.folder_id(name) for name in removal_folders(mode)} - {None}
        found = [m for m in found if m.get("parentFolderId") not in removed]
        if not found:
            return "skipped", "already_removed", []
        inbox = await mailbox.folder_id(FOLDER_INBOX)
        items: List[Dict[str, str]] = []
        for message in found:
            parent = item_id(message.get("parentFolderId"))
            folder = FOLDER_INBOX if parent is None or parent == inbox else parent
            items.append({"id": str(message["id"]), "folder": folder})
        return "pending", None, items

    async def _removed(self, mailbox: Mailbox, message: str, mode: str) -> bool:
        """Whether Graph no longer finds the item by id, or finds it in the mode's removal folder."""
        current = await mailbox.message(message)
        if current is None:
            return True
        parent = current.get("parentFolderId")
        for name in removal_folders(mode):
            if parent is not None and parent == await mailbox.folder_id(name):
                return True
        return False

    # ------------------------------------------------------------------ execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        try:
            if action.action_type == "restore_message":
                return await self._restore(action)
            return await self._purge(action)
        except Refusal as refusal:
            return refusal.result()

    async def _purge(self, action: ResponseAction) -> ConnectorResult:
        message_id = odata.internet_message_id(action.target)
        sender = self._sender(action)
        ref = dict(action.external_ref or {})
        recorded = StepBook.recorded(ref)
        if recorded:
            # A re-run keeps the mailboxes, the mode and the start of the first run.
            mode = _mode(ref.get("mode"), self.options.mode)
            started = _parse_time(ref.get("started_at")) or now_utc()
            book = StepBook(self.ctx, self._header(ref, message_id, mode, started), recorded)
        else:
            mailboxes, dropped = await self._mailboxes(message_id)
            mode = self.options.mode
            header = self._header({"invalid_recipients": dropped or None}, message_id, mode, now_utc())
            book = StepBook(self.ctx, header)
            await book.start(mailboxes)
        todo = [m for m in book.mailboxes() if book.status(m) != "done"]

        async def work(address: str) -> None:
            await guarded_step(book, address, lambda: self._purge_mailbox(book, address, message_id, sender, mode))

        await each_mailbox(self.ctx, todo, work)
        return await self._purge_result(book, message_id, mode)

    @staticmethod
    def _header(ref: Mapping[str, Any], message_id: str, mode: str, started: datetime) -> Dict[str, Any]:
        header: Dict[str, Any] = {"mode": mode, "internet_message_id": message_id, "started_at": started.isoformat()}
        if isinstance(ref.get("invalid_recipients"), int) and ref["invalid_recipients"] > 0:
            header["invalid_recipients"] = ref["invalid_recipients"]
        return header

    async def _purge_mailbox(
        self, book: StepBook, address: str, message_id: str, sender: Optional[str], mode: str
    ) -> None:
        mailbox = Mailbox(self.ctx, address, book.user_id(address))
        items = book.items(address) if book.status(address) in ("pending", "failed") else []
        if items:
            # Handles recorded by an interrupted run: act only on what is not removed yet.
            todo = [item for item in items if not await self._removed(mailbox, item["id"], mode)]
        else:
            status, reason, items = await self._candidates(mailbox, message_id, sender, mode)
            if status != "pending":
                await book.save(address, status, reason=reason, user_id=mailbox.user_id)
                return
            # Before anything in this mailbox changes (with the owner's id when the address is an alias).
            await book.save(address, "pending", items=items, user_id=mailbox.user_id)
            todo = items
        for item in todo:
            if mode == "soft_delete":
                await mailbox.delete(item["id"])  # False (404): already gone
                continue
            moved = await mailbox.move(item["id"], FOLDER_DELETED)
            new_id = item_id(moved.get("id")) if moved else None
            if new_id is not None:
                item["id"] = new_id
        await book.save(address, "done", items=items)

    def _rollback_until(self, book: StepBook) -> str:
        started = _parse_time(book.header.get("started_at")) or now_utc()
        return (started + timedelta(days=self.options.rollback_window_days)).isoformat()

    async def _purge_result(self, book: StepBook, message_id: str, mode: str) -> ConnectorResult:
        counts = book.counts()
        steps = book.steps()
        done = counts["done"]
        ref: Dict[str, Any] = book.state()
        removed = sum(len(s.get("items") or []) for s in steps if s["status"] == "done")
        detail: Dict[str, Any] = {"counts": counts, "mailboxes": len(steps), "removed": removed, "mode": mode}
        if book.header.get("invalid_recipients"):
            detail["invalid_recipients"] = book.header["invalid_recipients"]
        verb = VERBS.get(mode, "removed")
        if counts["failed"] == 0 and counts["pending"] == 0:
            ref["reversible"] = done > 0
            if done:
                ref["rollback_until"] = self._rollback_until(book)
                summary = f"{verb} the message in {done} of {_plural(len(steps), 'mailbox')}"
                verify: Optional[VerifyPlan] = await self._purge_proof(book, message_id, mode)
            else:
                summary = f"nothing to remove: the message was not found in any of {_plural(len(steps), 'mailbox')}"
                verify = None
                if any(s.get("reason") == "already_removed" for s in steps):
                    detail["already"] = True
            return ConnectorResult("succeeded", {"summary": summary, "changed": done > 0, **detail},
                                   external_ref=ref, verify=verify)
        unfinished = counts["failed"] + counts["pending"]
        if done:
            ref.update(partial=True, reversible=True, rollback_until=self._rollback_until(book))
            return failed(
                "partial", f"{verb} the message in {done} of {_plural(len(steps), 'mailbox')}; "
                f"{unfinished} failed or unfinished (retry to continue)",
                retryable=True, changed=True, external_ref=ref,
                failed_mailboxes=listed(s["mailbox"] for s in steps if s["status"] in ("failed", "pending")),
                **detail,
            )
        ref["reversible"] = False
        error, retryable, code = failure_summary(steps)
        return failed(
            error, f"could not remove the message: {unfinished} of {_plural(len(steps), 'mailbox')} failed or "
            f"unfinished ({error})",
            retryable=retryable, ms_code=code, external_ref=ref,
            hint=PERMISSION_HINT if error == "permission_denied" else "",
            failed_mailboxes=listed(s["mailbox"] for s in steps if s["status"] in ("failed", "pending")),
            **detail,
        )

    # ------------------------------------------------------------------ proof

    async def _prove_purge(self, mailbox: Mailbox, items: List[Dict[str, str]], message_id: str, mode: str) -> str:
        """``proven``, ``unproven`` or ``reappeared`` for one mailbox's removed items."""
        removal = {await mailbox.folder_id(name) for name in removal_folders(mode)} - {None}
        state = "proven"
        for folder in dict.fromkeys(i["folder"] for i in items):
            if await mailbox.in_folder(folder, message_id):
                return "reappeared"
        for item in items:
            current = await mailbox.message(item["id"])
            if current is not None and current.get("parentFolderId") not in removal:
                state = "unproven"
        return state

    async def _prove_restore(self, mailbox: Mailbox, items: List[Dict[str, str]]) -> str:
        for item in items:
            current = await mailbox.message(item["id"])
            wanted = await mailbox.resolve(item["folder"])
            if current is None or wanted is None or current.get("parentFolderId") != wanted:
                return "unproven"
        return "proven"

    async def _prove(self, steps: List[Dict[str, Any]], check: ProofCheck, *, tolerant: bool) -> Dict[str, str]:
        """Run ``check(mailbox, items)`` for each done step; ``tolerant`` counts errors as ``unproven``."""
        results: Dict[str, str] = {}
        by_mailbox = {str(s["mailbox"]): list(s.get("items") or []) for s in steps}
        owners = {str(s["mailbox"]): s.get("user_id") for s in steps}

        async def one(address: str) -> None:
            try:
                results[address] = await check(Mailbox(self.ctx, address, owners[address]), by_mailbox[address])
            except (MicrosoftApiError, odata.InvalidTarget):
                if not tolerant:
                    raise
                results[address] = "unproven"

        await each_mailbox(self.ctx, list(by_mailbox), one, min_start_s=MIN_PROOF_START_S)
        return results

    async def _inline_proof(self, steps: List[Dict[str, Any]], check: ProofCheck) -> Dict[str, str]:
        """The proof right after the change: it never fails the action (the verification job proves it later)."""
        try:
            return await self._prove(steps, check, tolerant=True)
        except Exception as exc:  # noqa: BLE001 - the change is made and recorded; only the proof is postponed
            log.warning("microsoft.mail.inline_proof_failed", error_type=type(exc).__name__)
            return {}

    async def _purge_proof(self, book: StepBook, message_id: str, mode: str) -> VerifyPlan:
        done = [s for s in book.steps() if s["status"] == "done" and s.get("items")]
        results = await self._inline_proof(
            done, lambda mailbox, items: self._prove_purge(mailbox, items, message_id, mode)
        )
        proven = sorted(m for m, r in results.items() if r == "proven")
        detail: Dict[str, Any] = {"mode": mode, "mailboxes": len(done)}
        if len(proven) == len(done):
            return VerifyPlan("verified", detail=detail)
        return VerifyPlan("pending", first_check_s=PURGE_FIRST_CHECK_S, max_duration_s=PURGE_VERIFY_MAX_S,
                          detail={**detail, "proven": proven,
                                  "unproven": listed(s["mailbox"] for s in done if s["mailbox"] not in proven)})

    async def _restore_proof(self, book: StepBook) -> VerifyPlan:
        done = [s for s in book.steps() if s["status"] == "done" and s.get("items")]
        results = await self._inline_proof(done, self._prove_restore)
        proven = sorted(m for m, r in results.items() if r == "proven")
        detail: Dict[str, Any] = {"mailboxes": len(done)}
        if len(proven) == len(done):
            return VerifyPlan("verified", detail=detail)
        return VerifyPlan("pending", first_check_s=RESTORE_FIRST_CHECK_S, max_duration_s=RESTORE_VERIFY_MAX_S,
                          detail={**detail, "proven": proven,
                                  "unproven": listed(s["mailbox"] for s in done if s["mailbox"] not in proven)})

    async def verify(self, action: ResponseAction) -> VerificationResult:
        """Re-check the removed (or restored) items; mailboxes proven by an earlier check are not re-read."""
        ref = action.external_ref or {}
        restore = action.action_type == "restore_message"
        mode = _mode(ref.get("mode"), self.options.mode)
        done = [s for s in StepBook.recorded(ref) if s["status"] == "done" and s.get("items")]
        previous = action.verification_detail if isinstance(action.verification_detail, Mapping) else {}
        earlier = previous.get("proven")
        before: Set[str] = {m for m in earlier if isinstance(m, str)} if isinstance(earlier, list) else set()
        before &= {str(s["mailbox"]) for s in done}
        todo = [s for s in done if s["mailbox"] not in before]
        if restore:
            results = await self._prove(todo, self._prove_restore, tolerant=False)
        else:
            message_id = odata.internet_message_id(str(ref.get("internet_message_id") or action.target))
            results = await self._prove(
                todo, lambda mailbox, items: self._prove_purge(mailbox, items, message_id, mode), tolerant=False
            )
        detail: Dict[str, Any] = {"mailboxes": len(done)} if restore else {"mode": mode, "mailboxes": len(done)}
        reappeared = sorted(m for m, r in results.items() if r == "reappeared")
        if reappeared:
            return VerificationResult("failed", {**detail, "mailbox": reappeared[0], "reason": "message_reappeared",
                                                 "reappeared": listed(reappeared)})
        proven = sorted(before | {m for m, r in results.items() if r == "proven"})
        if len(proven) == len(done):
            return VerificationResult("verified", detail)
        return VerificationResult("pending", {
            **detail, "proven": proven, "unproven": listed(s["mailbox"] for s in done if s["mailbox"] not in proven)
        })

    # ------------------------------------------------------------------ restore

    async def _restore(self, action: ResponseAction) -> ConnectorResult:
        original = self.ctx.original
        if original is None or original.action_type != "purge_message":
            raise Refusal("invalid_target", "restore_message only runs as the rollback of a purge_message")
        message_id = odata.internet_message_id(original.target)
        original_ref = original.external_ref or {}
        mode = _mode(original_ref.get("mode"), self.options.mode)
        # Every item the purge recorded may have been changed (a failed step can have removed some).
        recorded = [s for s in StepBook.recorded(original_ref) if s.get("items")]
        sources = {str(s["mailbox"]): s["items"] for s in recorded}
        owners = {str(s["mailbox"]): s.get("user_id") for s in recorded}
        header = {"mode": mode, "internet_message_id": message_id, "restores": str(original.id)}
        book = StepBook(self.ctx, header, StepBook.recorded(action.external_ref))
        if not book.mailboxes() and sources:
            await book.start(list(sources))
        todo = [m for m in book.mailboxes() if book.status(m) != "done" and m in sources]

        async def work(address: str) -> None:
            await guarded_step(
                book, address,
                lambda: self._restore_mailbox(book, address, sources[address], message_id, mode, owners.get(address)),
            )

        await each_mailbox(self.ctx, todo, work)
        return await self._restore_result(book, original)

    async def _locate(
        self, mailbox: Mailbox, item: Mapping[str, str], message_id: str, mode: str, claimed: Set[str]
    ) -> Optional[Tuple[str, Optional[str]]]:
        """``(id, parent folder id)`` of a removed item: by its id, else by Message-ID in the removal folders."""
        current = await mailbox.message(item["id"])
        if current is not None:
            return item_id(current.get("id")) or item["id"], current.get("parentFolderId")
        for folder in removal_folders(mode):
            for found in await mailbox.in_folder(folder, message_id):
                if found not in claimed:
                    return found, await mailbox.folder_id(folder)
        return None

    async def _move_back(self, mailbox: Mailbox, item: Mapping[str, str]) -> Optional[Dict[str, str]]:
        """Move one item to its saved folder, or to the Inbox when that folder no longer exists."""
        destination = item["folder"]
        try:
            moved = await mailbox.move(item["id"], destination)
        except MicrosoftApiError as exc:
            if exc.code.lower() != "erroritemnotfound":
                raise
            moved = None
        if moved is None and destination != FOLDER_INBOX:
            destination = FOLDER_INBOX
            moved = await mailbox.move(item["id"], destination)
        if moved is None:
            return None
        folder = item_id(moved.get("parentFolderId")) or await mailbox.resolve(destination) or destination
        return {"id": item_id(moved.get("id")) or item["id"], "folder": folder}

    async def _restore_mailbox(
        self, book: StepBook, address: str, originals: List[Dict[str, str]], message_id: str, mode: str,
        user_id: Optional[str] = None,
    ) -> None:
        mailbox = Mailbox(self.ctx, address, user_id)
        interrupted = book.status(address) == "pending" and bool(book.items(address))
        claimed: Set[str] = set()
        to_move: List[Dict[str, str]] = []
        in_place: List[Dict[str, str]] = []
        for item in originals:
            located = await self._locate(mailbox, item, message_id, mode, claimed)
            if located is None:
                continue
            found, parent = located
            claimed.add(found)
            if parent is not None and parent == await mailbox.resolve(item["folder"]):
                in_place.append({"id": found, "folder": parent})
            else:
                to_move.append({"id": found, "folder": item["folder"]})
        if not to_move:
            if in_place and interrupted:
                await book.save(address, "done", items=in_place, user_id=user_id)  # moved back by the interrupted run
            elif in_place:
                await book.save(address, "skipped", reason="already_in_place", user_id=user_id)
            else:
                await book.save(address, "not_found", user_id=user_id)
            return
        await book.save(address, "pending", items=to_move, user_id=user_id)  # before anything in this mailbox moves
        restored = [dict(i) for i in in_place] if interrupted else []
        for item in to_move:
            moved = await self._move_back(mailbox, item)
            if moved is not None:
                restored.append(moved)
        await book.save(address, "done" if restored else "not_found", items=restored or None, user_id=user_id)

    async def _restore_result(self, book: StepBook, original: ResponseAction) -> ConnectorResult:
        counts = book.counts()
        steps = book.steps()
        done = counts["done"]
        ref: Dict[str, Any] = {**book.state(), "reversible": False}
        restored = sum(len(s.get("items") or []) for s in steps if s["status"] == "done")
        detail: Dict[str, Any] = {"counts": counts, "mailboxes": len(steps), "restored": restored}
        if counts["failed"] == 0 and counts["pending"] == 0:
            if done:
                summary = f"restored the message in {done} of {_plural(len(steps), 'mailbox')}"
                return ConnectorResult("succeeded", {"summary": summary, "changed": True, **detail},
                                       external_ref=ref, verify=await self._restore_proof(book))
            if counts["skipped"]:
                return ConnectorResult("succeeded", {
                    "summary": "nothing to restore: the message is already back in its folder", "changed": False,
                    "already": True, **detail,
                }, external_ref=ref)
            until = _parse_time((original.external_ref or {}).get("rollback_until"))
            if until is not None and until < now_utc():
                return failed("rollback_window_expired", "nothing to restore: the rollback window has passed and "
                              "the removed message was not found", external_ref=ref, **detail)
            return ConnectorResult("succeeded", {
                "summary": "nothing to restore: the removed message was not found", "changed": False,
                "error": "rollback_not_needed", **detail,
            }, external_ref=ref)
        unfinished = counts["failed"] + counts["pending"]
        pending_or_failed = listed(s["mailbox"] for s in steps if s["status"] in ("failed", "pending"))
        if done:
            ref["partial"] = True
            return failed(
                "partial", f"restored the message in {done} of {_plural(len(steps), 'mailbox')}; {unfinished} failed "
                "or unfinished (retry to continue)",
                retryable=True, changed=True, external_ref=ref, failed_mailboxes=pending_or_failed, **detail,
            )
        error, retryable, code = failure_summary(steps)
        return failed(
            error, f"could not restore the message: {unfinished} of {_plural(len(steps), 'mailbox')} failed or "
            f"unfinished ({error})",
            retryable=retryable, ms_code=code, external_ref=ref, failed_mailboxes=pending_or_failed,
            hint=PERMISSION_HINT if error == "permission_denied" else "", **detail,
        )

    # ------------------------------------------------------------------ rehearse and probe

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        """Recipients and the lookup in the first five mailboxes, with GETs only."""
        mode = self.options.mode
        if action.action_type == "restore_message":
            return {"summary": "restore_message runs only as the rollback of a purge", "would_execute": {"mode": mode}}
        message_id = odata.internet_message_id(action.target)
        sender = self._sender(action)
        try:
            mailboxes, dropped = await self._recipients(message_id)
        except Refusal as refusal:
            return {"summary": f"would not run: {refusal.summary}", "problem": refusal.error}
        would = {"mode": mode, "mailboxes": len(mailboxes)}
        if len(mailboxes) > self.options.max_mailboxes:
            return {"summary": f"would refuse: {len(mailboxes)} recipient mailboxes exceed max_mailboxes "
                               f"({self.options.max_mailboxes})",
                    "would_execute": would, "problem": "too_many_recipients", "count": len(mailboxes)}
        found: Dict[str, int] = {}
        missing: List[str] = []
        errors: Dict[str, str] = {}
        for address in mailboxes[:REHEARSAL_MAILBOXES]:
            try:
                status, _, items = await self._candidates(Mailbox(self.ctx, address), message_id, sender, mode)
            except MicrosoftApiError as exc:
                if exc.kind in ("throttled", "auth", "deadline"):
                    raise
                errors[address] = exc.ledger_error
                continue
            except AmbiguousMailbox:
                errors[address] = "ambiguous_target"
                continue
            if status == "mailbox_not_found":
                missing.append(address)
            else:
                found[address] = len(items)
        hits = sum(1 for n in found.values() if n)
        checked = min(len(mailboxes), REHEARSAL_MAILBOXES)
        out: Dict[str, Any] = {
            "summary": f"would {INTENTS.get(mode, 'remove')} the message in {_plural(len(mailboxes), 'mailbox')}; "
                       f"found in {hits} of the {checked} checked",
            "would_execute": would,
            "found": found,
        }
        if missing:
            out["mailbox_not_found"] = missing
        if errors:
            out["errors"] = errors
        if dropped:
            out["invalid_recipients"] = dropped
        return out

    async def probe(self) -> List[ProbeCheck]:
        checks: List[ProbeCheck] = []
        if self.options.probe_mailbox:
            mailbox = Mailbox(self.ctx, self.options.probe_mailbox)
            checks.append(await probe_get(self.ctx, "mailbox access", "Mail.ReadWrite",
                                          f"{mailbox.path}/mailFolders/{FOLDER_INBOX}", {"$select": "id"}))
        else:
            checks.append(ProbeCheck("mailbox access", "skipped", permission="Mail.ReadWrite",
                                     detail="set probe_mailbox to test mailbox access"))
        if self.options.recipient_source == "message_trace":
            checks.append(await probe_get(self.ctx, "message trace", "ExchangeMessageTrace.Read.All", TRACE_PATH,
                                          {"$top": "1"}))
        return checks


__all__ = ["MODES", "MailRemediateOptions", "RemediateHandler", "removal_folders"]
