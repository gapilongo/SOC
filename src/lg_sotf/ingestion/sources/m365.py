"""Microsoft 365 reported-phish mailbox (Microsoft Graph, application permissions).

Config:

``azure_tenant_id``  directory (tenant) GUID or domain
``mailbox``          the reporting mailbox (UPN/SMTP address or object id)
``folder``           folder to read, a well-known name (``inbox``, default) or a folder id
``after_processing`` ``mark_read`` (default) or ``move``
``processed_folder`` folder id or well-known name to move processed messages to (``move`` only)
``authority_url``    default ``https://login.microsoftonline.com`` (sovereign clouds)
``graph_url``        default ``https://graph.microsoft.com``
``initial_lookback_s`` how far back the first poll reads (default 3600)
``trusted_relays``   CIDRs of your own mail relays, skipped when choosing the relay IP

Credentials: ``client_id`` and ``client_secret`` of an app registration with
the ``Mail.ReadWrite`` application permission, scoped to the reporting
mailbox with an Exchange application access policy (``docs/phishing.md``).

Each poll lists the folder's messages received since the cursor (``isRead eq
false`` too in ``mark_read`` mode), oldest first, fetches each message's MIME
(``/messages/{id}/$value``, capped at ``ingestion.email.max_message_bytes``)
and parses it. After a page's alerts are committed, its messages are marked
read or moved; their ids also travel in the page cursor (``ack``) so a poll
interrupted between commit and acknowledgement finishes the job first thing
on the next poll. Pages are re-queried rather than followed with
``@odata.nextLink``: acknowledging a page changes the result set, so a skip
token would skip messages. A message that cannot be fetched whole or parsed
still becomes an alert (flagged ``email_unparsed``) so no report is dropped.

Every request goes through the source HTTP client (destination policy, TLS
verification, timeouts, bounded retries, response caps).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Mapping, Optional, Sequence
from urllib.parse import quote

from lg_sotf.ingestion.email import EmailLimits, EmailParseError, parse_email, unparsed_email
from lg_sotf.ingestion.email.auth import IPNetwork, parse_networks
from lg_sotf.ingestion.errors import SourceConfigError, SourceProtocolError, SourceRequestError, SourceResponseTooLarge
from lg_sotf.ingestion.sources.base import FetchedPage, PullConnector, SourceHealth, iso, window_cursor
from lg_sotf.ingestion.sources.http import OAuth2ClientCredentials, SourceHttpClient, json_mapping
from lg_sotf.ingestion.timeparse import parse_timestamp

GRAPH_SCOPE_SUFFIX = "/.default"
AFTER_PROCESSING = ("mark_read", "move")
MAX_ACK_IDS = 1_000
MAX_GRAPH_ID_CHARS = 1_024
LIST_RESPONSE_BYTES = 8 * 1024 * 1024
_GUID = re.compile(r"^[0-9A-Za-z-]{1,64}$")
_DIRECTORY = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_MAILBOX = re.compile(r"^(?:[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}|[0-9A-Fa-f-]{36})$")
_FOLDER = re.compile(r"^[A-Za-z0-9=_+/-]{1,512}$")
_SELECT = "id,receivedDateTime,internetMessageId,subject,from,isRead"


def _graph_id(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or len(value) > MAX_GRAPH_ID_CHARS:
        return None
    return value if all(32 < ord(ch) < 127 for ch in value) else None


class M365MailboxConnector(PullConnector):
    source_type = "m365_mailbox"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        directory = self.config_str("azure_tenant_id")
        if not _GUID.match(directory) and not _DIRECTORY.match(directory):
            raise SourceConfigError("m365_mailbox config.azure_tenant_id must be a tenant GUID or domain")
        self._mailbox = self.config_str("mailbox")
        if not _MAILBOX.match(self._mailbox):
            raise SourceConfigError("m365_mailbox config.mailbox must be an SMTP address or object id")
        self._folder = self.config_str("folder", "inbox")
        if not _FOLDER.match(self._folder):
            raise SourceConfigError("m365_mailbox config.folder must be a well-known folder name or folder id")
        self._after = self.config_str("after_processing", "mark_read")
        if self._after not in AFTER_PROCESSING:
            raise SourceConfigError(f"m365_mailbox config.after_processing must be one of {', '.join(AFTER_PROCESSING)}")
        self._processed: Optional[str] = None
        if self._after == "move":
            self._processed = self.config_str("processed_folder")
            if not _FOLDER.match(self._processed) or self._processed == self._folder:
                raise SourceConfigError(
                    "m365_mailbox config.processed_folder must be a folder id or well-known name other than folder"
                )
        try:
            self._trusted: List[IPNetwork] = parse_networks(self.config.get("trusted_relays"))
        except ValueError as exc:
            raise SourceConfigError(f"m365_mailbox config.trusted_relays {exc}") from exc
        try:
            self._limits = EmailLimits.from_settings(self.settings.ingestion)
        except ValueError as exc:
            raise SourceConfigError(str(exc)) from exc
        authority = self.config_str("authority_url", "https://login.microsoftonline.com").rstrip("/")
        graph = self.config_str("graph_url", "https://graph.microsoft.com").rstrip("/")
        self._auth = OAuth2ClientCredentials(
            self.destination(f"{authority}/{directory}/oauth2/v2.0/token"),
            self.credential("client_id"),
            self.credential("client_secret"),
            scope=f"{graph}{GRAPH_SCOPE_SUFFIX}",
        )
        self._http: SourceHttpClient = self.http(graph, self._auth, max_response_bytes=LIST_RESPONSE_BYTES)
        self._mime_http: SourceHttpClient = self.http(
            graph, self._auth, max_response_bytes=self._limits.max_message_bytes
        )
        self._base = f"/v1.0/users/{quote(self._mailbox, safe='')}"

    # -- Graph calls -------------------------------------------------------------

    def _folder_path(self, folder: str) -> str:
        return f"{self._base}/mailFolders/{quote(folder, safe='')}"

    def _message_path(self, message_id: str) -> str:
        return f"{self._base}/messages/{quote(message_id, safe='')}"

    async def test(self) -> SourceHealth:
        folder = json_mapping(
            await self._http.request("GET", self._folder_path(self._folder), params={"$select": "id,displayName"}),
            "mail folder",
        )
        if self._processed is not None:
            await self._http.request("GET", self._folder_path(self._processed), params={"$select": "id"})
        name = str(folder.get("displayName") or self._folder)[:64]
        return SourceHealth(True, f"read folder {name} of the reporting mailbox")

    async def _list(self, since: datetime) -> List[Mapping[str, Any]]:
        flt = f"receivedDateTime ge {iso(since - self.overlap)}"
        if self._after == "mark_read":
            flt += " and isRead eq false"
        params = {
            "$select": _SELECT,
            "$filter": flt,
            "$orderby": "receivedDateTime asc",
            "$top": str(self.options.page_size),
        }
        body = json_mapping(
            await self._http.request("GET", f"{self._folder_path(self._folder)}/messages", params=params),
            "message list",
        )
        items = body.get("value")
        if not isinstance(items, list):
            raise SourceProtocolError("m365_mailbox message list has no value array")
        return [i for i in items[: self.options.page_size] if isinstance(i, Mapping)]

    async def _mime(self, message_id: str) -> bytes:
        resp = await self._mime_http.request("GET", f"{self._message_path(message_id)}/$value")
        return resp.content

    async def _ack(self, ids: Sequence[str]) -> None:
        """Mark read or move each message (idempotent: a message already moved or deleted is skipped)."""
        for message_id in ids:
            try:
                if self._after == "move":
                    assert self._processed is not None
                    await self._http.request(
                        "POST", f"{self._message_path(message_id)}/move", json_body={"destinationId": self._processed}
                    )
                else:
                    await self._http.request("PATCH", self._message_path(message_id), json_body={"isRead": True})
            except SourceRequestError as exc:
                if exc.status_code != 404:
                    raise

    # -- events ------------------------------------------------------------------

    async def _event(self, item: Mapping[str, Any], message_id: str, received: Optional[datetime],
                     data: Optional[bytes], error: Optional[str]) -> Dict[str, Any]:
        transport = {"source": self.source_type, "mailbox_message_id": message_id[:256]}
        if data is not None and error is None:
            try:
                # CPU-bound on untrusted input: off the event loop, like the push path.
                return await asyncio.to_thread(
                    parse_email,
                    data,
                    limits=self._limits,
                    received_at=received,
                    trusted_relays=self._trusted,
                    transport=transport,
                )
            except EmailParseError as exc:
                error = str(exc)
        sender = item.get("from")
        address = sender.get("emailAddress", {}).get("address") if isinstance(sender, Mapping) else None
        key = hashlib.sha256(f"{self.source.id}\x00{message_id}".encode()).hexdigest()
        return unparsed_email(
            error or "message could not be read",
            dedup_key=f"email:m365:{key}",
            received_at=received,
            metadata={
                "subject": item.get("subject") if isinstance(item.get("subject"), str) else None,
                "message_id": item.get("internetMessageId") if isinstance(item.get("internetMessageId"), str) else None,
                "reporter": address,
            },
            transport=transport,
        )

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        pending = [i for i in (cursor or {}).get("ack") or [] if _graph_id(i)][:MAX_ACK_IDS]
        if pending:
            await self._ack(pending)
        since = self.cursor_since(cursor)
        seen: set[str] = set()
        while True:
            listed = await self._list(since)
            items: List[Mapping[str, Any]] = []
            for item in listed:
                message_id = _graph_id(item.get("id"))
                if message_id is None:
                    raise SourceProtocolError("m365_mailbox message has no usable id")
                if message_id not in seen:
                    items.append(item)
            if listed and not items:
                # Graph still lists messages this poll acknowledged (eventual consistency): try again next poll.
                return
            if not items:
                if cursor is None or pending:
                    # Persist the starting point (and clear acknowledged ids) even when nothing is new.
                    yield FetchedPage([], window_cursor(since), since)
                return
            events: List[Dict[str, Any]] = []
            ids: List[str] = []
            newest = since
            for item in items:
                message_id = str(item["id"])
                seen.add(message_id)
                received = parse_timestamp(item.get("receivedDateTime"), now=self.deps.now()).value
                data: Optional[bytes] = None
                error: Optional[str] = None
                try:
                    data = await self._mime(message_id)
                except SourceResponseTooLarge:
                    error = f"message is larger than {self._limits.max_message_bytes} bytes"
                events.append(await self._event(item, message_id, received, data, error))
                ids.append(message_id)
                if received is not None and received > newest:
                    newest = received
            drained = len(listed) < self.options.page_size
            yield FetchedPage(events, window_cursor(newest, ack=ids), newest)
            # The page is committed: acknowledge its messages so the next query no longer returns them.
            await self._ack(ids)
            pending = []
            since = newest
            if drained:
                return
