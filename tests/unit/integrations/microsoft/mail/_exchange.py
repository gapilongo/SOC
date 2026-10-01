"""A stateful fake of the Exchange Online mail API of Microsoft Graph, on top of :class:`FakeMicrosoft`.

It behaves as the verified Graph facts the mail package codes against:

* ``GET /users/{mb}/messages`` lists the whole mailbox (Deleted Items
  included, Recoverable Items not) and filters on ``internetMessageId``;
* ``DELETE /users/{mb}/messages/{id}`` moves the message to
  Recoverable Items\\Deletions (204); whether Graph still finds it there by
  id is a switch (``recoverable_by_id``: an open question in the spec);
* ``POST .../move`` answers 201 with the moved message; the id survives only
  when the request sent ``Prefer: IdType="ImmutableId"``;
* sending a draft moves it to Sent Items under a new id (202);
* a mailbox is addressed by its user principal name or its owner's object
  id; any other address (an alias, see :meth:`FakeExchange.alias`) answers
  404 ``ErrorInvalidUser`` like an unknown mailbox, and an unknown message
  or folder 404 ``ErrorItemNotFound``;
* ``GET /users?$filter=`` answers ``mail eq`` and
  ``proxyAddresses/any(x:x eq 'smtp:...')`` from the mailboxes' addresses
  (the ``smtp:`` prefix case-insensitively), with the users' ids only;
* message trace filters on ``messageId`` and ``receivedDateTime`` and pages
  with ``@odata.nextLink``.

Every Graph request is recorded in :attr:`FakeExchange.log`; requests without
the ``Prefer`` header are collected in :attr:`FakeExchange.missing_prefer`.
Ids are built at runtime.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple, Union

import httpx

from tests.fixtures.microsoft import FakeMicrosoft, graph_error

WELL_KNOWN = ("inbox", "sentitems", "deleteditems", "recoverableitemsdeletions", "drafts", "junkemail")
IMMUTABLE = 'IdType="ImmutableId"'
_IMID = re.compile(r"internetMessageId eq '((?:[^']|'')*)'")
_TAG = re.compile(r"singleValueExtendedProperties/any\(ep: ep/id eq '((?:[^']|'')*)' and ep/value eq '((?:[^']|'')*)'\)")
_MAIL_EQ = re.compile(r"mail eq '((?:[^']|'')*)'")
_PROXY_EQ = re.compile(r"proxyAddresses/any\(x:x eq '((?:[^']|'')*)'\)")
_TRACE = re.compile(
    r"messageId eq '((?:[^']|'')*)' and receivedDateTime ge (\S+) and receivedDateTime le (\S+)"
)
USER = r"/v1\.0/users/([^/]+)"
Reply = Union[httpx.Response, Callable[[httpx.Request], httpx.Response]]


def new_id(kind: str = "msg") -> str:
    """A Graph-looking object id (runtime-built)."""
    return f"AAMkA{uuid.uuid4().hex}{uuid.uuid4().hex[:12]}-{kind}_A="


def _unquote(value: str) -> str:
    return value.replace("''", "'")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FakeMessage:
    id: str
    folder: str
    internet_message_id: str
    sender: str
    subject: str = "Invoice overdue"
    received: str = field(default_factory=_now)
    is_draft: bool = False
    props: Dict[str, str] = field(default_factory=dict)
    sent_at: Optional[str] = None
    to: List[str] = field(default_factory=list)
    body: Dict[str, Any] = field(default_factory=dict)
    previous_folder: Optional[str] = None

    def as_json(self, select: Optional[str] = None) -> Dict[str, Any]:
        full: Dict[str, Any] = {
            "id": self.id,
            "parentFolderId": self.folder,
            "internetMessageId": self.internet_message_id,
            "from": {"emailAddress": {"address": self.sender, "name": self.sender.split("@")[0]}},
            "subject": self.subject,
            "receivedDateTime": self.received,
            "isDraft": self.is_draft,
            "sentDateTime": self.sent_at,
        }
        if not select:
            return full
        wanted = select.split(",")
        return {"@odata.etag": 'W/"fake"', **{k: v for k, v in full.items() if k in wanted}}


class FakeMailbox:
    """One mailbox: well-known folders (and custom ones) and its messages.

    ``address`` is the owner's user principal name; ``mail`` and ``proxies``
    are the other SMTP addresses it receives mail for.
    """

    def __init__(self, address: str) -> None:
        self.address = address
        self.id = str(uuid.uuid4())
        self.mail = address
        self.proxies: List[str] = []
        self.folders: Dict[str, str] = {name: new_id("folder") for name in WELL_KNOWN}
        self.messages: Dict[str, FakeMessage] = {}

    def folder_id(self, name_or_id: str) -> Optional[str]:
        if name_or_id in self.folders:
            return self.folders[name_or_id]
        return name_or_id if name_or_id in self.folders.values() else None

    def folder_name(self, folder_id: str) -> Optional[str]:
        return next((n for n, i in self.folders.items() if i == folder_id), None)

    def add_folder(self, name: str) -> str:
        self.folders[name] = new_id("folder")
        return self.folders[name]

    def add(self, internet_message_id: str, *, folder: str = "inbox", sender: str = "billing@attacker.example",
            subject: str = "Invoice overdue", **fields: Any) -> FakeMessage:
        message = FakeMessage(new_id(), self.folders[folder], internet_message_id, sender, subject, **fields)
        self.messages[message.id] = message
        return message

    def where(self, message: FakeMessage) -> Optional[str]:
        """The folder name the message is in now (``None``: gone)."""
        current = self.messages.get(message.id) or next(
            (m for m in self.messages.values() if m.internet_message_id == message.internet_message_id
             and m.sender == message.sender), None
        )
        return self.folder_name(current.folder) if current is not None else None

    def in_folder(self, name: str) -> List[FakeMessage]:
        return [m for m in self.messages.values() if m.folder == self.folders[name]]


@dataclass
class _Override:
    method: str
    pattern: Pattern[str]
    reply: Reply
    times: Optional[int]
    calls: int = 0


class FakeExchange:
    """Graph mail endpoints answered from :class:`FakeMailbox` state (see the module docstring)."""

    def __init__(self, fake: FakeMicrosoft, *, recoverable_by_id: bool = True) -> None:
        self.fake = fake
        self.mailboxes: Dict[str, FakeMailbox] = {}
        self.traces: List[Dict[str, Any]] = []
        self.trace_page_size = 1000
        self.trace_filters: List[str] = []
        self.recoverable_by_id = recoverable_by_id
        # Folder queries that still return messages moved out of the folder (a lagging index).
        self.stale_folder_reads = 0
        self.log: List[Tuple[str, str]] = []
        self.missing_prefer: List[str] = []
        self.on_write: Optional[Callable[[httpx.Request], None]] = None
        self._overrides: List[_Override] = []
        self._trace_pages: Dict[str, List[Dict[str, Any]]] = {}
        routes: List[Tuple[str, str, Callable[..., httpx.Response]]] = [
            ("GET", USER + r"/messages", self._list),
            ("POST", USER + r"/messages", self._create),
            ("GET", USER + r"/messages/([^/]+)", self._get),
            ("DELETE", USER + r"/messages/([^/]+)", self._delete),
            ("POST", USER + r"/messages/([^/]+)/move", self._move),
            ("POST", USER + r"/messages/([^/]+)/send", self._send),
            ("GET", USER + r"/mailFolders/([^/]+)", self._folder),
            ("GET", USER + r"/mailFolders/([^/]+)/messages", self._folder_messages),
            ("GET", r"/v1\.0/admin/exchange/tracing/messageTraces", self._trace),
            ("GET", r"/v1\.0/users", self._users),
        ]
        for method, pattern, handler in routes:
            fake.route(method, "graph", re.compile(pattern), self._dispatch(method, re.compile(pattern), handler))

    # -- scripting -------------------------------------------------------------

    def mailbox(self, address: str) -> FakeMailbox:
        if address not in self.mailboxes:
            self.mailboxes[address] = FakeMailbox(address)
        return self.mailboxes[address]

    def alias(self, address: str, *aliases: str, mail: Optional[str] = None) -> FakeMailbox:
        """Give the mailbox of ``address`` (its UPN) proxy addresses and optionally another primary ``mail``."""
        box = self.mailbox(address)
        box.proxies.extend(aliases)
        if mail is not None:
            box.mail = mail
        return box

    def fail(self, method: str, pattern: str, reply: Reply, *, times: Optional[int] = 1) -> None:
        """Answer ``method`` on paths fully matching ``pattern`` with ``reply`` (before the normal behaviour)."""
        self._overrides.append(_Override(method, re.compile(pattern), reply, times))

    def trace(self, internet_message_id: str, recipient: str, *, received: Optional[str] = None,
              sender: str = "billing@attacker.example") -> None:
        self.traces.append({
            "id": str(uuid.uuid4()), "messageId": internet_message_id, "recipientAddress": recipient,
            "senderAddress": sender, "receivedDateTime": received or _now(), "status": "Delivered",
            "subject": "Invoice overdue",
        })

    # -- inspection ------------------------------------------------------------

    def calls(self, method: str, suffix: str = "") -> List[str]:
        return [p for m, p in self.log if m == method and p.endswith(suffix)]

    # -- plumbing --------------------------------------------------------------

    def _dispatch(self, method: str, pattern: Pattern[str], handler: Callable[..., httpx.Response]
                  ) -> Callable[[httpx.Request], httpx.Response]:
        def reply(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            self.log.append((request.method, path))
            if request.headers.get("Prefer") != IMMUTABLE:
                self.missing_prefer.append(f"{request.method} {path}")
            for override in self._overrides:
                if override.method == method and override.pattern.fullmatch(path) and (
                    override.times is None or override.calls < override.times
                ):
                    override.calls += 1
                    return override.reply(request) if callable(override.reply) else override.reply
            if method != "GET" and self.on_write is not None:
                self.on_write(request)
            match = pattern.fullmatch(path)
            assert match is not None
            return handler(request, *match.groups())

        return reply

    def _box(self, user: str) -> Optional[FakeMailbox]:
        # Graph takes the user principal name or the object id, never an alias.
        return self.mailboxes.get(user) or next((b for b in self.mailboxes.values() if b.id == user), None)

    @staticmethod
    def _no_user() -> httpx.Response:
        return graph_error(404, "ErrorInvalidUser")

    @staticmethod
    def _no_item() -> httpx.Response:
        return graph_error(404, "ErrorItemNotFound")

    def _visible(self, box: FakeMailbox, message: FakeMessage) -> bool:
        return self.recoverable_by_id or message.folder != box.folders["recoverableitemsdeletions"]

    def _moved(self, request: httpx.Request, box: FakeMailbox, message: FakeMessage, folder: str) -> FakeMessage:
        del box.messages[message.id]
        message.previous_folder = message.folder
        message.folder = folder
        if request.headers.get("Prefer") != IMMUTABLE:
            message.id = new_id()
        box.messages[message.id] = message
        return message

    # -- handlers --------------------------------------------------------------

    def _list(self, request: httpx.Request, user: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        match = _IMID.fullmatch(request.url.params.get("$filter", ""))
        if match is None:
            return graph_error(400, "BadRequest")
        wanted = _unquote(match.group(1))
        top = int(request.url.params.get("$top", "10"))
        hits = [m for m in box.messages.values() if m.internet_message_id == wanted
                and m.folder != box.folders["recoverableitemsdeletions"]]
        select = request.url.params.get("$select")
        return httpx.Response(200, json={"value": [m.as_json(select) for m in hits[:top]]})

    def _get(self, request: httpx.Request, user: str, message_id: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        message = box.messages.get(message_id)
        if message is None or not self._visible(box, message):
            return self._no_item()
        return httpx.Response(200, json=message.as_json(request.url.params.get("$select")))

    def _delete(self, request: httpx.Request, user: str, message_id: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        message = box.messages.get(message_id)
        if message is None or message.folder == box.folders["recoverableitemsdeletions"]:
            return self._no_item()
        self._moved(request, box, message, box.folders["recoverableitemsdeletions"])
        return httpx.Response(204)

    def _move(self, request: httpx.Request, user: str, message_id: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        destination = box.folder_id(str(json.loads(request.content).get("destinationId") or ""))
        message = box.messages.get(message_id)
        if destination is None or message is None:
            return self._no_item()
        moved = self._moved(request, box, message, destination)
        return httpx.Response(201, json=moved.as_json())

    def _create(self, request: httpx.Request, user: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        body = json.loads(request.content)
        message = box.add(f"<{uuid.uuid4().hex}@contoso.example>", folder="drafts", sender=user,
                          subject=body.get("subject", ""), is_draft=True)
        message.props = {p["id"]: p["value"] for p in body.get("singleValueExtendedProperties") or []}
        message.to = [r["emailAddress"]["address"] for r in body.get("toRecipients") or []]
        message.body = dict(body.get("body") or {})
        return httpx.Response(201, json=message.as_json())

    def _send(self, request: httpx.Request, user: str, message_id: str) -> httpx.Response:
        box = self._box(user)
        message = box.messages.get(message_id) if box is not None else None
        if box is None or message is None or not message.is_draft:
            return self._no_item()
        del box.messages[message.id]
        message.id = new_id()  # sending a draft gives the sent message a new id
        message.folder = box.folders["sentitems"]
        message.is_draft = False
        message.sent_at = _now()
        box.messages[message.id] = message
        return httpx.Response(202)

    def _folder(self, request: httpx.Request, user: str, folder: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        found = box.folder_id(folder)
        if found is None:
            return self._no_item()
        return httpx.Response(200, json={"id": found})

    def _folder_messages(self, request: httpx.Request, user: str, folder: str) -> httpx.Response:
        box = self._box(user)
        if box is None:
            return self._no_user()
        found = box.folder_id(folder)
        if found is None:
            return self._no_item()
        text = request.url.params.get("$filter", "")
        select = request.url.params.get("$select")
        tag = _TAG.fullmatch(text)
        if tag is not None:
            prop, value = _unquote(tag.group(1)), _unquote(tag.group(2))
            hits = [m for m in box.messages.values() if m.folder == found and m.props.get(prop) == value]
            return httpx.Response(200, json={"value": [m.as_json(select) for m in hits]})
        match = _IMID.fullmatch(text)
        if match is None:
            return graph_error(400, "BadRequest")
        wanted = _unquote(match.group(1))
        stale = self.stale_folder_reads > 0
        if stale:
            self.stale_folder_reads -= 1
        hits = [m for m in box.messages.values() if m.internet_message_id == wanted
                and (m.folder == found or (stale and m.previous_folder == found))]
        return httpx.Response(200, json={"value": [m.as_json(select) for m in hits]})

    def _users(self, request: httpx.Request) -> httpx.Response:
        text = request.url.params.get("$filter", "")
        mail, proxy = _MAIL_EQ.fullmatch(text), _PROXY_EQ.fullmatch(text)
        if mail is not None:
            wanted = _unquote(mail.group(1)).lower()
            hits = [b for b in self.mailboxes.values() if b.mail.lower() == wanted]
        elif proxy is not None:
            prefix, _, wanted = _unquote(proxy.group(1)).partition(":")
            if prefix.lower() != "smtp":
                return httpx.Response(200, json={"value": []})
            hits = [b for b in self.mailboxes.values()
                    if wanted.lower() in {a.lower() for a in (b.mail, *b.proxies)}]
        else:
            return graph_error(400, "Request_UnsupportedQuery")
        return httpx.Response(200, json={"value": [{"id": b.id} for b in hits]})

    def _trace(self, request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("$skiptoken")
        text = request.url.params.get("$filter")
        if token is not None:
            rows = self._trace_pages.pop(token, [])
        elif text is None:  # without a filter: the last 48 hours, $top rows
            rows = self.traces[: int(request.url.params.get("$top", "1000"))]
        else:
            self.trace_filters.append(text)
            match = _TRACE.fullmatch(text)
            if match is None:
                return graph_error(400, "BadRequest")
            wanted, start, end = _unquote(match.group(1)), match.group(2), match.group(3)
            rows = [t for t in self.traces if t["messageId"] == wanted and start <= t["receivedDateTime"] <= end]
        page, rest = rows[: self.trace_page_size], rows[self.trace_page_size:]
        body: Dict[str, Any] = {"value": page}
        if rest:
            next_token = uuid.uuid4().hex
            self._trace_pages[next_token] = rest
            body["@odata.nextLink"] = (
                f"https://{self.fake.profile.graph_host}/v1.0/admin/exchange/tracing/messageTraces?$skiptoken={next_token}"
            )
        return httpx.Response(200, json=body)


__all__ = ["FakeExchange", "FakeMailbox", "FakeMessage", "IMMUTABLE", "new_id"]
