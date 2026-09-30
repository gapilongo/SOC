"""Mailbox pull sources against a mocked Microsoft Graph API and a fake IMAP server."""

from __future__ import annotations

import imaplib
import json
import re
import ssl
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import httpx
import pytest

from lg_sotf.ingestion.errors import SourceAuthError, SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, FetchedPage, PullConnector, create_connector
from lg_sotf.ingestion.sources.base import iso
from lg_sotf.ingestion.sources.netpolicy import DestinationRefused
from lg_sotf.settings import Settings
from tests.unit.ingestion._email import build, wrap
from tests.unit.ingestion._support import NOW, FakeClock, MapResolver, make_source, public_resolver

CLIENT_SECRET = "test-" + "x" * 20
PASSWORD = "test-" + "y" * 16


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(ingestion={"page_size": 2, "http_max_retries": 1, "email": {"max_message_bytes": 20_000}})


def connector(
    settings: Settings,
    source_type: str,
    config: Dict[str, Any],
    credentials: Dict[str, Any],
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    imap: Optional[Callable[..., Any]] = None,
    resolver: Any = public_resolver,
) -> PullConnector:
    deps = ConnectorDeps(
        transport=transport, sleep=FakeClock().sleep, now=lambda: NOW, rand=lambda: 0.0, resolver=resolver,
        extra={"imap_factory": imap} if imap else {},
    )
    return create_connector(
        make_source(source_type, config), credentials, settings=settings,
        options=IngestionOptions.from_settings(settings), deps=deps,
    )


async def drain(conn: PullConnector, cursor: Optional[Dict[str, Any]] = None, *, stop_after: int = 99) -> List[FetchedPage]:
    pages: List[FetchedPage] = []
    stream = conn.pages(cursor)
    try:
        async for page in stream:
            pages.append(page)
            if len(pages) >= stop_after:
                break
    finally:
        await stream.aclose()
    return pages


def report(subject: str, reporter: str = "bob@example.com") -> bytes:
    return wrap(build(subject=subject, message_id=f"<{subject.replace(' ', '-')}@partner.test>"), reporter)


# -- Microsoft 365 -------------------------------------------------------------------------

M365 = {"azure_tenant_id": "contoso.example", "mailbox": "phish@example.com"}
M365_CREDS = {"client_id": "app-id", "client_secret": CLIENT_SECRET}


class Graph:
    """A reporting mailbox behind a mocked Graph API; honours isRead filtering and moves."""

    def __init__(self, count: int, *, big: Sequence[str] = ()) -> None:
        self.messages: Dict[str, Dict[str, Any]] = {}
        for i in range(count):
            mid = f"AAMk{i:03d}=="
            self.messages[mid] = {
                "received": NOW - timedelta(minutes=30 - i), "read": False, "folder": "inbox",
                "mime": b"x" * 30_000 if mid in big else report(f"report {i}"),
            }
        self.tokens = 0
        self.requests: List[Tuple[str, str]] = []
        self.patched: List[str] = []
        self.moved: List[Tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path))
        if path.endswith("/oauth2/v2.0/token"):
            self.tokens += 1
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            assert form["scope"] == "https%3A%2F%2Fgraph.microsoft.com%2F.default"
            return httpx.Response(200, json={"access_token": "tok-" + "z" * 10, "expires_in": 3600})
        assert request.headers["Authorization"].startswith("Bearer tok-")
        base = "/v1.0/users/phish@example.com"  # httpx decodes the percent-encoded path
        if path == f"{base}/mailFolders/inbox/messages":
            flt = request.url.params["$filter"]
            unread_only = "isRead eq false" in flt
            since = flt.split("receivedDateTime ge ", 1)[1].split(" ", 1)[0]
            rows = sorted(
                (m for m in self.messages.items() if m[1]["folder"] == "inbox"
                 and (not unread_only or not m[1]["read"]) and iso(m[1]["received"]) >= since),
                key=lambda kv: kv[1]["received"],
            )[: int(request.url.params["$top"])]
            value = [{"id": k, "receivedDateTime": iso(v["received"]), "subject": "s",
                      "from": {"emailAddress": {"address": "bob@example.com"}}} for k, v in rows]
            return httpx.Response(200, json={"value": value, "@odata.nextLink": "https://graph.microsoft.com/next"})
        match = re.match(rf"{re.escape(base)}/messages/([^/]+)(/\$value|/move)?$", path)
        if match:
            mid = match.group(1)
            if mid not in self.messages:
                return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})
            if match.group(2) == "/$value":
                return httpx.Response(200, content=self.messages[mid]["mime"])
            if match.group(2) == "/move":
                self.moved.append((mid, json.loads(request.content)["destinationId"]))
                self.messages[mid]["folder"] = "processed"
                return httpx.Response(201, json={"id": "new-" + mid})
            assert request.method == "PATCH" and json.loads(request.content) == {"isRead": True}
            self.patched.append(mid)
            self.messages[mid]["read"] = True
            return httpx.Response(200, json={})
        if path == f"{base}/mailFolders/inbox":
            return httpx.Response(200, json={"id": "inbox-id", "displayName": "Inbox"})
        return httpx.Response(404)


async def test_m365_reads_marks_read_and_keeps_a_cursor(settings: Settings) -> None:
    graph = Graph(3)
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(graph))
    pages = await drain(conn)
    assert [len(p.events) for p in pages] == [2, 1]
    event = pages[0].events[0]
    assert event["schema"] == "lgsotf.email.v1" and event["subject"] == "report 0"
    assert event["report"]["reporter"] == "bob@example.com"
    assert event["transport"] == {"source": "m365_mailbox", "mailbox_message_id": "AAMk000=="}
    assert event["received_at"] == iso(NOW - timedelta(minutes=30))
    assert pages[0].cursor["ack"] == ["AAMk000==", "AAMk001=="]
    assert graph.patched == ["AAMk000==", "AAMk001==", "AAMk002=="]
    assert pages[-1].cursor["since"] == iso(NOW - timedelta(minutes=28))
    # The skip token is never followed (acknowledging a page changes the result set).
    assert all("/next" not in path for _, path in graph.requests)
    assert graph.tokens == 1
    await conn.aclose()


async def test_m365_finishes_an_interrupted_acknowledgement_first(settings: Settings) -> None:
    graph = Graph(1)
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(graph))
    cursor = {"v": 1, "since": iso(NOW - timedelta(hours=1)), "ack": ["AAMk000==", "gone-id"]}
    pages = await drain(conn, cursor)
    assert graph.patched[0] == "AAMk000=="  # the 404 for gone-id is ignored
    assert pages == [FetchedPage([], {"v": 1, "since": iso(NOW - timedelta(hours=1))}, NOW - timedelta(hours=1))]


async def test_m365_move_mode(settings: Settings) -> None:
    graph = Graph(2)
    config = {**M365, "after_processing": "move", "processed_folder": "AQMkProcessed"}
    conn = connector(settings, "m365_mailbox", config, M365_CREDS, transport=httpx.MockTransport(graph))
    await drain(conn)
    assert graph.moved == [("AAMk000==", "AQMkProcessed"), ("AAMk001==", "AQMkProcessed")]
    assert graph.patched == []


async def test_m365_oversized_message_still_becomes_an_alert(settings: Settings) -> None:
    graph = Graph(1, big=["AAMk000=="])
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(graph))
    pages = await drain(conn)
    event = pages[0].events[0]
    assert event["parse_error"] == "message is larger than 20000 bytes"
    assert event["report"]["reporter"] == "bob@example.com" and event["dedup_key"].startswith("email:m365:")


async def test_m365_first_poll_without_mail_persists_its_start(settings: Settings) -> None:
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(Graph(0)))
    pages = await drain(conn)
    assert len(pages) == 1 and pages[0].events == [] and pages[0].cursor["since"] == iso(NOW - timedelta(hours=1))
    assert await drain(connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(Graph(0))),
                       pages[0].cursor) == []


async def test_m365_health_check(settings: Settings) -> None:
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, transport=httpx.MockTransport(Graph(0)))
    health = await conn.test()
    assert health.ok and "Inbox" in health.detail


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"mailbox": "phish@example.com"}, "azure_tenant_id"),
        ({**M365, "mailbox": "not an address"}, "mailbox"),
        ({**M365, "folder": "in box"}, "folder"),
        ({**M365, "after_processing": "delete"}, "after_processing"),
        ({**M365, "after_processing": "move"}, "processed_folder"),
        ({**M365, "trusted_relays": ["not-a-cidr"]}, "trusted_relays"),
    ],
)
def test_m365_config_validation(settings: Settings, config: Dict[str, Any], message: str) -> None:
    with pytest.raises(SourceConfigError, match=message):
        connector(settings, "m365_mailbox", config, M365_CREDS)


def test_m365_requires_the_client_secret(settings: Settings) -> None:
    with pytest.raises(SourceConfigError, match="client_secret"):
        connector(settings, "m365_mailbox", M365, {"client_id": "app-id"})


async def test_m365_destinations_go_through_the_policy(settings: Settings) -> None:
    resolver = MapResolver({"login.microsoftonline.com": ["169.254.169.254"]})
    conn = connector(settings, "m365_mailbox", M365, M365_CREDS, resolver=resolver)
    with pytest.raises(DestinationRefused):
        await conn.check_destinations()


# -- IMAP ------------------------------------------------------------------------------------

IMAP = {"host": "imap.mail.test", "folder": "Phish Reports"}
IMAP_CREDS = {"username": "phish@example.com", "password": PASSWORD}


class FakeImap:
    """An imaplib.IMAP4_SSL stand-in holding one mailbox of reports."""

    instances: List[FakeImap] = []

    def __init__(self, messages: Dict[int, bytes], *, uidvalidity: int = 7, capabilities: Sequence[str] = ("IMAP4REV1", "MOVE"),
                 password: str = PASSWORD) -> None:
        self.messages = dict(messages)
        self.uidvalidity = uidvalidity
        self.capabilities = tuple(capabilities)
        self.password = password
        self.commands: List[Tuple[Any, ...]] = []
        self.flags: Dict[int, List[str]] = {}
        self.connected: Optional[Tuple[str, str, int]] = None
        self.logged_out = False

    def factory(self, host: str, address: str, port: int, context: ssl.SSLContext, timeout: float) -> FakeImap:
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname and timeout > 0
        self.connected = (host, address, port)
        return self

    def login(self, user: str, password: str) -> Tuple[str, List[bytes]]:
        if password != self.password:
            raise imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Invalid credentials")
        return "OK", [b"logged in"]

    def select(self, mailbox: str, readonly: bool = False) -> Tuple[str, List[bytes]]:
        self.commands.append(("SELECT", mailbox, readonly))
        return "OK", [str(len(self.messages)).encode()]

    def response(self, code: str) -> Tuple[str, List[Optional[bytes]]]:
        return code, [str(self.uidvalidity).encode()]

    def uid(self, command: str, *args: Any) -> Tuple[str, List[Any]]:
        self.commands.append((command, *args))
        if command == "SEARCH":
            if args[1] == "UID":
                low = int(args[2].split(":")[0])
                found = [u for u in self.messages if u >= low] or [max(self.messages, default=0)]
            else:
                found = list(self.messages)
            return "OK", [" ".join(str(u) for u in sorted(found) if u).encode()]
        if command == "FETCH":
            uids = [int(u) for u in args[0].split(",")]
            if "RFC822.SIZE" in args[1]:
                return "OK", [
                    f'{i} (UID {u} RFC822.SIZE {len(self.messages[u])} INTERNALDATE "28-Sep-2026 09:30:00 +0000")'.encode()
                    for i, u in enumerate(uids, 1) if u in self.messages
                ]
            cap = int(re.search(r"<0\.(\d+)>", args[1]).group(1))  # type: ignore[union-attr]
            u = uids[0]
            return "OK", [(f"1 (UID {u} BODY[]<0> {{{min(cap, len(self.messages[u]))}}}".encode(), self.messages[u][:cap]), b")"]
        if command == "STORE":
            for u in args[0].split(","):
                self.flags.setdefault(int(u), []).append(args[2])
            return "OK", [None]
        if command in ("MOVE", "COPY", "EXPUNGE"):
            if command == "MOVE":
                for u in args[0].split(","):
                    self.messages.pop(int(u), None)
            return "OK", [None]
        raise AssertionError(command)

    def expunge(self) -> Tuple[str, List[Any]]:
        self.commands.append(("EXPUNGE",))
        return "OK", [None]

    def logout(self) -> Tuple[str, List[bytes]]:
        self.logged_out = True
        return "BYE", [b""]


async def test_imap_reads_by_uid_marks_seen_and_pins_the_checked_address(settings: Settings) -> None:
    server = FakeImap({3: report("r3"), 5: report("r5"), 9: report("r9")})
    conn = connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory)
    pages = await drain(conn)
    assert server.connected == ("imap.mail.test", "93.184.216.34", 993)
    assert ("SELECT", '"Phish Reports"', False) in server.commands
    assert [[e["subject"] for e in p.events] for p in pages] == [["r3", "r5"], ["r9"]]
    assert pages[-1].cursor == {"v": 1, "uidvalidity": 7, "last_uid": 9, "ack": [9]}
    assert pages[0].events[0]["transport"] == {"source": "imap", "uidvalidity": 7, "uid": 3}
    assert pages[0].events[0]["received_at"] == "2026-09-28T09:30:00Z"
    assert server.flags == {3: ["(\\Seen)"], 5: ["(\\Seen)"], 9: ["(\\Seen)"]}
    assert server.logged_out
    # Next poll: only UIDs above the cursor; the "N:*" quirk returning the last UID is ignored.
    again = await drain(connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory), pages[-1].cursor)
    assert again == [FetchedPage([], {"v": 1, "uidvalidity": 7, "last_uid": 9, "ack": []}, NOW)]


async def test_imap_uidvalidity_change_restarts_from_the_lookback(settings: Settings) -> None:
    server = FakeImap({1: report("r1")}, uidvalidity=8)
    pages = await drain(connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory),
                        {"v": 1, "uidvalidity": 7, "last_uid": 50, "ack": [49]})
    assert [e["subject"] for e in pages[0].events] == ["r1"]
    assert any(c[0] == "SEARCH" and "SINCE" in c for c in server.commands)
    assert not any(c[0] == "STORE" and c[1] == "49" for c in server.commands)


async def test_imap_move_with_and_without_the_move_extension(settings: Settings) -> None:
    config = {**IMAP, "after_processing": "move", "processed_folder": "Processed"}
    server = FakeImap({1: report("r1")})
    await drain(connector(settings, "imap", config, IMAP_CREDS, imap=server.factory))
    assert ("MOVE", "1", '"Processed"') in server.commands
    legacy = FakeImap({1: report("r1")}, capabilities=("IMAP4REV1",))
    await drain(connector(settings, "imap", config, IMAP_CREDS, imap=legacy.factory))
    names = [c[0] for c in legacy.commands]
    assert names[-3:] == ["COPY", "STORE", "EXPUNGE"] and legacy.flags[1] == ["(\\Deleted)"]


async def test_imap_oversized_message_is_not_downloaded(settings: Settings) -> None:
    server = FakeImap({1: b"x" * 30_000})
    pages = await drain(connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory))
    assert pages[0].events[0]["parse_error"] == "message is larger than 20000 bytes"
    assert not any(c[0] == "FETCH" and "BODY.PEEK" in c[2] for c in server.commands)


async def test_imap_rejected_credentials(settings: Settings) -> None:
    server = FakeImap({}, password="other-" + "q" * 10)
    with pytest.raises(SourceAuthError):
        await drain(connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory))
    assert server.logged_out


async def test_imap_refuses_forbidden_destinations(settings: Settings) -> None:
    server = FakeImap({})
    for address in ("127.0.0.1", "169.254.169.254", "10.0.0.8"):
        conn = connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory,
                         resolver=MapResolver({"imap.mail.test": [address]}))
        with pytest.raises(DestinationRefused):
            await conn.check_destinations()
        with pytest.raises(DestinationRefused):
            await drain(conn)
    assert server.connected is None


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"folder": "INBOX"}, "host"),
        ({**IMAP, "host": "bad host"}, "host"),
        ({**IMAP, "port": 0}, "port"),
        ({**IMAP, "folder": "Ünicode"}, "folder"),
        ({**IMAP, "tls_verify": False}, "TLS"),
        ({**IMAP, "after_processing": "move"}, "processed_folder"),
    ],
)
def test_imap_config_validation(settings: Settings, config: Dict[str, Any], message: str) -> None:
    with pytest.raises(SourceConfigError, match=message):
        connector(settings, "imap", config, IMAP_CREDS)


async def test_imap_health_check(settings: Settings) -> None:
    server = FakeImap({1: report("r1"), 2: report("r2")})
    health = await connector(settings, "imap", IMAP, IMAP_CREDS, imap=server.factory).test()
    assert health.ok and "2 messages" in health.detail
    assert ("SELECT", '"Phish Reports"', True) in server.commands
