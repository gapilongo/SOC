"""IMAP reported-phish mailbox (Google Workspace, generic IMAP servers) with the stdlib ``imaplib``.

Config:

``host``             IMAP server name (``imap.gmail.com`` for Google Workspace)
``port``             default 993; IMAPS (implicit TLS) only, certificates always verified
``folder``           mailbox to read, default ``INBOX``
``after_processing`` ``mark_read`` (default) or ``move``
``processed_folder`` mailbox to move processed messages to (``move`` only)
``initial_lookback_s`` how far back the first poll reads (default 3600)
``trusted_relays``   CIDRs of your own mail relays, skipped when choosing the relay IP
``ca_cert_pem``      extra CA certificate (PEM) for servers with a private CA
``poll_timeout_s``   wall-clock limit of one poll's IMAP session (default 900)

Credentials: ``username`` and ``password`` (for Google Workspace an app
password of a dedicated reporting account, see ``docs/phishing.md``).

Security: before connecting, the host is resolved and every address checked
against the destination policy (the same one HTTP sources use); the socket
is then opened to the checked address, with the configured name kept for
SNI and certificate verification, so a DNS answer that changes in between
cannot redirect the connection. TLS verification cannot be switched off.
Every socket operation has a timeout; connecting is retried with backoff.
What the server sends is bounded too: a literal (``{n}``) larger than
``max_message_bytes`` plus a small slack, a line longer than 1 MB or a
response larger than a literal plus 8 MiB ends the poll before it is read,
and the whole session is limited to ``poll_timeout_s`` (checked before every
socket read, so a server that trickles bytes cannot hold a poll open).

Cursor: ``{"uidvalidity", "last_uid", "ack"}``. Messages are read by UID
above ``last_uid`` (the first poll, or a changed UIDVALIDITY, starts from
``initial_lookback_s`` with ``SEARCH SINCE``). Sizes are checked with
``RFC822.SIZE`` first and bodies fetched with a partial fetch bounded by
``ingestion.email.max_message_bytes``; an oversized or unparsable message
still becomes an alert (flagged ``email_unparsed``). After a page's alerts
are committed its messages are marked ``\\Seen`` or moved (``UID MOVE``, or
copy, flag ``\\Deleted`` and expunge where MOVE is not supported); the UIDs
also travel in the cursor so an interrupted acknowledgement is finished on
the next poll.

``imaplib`` is blocking: every call runs in a worker thread.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import imaplib
import io
import re
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any, AsyncGenerator, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, cast

from lg_sotf.ingestion.email import EmailLimits, EmailParseError, parse_email, unparsed_email
from lg_sotf.ingestion.email.auth import IPNetwork, parse_networks
from lg_sotf.ingestion.errors import (
    SourceAuthError,
    SourceConfigError,
    SourceProtocolError,
    SourceUnavailable,
)
from lg_sotf.ingestion.sources.base import CURSOR_VERSION, FetchedPage, PullConnector, SourceHealth
from lg_sotf.ingestion.sources.http import build_verify
from lg_sotf.ingestion.sources.netpolicy import system_resolve

DEFAULT_PORT = 993
DEFAULT_POLL_TIMEOUT_S = 900.0
MAX_POLL_TIMEOUT_S = 3_600.0
# imaplib's own line cap: SEARCH answers listing many UIDs are single long lines.
MAX_LINE_BYTES = 1_000_000
LITERAL_SLACK_BYTES = 64 * 1024
RESPONSE_SLACK_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
AFTER_PROCESSING = ("mark_read", "move")
MAX_ACK_UIDS = 1_000
MAX_SEARCH_UIDS = 100_000
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_MAILBOX_NAME = re.compile(r"^[A-Za-z0-9 _./\[\]&+,()-]{1,200}$")
_SIZE_RE = re.compile(rb"RFC822\.SIZE\s+(\d+)", re.IGNORECASE)
_UID_RE = re.compile(rb"UID\s+(\d+)", re.IGNORECASE)
_INTERNALDATE_RE = re.compile(rb'INTERNALDATE\s+"([^"]+)"', re.IGNORECASE)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# (host, address, port, ssl_context, timeout, *, max_literal, lifetime_s) -> an imaplib.IMAP4-like session
ImapFactory = Callable[..., Any]


class ImapLimitExceeded(imaplib.IMAP4.abort):
    """The server sent more than a poll reads, or the session ran past its deadline (the session is unusable)."""


class BoundedIMAP4_SSL(imaplib.IMAP4_SSL):
    """``imaplib.IMAP4_SSL`` that bounds what it reads from the server.

    ``imaplib`` reads whatever literal size the server announces and has no
    overall deadline. Here a literal above ``max_literal`` is refused before
    it is read, every command's response is capped, and every socket read is
    preceded by a deadline check (with the socket timeout lowered to the time
    left), so the whole session ends within ``lifetime_s`` plus one read.
    """

    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext, timeout: float, *,
                 max_literal: int, lifetime_s: float):
        self._io_timeout = timeout
        self._max_literal = max_literal
        self._max_response = max_literal + RESPONSE_SLACK_BYTES
        self._deadline = time.monotonic() + lifetime_s
        self._received = 0
        self._limit_error: Optional[str] = None
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _command(self, name: str, *args: Any) -> Any:
        self._received = 0
        return super()._command(name, *args)  # type: ignore[misc]

    def _command_complete(self, name: str, tag: Any) -> Any:
        try:
            return super()._command_complete(name, tag)  # type: ignore[misc]
        except self.abort:
            # imaplib re-raises every abort as a plain one; keep the limit's own type and message.
            if self._limit_error is not None:
                raise ImapLimitExceeded(self._limit_error) from None
            raise

    def _exceeded(self, message: str) -> ImapLimitExceeded:
        self._limit_error = message
        return ImapLimitExceeded(message)

    def _before_read(self) -> None:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise self._exceeded("imap session ran past poll_timeout_s")
        self.sock.settimeout(min(self._io_timeout, left))

    def _count(self, size: int) -> None:
        self._received += size
        if self._received > self._max_response:
            raise self._exceeded("imap server response is larger than allowed")

    def _reader(self) -> io.BufferedReader:
        return cast(io.BufferedReader, self.file)  # socket.makefile("rb")

    def _timed(self, fn: Callable[[int], bytes], size: int) -> bytes:
        try:
            return fn(size)
        except TimeoutError:
            # The socket timeout was lowered to the time left: report the deadline, not a slow read.
            if time.monotonic() >= self._deadline:
                raise self._exceeded("imap session ran past poll_timeout_s") from None
            raise

    def read(self, size: int) -> bytes:
        if size > self._max_literal:
            raise self._exceeded("imap server announced a literal larger than allowed")
        self._count(size)
        chunks: List[bytes] = []
        while size > 0:
            self._before_read()
            chunk = self._timed(self._reader().read1, min(size, READ_CHUNK_BYTES))
            if not chunk:
                break
            chunks.append(chunk)
            size -= len(chunk)
        return b"".join(chunks)

    def readline(self) -> bytes:
        chunks: List[bytes] = []
        total = 0
        while True:
            self._before_read()
            buffered = self._timed(self._reader().peek, 1)  # at most one socket read
            if not buffered:
                break
            end = buffered.find(b"\n")
            chunk = self._reader().read(len(buffered) if end < 0 else end + 1)  # served from the buffer
            chunks.append(chunk)
            total += len(chunk)
            self._count(len(chunk))
            if total > MAX_LINE_BYTES:
                raise self._exceeded("imap server sent a line longer than allowed")
            if end >= 0:
                break
        return b"".join(chunks)


class _PinnedIMAP4_SSL(BoundedIMAP4_SSL):
    """IMAPS to an already-checked address; ``host`` stays the name used for SNI and certificate checks."""

    def __init__(self, host: str, address: str, port: int, ssl_context: ssl.SSLContext, timeout: float, *,
                 max_literal: int, lifetime_s: float):
        self._pinned_address = address
        super().__init__(host, port, ssl_context, timeout, max_literal=max_literal, lifetime_s=lifetime_s)

    def _create_socket(self, timeout: Optional[float]) -> socket.socket:
        sock = socket.create_connection((self._pinned_address, self.port), timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def default_factory(host: str, address: str, port: int, context: ssl.SSLContext, timeout: float, *,
                    max_literal: int, lifetime_s: float) -> Any:
    return _PinnedIMAP4_SSL(host, address, port, context, timeout, max_literal=max_literal, lifetime_s=lifetime_s)


def quote_mailbox(name: str) -> str:
    """An IMAP quoted string for a mailbox name (names are restricted to printable ASCII)."""
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def imap_date(value: datetime) -> str:
    """``SEARCH SINCE`` date (``05-Mar-2024``), locale independent."""
    return f"{value.day:02d}-{_MONTHS[value.month - 1]}-{value.year}"


def uid_set(uids: Sequence[int]) -> str:
    return ",".join(str(u) for u in uids)


def _ok(typ: Any, what: str) -> None:
    if typ != "OK":
        raise SourceProtocolError(f"imap {what} failed")


class ImapConnector(PullConnector):
    source_type = "imap"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._host = self.config_str("host")
        if not _HOST.match(self._host):
            raise SourceConfigError("imap config.host must be a host name")
        port = self.config.get("port", DEFAULT_PORT)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise SourceConfigError("imap config.port must be a port number")
        self._port = port
        self._folder = self.config_str("folder", "INBOX")
        if not _MAILBOX_NAME.match(self._folder):
            raise SourceConfigError("imap config.folder must be a printable ASCII mailbox name")
        self._after = self.config_str("after_processing", "mark_read")
        if self._after not in AFTER_PROCESSING:
            raise SourceConfigError(f"imap config.after_processing must be one of {', '.join(AFTER_PROCESSING)}")
        self._processed: Optional[str] = None
        if self._after == "move":
            self._processed = self.config_str("processed_folder")
            if not _MAILBOX_NAME.match(self._processed) or self._processed == self._folder:
                raise SourceConfigError("imap config.processed_folder must be a mailbox name other than folder")
        verify = build_verify(self.config, production=self.settings.is_production)
        if verify is False:
            raise SourceConfigError("imap sources always verify TLS certificates (use ca_cert_pem for a private CA)")
        self._ssl = verify if isinstance(verify, ssl.SSLContext) else ssl.create_default_context()
        try:
            self._trusted: List[IPNetwork] = parse_networks(self.config.get("trusted_relays"))
        except ValueError as exc:
            raise SourceConfigError(f"imap config.trusted_relays {exc}") from exc
        try:
            self._limits = EmailLimits.from_settings(self.settings.ingestion)
        except ValueError as exc:
            raise SourceConfigError(str(exc)) from exc
        poll_timeout = self.config.get("poll_timeout_s", DEFAULT_POLL_TIMEOUT_S)
        if (isinstance(poll_timeout, bool) or not isinstance(poll_timeout, (int, float))
                or not 10 <= poll_timeout <= MAX_POLL_TIMEOUT_S):
            raise SourceConfigError(f"imap config.poll_timeout_s must be between 10 and {int(MAX_POLL_TIMEOUT_S)}")
        self._poll_timeout = float(poll_timeout)
        self._deadline: Optional[float] = None
        self._username = self.credential("username")
        self._password = self.credential("password")
        factory = self.deps.extra.get("imap_factory")
        self._factory: ImapFactory = factory if callable(factory) else default_factory

    # -- connection --------------------------------------------------------------

    async def check_destinations(self) -> None:
        resolver = self.deps.resolver or system_resolve
        await self.policy.resolve_allowed(self._host, self._port, resolver)

    async def _call(self, fn: Callable[..., Any], *args: Any) -> Any:
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise SourceUnavailable("imap poll ran past poll_timeout_s")
        try:
            return await asyncio.to_thread(fn, *args)
        except ImapLimitExceeded as exc:
            raise SourceProtocolError(str(exc)) from exc
        except imaplib.IMAP4.abort as exc:
            raise SourceUnavailable("imap connection was lost") from exc
        except imaplib.IMAP4.error as exc:
            raise SourceProtocolError(f"imap command failed ({type(exc).__name__})") from exc
        except (OSError, EOFError) as exc:
            raise SourceUnavailable(f"imap server did not respond ({type(exc).__name__})") from exc

    async def _connect(self) -> Any:
        resolver = self.deps.resolver or system_resolve
        address = await self.policy.resolve_allowed(self._host, self._port, resolver)
        timeout = self.options.http_timeout_s
        self._deadline = time.monotonic() + self._poll_timeout
        limits = {
            "max_literal": self._limits.max_message_bytes + LITERAL_SLACK_BYTES,
            "lifetime_s": self._poll_timeout,
        }
        attempt = 0
        while True:
            try:
                session = await asyncio.to_thread(
                    functools.partial(self._factory, self._host, address, self._port, self._ssl, timeout, **limits)
                )
                break
            except (OSError, EOFError, imaplib.IMAP4.error) as exc:
                if attempt >= self.options.http_max_retries:
                    raise SourceUnavailable(f"imap connection failed after {attempt + 1} attempts "
                                            f"({type(exc).__name__})") from exc
                delay = min(self.options.http_backoff_max_s, self.options.http_backoff_base_s * (2**attempt))
                await self.deps.sleep(delay)
                attempt += 1
        try:
            await asyncio.to_thread(session.login, self._username, self._password)
        except imaplib.IMAP4.error as exc:
            await self._logout(session)
            raise SourceAuthError("imap server rejected the credentials") from exc
        except (OSError, EOFError) as exc:
            await self._logout(session)
            raise SourceUnavailable(f"imap login failed ({type(exc).__name__})") from exc
        return session

    async def _logout(self, session: Any) -> None:
        try:
            await asyncio.to_thread(session.logout)
        except (OSError, EOFError, imaplib.IMAP4.error):
            # LOGOUT failed (for example past the deadline): still close the socket.
            shutdown = getattr(session, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except OSError:
                    pass

    async def _select(self, session: Any, readonly: bool) -> Tuple[int, int]:
        """(UIDVALIDITY, message count) of the configured folder."""
        typ, data = await self._call(session.select, quote_mailbox(self._folder), readonly)
        _ok(typ, "SELECT")
        typ, validity = await self._call(session.response, "UIDVALIDITY")
        values = [v for v in (validity or []) if v]
        if not values:
            raise SourceProtocolError("imap server sent no UIDVALIDITY")
        try:
            uidvalidity = int(values[-1])
            count = int(data[0]) if data and data[0] else 0
        except (TypeError, ValueError) as exc:
            raise SourceProtocolError("imap SELECT response is malformed") from exc
        return uidvalidity, count

    async def test(self) -> SourceHealth:
        session = await self._connect()
        try:
            _, count = await self._select(session, True)
        finally:
            await self._logout(session)
        return SourceHealth(True, f"read mailbox {self._folder} ({count} messages)")

    # -- reading -----------------------------------------------------------------

    async def _search(self, session: Any, last_uid: int, since: Optional[datetime]) -> List[int]:
        if since is not None:
            typ, data = await self._call(session.uid, "SEARCH", None, "SINCE", imap_date(since))
        else:
            typ, data = await self._call(session.uid, "SEARCH", None, "UID", f"{last_uid + 1}:*")
        _ok(typ, "SEARCH")
        uids: List[int] = []
        for chunk in data or []:
            if isinstance(chunk, bytes):
                uids.extend(int(t) for t in chunk.split()[:MAX_SEARCH_UIDS] if t.isdigit())
        # "N:*" always returns the highest UID, even when it is below N.
        return sorted(u for u in set(uids) if u > last_uid)

    async def _sizes(self, session: Any, uids: Sequence[int]) -> Dict[int, Tuple[int, Optional[datetime]]]:
        typ, data = await self._call(session.uid, "FETCH", uid_set(uids), "(UID RFC822.SIZE INTERNALDATE)")
        _ok(typ, "FETCH")
        out: Dict[int, Tuple[int, Optional[datetime]]] = {}
        for item in data or []:
            line = item[0] if isinstance(item, tuple) else item
            if not isinstance(line, bytes):
                continue
            uid, size = _UID_RE.search(line), _SIZE_RE.search(line)
            if uid and size:
                date = _INTERNALDATE_RE.search(line)
                out[int(uid.group(1))] = (int(size.group(1)), _internaldate(date.group(1)) if date else None)
        return out

    async def _body(self, session: Any, uid: int) -> Optional[bytes]:
        cap = self._limits.max_message_bytes
        typ, data = await self._call(session.uid, "FETCH", str(uid), f"(BODY.PEEK[]<0.{cap + 1}>)")
        _ok(typ, "FETCH")
        for item in data or []:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return item[1]
        return None

    async def _ack(self, session: Any, uids: Sequence[int]) -> None:
        if not uids:
            return
        targets = uid_set(uids)
        if self._after == "mark_read":
            typ, _ = await self._call(session.uid, "STORE", targets, "+FLAGS.SILENT", r"(\Seen)")
            _ok(typ, "STORE")
            return
        assert self._processed is not None
        folder = quote_mailbox(self._processed)
        capabilities = {str(c).upper() for c in getattr(session, "capabilities", ())}
        if "MOVE" in capabilities:
            typ, _ = await self._call(session.uid, "MOVE", targets, folder)
            _ok(typ, "MOVE")
            return
        typ, _ = await self._call(session.uid, "COPY", targets, folder)
        _ok(typ, "COPY")
        typ, _ = await self._call(session.uid, "STORE", targets, "+FLAGS.SILENT", r"(\Deleted)")
        _ok(typ, "STORE")
        if "UIDPLUS" in capabilities:
            typ, _ = await self._call(session.uid, "EXPUNGE", targets)
        else:
            typ, _ = await self._call(session.expunge)
        _ok(typ, "EXPUNGE")

    async def _event(self, uidvalidity: int, uid: int, data: Optional[bytes], error: Optional[str],
                     received: Optional[datetime]) -> Dict[str, Any]:
        transport = {"source": self.source_type, "uidvalidity": uidvalidity, "uid": uid}
        if data is not None and error is None:
            try:
                # CPU-bound on untrusted input: off the event loop, like the push path.
                return await asyncio.to_thread(
                    parse_email, data, limits=self._limits, received_at=received, trusted_relays=self._trusted, transport=transport
                )
            except EmailParseError as exc:
                error = str(exc)
        key = hashlib.sha256(f"{self.source.id}\x00{uidvalidity}\x00{uid}".encode()).hexdigest()
        return unparsed_email(
            error or "message could not be read", dedup_key=f"email:imap:{key}", received_at=received, transport=transport
        )

    async def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        session = await self._connect()
        try:
            uidvalidity, _ = await self._select(session, False)
            state = cursor or {}
            same = state.get("uidvalidity") == uidvalidity
            last_uid = state.get("last_uid") if same else None
            if isinstance(last_uid, bool) or not isinstance(last_uid, int) or last_uid < 0:
                last_uid = None
            pending = [u for u in (state.get("ack") or []) if isinstance(u, int) and not isinstance(u, bool)]
            if same and pending:
                await self._ack(session, pending[:MAX_ACK_UIDS])
            since = self.initial_since() if last_uid is None else None
            uids = await self._search(session, last_uid or 0, since)
            start = last_uid or 0
            if not uids:
                if last_uid is None or pending:
                    yield FetchedPage([], _cursor(uidvalidity, start, []), self.deps.now())
                return
            size = self.options.page_size
            for offset in range(0, len(uids), size):
                chunk = uids[offset : offset + size]
                facts = await self._sizes(session, chunk)
                events: List[Dict[str, Any]] = []
                for uid in chunk:
                    length, received = facts.get(uid, (0, None))
                    too_large = f"message is larger than {self._limits.max_message_bytes} bytes"
                    if length > self._limits.max_message_bytes:
                        events.append(await self._event(uidvalidity, uid, None, too_large, received))
                        continue
                    body = await self._body(session, uid)
                    error: Optional[str] = None
                    if body is None:
                        error = "message body was not returned"
                    elif len(body) > self._limits.max_message_bytes:
                        body, error = None, too_large
                    events.append(await self._event(uidvalidity, uid, body, error, received))
                yield FetchedPage(events, _cursor(uidvalidity, chunk[-1], chunk), self.deps.now())
                # The page is committed: acknowledge its messages.
                await self._ack(session, chunk)
        finally:
            await self._logout(session)


def _cursor(uidvalidity: int, last_uid: int, ack: Sequence[int]) -> Dict[str, Any]:
    return {"v": CURSOR_VERSION, "uidvalidity": uidvalidity, "last_uid": last_uid, "ack": list(ack)}


def _internaldate(value: bytes) -> Optional[datetime]:
    """``INTERNALDATE`` (``05-Mar-2024 10:15:30 +0000``) as UTC."""
    try:
        parsed = datetime.strptime(value.decode("ascii").strip(), "%d-%b-%Y %H:%M:%S %z")
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed.astimezone(UTC)
