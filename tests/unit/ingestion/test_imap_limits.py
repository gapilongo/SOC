"""The bounded IMAP client against a scripted server on a socket pair: literal, line, response and time limits."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import Callable, List, Optional, Tuple

import pytest

from lg_sotf.ingestion.sources.imap import BoundedIMAP4_SSL, ImapLimitExceeded

Script = Callable[[socket.socket, bytes, Callable[[], None]], None]


class _Client(BoundedIMAP4_SSL):
    """The production class with the TLS connection replaced by one end of a socket pair."""

    def __init__(self, sock: socket.socket, **kwargs: float) -> None:
        self._test_sock = sock
        super().__init__("imap.mail.test", 993, ssl.create_default_context(), float(kwargs.pop("timeout", 5.0)),
                         max_literal=int(kwargs["max_literal"]), lifetime_s=kwargs["lifetime_s"])

    def _create_socket(self, timeout: Optional[float]) -> socket.socket:
        self._test_sock.settimeout(timeout)
        return self._test_sock


class _Server:
    """Greets, answers CAPABILITY, then runs ``script`` for the next command (NOOP in these tests)."""

    def __init__(self, script: Script) -> None:
        self.client, self._server = socket.socketpair()
        self._script = script
        self._done = threading.Event()
        self.errors: List[BaseException] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        conn = self._server
        reader = conn.makefile("rb")
        try:
            conn.sendall(b"* OK IMAP4rev1 ready\r\n")
            tag = reader.readline().split(b" ", 1)[0]
            conn.sendall(b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK done\r\n")
            tag = reader.readline().split(b" ", 1)[0]
            self._script(conn, tag, lambda: self._done.wait(10))
        except OSError:
            pass  # the client gave up and closed its end
        except BaseException as exc:  # noqa: BLE001 - surfaced by the test
            self.errors.append(exc)

    def close(self) -> None:
        self._done.set()
        for sock in (self.client, self._server):
            try:
                sock.shutdown(socket.SHUT_RDWR)  # unblocks a sendall in progress (close alone does not)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._thread.join(timeout=5)


def _run(
    script: Script, *, max_literal: int = 1_000, lifetime_s: float = 30.0, timeout: float = 5.0
) -> Tuple[float, str]:
    """Connect and send NOOP; asserts it failed with ImapLimitExceeded and returns (seconds taken, message)."""
    server = _Server(script)
    start = time.monotonic()
    try:
        with pytest.raises(ImapLimitExceeded) as caught:
            client = _Client(server.client, max_literal=max_literal, lifetime_s=lifetime_s, timeout=timeout)
            client.noop()
        assert not server.errors
        return time.monotonic() - start, str(caught.value)
    finally:
        server.close()


def test_a_literal_within_the_limit_is_read() -> None:
    def script(conn: socket.socket, tag: bytes, hold: Callable[[], None]) -> None:
        conn.sendall(b"* 1 FETCH (BODY[] {5}\r\nhello)\r\n" + tag + b" OK done\r\n")

    server = _Server(script)
    try:
        client = _Client(server.client, max_literal=1_000, lifetime_s=30.0)
        typ, _ = client.noop()
        assert typ == "OK"
        assert client.untagged_responses["FETCH"][0] == (b"1 (BODY[] {5}", b"hello")
    finally:
        server.close()


def test_a_huge_announced_literal_is_refused_before_it_is_read() -> None:
    def script(conn: socket.socket, tag: bytes, hold: Callable[[], None]) -> None:
        # Announces a 4 GiB literal and sends nothing more: imaplib would wait to read (and allocate) it all.
        conn.sendall(b"* 1 FETCH (BODY[] {4294967296}\r\n")
        hold()

    elapsed, error = _run(script)
    assert elapsed < 1.5 and "literal" in error


def test_an_endless_line_is_refused() -> None:
    def script(conn: socket.socket, tag: bytes, hold: Callable[[], None]) -> None:
        conn.sendall(b"* " + b"x" * 1_100_000)
        hold()

    assert "line" in _run(script)[1]


def test_a_response_larger_than_a_literal_plus_slack_is_refused() -> None:
    def script(conn: socket.socket, tag: bytes, hold: Callable[[], None]) -> None:
        line = b"* OK " + b"y" * 100_000 + b"\r\n"
        for _ in range(100):  # about 10 MB of untagged lines, each one within the line limit
            conn.sendall(line)
        hold()

    assert "response" in _run(script)[1]


def test_a_trickling_server_cannot_hold_the_session_past_its_deadline() -> None:
    def script(conn: socket.socket, tag: bytes, hold: Callable[[], None]) -> None:
        conn.sendall(b"* ")
        for _ in range(200):  # one byte every 50 ms: each read succeeds long before the socket timeout
            conn.sendall(b"z")  # raises once the client has given up and the pair is closed
            time.sleep(0.05)

    elapsed, error = _run(script, lifetime_s=1.0, timeout=5.0)
    assert elapsed < 3.0 and "poll_timeout_s" in error
