"""Helpers shared by the evaluation tests."""

from __future__ import annotations

import socket
from typing import Any, List, Set, Tuple
from urllib.parse import urlsplit

import httpx
import pytest

from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.settings import Settings

EVAL_TENANT = "eval-it"


class NetworkGuard:
    """Blocks and records every outbound connection and name lookup except the test database and Redis."""

    def __init__(self, settings: Settings) -> None:
        self.hosts: Set[str] = set()
        self.endpoints: Set[Tuple[str, int]] = set()
        for url in (settings.database.url.get_secret_value(), settings.redis.url.get_secret_value()):
            parts = urlsplit(url)
            host, port = parts.hostname or "localhost", parts.port or 0
            self.hosts.add(host)
            for info in socket.getaddrinfo(host, port):
                self.endpoints.add((str(info[4][0]), port))
                self.hosts.add(str(info[4][0]))
        self.attempts: List[str] = []

    def _allowed(self, address: Any) -> bool:
        return not isinstance(address, tuple) or (str(address[0]), int(address[1])) in self.endpoints

    def _blocked(self, what: str) -> ConnectionRefusedError:
        self.attempts.append(what)
        return ConnectionRefusedError("network blocked in this test")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_connect, real_connect_ex, real_getaddrinfo = (
            socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo,
        )

        def connect(sock: socket.socket, address: Any) -> None:
            if not self._allowed(address):
                raise self._blocked(f"connect {address}")
            real_connect(sock, address)

        def connect_ex(sock: socket.socket, address: Any) -> int:
            if not self._allowed(address):
                raise self._blocked(f"connect {address}")
            return real_connect_ex(sock, address)

        def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            if host not in self.hosts:
                self.attempts.append(f"resolve {host}")
                raise socket.gaierror("name resolution blocked in this test")
            return real_getaddrinfo(host, *args, **kwargs)

        async def no_http(transport: Any, request: httpx.Request) -> httpx.Response:
            self.attempts.append(f"http {request.url.host}")
            raise httpx.ConnectError("network blocked in this test", request=request)

        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", no_http)


def block_network_and_model(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> NetworkGuard:
    guard = NetworkGuard(settings)
    guard.install(monkeypatch)

    def no_model(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a replay must not call the configured model")

    monkeypatch.setattr(FakeChatModel, "with_structured_output", no_model)
    monkeypatch.setattr(FakeChatModel, "_generate", no_model)
    return guard
