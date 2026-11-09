"""Helpers shared by the evaluation tests."""

from __future__ import annotations

import dataclasses
import socket
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlsplit

import httpx
import pytest

from lg_sotf.eval.dataset import Dataset
from lg_sotf.eval.results import ItemResult
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


def at_tier(dataset: Dataset, tier: str) -> Dataset:
    """``dataset`` with its evaluation tenants at the model-led closure ``tier`` (FIX-1)."""
    tenant_settings = {**dict(dataset.meta.get("tenant_settings") or {}), "ai_closure": {"tier": tier}}
    return dataclasses.replace(dataset, meta={**dataset.meta, "tenant_settings": tenant_settings})


def closures(results: List[ItemResult]) -> Dict[str, int]:
    """Items automation closed, by label, and how many of them the models closed alone (``model_closed``)."""
    closed = [r for r in results if r.status == "closed"]
    return {
        "benign_closed": sum(r.expected == "benign" for r in closed),
        "malicious_closed": sum(r.expected == "malicious" for r in closed),
        "benign_model_closed": sum(r.expected == "benign" and r.decision_code == "model_closed" for r in closed),
        "malicious_model_closed": sum(r.expected == "malicious" and r.decision_code == "model_closed" for r in closed),
    }
