"""Integrations tests: real Postgres (outbox, RLS) with receivers stubbed by ``httpx.MockTransport``."""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx
import pytest

from lg_sotf.db.repos import Integration, Repositories
from lg_sotf.integrations.config import encrypt_secret
from lg_sotf.integrations.delivery import OutboxDelivery
from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from tests.integration.api.conftest import api, api_settings, make_api  # noqa: F401 - API fixtures for test_api.py

PUBLIC_IP = "93.184.216.34"


async def public_resolver(host: str, port: int) -> List[str]:
    return [PUBLIC_IP]


async def no_sleep(_: float) -> None:
    return None


def fake_secret(label: str = "secret") -> str:
    return f"test-{label}-" + "x" * 24


def slack_url() -> str:
    return "https://hooks.slack.com/services/" + "/".join(["T" + "1" * 8, "B" + "1" * 8, "y" * 24])


@pytest.fixture
def integ_settings(
    make_settings: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> Callable[..., Settings]:
    def build(**overrides: Any) -> Settings:
        base: Dict[str, Any] = {
            "database": {"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            "redis": {"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            "api": {"public_url": "https://soc.example.com"},
            "integrations": {"backoff_base_s": 5.0, "backoff_max_s": 60.0, "max_attempts": 3},
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return make_settings(**base)

    return build


@pytest.fixture
def box(make_settings: Callable[..., Settings]) -> SecretBox:
    return SecretBox.from_settings(make_settings())


async def add_integration(
    repos: Repositories,
    box: SecretBox,
    tenant_id: str,
    kind: str,
    *,
    config: Optional[Dict[str, Any]] = None,
    secret: Optional[Dict[str, str]] = None,
    events: Sequence[str] = ("escalation.created",),
    min_severity: str = "low",
    name: Optional[str] = None,
) -> Integration:
    integration_id = uuid.uuid4()
    ciphertext = encrypt_secret(box, tenant_id, integration_id, secret or {})
    return await repos.integrations.create(
        tenant_id,
        kind,
        name or f"{kind}-{integration_id.hex[:6]}",
        integration_id=integration_id,
        config=config or {},
        secret_ciphertext=ciphertext,
        events=list(events),
        min_severity=min_severity,
    )


class Receiver:
    """A scripted HTTP receiver: routes ``"METHOD /path"`` to handlers, records every request."""

    def __init__(self, routes: Optional[Dict[str, Any]] = None, default: Any = None) -> None:
        self.routes: Dict[str, Any] = dict(routes or {})
        self.default = default if default is not None else httpx.Response(200, text="ok")
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get(f"{request.method} {request.url.path}", self.default)
        if callable(answer) and not isinstance(answer, httpx.Response):
            answer = answer(request)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def paths(self) -> List[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]

    def http(self, settings: Settings) -> IntegrationHttp:
        return IntegrationHttp(settings, transport=httpx.MockTransport(self), resolver=public_resolver, sleep=no_sleep)

    def delivery(self, repos: Repositories, settings: Settings, box: SecretBox, **kwargs: Any) -> OutboxDelivery:
        return OutboxDelivery(repos, settings, http=self.http(settings), secret_box=box, rand=lambda: 0.5, **kwargs)
