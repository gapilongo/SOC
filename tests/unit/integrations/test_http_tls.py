"""Integration, webhook and Microsoft clients reuse cached TLS contexts (roadmap D3, X2.2).

All three open one ``httpx.AsyncClient`` per request. Before D3 the first two
built a transport with ``verify=True``, so ``httpx`` loaded the CA bundle into
a new ``SSLContext`` on the event loop for every request; the Microsoft
factory kept its own copy of the default context until X2.2. The real transport
class runs here (its constructor builds the context); only the network send
is stubbed.
"""

from __future__ import annotations

import ssl
from typing import Any, Callable, List

import httpx
import pytest

from lg_sotf.integrations.http import IntegrationHttp, tls_verify
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.net.tls import TlsContexts
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.services.connectors import ConnectorRegistry, WebhookConnector, WebhookTarget, encrypt_webhook_secret
from lg_sotf.settings import Settings
from tests.unit.ingestion._support import public_resolver
from tests.unit.net._support import self_signed_pem
from tests.unit.services._support import make_action

SECRET = b"s3cr3t-webhook-key-0123456789abcdef"


class Transports:
    """Records the ``verify`` each real ``AsyncHTTPTransport`` is built with, and counts new SSL contexts."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.verify: List[Any] = []
        self.contexts_built = 0
        real_create = ssl.create_default_context
        seen = self

        def counting_create(*args: Any, **kwargs: Any) -> ssl.SSLContext:
            seen.contexts_built += 1
            return real_create(*args, **kwargs)

        class Recording(httpx.AsyncHTTPTransport):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                seen.verify.append(kwargs.get("verify", True))
                super().__init__(*args, **kwargs)

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, json={"status": "succeeded"})

        monkeypatch.setattr(ssl, "create_default_context", counting_create)
        monkeypatch.setattr(httpx, "AsyncHTTPTransport", Recording)


@pytest.fixture
def transports(monkeypatch: pytest.MonkeyPatch) -> Transports:
    return Transports(monkeypatch)


async def test_integration_requests_build_one_ssl_context(
    transports: Transports, make_settings: Callable[..., Settings]
) -> None:
    http = IntegrationHttp(make_settings(), resolver=public_resolver, tls=TlsContexts())
    await http.request("POST", "https://hooks.example.com/a", json_body={"n": 1})
    await http.request("POST", "https://hooks.example.com/b", json_body={"n": 2})
    assert transports.contexts_built == 1
    first, second = transports.verify
    assert isinstance(first, ssl.SSLContext) and second is first


async def test_integration_clients_share_the_process_context(
    transports: Transports, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    await IntegrationHttp(settings, resolver=public_resolver).request("GET", "https://jira.example.com/rest")
    await IntegrationHttp(settings, resolver=public_resolver).request("GET", "https://snow.example.com/api")
    first, second = transports.verify
    assert isinstance(first, ssl.SSLContext) and second is first


async def test_each_integration_keeps_its_own_ca(
    transports: Transports, make_settings: Callable[..., Settings]
) -> None:
    contexts = TlsContexts()
    http = IntegrationHttp(make_settings(), resolver=public_resolver, tls=contexts)
    pem_a, pem_b = self_signed_pem("jira-ca"), self_signed_pem("snow-ca")
    for pem in (pem_a, pem_b, pem_a, None):
        verify = tls_verify({"ca_cert_pem": pem} if pem else {}, contexts=contexts)
        await http.request("GET", "https://ticketing.example.com/api", verify=verify)
    ctx_a, ctx_b, ctx_a_again, default = transports.verify
    assert ctx_a_again is ctx_a and ctx_b is not ctx_a
    assert default is contexts.default() and default not in (ctx_a, ctx_b)
    assert ctx_a.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(pem_a)]
    assert ctx_b.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(pem_b)]
    assert transports.contexts_built == 3  # one per CA plus the default, not one per request


async def test_webhook_deliveries_build_one_ssl_context(transports: Transports) -> None:
    hook = WebhookConnector(
        WebhookTarget(url="https://soar.example.com/hook", secret=SECRET),
        policy=DestinationPolicy(require_https=True),
        target_kinds={"block_ip": "ip"},
        resolver=public_resolver,
        tls=TlsContexts(),
    )
    for _ in range(2):
        result = await hook.execute(make_action())
        assert result.status == "succeeded"
    assert transports.contexts_built == 1
    first, second = transports.verify
    assert isinstance(first, ssl.SSLContext) and second is first


async def test_webhook_connectors_share_the_process_context(transports: Transports) -> None:
    for _ in range(2):
        hook = WebhookConnector(
            WebhookTarget(url="https://soar.example.com/hook", secret=SECRET),
            policy=DestinationPolicy(require_https=True),
            target_kinds={"block_ip": "ip"},
            resolver=public_resolver,
        )
        await hook.execute(make_action())
    first, second = transports.verify
    assert isinstance(first, ssl.SSLContext) and second is first


async def test_tenant_webhook_cas_are_cached_per_ca(
    transports: Transports, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(response={"dry_run": False})
    box = SecretBox([generate_key()])
    registry = ConnectorRegistry(settings, secret_box=box, resolver=public_resolver, tls=TlsContexts())
    pem_1, pem_2 = self_signed_pem("tenant-1-ca"), self_signed_pem("tenant-2-ca")

    def tenant(tenant_id: str, pem: Any) -> dict:
        response = {
            "connector": "webhook",
            "webhook_url": f"https://{tenant_id}.soar.example.com/hook",
            "webhook_secret_ciphertext": encrypt_webhook_secret(box, tenant_id, "tenant-secret-0123456789"),
        }
        return {"response": {**response, **({"ca_cert_pem": pem} if pem else {})}}

    for tenant_id, pem in (("t1", pem_1), ("t2", pem_2), ("t1", pem_1), ("t3", None)):
        hook = registry.for_tenant(tenant_id, tenant(tenant_id, pem))
        assert isinstance(hook, WebhookConnector)
        await hook.execute(make_action(tenant_id=tenant_id))
    t1, t2, t1_again, t3 = transports.verify
    assert t1_again is t1 and t2 is not t1 and t3 not in (t1, t2)
    assert t1.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(pem_1)]
    assert t2.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(pem_2)]
    assert len(t3.get_ca_certs()) > 1  # verify on with the default bundle, not another tenant's CA


async def test_microsoft_requests_share_the_default_context(
    transports: Transports, make_settings: Callable[..., Settings]
) -> None:
    contexts = TlsContexts()
    factory = MicrosoftHttpFactory(make_settings(), resolver=public_resolver, tls=contexts)
    for path in ("/v1.0/users", "/v1.0/groups"):
        status, _body, _headers = await factory.send_once(
            "GET", f"https://graph.microsoft.com{path}", headers={}, content=None, timeout_s=5.0, max_bytes=1024
        )
        assert status == 200
    first, second = transports.verify
    assert first is second is contexts.default()
    assert transports.contexts_built == 1
