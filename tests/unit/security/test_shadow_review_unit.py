"""Shadow mode (AI-E1.5a), review of #295, unit level: the probes of the review, asserting the safe behaviour."""

from __future__ import annotations

import asyncio
import contextvars
from email.message import EmailMessage
from typing import Any, List

import pytest

from lg_sotf.integrations.channels import _smtp_send
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from lg_sotf.tools.enrichment.base import EnrichmentResult, LookupRequest
from lg_sotf.tools.enrichment.service import EnrichmentService

pytestmark = pytest.mark.unit


class CountingProvider:
    name = "probe_ti"
    kinds = frozenset({"ip"})
    external = True
    cache_ttl_s = 300.0
    requests_per_minute = 1

    def __init__(self) -> None:
        self.sent: List[str] = []

    def requires_credentials(self) -> bool:
        return False

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        self.sent.append(request.value)  # the indicator leaves the platform here
        return EnrichmentResult.failed(self.name, request.kind, "not_found")

    async def aclose(self) -> None:
        return None


async def test_shadow_enrichment_answers_from_the_cache_only(make_settings: Any) -> None:
    """No provider call, no request budget spent, no 429 back-off: a shadow cache miss is ``skipped``."""
    provider = CountingProvider()
    service = EnrichmentService([provider], make_settings())
    with shadow_scope(ShadowRun("shadow/ti")) as run:
        shadow = await service.lookup("tenant-a", "ip", "185.220.101.44")
    live = await service.lookup("tenant-a", "ip", "45.155.205.233")
    assert provider.sent == ["45.155.205.233"], "only the live lookup reached the provider"
    assert shadow[0].status == "skipped"
    assert live[0].status == "not_found", "the production lookup kept its request budget"
    assert [(e.boundary, e.detail) for e in run.sink.effects] == [
        ("enrichment_lookup", {"provider": "probe_ti", "kind": "ip"})
    ]


async def test_shadow_enrichment_still_reads_what_production_cached(make_settings: Any) -> None:
    provider = CountingProvider()
    service = EnrichmentService([provider], make_settings())
    await service.lookup("tenant-a", "ip", "185.220.101.44")
    with shadow_scope(ShadowRun("shadow/ti")):
        shadow = await service.lookup("tenant-a", "ip", "185.220.101.44")
    assert shadow[0].status == "not_found" and shadow[0].cached and provider.sent == ["185.220.101.44"]


async def test_a_sync_boundary_holds_on_a_thread_that_carries_the_context(make_settings: Any) -> None:
    """``_smtp_send`` is REFUSE in shadow mode on every hop the platform uses (``to_thread``, copied context)."""
    sent: List[str] = []

    class FakeSMTP:
        def __init__(self, *a: Any, **k: Any) -> None:
            sent.append("connect")

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def __getattr__(self, name: str) -> Any:
            return lambda *a, **k: sent.append(name)

    settings = make_settings(integrations={"smtp_host": "smtp.example.com", "smtp_from": "soc@example.com"})
    message = EmailMessage()
    message["To"] = "x@example.com"
    with shadow_scope(ShadowRun("shadow/smtp")):
        with pytest.raises(ShadowEgressRefused):
            await asyncio.to_thread(_smtp_send, settings, message, FakeSMTP)
        loop = asyncio.get_running_loop()
        with pytest.raises(ShadowEgressRefused):
            await loop.run_in_executor(None, contextvars.copy_context().run, _smtp_send, settings, message, FakeSMTP)
    assert sent == [], "the boundary never ran live in a thread"
    # A bare run_in_executor (which drops the context) is kept out of the source by
    # tests/unit/architecture/test_shadow_egress.py::test_no_code_drops_the_run_mode_on_a_thread_or_fresh_context.
