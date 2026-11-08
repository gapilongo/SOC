"""Shadow mode (AI-E1.5a), second review round, unit level: gaps a mutation found, and the statement guard."""

from __future__ import annotations

from typing import Any, List

import pytest

from lg_sotf.db.shadow_connection import ShadowConnection, check_shadow_statement
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from lg_sotf.tools.enrichment.base import EnrichmentResult, LookupRequest
from lg_sotf.tools.enrichment.service import EnrichmentService

pytestmark = pytest.mark.unit


class CountingProvider:
    name = "gap_ti"
    kinds = frozenset({"ip"})
    external = True
    cache_ttl_s = 300.0
    requests_per_minute = 0

    def __init__(self) -> None:
        self.sent: List[str] = []

    def requires_credentials(self) -> bool:
        return False

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        self.sent.append(request.value)
        return EnrichmentResult.ok(self.name, request.kind, "malicious", {"score": 99})

    async def aclose(self) -> None:
        return None


async def test_gap_a_shadow_cache_miss_is_never_served_to_production(make_settings: Any) -> None:
    """The shadow stand-in ('skipped') must not land in the shared cache, or production loses the TI answer."""
    provider = CountingProvider()
    service = EnrichmentService([provider], make_settings())
    with shadow_scope(ShadowRun("shadow/gap-ti")):
        shadow = await service.lookup("tenant-a", "ip", "185.220.101.44")
    live = await service.lookup("tenant-a", "ip", "185.220.101.44")
    assert shadow[0].status == "skipped"
    assert live[0].status == "ok" and live[0].verdict == "malicious" and provider.sent == ["185.220.101.44"]


@pytest.mark.parametrize("sql", [
    'SELECT "pg_notify"(\'gap\', \'x\')',
    "SELECT pg_catalog.pg_notify('gap', 'x')",
    'SELECT "pg_advisory_lock"(1)',
    "SELECT set_config('app.x', 'y', false)",
    "SELECT set_config('app.x', 'y', $1)",
    "SELECT \"set_config\"('app.x', 'y', (SELECT false))",
    "/* hidden */ COMMIT",
])
def test_the_statement_guard_refuses_what_escapes_the_transaction(sql: str) -> None:
    with shadow_scope(ShadowRun("shadow/gap-sql")):
        with pytest.raises(ShadowEgressRefused):
            check_shadow_statement(sql)


@pytest.mark.parametrize("sql", [
    "SELECT set_config('app.tenant_id', $1, true)",
    "SELECT pg_try_advisory_xact_lock(1)",
    "UPDATE alerts SET status = 'x'",
    "SET LOCAL statement_timeout = 1000",
])
def test_the_statement_guard_lets_transaction_scoped_statements_through(sql: str) -> None:
    with shadow_scope(ShadowRun("shadow/gap-sql")):
        check_shadow_statement(sql)


class _Driver:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def __getattr__(self, name: str) -> Any:
        return lambda *a, **k: self.calls.append(name)


@pytest.mark.parametrize("name", ["copy_to_table", "copy_records_to_table", "copy_from_query", "add_listener",
                                  "set_type_codec", "close", "terminate", "anything_new"])
def test_a_shadow_connection_refuses_every_driver_method_it_does_not_check(name: str) -> None:
    driver = _Driver()
    with shadow_scope(ShadowRun("shadow/gap-attr")):
        with pytest.raises(ShadowEgressRefused):
            getattr(ShadowConnection(driver), name)()  # type: ignore[arg-type]
    assert driver.calls == []


def test_a_shadow_connection_checks_fetchmany() -> None:
    driver = _Driver()
    with shadow_scope(ShadowRun("shadow/gap-attr")):
        with pytest.raises(ShadowEgressRefused):
            ShadowConnection(driver).fetchmany("SELECT pg_notify('gap', 'x')", [])  # type: ignore[arg-type]
        ShadowConnection(driver).transaction()  # type: ignore[arg-type]
    assert driver.calls == ["transaction"]
