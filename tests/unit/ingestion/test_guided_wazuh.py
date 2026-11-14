"""Guided Wazuh setup, pull checks: what each answer of the indexer (or of the network) is reported as.

The walk through the misconfigurations an admin meets is
``tests/integration/e2e/test_guided_wazuh.py``; these pin the cases around it.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx
import pytest

from lg_sotf.ingestion.guided import SKIPPED_MESSAGE, Failure, SetupCheck, all_passed, ordered_checks
from lg_sotf.ingestion.guided.wazuh import PULL_CHECKS, check_wazuh_pull
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps
from lg_sotf.settings import Settings
from tests.fixtures.wazuh_lab.fake import EXPIRED, HOSTNAME_MISMATCH, FakeWazuhIndexer, certificate_failure
from tests.unit.ingestion._support import FakeClock, public_resolver

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
ORDER = [check_id for check_id, _ in PULL_CHECKS]
USERNAME = "soc-reader"
PASSWORD = f"test-only-{secrets.token_hex(8)}"
CREDENTIALS = {"username": USERNAME, "password": PASSWORD}
BASE_URL = "https://wazuh.example.com:9200"
Handler = Callable[[httpx.Request], httpx.Response]
Resolver = Callable[[str, int], Any]


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(ingestion={"http_max_retries": 2})


def indexer(clock_offset_s: float = 0.0, alerts: Sequence[timedelta] = (timedelta(minutes=5),)) -> FakeWazuhIndexer:
    fake = FakeWazuhIndexer(clock=lambda: NOW + timedelta(seconds=clock_offset_s))
    fake.put_user(USERNAME, PASSWORD, patterns=["wazuh-alerts-*"])
    fake.add_alerts("wazuh-alerts-4.x-2026.11.14", [NOW - age for age in alerts])
    return fake


async def run(
    settings: Settings,
    handler: Handler,
    *,
    resolver: Resolver = public_resolver,
    credentials: Optional[Dict[str, Any]] = None,
    **config: Any,
) -> List[SetupCheck]:
    deps = ConnectorDeps(
        transport=httpx.MockTransport(handler), sleep=FakeClock().sleep, now=lambda: NOW, rand=lambda: 0.0,
        resolver=resolver,
    )
    checks = await check_wazuh_pull(
        "tenant-a", {"base_url": BASE_URL, **config}, CREDENTIALS if credentials is None else credentials,
        settings=settings, options=IngestionOptions.from_settings(settings), deps=deps,
    )
    assert [c.id for c in checks] == ORDER
    for check in checks:
        assert PASSWORD not in check.message + str(check.fix) and USERNAME not in check.message + str(check.fix)
        assert (check.fix is not None) == (check.status == "failed")
    return checks


def the_failure(checks: List[SetupCheck]) -> SetupCheck:
    failed = [c for c in checks if c.status == "failed"]
    assert len(failed) == 1, checks
    return failed[0]


def states(checks: List[SetupCheck]) -> Dict[str, str]:
    return {c.id: c.status for c in checks}


# -- the list itself ---------------------------------------------------------------


def test_checks_after_a_failure_are_skipped_and_skipped_checks_prove_nothing() -> None:
    order = (("a", "A"), ("b", "B"), ("c", "C"), ("d", "D"))
    checks = ordered_checks(order, {"a": "fine"}, Failure("b", "broken", "mend it"), {"d": "does not apply"})
    assert [(c.id, c.status, c.message, c.fix) for c in checks] == [
        ("a", "passed", "fine", None),
        ("b", "failed", "broken", "mend it"),
        ("c", "skipped", SKIPPED_MESSAGE, None),
        ("d", "skipped", "does not apply", None),
    ]
    assert not all_passed(checks)
    assert not all_passed([SetupCheck("a", "A", "skipped", "nothing to check")])
    assert all_passed([SetupCheck("a", "A", "passed", "fine"), SetupCheck("b", "B", "skipped", "n/a")])


# -- settings ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("config", "credentials", "names"),
    [
        ({"index": "../_all"}, None, "config.index"),
        ({"time_field": "a b"}, None, "config.time_field"),
        ({"ca_cert_pem": "not a certificate"}, None, "invalid CA certificate"),
        ({"base_url": "ftp://wazuh.example.com"}, None, "http(s)"),
        ({"base_url": ""}, None, "config.base_url"),
        ({}, {"username": USERNAME}, "'password' credential"),
        ({}, {"username": "", "password": PASSWORD}, "'username' credential"),
    ],
)
async def test_settings_that_cannot_work_are_refused_before_anything_is_sent(
    settings: Settings, config: Dict[str, Any], credentials: Optional[Dict[str, Any]], names: str
) -> None:
    fake = indexer()
    checks = await run(settings, fake, credentials=credentials, **config)
    failure = the_failure(checks)
    assert failure.id == "settings" and names in failure.message
    assert "https://wazuh-indexer.example.com:9200" in str(failure.fix)
    assert all(c.status == "skipped" for c in checks[1:]) and fake.requests == []


async def test_plain_http_is_refused_in_production(make_settings: Callable[..., Settings]) -> None:
    production = make_settings(environment="production")
    failure = the_failure(await run(production, indexer(), base_url="http://wazuh.example.com:9200"))
    assert failure.id == "settings" and "https" in failure.message


async def test_plain_http_skips_the_certificate_check(settings: Settings) -> None:
    checks = await run(settings, indexer(), base_url="http://wazuh.example.com:9200")
    assert all_passed(checks) and states(checks)["tls"] == "skipped"
    assert "not encrypted" in checks[2].message
    assert checks[1].message == "wazuh.example.com:9200 answered."


# -- reachable ---------------------------------------------------------------------


async def test_a_destination_the_install_refuses_names_the_allow_list(
    settings: Settings, make_settings: Callable[..., Settings]
) -> None:
    async def private(host: str, port: int) -> Sequence[str]:
        return ["10.0.0.5"]

    fake = indexer()
    failure = the_failure(await run(settings, fake, resolver=private))
    assert failure.id == "reachable"
    assert failure.message == "This install is not allowed to connect to wazuh.example.com."
    assert "allow_private_destinations" in str(failure.fix) and "--allow-private" in str(failure.fix)

    pov = make_settings(ingestion={"allowed_destination_hosts": ["siem.prospect.example"]})
    checks = await run(pov, fake)
    failure = the_failure(checks)
    assert failure.id == "reachable" and states(checks)["settings"] == "passed"
    assert "allowed_destination_hosts" in str(failure.fix) and "scripts/pov.sh --allow-host" in str(failure.fix)
    assert fake.requests == []


async def test_a_name_that_does_not_resolve_is_named(settings: Settings) -> None:
    async def no_such_host(host: str, port: int) -> Sequence[str]:
        raise httpx.ConnectError("could not resolve host (gaierror)")

    failure = the_failure(await run(settings, indexer(), resolver=no_such_host))
    assert failure.id == "reachable" and failure.message == "The name wazuh.example.com does not resolve from this server."
    assert "DNS" in str(failure.fix)


async def test_an_unreachable_indexer_is_tried_once(settings: Settings) -> None:
    fake = indexer()
    fake.down = True
    failure = the_failure(await run(settings, fake))
    assert failure.id == "reachable" and failure.message == "No answer from wazuh.example.com:9200."
    assert len(fake.requests) == 1, "a guided check does not retry"


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(429, text="slow down"), "wazuh.example.com:9200 did not give a usable answer."),
        (
            httpx.Response(200, text="<html>Wazuh dashboard</html>"),
            "wazuh.example.com:9200 answered (HTTP 200), but not like a Wazuh indexer.",
        ),
        (
            httpx.Response(200, json={"title": "Wazuh API REST"}),
            "wazuh.example.com:9200 answered (HTTP 200), but not like a Wazuh indexer.",
        ),
        (
            httpx.Response(302, headers={"Location": "/app/login"}),
            "wazuh.example.com:9200 answered (HTTP 302), but not like a Wazuh indexer.",
        ),
        (
            httpx.Response(404, json={"title": "Not Found"}),
            "wazuh.example.com:9200 answered (HTTP 404), but not like a Wazuh indexer.",
        ),
        (
            httpx.Response(400, text="Bad Request"),
            "wazuh.example.com:9200 answered (HTTP 400), but not like a Wazuh indexer.",
        ),
    ],
)
async def test_another_server_at_the_url_is_not_mistaken_for_an_indexer(
    settings: Settings, response: httpx.Response, message: str
) -> None:
    failure = the_failure(await run(settings, lambda request: response))
    assert failure.id == "reachable" and failure.message == message
    assert "9200" in str(failure.fix)


async def test_a_server_error_points_at_the_indexers_health(settings: Settings) -> None:
    failure = the_failure(await run(settings, lambda request: httpx.Response(503, text="starting")))
    assert failure.id == "reachable" and failure.message == "wazuh.example.com:9200 answered with a server error."
    assert "_cluster/health" in str(failure.fix)


# -- tls ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("certificate", "message", "fix"),
    [
        (HOSTNAME_MISMATCH, "The indexer's certificate is not issued for wazuh.example.com.", "subject alternative names"),
        (EXPIRED, "The indexer's certificate has expired or is not valid yet.", "Renew the indexer certificate"),
        ((7, "certificate signature failure"), "The certificate of wazuh.example.com could not be verified.", "root CA"),
    ],
)
async def test_each_certificate_problem_has_its_own_fix(
    settings: Settings, certificate: Any, message: str, fix: str
) -> None:
    fake = indexer()
    fake.certificate = certificate
    checks = await run(settings, fake)
    failure = the_failure(checks)
    assert failure.id == "tls" and failure.message == message and fix in str(failure.fix)
    assert states(checks)["reachable"] == "passed" and states(checks)["credentials"] == "skipped"


async def test_a_tls_failure_that_is_not_a_certificate_is_only_unreachable(settings: Settings) -> None:
    def not_tls(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER] wrong version number")

    assert the_failure(await run(settings, not_tls)).id == "reachable"
    assert isinstance(certificate_failure(20, "x").__cause__, Exception)


# -- credentials, permission, index --------------------------------------------------


async def test_a_denied_action_is_read_from_the_indexer_and_nothing_else_is(settings: Settings) -> None:
    def denied(reason: str) -> Handler:
        return lambda request: httpx.Response(403, json={"error": {"type": "security_exception", "reason": reason}})

    scroll = "no permissions for [indices:data/read/scroll] and User [name=soc-reader, backend_roles=[admin]]"
    failure = the_failure(await run(settings, denied(scroll)))
    assert failure.id == "index_permission" and "the permission indices:data/read/scroll is missing" in failure.message
    assert "backend_roles" not in failure.message
    for unreadable in ("no permissions for [<script>] and User", "Forbidden"):
        failure = the_failure(await run(settings, denied(unreadable)))
        assert "the permission indices:data/read/search is missing" in failure.message
    plain = the_failure(await run(settings, lambda request: httpx.Response(403, text="Forbidden")))
    assert plain.id == "index_permission" and "wazuh-alerts-*" in plain.message


async def test_a_missing_index_and_a_field_that_does_not_sort_are_named(settings: Settings) -> None:
    fake = indexer()
    failure = the_failure(await run(settings, fake, index="wazuh-alerts-4.x-2026.01.01"))
    assert failure.id == "index" and failure.message == "No index matches wazuh-alerts-4.x-2026.01.01."

    failure = the_failure(await run(settings, fake, time_field="event.ingested"))
    assert failure.id == "index" and "time field event.ingested" in failure.message
    assert "GET wazuh-alerts-*/_mapping/field/event.ingested" in str(failure.fix)

    fake.failed_shards = 1
    failure = the_failure(await run(settings, fake))
    assert failure.id == "index" and failure.message == "1 of 1 shards of wazuh-alerts-* did not answer."


async def test_an_index_without_alerts_passes_and_says_so(settings: Settings) -> None:
    fake = indexer(alerts=())
    checks = await run(settings, fake)
    assert all_passed(checks)
    found = {c.id: c.message for c in checks}
    assert found["index"].startswith("wazuh-alerts-* exists and holds no alert yet")
    assert found["clock"] == "The indexer's clock is within 120 seconds of this server's."


def search_answer(newest: Optional[datetime], *, total: int = 1, relation: str = "eq") -> Handler:
    """A search answer without aggregations (an indexer that does not report its clock)."""
    hits = [{"_id": "a", "sort": [int(newest.timestamp() * 1000)]}] if newest else []
    body = {"_shards": {"total": 1, "failed": 0}, "hits": {"total": {"value": total, "relation": relation}, "hits": hits}}
    return lambda request: httpx.Response(200, json=body)


async def test_the_alert_count_is_read_as_the_indexer_gives_it(settings: Settings) -> None:
    newest = NOW - timedelta(minutes=1)
    checks = await run(settings, search_answer(newest, total=10_000, relation="gte"))
    assert checks[5].message == "wazuh-alerts-* holds 10,000 or more alerts; the newest is dated 2026-11-14 11:59 UTC."
    checks = await run(settings, lambda request: httpx.Response(200, json={
        "_shards": {"total": 1}, "hits": {"total": 7, "hits": [{"sort": [int(newest.timestamp() * 1000)]}]},
    }))
    assert checks[5].message == "wazuh-alerts-* holds alerts; the newest is dated 2026-11-14 11:59 UTC."


# -- clock -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("offset_s", "message"),
    [
        (-121, "The indexer's clock is 2 minutes behind this server's clock."),
        (150, "The indexer's clock is 2 minutes ahead of this server's clock."),
        (3 * 3600, "The indexer's clock is 3 hours ahead of this server's clock."),
        (-3 * 86_400, "The indexer's clock is 3 days behind this server's clock."),
    ],
)
async def test_a_clock_out_of_step_fails_with_the_size_and_direction(
    settings: Settings, offset_s: float, message: str
) -> None:
    checks = await run(settings, indexer(clock_offset_s=offset_s))
    failure = the_failure(checks)
    assert failure.id == "clock" and failure.message == message and "NTP" in str(failure.fix)
    assert states(checks)["index"] == "passed"


@pytest.mark.parametrize("offset_s", [-120, -5, 0, 90, 120])
async def test_clocks_within_the_tolerance_pass(settings: Settings, offset_s: float) -> None:
    assert all_passed(await run(settings, indexer(clock_offset_s=offset_s)))


async def test_an_alert_dated_in_the_future_shows_a_manager_clock_that_runs_ahead(settings: Settings) -> None:
    failure = the_failure(await run(settings, indexer(alerts=(timedelta(minutes=-45),))))
    assert failure.id == "clock"
    assert failure.message == (
        "The newest alert in wazuh-alerts-* is dated 45 minutes in the future: the Wazuh manager's clock is ahead of "
        "this server's."
    )
    failure = the_failure(await run(settings, search_answer(NOW + timedelta(seconds=121))))
    assert failure.id == "clock" and "2 minutes in the future" in failure.message


async def test_without_a_clock_reading_the_newest_alert_is_all_there_is(settings: Settings) -> None:
    checks = await run(settings, search_answer(NOW - timedelta(hours=1)))
    assert all_passed(checks) and checks[6].message == "The newest alert is not dated in the future."
    checks = await run(settings, search_answer(None, total=0))
    assert all_passed(checks) and states(checks)["clock"] == "skipped"
    assert checks[6].message == "Not checked: the index holds no alert to compare clocks with."
    for odd in ({"clock": {"buckets": [{"from": "soon"}]}}, {"clock": {"buckets": [{"from": 1e30}]}}, {"clock": 3}):
        body = {"_shards": {"total": 1}, "hits": {"hits": [{"sort": ["2026-11-14"]}]}, "aggregations": odd}
        checks = await run(settings, lambda request, body=body: httpx.Response(200, json=body))
        assert states(checks)["clock"] == "skipped"
