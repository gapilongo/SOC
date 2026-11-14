"""Live guided setup (PRD-13.2a): the Wazuh setup checks against a real Wazuh 4.14 indexer.

``tests/integration/e2e/test_guided_wazuh.py`` walks the guided flow against
:class:`~tests.fixtures.wazuh_lab.fake.FakeWazuhIndexer`. These ask the real
indexer the same questions, so the fake's answers stay honest: what the
security plugin says to a wrong password and to a user without a role, what
a pattern that matches nothing returns, how a real TLS handshake fails
without the CA or under another host name, and that a ``date_range``
aggregation from ``now`` reports the indexer's clock.

Skipped unless ``LG_SOTF_TEST_WAZUH_ADDRESS`` is set (``make test-wazuh``).
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Sequence

import pytest

from lg_sotf.ingestion.guided import SetupCheck, all_passed
from lg_sotf.ingestion.guided.wazuh import PULL_CHECKS, check_wazuh_pull
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps
from lg_sotf.ingestion.sources.base import iso
from lg_sotf.settings import Settings
from tests.fixtures.wazuh_lab import SAMPLE_ALERTS, WazuhLab, read_alerts
from tests.live.wazuh._support import SKIP_REASON, Lab, lab_address

pytestmark = [pytest.mark.live, pytest.mark.skipif(lab_address() is None, reason=SKIP_REASON)]

Check = Callable[..., Any]
ORDER = [check_id for check_id, _ in PULL_CHECKS]


def recent_alerts(count: int = 3, newest: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Sample alerts re-dated to the last minutes: the clock check compares them with the real time."""
    newest = newest or datetime.now(UTC) - timedelta(minutes=2)
    alerts = []
    for i, template in enumerate(read_alerts(SAMPLE_ALERTS)[:count]):
        alert = copy.deepcopy(template)
        alert["timestamp"] = iso(newest - timedelta(minutes=i)).replace("Z", "+0000")
        alerts.append(alert)
    return alerts


@pytest.fixture
def check(lab: Lab, lab_settings: Settings, reader: Dict[str, str], alert_index: str) -> Check:
    """``await check(**overrides)`` runs the pull checks against the lab as ``reader`` on ``alert_index``."""
    with open(lab.ca_file, encoding="utf-8") as fh:
        ca_pem = fh.read()

    async def run(
        credentials: Optional[Dict[str, str]] = None,
        *,
        base_url: Optional[str] = None,
        trust_ca: bool = True,
        now: Optional[Callable[[], datetime]] = None,
        **config: Any,
    ) -> List[SetupCheck]:
        async def resolve(host: str, port: int) -> Sequence[str]:
            return [lab.address]

        source_config = {"base_url": base_url or lab.base_url, "index": alert_index, **config}
        if trust_ca:
            source_config["ca_cert_pem"] = ca_pem
        deps = ConnectorDeps(resolver=resolve, **({"now": now} if now else {}))
        return await check_wazuh_pull(
            "tenant-a", source_config, credentials or reader, settings=lab_settings,
            options=IngestionOptions.from_settings(lab_settings), deps=deps,
        )

    return run


def the_failure(checks: List[SetupCheck]) -> SetupCheck:
    """The one failed check; the checks before it passed and the ones after it were skipped."""
    assert [c.id for c in checks] == ORDER
    failed = [c for c in checks if c.status == "failed"]
    assert len(failed) == 1, checks
    position = ORDER.index(failed[0].id)
    assert all(c.status == "passed" for c in checks[:position]), checks
    assert all(c.status == "skipped" for c in checks[position + 1 :]), checks
    assert failed[0].fix
    return failed[0]


async def test_a_working_setup_passes_every_check(check: Check, lab_admin: WazuhLab, alert_index: str) -> None:
    lab_admin.load(recent_alerts(), alert_index)
    checks = await check()
    assert all_passed(checks) and [(c.id, c.status) for c in checks] == [(c, "passed") for c in ORDER], checks
    found = {c.id: c.message for c in checks}
    assert found["index"].startswith(f"{alert_index} holds 3 alerts; the newest is dated ")
    assert found["clock"] == "The indexer's clock is within 120 seconds of this server's."


async def test_a_wrong_password_fails_the_sign_in(check: Check, reader: Dict[str, str]) -> None:
    failure = the_failure(await check({"username": reader["username"], "password": "test-only-not-the-password"}))
    assert failure.id == "credentials" and "HTTP 401" in failure.message
    assert reader["username"] not in failure.message + str(failure.fix)


async def test_a_user_without_a_role_is_told_the_permission_and_the_index(
    check: Check, no_access_user: Dict[str, str], lab_admin: WazuhLab, alert_index: str
) -> None:
    lab_admin.load(recent_alerts(1), alert_index)
    failure = the_failure(await check(no_access_user))
    assert failure.id == "index_permission"
    assert alert_index in failure.message and "indices:data/read/search" in failure.message
    assert f"index pattern {alert_index}" in str(failure.fix)
    assert no_access_user["username"] not in failure.message + str(failure.fix)


async def test_a_pattern_or_an_index_that_does_not_exist_is_named(check: Check, alert_index: str) -> None:
    pattern = f"{alert_index}-nothing-*"
    failure = the_failure(await check(index=pattern))
    assert failure.id == "index" and failure.message == f"No index matches {pattern}."
    # No document was loaded: the per-test index itself does not exist, and a concrete name answers 404.
    failure = the_failure(await check())
    assert failure.id == "index" and failure.message == f"No index matches {alert_index}."


async def test_an_index_without_the_time_field_is_named(check: Check, lab_admin: WazuhLab, alert_index: str) -> None:
    lab_admin.load(recent_alerts(1), alert_index)
    failure = the_failure(await check(time_field="no_such_time"))
    assert failure.id == "index" and "time field no_such_time" in failure.message and "HTTP 400" in failure.message


async def test_the_certificate_is_checked_against_the_ca_and_the_host_name(check: Check, lab: Lab) -> None:
    failure = the_failure(await check(trust_ca=False))
    assert failure.id == "tls" and "certificate authority this server does not trust" in failure.message
    assert "CA certificate field" in str(failure.fix)
    failure = the_failure(await check(base_url="https://indexer.lab.example:9200"))
    assert failure.id == "tls" and failure.message == "The indexer's certificate is not issued for indexer.lab.example."


async def test_a_closed_port_is_unreachable(check: Check, lab: Lab) -> None:
    failure = the_failure(await check(base_url=lab.base_url.replace(":9200", ":9219")))
    assert failure.id == "reachable" and failure.message == "No answer from demo.indexer:9219."


async def test_clocks_that_disagree_fail_the_clock_check(check: Check, lab_admin: WazuhLab, alert_index: str) -> None:
    lab_admin.load(recent_alerts(), alert_index)
    failure = the_failure(await check(now=lambda: datetime.now(UTC) + timedelta(minutes=10)))
    assert failure.id == "clock"
    assert failure.message in (
        "The indexer's clock is 10 minutes behind this server's clock.",
        "The indexer's clock is 9 minutes behind this server's clock.",
    )
    # An alert stamped by a manager whose clock runs ahead.
    lab_admin.load(recent_alerts(1, newest=datetime.now(UTC) + timedelta(minutes=30)), alert_index)
    failure = the_failure(await check())
    assert failure.id == "clock" and "in the future: the Wazuh manager's clock is ahead" in failure.message
