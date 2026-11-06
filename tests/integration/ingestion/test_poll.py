"""IngestionService.poll_source / test_source against real PostgreSQL."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List, Mapping, Sequence

import httpx
import pytest

from lg_sotf.db.repos import NewAlert, Repositories, Source
from lg_sotf.db.repos.alerts import AlertsRepo
from lg_sotf.ingestion.errors import SourceNotPullable
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps, FetchedPage, PullConnector, encrypt_source_secret
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from tests.fixtures.vendors import vendor_events
from tests.integration.db._support import TENANT_A
from tests.integration.ingestion._support import T0, QRadarMock, ScriptedConnector, page
from tests.unit.ingestion._support import public_resolver

pytestmark = pytest.mark.integration

class FailingAlertsRepo(AlertsRepo):
    def __init__(self, db: Any, fail_on_call: int) -> None:
        super().__init__(db)
        self.calls = 0
        self.fail_on_call = fail_on_call

    async def insert_many_if_absent(self, tenant_id: str, rows: Sequence[NewAlert], **kwargs: Any) -> List[str]:
        self.calls += 1
        result = await super().insert_many_if_absent(tenant_id, rows, **kwargs)
        if self.calls == self.fail_on_call:
            raise ConnectionResetError("database connection lost")
        return result


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(ingestion={"page_size": 2, "max_pages_per_poll": 10})


async def _source(repos: Repositories, source_type: str = "splunk", **kwargs: Any) -> Source:
    return await repos.sources.create(TENANT_A, source_type, f"{source_type} src", source_id=f"{source_type}-1", **kwargs)


async def test_poll_commits_pages_with_their_cursor(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos)
    connectors: List[ScriptedConnector] = []

    def factory(src: Source, creds: Mapping[str, Any]) -> PullConnector:
        c = ScriptedConnector(src, [page(0, 2, watermark_min=1), page(2, 1, watermark_min=2)], settings=settings)
        connectors.append(c)
        return c

    service = IngestionService(repos.db, settings, repos=repos, connector_factory=factory)
    result = await service.poll_source(TENANT_A, source)
    assert result.error is None and result.pages == 2 and not result.more_pending
    assert len(result.inserted) == 3 and all(a.severity == "high" for a in result.inserted)

    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == {"v": 1, "since": (T0 + timedelta(minutes=2)).isoformat(), "page": 2}
    assert stored.cursor_watermark == T0 + timedelta(minutes=2)
    assert stored.health == "healthy" and stored.consecutive_failures == 0
    assert stored.last_polled_at is not None and stored.next_poll_at is not None

    again = await service.poll_source(TENANT_A, stored)
    assert again.inserted == [] and again.duplicates == 3
    assert len(connectors) == 1, "the connector (and its HTTP client) is reused between polls"
    assert connectors[0].seen_cursors[1] == stored.cursor

    changed = await repos.sources.update(TENANT_A, source.id, config={"search": "search index=x"})
    await service.poll_source(TENANT_A, changed)
    assert len(connectors) == 2 and connectors[0].closed
    await service.close()
    assert connectors[1].closed


async def test_outage_keeps_committed_pages_and_records_failure(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos)
    pages = [page(0, 2, watermark_min=1), page(2, 2, watermark_min=2)]
    service = IngestionService(
        repos.db,
        settings,
        repos=repos,
        connector_factory=lambda src, creds: ScriptedConnector(src, pages, settings=settings, fail_after=1),
    )
    result = await service.poll_source(TENANT_A, source)
    assert result.error is not None and "HTTP 503" in result.error
    assert len(result.inserted) == 2, "alerts committed before the failure are returned for dispatch"

    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == pages[0].cursor
    assert stored.health == "degraded" and stored.consecutive_failures == 1
    assert "HTTP 503" in (stored.last_error or "")


async def test_outage_before_any_page_leaves_cursor_unchanged(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos)
    await repos.sources.set_cursor(TENANT_A, source.id, {"v": 1, "since": T0.isoformat()}, T0)
    source = await repos.sources.get(TENANT_A, source.id)
    service = IngestionService(
        repos.db,
        settings,
        repos=repos,
        connector_factory=lambda src, creds: ScriptedConnector(src, [page(0, 2, watermark_min=5)], settings=settings,
                                                               fail_after=0),
    )
    result = await service.poll_source(TENANT_A, source)
    assert result.inserted == [] and result.error
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == {"v": 1, "since": T0.isoformat()} and stored.cursor_watermark == T0


async def test_cursor_advances_only_after_commit(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos)
    failing = FailingAlertsRepo(repos.db, fail_on_call=2)
    pages = [page(0, 2, watermark_min=1), page(2, 2, watermark_min=2)]
    service = IngestionService(
        repos.db,
        settings,
        repos=dataclasses.replace(repos, alerts=failing),
        connector_factory=lambda src, creds: ScriptedConnector(src, pages, settings=settings),
    )
    result = await service.poll_source(TENANT_A, source)
    assert result.error == "ConnectionResetError"
    assert [a.alert_id for a in result.inserted] and len(result.inserted) == 2
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == pages[0].cursor, "the second page's insert rolled back, so its cursor did too"
    page_two = await repos.alerts.ids_by_source_keys(TENANT_A, source.id, ["e2", "e3"])
    assert page_two == {}


async def test_page_cap_leaves_a_resumable_cursor_and_polls_again_soon(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(ingestion={"max_pages_per_poll": 2})
    source = await _source(repos)
    pages = [page(0, 1, watermark_min=1), page(1, 1, watermark_min=2), page(2, 1, watermark_min=3)]
    service = IngestionService(
        repos.db, settings, repos=repos,
        connector_factory=lambda src, creds: ScriptedConnector(src, pages, settings=settings),
    )
    before = datetime.now(UTC)
    result = await service.poll_source(TENANT_A, source)
    assert result.more_pending and result.pages == 2 and len(result.inserted) == 2
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == pages[1].cursor
    assert stored.next_poll_at is not None and stored.next_poll_at <= before + timedelta(seconds=5)


async def test_push_only_sources_are_not_polled(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos, "guardduty")
    service = IngestionService(repos.db, settings, repos=repos)
    with pytest.raises(SourceNotPullable):
        await service.poll_source(TENANT_A, source)
    health = await service.test_source(TENANT_A, source)
    assert health.ok and "push" in health.detail


async def test_real_connector_with_encrypted_credentials(repos: Repositories, settings: Settings) -> None:
    box = SecretBox.from_settings(settings)
    offenses = vendor_events("qradar_offenses")
    for o in offenses:
        o["start_time"] = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp() * 1000)
    mock = QRadarMock(offenses)
    source = await _source(
        repos,
        "qradar",
        config={"base_url": "https://qradar.example.com"},
        secret_ciphertext=encrypt_source_secret(box, TENANT_A, "qradar-1", {"token": "qr-secret-token"}),
    )
    service = IngestionService(
        repos.db, settings, secret_box=box, repos=repos,
        connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(mock)),
    )
    result = await service.poll_source(TENANT_A, source)
    assert result.error is None and len(result.inserted) == 2
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor is not None and stored.cursor["last_id"] == 1043

    second = await service.poll_source(TENANT_A, stored)
    assert second.inserted == [] and second.duplicates == 0
    assert mock.filters[-1] == "id > 1043"

    health = await service.test_source(TENANT_A, stored)
    assert health.ok and "7.5.0" in health.detail
    await service.close()


async def test_credentials_bound_to_another_source_are_refused(repos: Repositories, settings: Settings) -> None:
    box = SecretBox.from_settings(settings)
    stolen = encrypt_source_secret(box, "tenant-b", "qradar-1", {"token": "qr-secret-token"})
    source = await _source(repos, "qradar", config={"base_url": "https://qradar.example.com"}, secret_ciphertext=stolen)
    service = IngestionService(
        repos.db, settings, secret_box=box, repos=repos,
        connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(QRadarMock([]))),
    )
    result = await service.poll_source(TENANT_A, source)
    assert result.error == "source credentials could not be decrypted"
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.last_error == "source credentials could not be decrypted"
    health = await service.test_source(TENANT_A, source)
    assert not health.ok


async def test_test_source_reports_auth_failure_without_secrets(repos: Repositories, settings: Settings) -> None:
    box = SecretBox.from_settings(settings)
    source = await _source(
        repos,
        "qradar",
        config={"base_url": "https://qradar.example.com"},
        secret_ciphertext=encrypt_source_secret(box, TENANT_A, "qradar-1", {"token": "wrong-token-value"}),
    )
    service = IngestionService(
        repos.db, settings, secret_box=box, repos=repos,
        connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(QRadarMock([]))),
    )
    health = await service.test_source(TENANT_A, source)
    assert not health.ok
    assert "HTTP 401" in health.detail and "wrong-token-value" not in health.detail


async def test_malformed_event_on_a_page_does_not_wedge_the_cursor(repos: Repositories, settings: Settings) -> None:
    source = await _source(repos)
    wm = T0 + timedelta(minutes=7)
    bad_page = FetchedPage(
        [
            {"event_id": "good-1", "rule_title": "Brute force", "urgency": "high"},
            {"event_id": "bad-1", "rule_title": "Win event \udc80", "urgency": "high", "_time": "0001-01-01T00:00:00+01:00"},
            {"event_id": "bad-2", "rule_title": "Huge", "urgency": "high", "_time": 10**400},
        ],
        {"v": 1, "since": wm.isoformat()},
        wm,
    )

    def factory(src: Source, creds: Mapping[str, Any]) -> PullConnector:
        return ScriptedConnector(src, [bad_page], settings=settings)

    service = IngestionService(repos.db, settings, repos=repos, connector_factory=factory)
    result = await service.poll_source(TENANT_A, source)
    assert result.error is None and len(result.inserted) == 3
    stored = await repos.sources.get(TENANT_A, source.id)
    assert stored.cursor == {"v": 1, "since": wm.isoformat()}
    assert stored.health == "healthy" and stored.last_error is None
    await service.close()
