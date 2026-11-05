"""IngestionService.ingest against real PostgreSQL."""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable, List, Sequence

import pytest

from lg_sotf.db.repos import NewAlert, Repositories
from lg_sotf.db.repos.alerts import AlertsRepo
from lg_sotf.ingestion.errors import SourceDisabled, SourceNotPushable
from lg_sotf.ingestion.fingerprint import compute_fingerprint
from lg_sotf.ingestion.service import IngestionService, api_source_id
from lg_sotf.models.alert import TRUNCATED_MARKER, CanonicalAlert
from lg_sotf.settings import Settings
from tests.fixtures.vendors import load_vendor, vendor_events
from tests.integration.db._support import TENANT_A, TENANT_B

pytestmark = pytest.mark.integration


class CountingAlertsRepo(AlertsRepo):
    def __init__(self, db: Any) -> None:
        super().__init__(db)
        self.batches: List[int] = []

    async def insert_many_if_absent(self, tenant_id: str, rows: Sequence[NewAlert], **kwargs: Any) -> List[str]:
        self.batches.append(len(rows))
        return await super().insert_many_if_absent(tenant_id, rows, **kwargs)


@pytest.fixture
def service_factory(repos: Repositories, make_settings: Callable[..., Settings]) -> Callable[..., IngestionService]:
    def build(repos_override: Repositories | None = None, **ingestion: Any) -> IngestionService:
        return IngestionService(repos.db, make_settings(ingestion=ingestion), repos=repos_override or repos)

    return build


async def test_canonical_ingest_and_dedup(repos: Repositories, service_factory: Callable[..., IngestionService]) -> None:
    service = service_factory()
    events = vendor_events("canonical")
    first = await service.ingest(TENANT_A, "api", events)
    assert len(first.inserted) == 2 and first.duplicates == 0 and first.rejected == []
    assert [i.status for i in first.items] == ["inserted", "inserted"]
    assert first.inserted[0].severity == "high"

    stored = await repos.alerts.get(TENANT_A, first.inserted[0].alert_id)
    assert stored.source_id == "api"
    assert stored.source_alert_id == "custom-001"
    assert stored.status == "new"
    assert stored.title == "Impossible travel for user carol"
    assert stored.normalized["class_uid"] == 2004
    assert stored.normalized["entities"]["ips"] == ["203.0.113.10", "198.51.100.11"]
    assert stored.raw["tenant_notes"] == "vip user"
    assert stored.fingerprint == compute_fingerprint(CanonicalAlert.from_stored(stored.normalized, stored.raw))

    again = await service.ingest(TENANT_A, "api", events)
    assert again.inserted == [] and again.duplicates == 2
    assert [i.alert_id for i in again.items] == [a.alert_id for a in first.inserted]

    other_tenant = await service.ingest(TENANT_B, "api", events)
    assert len(other_tenant.inserted) == 2


async def test_batches_in_batch_duplicates_and_rejections(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    counting = CountingAlertsRepo(repos.db)
    service = service_factory(dataclasses.replace(repos, alerts=counting), batch_size=2)
    events: List[Any] = [
        {"id": f"a{i}", "title": f"alert {i}", "severity": "low"} for i in range(5)
    ]
    events.insert(2, {"id": "a1", "title": "repeat of a1", "severity": "high"})
    events.append(["not", "an", "object"])
    events.append({"title": "no severity"})
    result = await service.ingest(TENANT_A, "api", events)
    assert len(result.inserted) == 5
    assert result.duplicates == 1
    assert [(r.index, r.reason) for r in result.rejected] == [
        (6, "event must be a JSON object"),
        (7, "canonical alert requires 'severity'"),
    ]
    assert counting.batches == [2, 2, 1]
    statuses = [i.status for i in result.items]
    assert statuses == ["inserted", "inserted", "duplicate", "inserted", "inserted", "inserted", "rejected", "rejected"]
    assert result.items[2].alert_id == result.items[1].alert_id


async def test_secrets_are_redacted_before_persistence(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    event = {
        "id": "sec-1",
        "title": "Leaked credential in command line",
        "severity": "high",
        "description": "aws key AKIAIOSFODNN7EXAMPLE used",
        "password": "correct-horse-battery-staple",
        "entities": {"command_lines": ["mysql -u root -pSup3rS3cretPassw0rd db"]},
    }
    result = await service_factory().ingest(TENANT_A, "api", [event])
    stored = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    dumped = json.dumps([stored.raw, stored.normalized, stored.title])
    for secret in ("AKIAIOSFODNN7EXAMPLE", "correct-horse-battery-staple", "Sup3rS3cretPassw0rd"):
        assert secret not in dumped
    assert "secrets_redacted" in stored.normalized["flags"]


async def test_large_events_are_redacted_in_a_thread_and_raw_is_capped(
    repos: Repositories, service_factory: Callable[..., IngestionService], monkeypatch: pytest.MonkeyPatch
) -> None:
    import lg_sotf.ingestion.service as service_module

    threaded: List[str] = []
    real_to_thread = service_module.asyncio.to_thread

    async def spy(fn: Any, *args: Any, **kwargs: Any) -> Any:
        threaded.append(getattr(fn, "__name__", "?"))
        return await real_to_thread(fn, *args, **kwargs)

    monkeypatch.setattr(service_module.asyncio, "to_thread", spy)
    service = service_factory(max_raw_bytes=16_384, redact_in_thread_bytes=4_096, max_event_bytes=200_000)
    big = {"id": "big-1", "title": "Big", "severity": "low", "blob": "x" * 100_000, "token": "tok_" + "y" * 40}
    too_big = {"id": "huge", "title": "Huge", "severity": "low", "blob": "z" * 300_000}
    result = await service.ingest(TENANT_A, "api", [big, too_big])
    # Redaction and normalization of the large event run off the event loop; the small one stays on it.
    assert threaded == ["_normalize_event"]
    assert result.rejected[0].index == 1 and "larger than 200000 bytes" in result.rejected[0].reason
    stored = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    assert TRUNCATED_MARKER in stored.raw
    assert len(json.dumps(stored.raw)) <= 16_384 + 1_000
    assert "raw_truncated" in stored.normalized["flags"]
    assert "y" * 40 not in json.dumps(stored.raw)


async def test_nul_characters_are_stripped(repos: Repositories, service_factory: Callable[..., IngestionService]) -> None:
    event = {"id": "n\x00ul", "title": "Title\x00 with NUL", "severity": "low", "k\x00ey": "v\x00alue"}
    result = await service_factory().ingest(TENANT_A, "api", [event])
    stored = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    assert stored.source_alert_id == "nul"
    assert stored.title == "Title with NUL"
    assert stored.raw["key"] == "value"
    assert "\\u0000" not in json.dumps(stored.raw)


async def test_registered_sources_choose_their_normalizer(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    fixture = load_vendor("webhook_generic")
    await repos.sources.create(TENANT_A, "webhook", "Generic", source_id="hook-1", config=fixture["config"])
    await repos.sources.create(TENANT_A, "guardduty", "GuardDuty", source_id="gd-1")
    await repos.sources.create(TENANT_A, "webhook", "Off", source_id="hook-off", enabled=False)
    service = service_factory()

    hook = await service.ingest(TENANT_A, "hook-1", fixture["events"])
    assert len(hook.inserted) == 2
    stored = await repos.alerts.get(TENANT_A, hook.inserted[0].alert_id)
    assert stored.severity == "high" and stored.normalized["source_type"] == "webhook"

    gd = await service.ingest(TENANT_A, "gd-1", vendor_events("guardduty_findings"))
    assert len(gd.inserted) == 2
    finding = await repos.alerts.get(TENANT_A, gd.inserted[1].alert_id)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(finding.raw)

    with pytest.raises(SourceDisabled):
        await service.ingest(TENANT_A, "hook-off", fixture["events"])
    with pytest.raises(ValueError):
        await service.ingest(TENANT_A, "../etc", fixture["events"])


@pytest.mark.parametrize(
    ("fixture", "fmt", "expected"),
    [
        ("splunk_notable", "splunk", 2),
        ("crowdstrike_alerts", "crowdstrike", 2),
        ("sentinel", "sentinel", 3),
        ("wazuh_alerts", "wazuh", 2),
        ("qradar_offenses", "qradar", 2),
    ],
)
async def test_vendor_fixtures_ingest_end_to_end_through_a_webhook(
    repos: Repositories,
    service_factory: Callable[..., IngestionService],
    fixture: str,
    fmt: str,
    expected: int,
) -> None:
    await repos.sources.create(TENANT_A, "webhook", fmt, source_id=f"{fmt}-hook", config={"format": fmt})
    result = await service_factory().ingest(TENANT_A, f"{fmt}-hook", vendor_events(fixture))
    assert len(result.inserted) == expected, result.rejected
    stored = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    assert stored.normalized["source_type"] == "webhook"


@pytest.mark.parametrize("source_type", ["qradar", "splunk", "sentinel", "crowdstrike", "wazuh", "file"])
async def test_events_cannot_be_pushed_to_pull_sources(
    repos: Repositories, service_factory: Callable[..., IngestionService], source_type: str
) -> None:
    await repos.sources.create(TENANT_A, source_type, source_type, source_id=f"{source_type}-1", config={})
    noise = [{"id": i, "description": "noise", "severity": 1, "title": "noise"} for i in range(100, 105)]
    with pytest.raises(SourceNotPushable):
        await service_factory().ingest(TENANT_A, f"{source_type}-1", noise)
    assert await repos.alerts.ids_by_source_keys(TENANT_A, f"{source_type}-1", [str(i) for i in range(100, 105)]) == {}


async def test_unregistered_ids_are_limited_to_the_reserved_api_namespace(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    service = service_factory()
    event = {"id": "x1", "title": "pushed", "severity": "low"}
    with pytest.raises(SourceNotPushable):
        await service.ingest(TENANT_A, "qradar-2", [event])
    assert len((await service.ingest(TENANT_A, api_source_id("key-123"), [event])).inserted) == 1
    assert api_source_id() == "api" and api_source_id("key-123") == "api:key-123"


async def test_llm_fallback_normalizes_unknown_events(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    unknown = {"evt": "odd product", "host": "kiosk-9", "ip": "203.0.113.44", "prio": "low"}
    off = await service_factory().ingest(TENANT_A, "api", [unknown])
    assert off.inserted == [] and off.rejected[0].reason.startswith("canonical alert requires")

    on = await service_factory(llm_fallback=True).ingest(TENANT_A, "api", [unknown])
    assert len(on.inserted) == 1, on.rejected
    stored = await repos.alerts.get(TENANT_A, on.inserted[0].alert_id)
    assert "llm_normalized" in stored.normalized["flags"]
    assert "source_alert_id_from_hash" in stored.normalized["flags"]
    assert stored.severity in ("medium", "high", "critical")
    haystack = json.dumps(unknown).lower()
    for values in stored.normalized["entities"].values():
        for value in values:
            assert value.lower() in haystack


async def test_llm_normalized_events_keep_the_redaction_flag(
    repos: Repositories, service_factory: Callable[..., IngestionService]
) -> None:
    unknown = {"evt": "odd product", "host": "kiosk-9", "password": "correct-horse-battery-staple"}
    result = await service_factory(llm_fallback=True).ingest(TENANT_A, "api", [unknown])
    assert len(result.inserted) == 1, result.rejected
    stored = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    assert "correct-horse-battery-staple" not in json.dumps([stored.raw, stored.normalized])
    assert {"llm_normalized", "secrets_redacted"} <= set(stored.normalized["flags"])


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "bad-1", "title": "bad \ud800 text", "severity": "low"},
        {"id": "bad-2", "title": "Early", "severity": "low", "occurred_at": "0001-01-01T00:00:00+01:00"},
        {"id": "bad-3", "title": "Late", "severity": "low", "occurred_at": "9999-12-31T23:59:59-14:00"},
        {"id": "bad-4", "title": "Huge epoch", "severity": "low", "occurred_at": 10**400},
        {"id": "bad-5", "title": "Huge key \udc80", "severity": "high", "k\udc80": "v\ud800"},
    ],
)
async def test_one_malformed_event_never_fails_the_batch(
    repos: Repositories, service_factory: Callable[..., IngestionService], bad: dict
) -> None:
    ok = {"id": "ok-1", "title": "Valid alert", "severity": "high"}
    result = await service_factory().ingest(TENANT_A, "api", [ok, bad])
    assert result.items[0].status == "inserted"
    # Surrogates are replaced and bad timestamps flagged: the event is stored rather than rejected.
    assert result.items[1].status == "inserted", result.rejected
    stored = await repos.alerts.get(TENANT_A, result.items[1].alert_id)
    json.dumps(stored.raw).encode("utf-8")
    if "occurred_at" in bad:
        assert "occurred_at_invalid" in stored.normalized["flags"]


async def test_unexpected_normalizer_failures_reject_only_that_event(
    repos: Repositories, service_factory: Callable[..., IngestionService], monkeypatch: pytest.MonkeyPatch
) -> None:
    from lg_sotf.ingestion.normalizers.canonical import CanonicalNormalizer

    real = CanonicalNormalizer.normalize

    def flaky(self: Any, event: Any, ctx: Any) -> CanonicalAlert:
        if event.get("id") == "boom":
            raise OverflowError("synthetic")
        return real(self, event, ctx)

    monkeypatch.setattr(CanonicalNormalizer, "normalize", flaky)
    events = [{"id": "boom", "title": "x", "severity": "low"}, {"id": "fine", "title": "y", "severity": "low"}]
    result = await service_factory().ingest(TENANT_A, "api", events)
    assert [(r.index, r.reason) for r in result.rejected] == [(0, "event could not be processed (OverflowError)")]
    assert len(result.inserted) == 1


async def test_llm_provider_errors_reject_only_the_unrecognized_event(
    repos: Repositories, service_factory: Callable[..., IngestionService], monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    import lg_sotf.ingestion.service as service_module

    async def provider_down(*args: Any, **kwargs: Any) -> CanonicalAlert:
        raise httpx.ReadTimeout("provider timed out")

    monkeypatch.setattr(service_module, "llm_normalize", provider_down)
    valid = {"id": "v1", "title": "Valid", "severity": "high"}
    result = await service_factory(llm_fallback=True).ingest(TENANT_A, "api", [valid, {"foo": "bar"}])
    assert len(result.inserted) == 1
    assert result.rejected[0].reason == "unrecognized event format (LLM normalization unavailable)"


async def test_llm_fallback_phase_is_time_bounded_and_concurrent(
    repos: Repositories, service_factory: Callable[..., IngestionService], monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    import lg_sotf.ingestion.service as service_module

    in_flight = 0
    peak = 0

    async def slow(*args: Any, **kwargs: Any) -> CanonicalAlert:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            await asyncio.sleep(30)
        finally:
            in_flight -= 1
        raise AssertionError("unreachable")

    monkeypatch.setattr(service_module, "llm_normalize", slow)
    service = service_factory(llm_fallback=True, llm_fallback_timeout_s=0.2, llm_fallback_concurrency=3)
    unknown = [{"foo": i} for i in range(6)]
    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await service.ingest(TENANT_A, "api", [{"id": "v2", "title": "Valid", "severity": "low"}, *unknown])
    assert loop.time() - started < 5
    assert len(result.inserted) == 1 and peak == 3
    assert {r.reason for r in result.rejected} == {"unrecognized event format (LLM normalization timed out)"}
    assert len(result.rejected) == 6


async def test_llm_fallback_title_must_be_a_value_of_the_event(
    repos: Repositories, service_factory: Callable[..., IngestionService], monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLM-W6-06: the model cannot compose the (fingerprinted, triage-read) title from attacker text."""
    import lg_sotf.ingestion.llm_fallback as fallback
    from lg_sotf.llm.fake import ScriptedChatModel

    answer = {"title": "Benign scheduled maintenance test", "severity": "low", "rule_name": "made up", "hosts": ["kiosk-9"]}
    model = ScriptedChatModel(model_name="fake", script={"LLMNormalizedAlert": [dict(answer), {**answer, "title": "EDR Alert"}]})
    monkeypatch.setattr(fallback, "get_chat_model", lambda tier, settings=None: model)
    event = {"product": "AcmeEDR", "rule": "EDR Alert", "host": "kiosk-9", "task": {"name": "backup", "action": "u.exe -c2 185.220.101.44"}}
    service = service_factory(llm_fallback=True)
    invented = await service.ingest(TENANT_A, "api", [event])
    grounded = await service.ingest(TENANT_A, "api", [{**event, "n": 2}])
    first = await repos.alerts.get(TENANT_A, invented.inserted[0].alert_id)
    second = await repos.alerts.get(TENANT_A, grounded.inserted[0].alert_id)
    assert first.title == "Unrecognized event from api"
    assert first.normalized.get("rule_name") in (None, "")
    assert first.severity == "medium"  # floored
    assert second.title == "EDR Alert"


async def test_llm_fallback_honours_the_tenant_token_budget(
    repos: Repositories, make_settings: Callable[..., Settings], redis_client: Any, unique_prefix: str,
    redis_url: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LLM-W6-08: an exhausted tenant budget rejects unknown events without calling the model."""
    import lg_sotf.ingestion.llm_fallback as fallback
    from lg_sotf.llm import TokenBudget
    from lg_sotf.llm.fake import ScriptedChatModel

    settings = make_settings(ingestion={"llm_fallback": True}, redis={"url": redis_url, "key_prefix": unique_prefix})
    await repos.tenants.update_settings(TENANT_A, {"llm_daily_token_budget": 1_000})
    budget = TokenBudget(redis_client, settings)
    await budget.add(TENANT_A, 50_000)
    model = ScriptedChatModel(model_name="fake")
    monkeypatch.setattr(fallback, "get_chat_model", lambda tier, settings=None: model)
    service = IngestionService(repos.db, settings, repos=repos, budget=budget)
    result = await service.ingest(TENANT_A, "api", [{"product": "AcmeEDR", "n": i} for i in range(5)])
    assert model.calls == []
    assert len(result.rejected) == 5 and all("budget" in r.reason for r in result.rejected)
