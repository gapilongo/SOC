"""Sources, alert ingestion, listing/pagination, lifecycle and aggregates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.db.errors import Conflict, InvalidCursor, InvalidTransition, InvalidValue, NotFound, ReferenceNotFound
from lg_sotf.db.pagination import encode_cursor
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.alerts import ALERT_TRANSITIONS, DEFAULT_SEARCH_WINDOW
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert, new_alert

pytestmark = pytest.mark.asyncio

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


class TestSources:
    async def test_crud_and_conflict(self, repos: Repositories) -> None:
        src = await repos.sources.create(
            TENANT_A,
            "splunk",
            "Splunk prod",
            source_id="splunk-prod",
            config={"url": "https://s"},
            secret_ciphertext="gAAAA-cipher",
            poll_interval_s=30,
        )
        assert src.id == "splunk-prod" and src.health == "unknown"
        assert "gAAAA" not in repr(src)
        with pytest.raises(Conflict):
            await repos.sources.create(TENANT_A, "wazuh", "Splunk prod")
        with pytest.raises(Conflict):
            await repos.sources.create(TENANT_A, "wazuh", "Other name", source_id="splunk-prod")
        await repos.sources.create(TENANT_B, "splunk", "Splunk prod")
        src = await repos.sources.update(TENANT_A, "splunk-prod", enabled=False, config={"url": "https://t"})
        assert not src.enabled and src.config == {"url": "https://t"}
        assert [s.id for s in await repos.sources.list(TENANT_A, enabled=False)] == ["splunk-prod"]
        assert await repos.sources.list(TENANT_A, type="wazuh") == []
        with pytest.raises(ValueError):
            await repos.sources.create(TENANT_A, "elastic", "x")
        assert await repos.sources.delete(TENANT_A, "splunk-prod") is True
        with pytest.raises(NotFound):
            await repos.sources.get(TENANT_A, "splunk-prod")

    async def test_source_ids_are_scoped_per_tenant(self, repos: Repositories) -> None:
        """One tenant choosing an id neither blocks nor reveals another tenant's source."""
        a = await repos.sources.create(TENANT_A, "splunk", "a-src", source_id="splunk-prod")
        b = await repos.sources.create(TENANT_B, "qradar", "b-src", source_id="splunk-prod")
        assert (a.tenant_id, b.tenant_id) == (TENANT_A, TENANT_B)
        assert (await repos.sources.get(TENANT_A, "splunk-prod")).type == "splunk"
        assert (await repos.sources.get(TENANT_B, "splunk-prod")).type == "qradar"
        await repos.sources.update(TENANT_B, "splunk-prod", enabled=False)
        assert (await repos.sources.get(TENANT_A, "splunk-prod")).enabled
        assert await repos.sources.delete(TENANT_B, "splunk-prod") is True
        assert (await repos.sources.get(TENANT_A, "splunk-prod")).name == "a-src"

    async def test_cursor_only_moves_forward(self, repos: Repositories) -> None:
        await repos.sources.create(TENANT_A, "sentinel", "S", source_id="s1")
        assert await repos.sources.set_cursor(TENANT_A, "s1", {"after": "b"}, T0 + timedelta(minutes=5))
        assert not await repos.sources.set_cursor(TENANT_A, "s1", {"after": "a"}, T0)
        assert await repos.sources.set_cursor(TENANT_A, "s1", {"after": "c"}, T0 + timedelta(minutes=5))
        src = await repos.sources.get(TENANT_A, "s1")
        assert src.cursor == {"after": "c"} and src.cursor_watermark == T0 + timedelta(minutes=5)
        with pytest.raises(NotFound):
            await repos.sources.set_cursor(TENANT_A, "missing", {}, T0)

    async def test_poll_results_drive_health_and_backoff(self, repos: Repositories) -> None:
        await repos.sources.create(TENANT_A, "qradar", "Q", source_id="q1", poll_interval_s=60)
        src = await repos.sources.record_poll_result(TENANT_A, "q1", ok=True, polled_at=T0)
        assert src.health == "healthy" and src.next_poll_at == T0 + timedelta(seconds=60)
        expected_delays = [120, 240, 480]
        for n, delay in enumerate(expected_delays, start=1):
            src = await repos.sources.record_poll_result(TENANT_A, "q1", ok=False, error="HTTP 503", polled_at=T0)
            assert src.consecutive_failures == n
            assert src.next_poll_at == T0 + timedelta(seconds=delay)
            assert src.last_error == "HTTP 503"
        assert src.health == "failing"
        src = await repos.sources.record_poll_result(TENANT_A, "q1", ok=False, polled_at=T0, max_backoff_s=300)
        assert src.next_poll_at == T0 + timedelta(seconds=300)
        src = await repos.sources.record_poll_result(TENANT_A, "q1", ok=True, polled_at=T0)
        assert (src.health, src.consecutive_failures, src.last_error) == ("healthy", 0, None)

    async def test_due_sources_across_tenants(self, repos: Repositories) -> None:
        await repos.sources.create(TENANT_A, "splunk", "due-a", source_id="due-a")
        await repos.sources.create(TENANT_B, "wazuh", "due-b", source_id="due-b")
        await repos.sources.create(TENANT_A, "webhook", "push", source_id="push")
        await repos.sources.create(TENANT_A, "splunk", "off", source_id="off", enabled=False)
        await repos.sources.create(TENANT_A, "splunk", "later", source_id="later")
        await repos.sources.record_poll_result(TENANT_A, "later", ok=True, polled_at=T0)
        due = await repos.sources.list_due_sources_all_tenants(now=T0 + timedelta(seconds=1))
        assert {s.id for s in due} == {"due-a", "due-b"}
        await repos.tenants.set_status(TENANT_B, "suspended")
        due = await repos.sources.list_due_sources_all_tenants(now=T0 + timedelta(hours=1))
        assert {s.id for s in due} == {"due-a", "later"}


class TestAlertInsert:
    async def test_insert_many_if_absent_dedups(self, repos: Repositories) -> None:
        a1, a2 = new_alert("e1"), new_alert("e2")
        dup_in_batch = new_alert("e1")
        ids = await repos.alerts.insert_many_if_absent(TENANT_A, [a1, a2, dup_in_batch])
        assert ids == [a1.id, a2.id]
        again = await repos.alerts.insert_many_if_absent(TENANT_A, [new_alert("e2"), new_alert("e3")])
        assert len(again) == 1
        other_source = new_alert("e1", source_id="crowdstrike")
        assert await repos.alerts.insert_many_if_absent(TENANT_A, [other_source]) == [other_source.id]
        other_tenant = new_alert("e1")
        assert await repos.alerts.insert_many_if_absent(TENANT_B, [other_tenant]) == [other_tenant.id]
        existing = await repos.alerts.ids_by_source_keys(TENANT_A, "splunk-prod", ["e1", "e2", "zz"])
        assert existing == {"e1": a1.id, "e2": a2.id}
        assert await repos.alerts.insert_many_if_absent(TENANT_A, []) == []

    async def test_unstorable_characters_do_not_fail_the_batch(self, repos: Repositories) -> None:
        """NUL and lone surrogates in attacker-controlled content are replaced, not fatal."""
        poisoned = new_alert(
            "nul-1",
            title="evil\x00title",
            raw={"x": "a\u0000b", "k\x00ey": ["\ud800", {"deep": "c\x00"}], "slash": "\\u0000 literal"},
            normalized={"cmd": "rm\x00-rf"},
            summary={"note": "\x00"},
        )
        clean = new_alert("nul-2")
        ids = await repos.alerts.insert_many_if_absent(TENANT_A, [poisoned, clean])
        assert ids == [poisoned.id, clean.id]
        got = await repos.alerts.get(TENANT_A, poisoned.id)
        assert got.title == "evil\ufffdtitle"
        assert got.raw == {"x": "a\ufffdb", "k\ufffdey": ["?", {"deep": "c\ufffd"}], "slash": "\\u0000 literal"}
        assert got.normalized == {"cmd": "rm\ufffd-rf"} and got.summary == {"note": "\ufffd"}
        page = await repos.alerts.list(TENANT_A, q="evil\x00title")
        assert [a.id for a in page.items] == [poisoned.id]

    async def test_stored_fields(self, repos: Repositories) -> None:
        occurred = T0 - timedelta(minutes=3)
        alert = new_alert("s1", occurred_at=occurred, category="identity", case_key="c-1")
        await repos.alerts.insert_many_if_absent(TENANT_A, [alert])
        got = await repos.alerts.get(TENANT_A, alert.id)
        assert got.status == "new" and got.disposition is None
        assert got.occurred_at == occurred and got.raw == {"vendor": "test"}
        assert got.category == "identity" and got.case_key == "c-1"
        with pytest.raises(ValueError):
            new_alert("bad", severity="urgent")
        with pytest.raises(ValueError):
            new_alert("bad", occurred_at=datetime(2026, 1, 1))


class TestAlertListing:
    async def test_keyset_pagination_is_stable_under_inserts_and_ties(self, repos: Repositories) -> None:
        rows = [new_alert(f"p{i:02d}", ingested_at=T0 + timedelta(seconds=i // 3)) for i in range(25)]
        await repos.alerts.insert_many_if_absent(TENANT_A, rows)
        expected = [a.id for a in sorted(rows, key=lambda a: (a.ingested_at, a.id), reverse=True)]

        seen: list[str] = []
        cursor = None
        pages = 0
        while True:
            page = await repos.alerts.list(TENANT_A, limit=7, cursor=cursor)
            seen += [a.id for a in page.items]
            pages += 1
            if pages == 1:
                newer = [new_alert(f"late{i}", ingested_at=T0 + timedelta(hours=1)) for i in range(5)]
                await repos.alerts.insert_many_if_absent(TENANT_A, newer)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        assert seen == expected
        assert pages == 4

        items, next_cursor = await repos.alerts.list(TENANT_A, limit=200)
        assert len(items) == 30 and next_cursor is None

    async def test_filters(self, repos: Repositories) -> None:
        now = datetime.now(UTC)
        a = await make_alert(
            repos, TENANT_A, source_alert_id="f1", title="Brute force 100% on host_1", severity="critical"
        )
        b = await make_alert(
            repos, TENANT_A, source_alert_id="f2", title="Malware beacon", severity="low", source_id="edr"
        )
        c = await make_alert(
            repos,
            TENANT_A,
            source_alert_id="f3",
            title="Brute force attempt",
            severity="high",
            ingested_at=now - timedelta(days=2),
        )
        await repos.alerts.update_status(TENANT_A, b, "queued")
        await repos.alerts.update(TENANT_A, c, disposition="benign")

        async def ids(**kw: object) -> set:
            return {x.id for x in (await repos.alerts.list(TENANT_A, **kw)).items}  # type: ignore[arg-type]

        assert await ids(status="queued") == {b}
        assert await ids(status=["new", "queued"]) == {a, b, c}
        assert await ids(severity=["critical", "high"]) == {a, c}
        assert await ids(disposition="benign") == {c}
        assert await ids(source_id="edr") == {b}
        assert await ids(q="brute FORCE") == {a, c}
        assert await ids(q="100%") == {a}
        assert await ids(q="host_1") == {a}
        assert await ids(q="%") == {a}
        assert await ids(q="   ") == {a, b, c}
        assert await ids(since=now - timedelta(days=1)) == {a, b}
        assert await ids(until=now - timedelta(days=1)) == {c}
        with pytest.raises(ValueError):
            await repos.alerts.list(TENANT_A, status="bogus")
        with pytest.raises(ValueError):
            await repos.alerts.list(TENANT_A, limit=0)

    async def test_text_search_is_bounded_to_a_time_window(self, repos: Repositories) -> None:
        now = datetime.now(UTC)
        recent = await make_alert(repos, TENANT_A, source_alert_id="w1", title="Beacon to C2")
        old = await make_alert(
            repos, TENANT_A, source_alert_id="w2", title="Beacon to C2", ingested_at=now - timedelta(days=60)
        )

        async def ids(**kw: object) -> set:
            return {x.id for x in (await repos.alerts.list(TENANT_A, **kw)).items}  # type: ignore[arg-type]

        assert await ids(q="beacon") == {recent}
        assert await ids(q="beacon", since=now - timedelta(days=90)) == {recent, old}
        assert await ids(q="beacon", until=now - timedelta(days=45)) == {old}
        assert await ids() == {recent, old}
        with pytest.raises(ValueError):
            await repos.alerts.list(TENANT_A, q="beacon", since=now - timedelta(days=365))
        assert DEFAULT_SEARCH_WINDOW == timedelta(days=30)

    async def test_invalid_cursor(self, repos: Repositories) -> None:
        now = datetime.now(UTC)
        for bad in ("not-base64!!", "eyJ2IjoyfQ", "a" * 600, encode_cursor(now, 42), encode_cursor(now, "x" * 300)):
            with pytest.raises(InvalidCursor):
                await repos.alerts.list(TENANT_A, cursor=bad)


class TestAlertLifecycle:
    async def test_happy_path_and_closed_at(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        for status in ("queued", "processing", "waiting_human", "processing"):
            assert (await repos.alerts.update_status(TENANT_A, alert_id, status)).status == status
        closed = await repos.alerts.update_status(TENANT_A, alert_id, "closed", now=T0)
        assert closed.closed_at == T0
        reopened = await repos.alerts.update_status(TENANT_A, alert_id, "queued")
        assert reopened.closed_at is None

    async def test_illegal_transitions_raise(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        with pytest.raises(InvalidTransition) as info:
            await repos.alerts.update_status(TENANT_A, alert_id, "closed")
        assert (info.value.current, info.value.target) == ("new", "closed")
        with pytest.raises(NotFound):
            await repos.alerts.update_status(TENANT_A, "missing", "queued")
        with pytest.raises(ValueError):
            await repos.alerts.update_status(TENANT_A, alert_id, "resolved")

    async def test_same_status_is_noop(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.alerts.update_status(TENANT_A, alert_id, "queued")
        assert (await repos.alerts.update_status(TENANT_A, alert_id, "queued")).status == "queued"

    async def test_transition_table_matches_contract(self) -> None:
        assert ALERT_TRANSITIONS["new"] == {"queued"}
        assert ALERT_TRANSITIONS["queued"] >= {"processing"}
        assert ALERT_TRANSITIONS["processing"] == {"waiting_human", "waiting_approval", "closed", "failed"}
        assert ALERT_TRANSITIONS["waiting_human"] == {"processing"}
        assert ALERT_TRANSITIONS["waiting_approval"] == {"processing"}

    async def test_update_fields_and_summary_merge(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        user = await repos.users.create(TENANT_A, "an@x.io", "analyst")
        await repos.alerts.update(TENANT_A, alert_id, summary={"verdict": "tp", "indicators": [1]})
        alert = await repos.alerts.update(
            TENANT_A,
            alert_id,
            confidence=87.5,
            threat_score=90,
            priority=2,
            disposition="malicious",
            assigned_to=user.id,
            summary={"indicators": [1, 2], "llm_usage": {"tokens": 10}},
        )
        assert alert.summary == {"verdict": "tp", "indicators": [1, 2], "llm_usage": {"tokens": 10}}
        assert (alert.confidence, alert.threat_score, alert.priority) == (87.5, 90.0, 2)
        assert alert.disposition == "malicious" and alert.assigned_to == user.id
        alert = await repos.alerts.update(TENANT_A, alert_id, disposition=None, assigned_to=None)
        assert alert.disposition is None and alert.assigned_to is None
        with pytest.raises(ValueError):
            await repos.alerts.update(TENANT_A, alert_id, disposition="evil")
        with pytest.raises(NotFound):
            await repos.alerts.update(TENANT_A, "missing", priority=1)

    async def test_cross_tenant_assignee_rejected(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        outsider = await repos.users.create(TENANT_B, "out@x.io", "analyst")
        with pytest.raises(ReferenceNotFound) as info:
            await repos.alerts.update(TENANT_A, alert_id, assigned_to=outsider.id)
        assert info.value.resource == "user" and str(outsider.id) not in str(info.value)

    async def test_constraint_violations_are_domain_errors(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        with pytest.raises(InvalidValue):
            await repos.alerts.update(TENANT_A, alert_id, priority=50)
        with pytest.raises(InvalidValue):
            await repos.alerts.update(TENANT_A, alert_id, confidence=101.0)
        assert (await repos.alerts.get(TENANT_A, alert_id)).priority is None


class TestAggregates:
    async def test_dashboard_counts(self, repos: Repositories) -> None:
        a = await make_alert(repos, TENANT_A, severity="high")
        b = await make_alert(repos, TENANT_A, severity="high")
        await make_alert(repos, TENANT_A, severity="low")
        await make_alert(repos, TENANT_A, severity="low", ingested_at=T0 - timedelta(days=30))
        await make_alert(repos, TENANT_B, severity="critical")
        await repos.alerts.update_status(TENANT_A, a, "queued")
        await repos.alerts.update(TENANT_A, b, disposition="benign")
        counts = await repos.alerts.dashboard_counts(TENANT_A, T0 - timedelta(days=1))
        assert counts.total == 3
        assert counts.by_status == {"new": 2, "queued": 1}
        assert counts.by_severity == {"high": 2, "low": 1}
        assert counts.by_disposition == {"benign": 1, "undecided": 2}

    async def test_response_times(self, db: Database, repos: Repositories) -> None:
        a = await make_alert(repos, TENANT_A, ingested_at=T0)
        b = await make_alert(repos, TENANT_A, ingested_at=T0)
        for alert_id, minutes in ((a, 10), (b, 30)):
            for status in ("queued", "processing"):
                await repos.alerts.update_status(TENANT_A, alert_id, status)
            await repos.alerts.update_status(TENANT_A, alert_id, "closed", now=T0 + timedelta(minutes=minutes))
        c = await make_alert(repos, TENANT_A)
        esc, _ = await repos.escalations.create_or_attach(TENANT_A, c, reason="r")
        user = await repos.users.create(TENANT_A, "u@x.io", "analyst")
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute("UPDATE escalations SET created_at = $1 WHERE id = $2", T0, esc.id)
        await repos.escalations.claim(TENANT_A, esc.id, user.id, esc.version, now=T0 + timedelta(minutes=4))
        times = await repos.alerts.response_times(TENANT_A, T0 - timedelta(hours=1))
        assert times.resolved == 2 and times.mttr_s == pytest.approx(20 * 60)
        assert times.acknowledged == 1 and times.mtta_s == pytest.approx(4 * 60)
        empty = await repos.alerts.response_times(TENANT_B, T0)
        assert empty.mtta_s is None and empty.mttr_s is None and empty.resolved == 0
