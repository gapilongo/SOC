"""Action ledger, suppression rules, indicator sightings and LLM usage."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import asyncpg
import pytest

from lg_sotf.db.errors import AlreadyInState, InvalidCursor, InvalidTransition, NotFound, ReferenceNotFound
from lg_sotf.db.pagination import encode_cursor
from lg_sotf.db.repos import LLMUsageDelta, Repositories, action_idempotency_key
from lg_sotf.db.repos.actions import ACTION_TRANSITIONS
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class TestActionLedger:
    async def test_idempotency_key_is_deterministic_and_unambiguous(self) -> None:
        k = action_idempotency_key("t", "a", "block_ip", "1.2.3.4")
        assert k == action_idempotency_key("t", "a", "block_ip", "1.2.3.4") and len(k) == 64
        assert action_idempotency_key("t", "a:b", "c", "d") != action_idempotency_key("t", "a", "b:c", "d")

    async def test_propose_is_idempotent(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        a, created = await repos.actions.propose(
            TENANT_A,
            alert_id,
            "block_ip",
            "203.0.113.9",
            "high",
            params={"duration_h": 24},
            requested_by="agent:response",
        )
        assert created and a.status == "proposed" and a.params == {"duration_h": 24}
        b, created = await repos.actions.propose(TENANT_A, alert_id, "block_ip", "203.0.113.9", "low")
        assert not created and b.id == a.id and b.risk_level == "high"
        other = await make_alert(repos, TENANT_A)
        c, created = await repos.actions.propose(TENANT_A, other, "block_ip", "203.0.113.9", "high")
        assert created and c.id != a.id

    async def test_concurrent_proposals_create_one_row(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        results = await asyncio.gather(
            *(repos.actions.propose(TENANT_A, alert_id, "isolate_host", "ws-12", "high") for _ in range(6))
        )
        assert len({a.id for a, _ in results}) == 1 and sum(c for _, c in results) == 1

    async def test_initial_status_options(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        blocked, _ = await repos.actions.propose(
            TENANT_A,
            alert_id,
            "block_ip",
            "10.0.0.1",
            "medium",
            status="blocked",
            blocked_reason="private range",
        )
        assert blocked.status == "blocked" and blocked.blocked_reason == "private range"
        approved, _ = await repos.actions.propose(TENANT_A, alert_id, "disable_user", "bob", "low", status="approved")
        assert approved.approved_at is not None
        with pytest.raises(ValueError):
            await repos.actions.propose(TENANT_A, alert_id, "x", "y", "low", status="succeeded")
        with pytest.raises(ValueError):
            await repos.actions.propose(TENANT_A, alert_id, "x", "y", "extreme")

    async def test_legal_path_and_stamps(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        a, _ = await repos.actions.propose(TENANT_A, alert_id, "block_ip", "198.51.100.1", "medium")
        a = await repos.actions.transition(TENANT_A, a.id, "awaiting_approval")
        a = await repos.actions.transition(TENANT_A, a.id, "approved", approved_by="user:1", now=T0)
        assert a.approved_at == T0 and a.approved_by == "user:1"
        a = await repos.actions.transition(TENANT_A, a.id, "executing", connector="webhook", now=T0)
        assert a.executed_at == T0 and a.connector == "webhook"
        a = await repos.actions.transition(TENANT_A, a.id, "failed", result={"error": "HTTP 502"})
        a = await repos.actions.transition(TENANT_A, a.id, "executing")
        a = await repos.actions.transition(TENANT_A, a.id, "succeeded", result={"ticket": "T-1"})
        assert a.status == "succeeded" and a.result == {"ticket": "T-1"}
        with pytest.raises(AlreadyInState) as info:
            await repos.actions.transition(TENANT_A, a.id, "succeeded", result={"ticket": "T-2"})
        assert isinstance(info.value, InvalidTransition) and info.value.current == "succeeded"
        assert (await repos.actions.get(TENANT_A, a.id)).result == {"ticket": "T-1"}

    async def test_illegal_transitions_rejected(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        a, _ = await repos.actions.propose(TENANT_A, alert_id, "block_ip", "198.51.100.2", "medium")
        for target in ("executing", "succeeded", "failed"):
            with pytest.raises(InvalidTransition):
                await repos.actions.transition(TENANT_A, a.id, target)
        await repos.actions.transition(TENANT_A, a.id, "rejected")
        for target in ("approved", "executing", "awaiting_approval", "proposed"):
            with pytest.raises(InvalidTransition):
                await repos.actions.transition(TENANT_A, a.id, target)
        with pytest.raises(ValueError):
            await repos.actions.transition(TENANT_A, a.id, "done")
        with pytest.raises(NotFound):
            await repos.actions.transition(TENANT_B, a.id, "approved")

    async def test_expected_from_and_racing_decisions(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        a, _ = await repos.actions.propose(
            TENANT_A, alert_id, "block_ip", "198.51.100.3", "high", status="awaiting_approval"
        )
        with pytest.raises(InvalidTransition):
            await repos.actions.transition(TENANT_A, a.id, "approved", expected_from="proposed")
        results = await asyncio.gather(
            repos.actions.transition(TENANT_A, a.id, "approved"),
            repos.actions.transition(TENANT_A, a.id, "rejected"),
            return_exceptions=True,
        )
        assert sum(isinstance(r, InvalidTransition) for r in results) == 1
        final = await repos.actions.get(TENANT_A, a.id)
        assert final.status in ("approved", "rejected")

    @pytest.mark.parametrize("start", ["approved", "failed"])
    async def test_racing_execution_claims_have_one_winner(self, repos: Repositories, start: str) -> None:
        """Only one of several workers moving the same action to executing may run the connector."""
        alert_id = await make_alert(repos, TENANT_A)
        a, _ = await repos.actions.propose(TENANT_A, alert_id, "block_ip", "198.51.100.9", "low", status="approved")
        if start == "failed":
            await repos.actions.transition(TENANT_A, a.id, "executing")
            await repos.actions.transition(TENANT_A, a.id, "failed", result={"error": "timeout"})
        results = await asyncio.gather(
            *(
                repos.actions.transition(
                    TENANT_A, a.id, "executing", expected_from=start, connector=f"worker-{i}", now=T0
                )
                for i in range(5)
            ),
            return_exceptions=True,
        )
        winners = [r for r in results if not isinstance(r, BaseException)]
        assert len(winners) == 1
        assert all(isinstance(r, AlreadyInState) for r in results if isinstance(r, BaseException))
        final = await repos.actions.get(TENANT_A, a.id)
        assert final.status == "executing" and final.connector == winners[0].connector

    async def test_rollback_of_must_reference_own_tenant(self, repos: Repositories) -> None:
        a_alert = await make_alert(repos, TENANT_A)
        b_alert = await make_alert(repos, TENANT_B)
        own, _ = await repos.actions.propose(TENANT_A, a_alert, "block_ip", "192.0.2.50", "low")
        foreign, _ = await repos.actions.propose(TENANT_B, b_alert, "block_ip", "192.0.2.50", "low")
        undo, _ = await repos.actions.propose(TENANT_A, a_alert, "unblock_ip", "192.0.2.50", "low", rollback_of=own.id)
        assert undo.rollback_of == own.id
        errors = []
        for target in (foreign.id, uuid4()):
            with pytest.raises(ReferenceNotFound) as info:
                await repos.actions.propose(TENANT_A, a_alert, "unblock_ip", f"x-{target}", "low", rollback_of=target)
            errors.append((type(info.value), info.value.resource, str(info.value)))
        assert errors[0] == errors[1] == (ReferenceNotFound, "response action", "response action not found")

    async def test_tampered_cursor_is_invalid(self, repos: Repositories) -> None:
        for key in ("not-a-uuid", 7):
            with pytest.raises(InvalidCursor):
                await repos.actions.list(TENANT_A, cursor=encode_cursor(T0, key))

    async def test_terminal_states_have_no_exits(self) -> None:
        for status in ("succeeded", "rejected", "dry_run", "blocked"):
            assert ACTION_TRANSITIONS[status] == frozenset()

    async def test_list_get_many_and_hourly_count(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        ids = []
        for i in range(5):
            a, _ = await repos.actions.propose(TENANT_A, alert_id, "block_ip", f"192.0.2.{i}", "low", status="approved")
            ids.append(a.id)
        for i, action_id in enumerate(ids[:3]):
            await repos.actions.transition(TENANT_A, action_id, "executing", now=T0 + timedelta(minutes=i * 40))
        await repos.actions.transition(TENANT_A, ids[3], "dry_run")
        assert await repos.actions.count_executed_since(TENANT_A, T0 + timedelta(minutes=30)) == 2
        assert await repos.actions.count_executed_since(TENANT_B, T0) == 0

        got = []
        cursor = None
        while True:
            items, cursor = await repos.actions.list(TENANT_A, limit=2, cursor=cursor)
            got += [a.id for a in items]
            if cursor is None:
                break
        assert sorted(got) == sorted(ids)
        assert len((await repos.actions.list(TENANT_A, status="executing")).items) == 3
        assert len((await repos.actions.list(TENANT_A, alert_id=alert_id, action_type="block_ip")).items) == 5
        assert [a.id for a in await repos.actions.get_many(TENANT_A, ids[:2])] == ids[:2]
        assert await repos.actions.get_many(TENANT_B, ids) == []


class TestSuppressions:
    async def test_crud_active_and_hits(self, repos: Repositories) -> None:
        live = await repos.suppressions.create(TENANT_A, "scanner", {"source_ip": {"cidr": "10.9.0.0/16"}})
        expired = await repos.suppressions.create(TENANT_A, "old", {"title": "x"}, expires_at=T0 - timedelta(days=1))
        off = await repos.suppressions.create(TENANT_A, "off", {"title": "y"}, enabled=False)
        active = await repos.suppressions.list_active(TENANT_A, now=T0)
        assert [r.id for r in active] == [live.id]
        assert len(await repos.suppressions.list(TENANT_A)) == 3
        assert len(await repos.suppressions.list(TENANT_A, include_disabled=False)) == 2

        await repos.suppressions.record_hit(TENANT_A, live.id, now=T0)
        await repos.suppressions.record_hit(TENANT_A, live.id, now=T0 + timedelta(seconds=5))
        rule = await repos.suppressions.get(TENANT_A, live.id)
        assert rule.hit_count == 2 and rule.last_hit_at == T0 + timedelta(seconds=5)

        rule = await repos.suppressions.update(TENANT_A, off.id, enabled=True, match={"title": "z"}, expires_at=None)
        assert rule.enabled and rule.match == {"title": "z"}
        assert await repos.suppressions.delete(TENANT_A, expired.id) is True
        with pytest.raises(NotFound):
            await repos.suppressions.record_hit(TENANT_A, expired.id)
        with pytest.raises(NotFound):
            await repos.suppressions.get(TENANT_B, live.id)

    async def test_empty_match_rejected(self, repos: Repositories) -> None:
        with pytest.raises(ValueError):
            await repos.suppressions.create(TENANT_A, "all", {})
        rule = await repos.suppressions.create(TENANT_A, "ok", {"title": "t"})
        with pytest.raises(ValueError):
            await repos.suppressions.update(TENANT_A, rule.id, match={})
        async with repos.db.tenant_tx(TENANT_A) as conn:
            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute("UPDATE suppression_rules SET match = '{}'::jsonb WHERE id = $1", rule.id)


class TestIndicators:
    async def test_sightings_and_related_alerts(self, repos: Repositories) -> None:
        a = await make_alert(repos, TENANT_A)
        b = await make_alert(repos, TENANT_A)
        c = await make_alert(repos, TENANT_A)
        old = await make_alert(repos, TENANT_A)
        foreign = await make_alert(repos, TENANT_B)
        ip, dom, sha = ("ip", h("203.0.113.5")), ("domain", h("evil.test")), ("hash", h("abc"))
        inserted = await repos.indicators.add_sightings(
            TENANT_A,
            a,
            [(*ip, "203.0.113.x", T0), (*dom, "evil.test", T0), (*ip, "dup", T0 + timedelta(seconds=1))],
        )
        assert inserted == 2
        assert await repos.indicators.add_sightings(TENANT_A, a, [(*ip, "203.0.113.x", T0)]) == 0
        await repos.indicators.add_sightings(TENANT_A, b, [(*ip, None, T0 + timedelta(hours=1)), (*dom, None, T0)])
        await repos.indicators.add_sightings(TENANT_A, c, [(*ip, None, T0 + timedelta(hours=2)), (*sha, None, T0)])
        await repos.indicators.add_sightings(TENANT_A, old, [(*ip, None, T0 - timedelta(days=60))])
        await repos.indicators.add_sightings(TENANT_B, foreign, [(*ip, None, T0), (*dom, None, T0)])

        related = await repos.indicators.related_alerts(
            TENANT_A, [ip, dom, ip], since=T0 - timedelta(days=7), exclude_alert_id=a
        )
        assert [(r.alert_id, r.shared_indicator_count) for r in related] == [(b, 2), (c, 1)]
        assert related[0].last_seen == T0 + timedelta(hours=1)
        limited = await repos.indicators.related_alerts(TENANT_A, [ip], since=T0 - timedelta(days=90), limit=2)
        assert [r.alert_id for r in limited] == [c, b]
        assert await repos.indicators.related_alerts(TENANT_A, [], since=T0) == []
        sightings = await repos.indicators.sightings_for_alert(TENANT_A, a)
        assert {s.value_display for s in sightings} == {"dup", "evil.test"}

    async def test_display_value_truncated(self, repos: Repositories) -> None:
        a = await make_alert(repos, TENANT_A)
        await repos.indicators.add_sightings(TENANT_A, a, [("url", h("u"), "x" * 1000, T0)])
        [s] = await repos.indicators.sightings_for_alert(TENANT_A, a)
        assert len(s.value_display or "") == 256


class TestLLMUsage:
    async def test_upsert_adds_and_ranges(self, repos: Repositories) -> None:
        d1, d2 = date(2026, 9, 1), date(2026, 9, 2)
        rows = [
            LLMUsageDelta(
                tenant_id=TENANT_A,
                day=d1,
                model="haiku",
                agent="triage",
                calls=1,
                input_tokens=100,
                output_tokens=10,
                cost_usd=Decimal("0.001"),
            ),
            LLMUsageDelta(
                tenant_id=TENANT_A,
                day=d1,
                model="haiku",
                agent="triage",
                calls=2,
                input_tokens=50,
                output_tokens=5,
                cost_usd=Decimal("0.0005"),
                refusals=1,
            ),
            LLMUsageDelta(
                tenant_id=TENANT_A,
                day=d2,
                model="sonnet",
                agent="analysis",
                calls=1,
                input_tokens=1000,
                output_tokens=300,
                cache_read_tokens=800,
                cost_usd=Decimal("0.02"),
                errors=1,
            ),
            LLMUsageDelta(tenant_id=TENANT_B, day=d1, model="haiku", agent="triage", calls=7),
        ]
        assert await repos.llm_usage.upsert_daily(rows) == 3
        await repos.llm_usage.upsert_daily(rows[:1])
        usage = await repos.llm_usage.list_range(TENANT_A, d1, d2)
        assert [(u.day, u.model, u.calls) for u in usage] == [(d1, "haiku", 4), (d2, "sonnet", 1)]
        assert usage[0].input_tokens == 250 and usage[0].refusals == 1
        assert usage[0].cost_usd == Decimal("0.002500")
        totals = await repos.llm_usage.day_totals(TENANT_A, d2)
        assert (totals.calls, totals.input_tokens, totals.output_tokens) == (1, 1000, 300)
        assert (await repos.llm_usage.day_totals(TENANT_A, date(2020, 1, 1))).calls == 0
        assert [u.calls for u in await repos.llm_usage.list_range(TENANT_B, d1, d1)] == [7]
        with pytest.raises(ValueError):
            await repos.llm_usage.list_range(TENANT_A, d2, d1)
        with pytest.raises(ValueError):
            LLMUsageDelta(tenant_id=TENANT_A, day=d1, model="m", agent="a", calls=-1)

    async def test_upsert_is_all_or_nothing_across_tenants(self, repos: Repositories) -> None:
        """A failing tenant must not leave earlier tenants' deltas committed (retry would double count)."""
        day = date(2026, 9, 3)
        rows = [
            LLMUsageDelta(tenant_id=TENANT_A, day=day, model="m", agent="triage", calls=1, cost_usd=Decimal("0.5")),
            LLMUsageDelta(tenant_id=TENANT_B, day=day, model="m", agent="triage", calls=2),
            LLMUsageDelta(tenant_id="zz-missing", day=day, model="m", agent="triage", calls=1),
        ]
        with pytest.raises(ReferenceNotFound) as info:
            await repos.llm_usage.upsert_daily(rows)
        assert info.value.resource == "tenant"
        assert (await repos.llm_usage.day_totals(TENANT_A, day)).calls == 0
        assert (await repos.llm_usage.day_totals(TENANT_B, day)).calls == 0

        assert await repos.llm_usage.upsert_daily(rows[:2]) == 2
        assert await repos.llm_usage.upsert_daily([]) == 0
        totals = await repos.llm_usage.day_totals(TENANT_A, day)
        assert (totals.calls, totals.cost_usd) == (1, Decimal("0.5"))
        assert (await repos.llm_usage.day_totals(TENANT_B, day)).calls == 2

    async def test_concurrent_flushes_with_overlapping_keys(self, repos: Repositories) -> None:
        day = date(2026, 9, 4)
        keys = [(t, m) for t in (TENANT_A, TENANT_B) for m in ("m1", "m2", "m3")]
        batches = [
            [LLMUsageDelta(tenant_id=t, day=day, model=m, agent="a", calls=1) for t, m in order]
            for order in (keys, list(reversed(keys)), keys[1:] + keys[:1], list(reversed(keys))[2:] + keys[:2])
        ]
        await asyncio.gather(*(repos.llm_usage.upsert_daily(b) for b in batches * 3))
        for tenant_id in (TENANT_A, TENANT_B):
            expected = 3 * sum(d.calls for b in batches for d in b if d.tenant_id == tenant_id)
            assert (await repos.llm_usage.day_totals(tenant_id, day)).calls == expected
