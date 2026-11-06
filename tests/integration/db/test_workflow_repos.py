"""Alert events, workflow runs, escalations and analyst feedback."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lg_sotf.db.errors import (
    Conflict,
    InvalidCursor,
    InvalidTransition,
    LeaseLost,
    NotFound,
    ReferenceNotFound,
    RunNotClaimable,
)
from lg_sotf.db.pagination import encode_cursor
from lg_sotf.db.repos import NewAlertEvent, Repositories
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


class TestAlertEvents:
    async def test_append_and_page_timeline(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        first = await repos.alert_events.append(
            TENANT_A,
            alert_id,
            "triage.completed",
            node="triage",
            actor_type="agent",
            data={"score": 70},
            ts=T0,
        )
        assert first.data == {"score": 70} and first.ts == T0
        batch = [
            NewAlertEvent(alert_id=alert_id, event_type=f"e{i}", ts=T0 + timedelta(seconds=i % 2)) for i in range(9)
        ]
        assert await repos.alert_events.append_many(TENANT_A, batch) == 9
        seen = []
        cursor = None
        while True:
            page = await repos.alert_events.list_for_alert(TENANT_A, alert_id, limit=4, cursor=cursor)
            seen += page.items
            cursor = page.next_cursor
            if cursor is None:
                break
        assert len(seen) == 10 and len({e.id for e in seen}) == 10
        assert [(e.ts, e.id) for e in seen] == sorted((e.ts, e.id) for e in seen)
        assert (await repos.alert_events.list_for_alert(TENANT_B, alert_id)).items == []

    async def test_validation(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        with pytest.raises(ValueError):
            await repos.alert_events.append(TENANT_A, alert_id, "x", actor_type="robot")
        with pytest.raises(ReferenceNotFound) as info:
            await repos.alert_events.append(TENANT_A, "no-such-alert", "x")
        assert info.value.resource == "alert"
        for key in (10**30, "7", -(2**63) - 1):
            with pytest.raises(InvalidCursor):
                await repos.alert_events.list_for_alert(TENANT_A, alert_id, cursor=encode_cursor(T0, key))


class TestRuns:
    async def test_upsert_queued_is_idempotent(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        run = await repos.runs.upsert_queued(TENANT_A, alert_id)
        assert run.status == "queued" and run.thread_id == f"{TENANT_A}:{alert_id}" and run.attempt == 0
        assert (await repos.runs.upsert_queued(TENANT_A, alert_id)) == run

    async def test_claim_lease_semantics(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.upsert_queued(TENANT_A, alert_id)
        run = await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60, now=T0)
        assert (run.status, run.worker_id, run.attempt) == ("running", "w1", 1)
        assert run.lease_expires_at == T0 + timedelta(seconds=60)

        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w2", lease_s=60, now=T0 + timedelta(seconds=30))
        assert info.value.reason == "leased"
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60, now=T0 + timedelta(seconds=30))
        assert info.value.reason == "leased" and info.value.run.attempt == 1

        assert await repos.runs.heartbeat(TENANT_A, alert_id, "w1", lease_s=60, now=T0 + timedelta(seconds=50))
        assert not await repos.runs.heartbeat(TENANT_A, alert_id, "w2", lease_s=60)

        stolen = await repos.runs.start(TENANT_A, alert_id, "w2", lease_s=60, now=T0 + timedelta(seconds=111))
        assert (stolen.worker_id, stolen.attempt, stolen.claimed_from) == ("w2", 2, "running")
        assert not await repos.runs.heartbeat(TENANT_A, alert_id, "w1", lease_s=60)
        with pytest.raises(LeaseLost):
            await repos.runs.complete(TENANT_A, alert_id, worker_id="w1")

        done = await repos.runs.complete(TENANT_A, alert_id, worker_id="w2", now=T0 + timedelta(minutes=5))
        assert done.status == "completed" and done.worker_id is None and done.completed_at is not None
        assert (await repos.runs.complete(TENANT_A, alert_id)).status == "completed"
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w3", lease_s=60)
        assert info.value.reason == "completed"

    async def test_concurrent_claims_have_one_winner(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.upsert_queued(TENANT_A, alert_id)
        results = await asyncio.gather(
            *(repos.runs.start(TENANT_A, alert_id, f"w{i}", lease_s=60) for i in range(5)),
            return_exceptions=True,
        )
        winners = [r for r in results if not isinstance(r, Exception)]
        assert len(winners) == 1
        assert all(isinstance(r, RunNotClaimable) for r in results if isinstance(r, Exception))

    async def test_start_creates_missing_run(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        run = await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=30)
        assert run.status == "running" and run.attempt == 1 and run.claimed_from is None
        missing = await make_alert(repos, TENANT_A)
        with pytest.raises(NotFound):
            await repos.runs.start(TENANT_A, missing, "w1", lease_s=30, kind="resume")
        with pytest.raises(ValueError):
            await repos.runs.start(TENANT_A, missing, "w1", lease_s=30, kind="replay")  # type: ignore[arg-type]

    async def test_claim_kinds_respect_waiting_runs(self, repos: Repositories) -> None:
        """A redelivered ``process`` message must not run a graph that is waiting for an analyst."""
        alert_id = await make_alert(repos, TENANT_A)
        queued = await repos.runs.upsert_queued(TENANT_A, alert_id)
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60, kind="resume")
        assert info.value.reason == "not_waiting" and info.value.run.status == "queued"
        first = await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
        assert (first.claimed_from, first.attempt) == (queued.status, 1)
        await repos.runs.mark_waiting(TENANT_A, alert_id, "waiting_approval", worker_id="w1")

        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w2", lease_s=60)
        assert info.value.reason == "waiting" and info.value.run.status == "waiting_approval"
        resumed = await repos.runs.start(TENANT_A, alert_id, "w2", lease_s=60, kind="resume")
        assert (resumed.status, resumed.claimed_from, resumed.attempt) == ("running", "waiting_approval", 1)
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w3", lease_s=60, kind="resume")
        assert info.value.reason == "leased"

    async def test_concurrent_resume_claims_have_one_winner(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.start(TENANT_A, alert_id, "w0", lease_s=60)
        await repos.runs.mark_waiting(TENANT_A, alert_id, "waiting_human", worker_id="w0")
        results = await asyncio.gather(
            *(repos.runs.start(TENANT_A, alert_id, "same-worker", lease_s=60, kind="resume") for _ in range(4)),
            *(repos.runs.start(TENANT_A, alert_id, "other", lease_s=60) for _ in range(2)),
            return_exceptions=True,
        )
        winners = [r for r in results if not isinstance(r, BaseException)]
        assert len(winners) == 1 and winners[0].claimed_from == "waiting_human"
        reasons = {r.reason for r in results if isinstance(r, RunNotClaimable)}
        assert reasons <= {"leased", "waiting"} and len(results) - len(winners) == 5

    async def test_waiting_fail_retry_and_dead_letter(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
        waiting = await repos.runs.mark_waiting(TENANT_A, alert_id, "waiting_human", worker_id="w1")
        assert waiting.status == "waiting_human" and waiting.lease_expires_at is None
        with pytest.raises(ValueError):
            await repos.runs.mark_waiting(TENANT_A, alert_id, "completed")

        resumed = await repos.runs.start(TENANT_A, alert_id, "w2", lease_s=60, kind="resume")
        assert resumed.attempt == 1
        failed = await repos.runs.fail(TENANT_A, alert_id, "TimeoutError in analysis", worker_id="w2")
        assert failed.status == "failed" and failed.last_error == "TimeoutError in analysis"
        retry = await repos.runs.start(TENANT_A, alert_id, "w3", lease_s=60, kind="resume")
        assert retry.attempt == 2 and retry.last_error == "TimeoutError in analysis"
        assert retry.claimed_from == "failed"

        dead = await repos.runs.dead_letter(TENANT_A, alert_id, "max deliveries exceeded", now=T0)
        assert dead.status == "dead_lettered" and dead.completed_at == T0
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w4", lease_s=60)
        assert info.value.reason == "dead_lettered"
        with pytest.raises(InvalidTransition):
            await repos.runs.fail(TENANT_A, alert_id, "late")

        requeued = await repos.runs.upsert_queued(TENANT_A, alert_id, requeue_terminal=True)
        assert (requeued.status, requeued.attempt, requeued.last_error) == ("queued", 0, None)

    async def test_error_text_is_truncated(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.start(TENANT_A, alert_id, "w1", lease_s=60)
        failed = await repos.runs.fail(TENANT_A, alert_id, "x" * 10_000)
        assert len(failed.last_error or "") == 4_000

    async def test_stale_runs_across_tenants(self, repos: Repositories) -> None:
        a = await make_alert(repos, TENANT_A)
        b = await make_alert(repos, TENANT_B)
        c = await make_alert(repos, TENANT_A)
        await repos.runs.start(TENANT_A, a, "w1", lease_s=10, now=T0)
        await repos.runs.start(TENANT_B, b, "w2", lease_s=10, now=T0)
        await repos.runs.start(TENANT_A, c, "w3", lease_s=3_600, now=T0)
        stale = await repos.runs.find_stale_all_tenants(now=T0 + timedelta(seconds=11))
        assert {(r.tenant_id, r.alert_id) for r in stale} == {(TENANT_A, a), (TENANT_B, b)}
        sweep = await repos.runs.requeue_stale_all_tenants(max_attempts=5, now=T0 + timedelta(seconds=11))
        assert {(r.tenant_id, r.alert_id) for r in sweep.requeued} == {(TENANT_A, a), (TENANT_B, b)}
        assert sweep.dead_lettered == []
        again = await repos.runs.requeue_stale_all_tenants(max_attempts=5, now=T0 + timedelta(seconds=11))
        assert again.requeued == [] and again.dead_lettered == []
        assert (await repos.runs.get(TENANT_A, a)).status == "queued"
        assert await repos.runs.counts_by_status(TENANT_A) == {"queued": 1, "running": 1}
        assert await repos.runs.counts_by_status_all_tenants() == {"queued": 2, "running": 1}
        with pytest.raises(NotFound):
            await repos.runs.get(TENANT_B, a)

    async def test_poison_run_is_dead_lettered_after_max_attempts(self, repos: Repositories) -> None:
        """A run whose worker keeps dying must stop cycling through fresh queue messages."""
        alert_id = await make_alert(repos, TENANT_A)
        healthy = await make_alert(repos, TENANT_A)
        at = T0
        for attempt in range(1, 4):
            run = await repos.runs.start(TENANT_A, alert_id, f"w{attempt}", lease_s=10, now=at)
            assert run.attempt == attempt
            at += timedelta(seconds=11)
            if attempt == 3:
                await repos.runs.start(TENANT_A, healthy, "wh", lease_s=10, now=at - timedelta(seconds=11))
            sweep = await repos.runs.requeue_stale_all_tenants(max_attempts=3, now=at)
            if attempt < 3:
                assert [r.alert_id for r in sweep.requeued] == [alert_id] and sweep.dead_lettered == []
        assert [r.alert_id for r in sweep.requeued] == [healthy]
        [dead] = sweep.dead_lettered
        assert (dead.alert_id, dead.status, dead.completed_at) == (alert_id, "dead_lettered", at)
        assert dead.last_error == "lease expired on attempt 3 of 3" and dead.worker_id is None
        with pytest.raises(RunNotClaimable) as info:
            await repos.runs.start(TENANT_A, alert_id, "w9", lease_s=10)
        assert info.value.reason == "dead_lettered"
        with pytest.raises(ValueError):
            await repos.runs.requeue_stale_all_tenants(max_attempts=0)


class TestEscalations:
    async def test_create_or_attach_is_idempotent(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        esc, created = await repos.escalations.create_or_attach(
            TENANT_A,
            alert_id,
            reason="low confidence",
            priority=8,
            related_alert_ids=["r1"],
            sla_deadline=T0,
            summary={"verdict": "unknown"},
        )
        assert created and esc.status == "open" and esc.version == 1 and esc.level == "L1"
        again, created = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="other")
        assert not created and again.id == esc.id and again.reason == "low confidence"

    async def test_concurrent_create_or_attach(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        results = await asyncio.gather(
            *(repos.escalations.create_or_attach(TENANT_A, alert_id, reason=f"r{i}") for i in range(8))
        )
        assert len({e.id for e, _ in results}) == 1
        assert sum(created for _, created in results) == 1

    async def test_claim_and_decide_with_optimistic_locking(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        alice = await repos.users.create(TENANT_A, "alice@x.io", "analyst")
        bob = await repos.users.create(TENANT_A, "bob@x.io", "analyst")
        esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r")

        claimed = await repos.escalations.claim(TENANT_A, esc.id, alice.id, esc.version, now=T0)
        assert (claimed.status, claimed.assigned_to, claimed.version, claimed.claimed_at) == (
            "claimed",
            alice.id,
            2,
            T0,
        )
        with pytest.raises(Conflict):
            await repos.escalations.claim(TENANT_A, esc.id, bob.id, esc.version)
        with pytest.raises(Conflict):
            await repos.escalations.decide(
                TENANT_A, esc.id, decision="true_positive", decided_by=bob.id, expected_version=1
            )
        decided = await repos.escalations.decide(
            TENANT_A,
            esc.id,
            decision="true_positive",
            decided_by=alice.id,
            expected_version=2,
            notes="confirmed C2",
            approved_actions=["a1", "a2"],
            now=T0 + timedelta(minutes=5),
        )
        assert decided.status == "decided" and decided.version == 3
        assert decided.approved_actions == ["a1", "a2"] and decided.decided_at == T0 + timedelta(minutes=5)
        with pytest.raises(InvalidTransition):
            await repos.escalations.claim(TENANT_A, esc.id, bob.id, 3)
        with pytest.raises(ValueError):
            await repos.escalations.decide(TENANT_A, esc.id, decision="maybe", decided_by=bob.id, expected_version=3)
        with pytest.raises(NotFound):
            await repos.escalations.claim(TENANT_A, "missing", bob.id, 1)

        fresh, created = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="needs more info")
        assert created and fresh.id != esc.id

    async def test_concurrent_decisions_one_wins(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        users = [await repos.users.create(TENANT_A, f"u{i}@x.io", "analyst") for i in range(4)]
        esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r")
        results = await asyncio.gather(
            *(
                repos.escalations.decide(
                    TENANT_A, esc.id, decision="false_positive", decided_by=u.id, expected_version=esc.version
                )
                for u in users
            ),
            return_exceptions=True,
        )
        assert sum(not isinstance(r, Exception) for r in results) == 1
        assert all(isinstance(r, Conflict) for r in results if isinstance(r, Exception))

    async def test_unknown_references_are_not_found(self, repos: Repositories) -> None:
        with pytest.raises(ReferenceNotFound) as info:
            await repos.escalations.create_or_attach(TENANT_A, "nope", reason="r")
        assert info.value.resource == "alert"
        alert_id = await make_alert(repos, TENANT_A)
        esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r")
        with pytest.raises(ReferenceNotFound) as info:
            await repos.escalations.decide(
                TENANT_A, esc.id, decision="true_positive", decided_by=uuid4(), expected_version=esc.version
            )
        assert info.value.resource == "user"
        assert (await repos.escalations.get(TENANT_A, esc.id)).status == "open"
        for key in (5, "x" * 300):
            with pytest.raises(InvalidCursor):
                await repos.escalations.list(TENANT_A, cursor=encode_cursor(T0, key))

    async def test_levels_sla_and_expiry(self, repos: Repositories) -> None:
        a1 = await make_alert(repos, TENANT_A)
        a2 = await make_alert(repos, TENANT_B)
        e1, _ = await repos.escalations.create_or_attach(TENANT_A, a1, reason="r", sla_deadline=T0)
        e2, _ = await repos.escalations.create_or_attach(TENANT_B, a2, reason="r", sla_deadline=T0 + timedelta(hours=2))
        breached = await repos.escalations.find_sla_breached_all_tenants(now=T0 + timedelta(minutes=1))
        assert [e.id for e in breached] == [e1.id]

        l2 = await repos.escalations.escalate_level(TENANT_A, e1.id, sla_deadline=T0 + timedelta(hours=1))
        assert (l2.level, l2.version, l2.sla_deadline) == ("L2", 2, T0 + timedelta(hours=1))
        l3 = await repos.escalations.escalate_level(TENANT_A, e1.id, sla_deadline=None)
        assert l3.level == "L3"
        with pytest.raises(InvalidTransition):
            await repos.escalations.escalate_level(TENANT_A, e1.id, sla_deadline=None)

        expired = await repos.escalations.expire(TENANT_A, e1.id)
        assert expired.status == "expired"
        with pytest.raises(InvalidTransition):
            await repos.escalations.expire(TENANT_A, e1.id)
        assert (await repos.escalations.cancel(TENANT_B, e2.id)).status == "cancelled"
        assert await repos.escalations.count_active_all_tenants() == 0

    async def test_sla_sweep_skips_suspended_tenants_and_reactivation_extends(self, repos: Repositories) -> None:
        a1 = await make_alert(repos, TENANT_A)
        a2 = await make_alert(repos, TENANT_B)
        a3 = await make_alert(repos, TENANT_B)
        e1, _ = await repos.escalations.create_or_attach(TENANT_A, a1, reason="r", sla_deadline=T0)
        e2, _ = await repos.escalations.create_or_attach(TENANT_B, a2, reason="r", sla_deadline=T0)
        far = T0 + timedelta(days=3)
        e3, _ = await repos.escalations.create_or_attach(TENANT_B, a3, reason="r", sla_deadline=far)
        await repos.tenants.set_status(TENANT_B, "suspended")
        breached = await repos.escalations.find_sla_breached_all_tenants(now=T0 + timedelta(minutes=1))
        assert [e.id for e in breached] == [e1.id]

        deadlines = {"L1": T0 + timedelta(hours=1), "L2": T0 + timedelta(hours=2), "L3": T0 + timedelta(hours=3)}
        assert await repos.escalations.extend_sla_deadlines(TENANT_B, deadlines) == 1
        moved = await repos.escalations.get(TENANT_B, e2.id)
        assert (moved.sla_deadline, moved.version) == (deadlines["L1"], e2.version)
        # Never shortened; other tenants untouched.
        assert (await repos.escalations.get(TENANT_B, e3.id)).sla_deadline == far
        assert (await repos.escalations.get(TENANT_A, e1.id)).sla_deadline == T0

    async def test_list_filters_and_pagination(self, repos: Repositories) -> None:
        ids = []
        for i in range(7):
            alert_id = await make_alert(repos, TENANT_A)
            esc, _ = await repos.escalations.create_or_attach(
                TENANT_A, alert_id, reason="r", level="L2" if i % 2 else "L1"
            )
            ids.append(esc.id)
        user = await repos.users.create(TENANT_A, "c@x.io", "analyst")
        first = await repos.escalations.get(TENANT_A, ids[0])
        await repos.escalations.claim(TENANT_A, ids[0], user.id, first.version)
        got = []
        cursor = None
        while True:
            items, cursor = await repos.escalations.list(TENANT_A, limit=3, cursor=cursor)
            got += [e.id for e in items]
            if cursor is None:
                break
        assert sorted(got) == sorted(ids) and len(got) == 7
        assert len((await repos.escalations.list(TENANT_A, level="L2")).items) == 3
        assert [e.id for e in (await repos.escalations.list(TENANT_A, status="claimed")).items] == [ids[0]]
        assert [e.id for e in (await repos.escalations.list(TENANT_A, assigned_to=user.id)).items] == [ids[0]]
        assert await repos.escalations.count_active(TENANT_A) == 7
        assert (await repos.escalations.get_active_for_alert(TENANT_A, first.alert_id)).id == ids[0]


class TestFeedback:
    async def test_idempotent_create_and_stats(self, repos: Repositories) -> None:
        user = await repos.users.create(TENANT_A, "f@x.io", "analyst")
        rows = [
            ("true_positive", True, True, 60),
            ("false_positive", False, None, 120),
            ("false_positive", True, False, None),
        ]
        alert_ids = []
        for decision, triage_ok, corr, duration in rows:
            alert_id = await make_alert(repos, TENANT_A)
            alert_ids.append(alert_id)
            esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r")
            fb, created = await repos.feedback.create(
                TENANT_A,
                esc.id,
                alert_id,
                decision,
                user_id=user.id,
                triage_correct=triage_ok,
                correlation_helpful=corr,
                review_duration_s=duration,
                confidence=80,
            )
            assert created
            again, created = await repos.feedback.create(TENANT_A, esc.id, alert_id, "true_positive")
            assert not created and again.id == fb.id and again.decision == decision
            assert (await repos.feedback.get_for_escalation(TENANT_A, esc.id)).id == fb.id
        assert len(await repos.feedback.list_for_alert(TENANT_A, alert_ids[0])) == 1

        stats = await repos.feedback.decision_stats(TENANT_A, T0 - timedelta(days=3650))
        assert stats.total == 3
        assert stats.by_decision == {"true_positive": 1, "false_positive": 2}
        assert stats.triage_accuracy == pytest.approx(2 / 3)
        assert stats.correlation_helpful_rate == pytest.approx(0.5)
        assert stats.analysis_accuracy is None
        assert stats.avg_review_duration_s == pytest.approx(90)
        empty = await repos.feedback.decision_stats(TENANT_B, T0)
        assert empty.total == 0 and empty.by_decision == {}


class TestRecoverySweeps:
    """The repository halves of runtime/orphans.py and runtime/resumes.py (their wrappers are tested there)."""

    async def test_orphan_and_stranded_sweeps_return_typed_rows(self, repos: Repositories) -> None:
        queued = await make_alert(repos, TENANT_A, severity="critical")
        await repos.runs.queue_alerts(TENANT_A, [queued])
        stranded = await make_alert(repos, TENANT_B, severity="low")
        async with repos.db.system_tx() as conn:
            await conn.execute("UPDATE workflow_runs SET updated_at = now() - interval '1 hour'")
            await conn.execute("UPDATE alerts SET ingested_at = now() - interval '1 hour' WHERE id = $1", stranded)
        with pytest.raises(ValueError):
            await repos.runs.claim_orphaned_all_tenants(queued_older_than_s=60, failed_older_than_s=60, limit=0)
        assert await repos.runs.claim_orphaned_all_tenants(
            queued_older_than_s=None, failed_older_than_s=60, limit=10
        ) == []
        [orphan] = await repos.runs.claim_orphaned_all_tenants(queued_older_than_s=60, failed_older_than_s=60, limit=10)
        assert (orphan.tenant_id, orphan.alert_id, orphan.status, orphan.severity) == (
            TENANT_A, queued, "queued", "critical"
        )
        # Claimed once per threshold: the claim touched updated_at.
        assert await repos.runs.claim_orphaned_all_tenants(queued_older_than_s=60, failed_older_than_s=60, limit=10) == []
        [alert] = await repos.alerts.find_stranded_new_all_tenants(older_than_s=60, limit=10)
        assert (alert.tenant_id, alert.alert_id, alert.severity) == (TENANT_B, stranded, "low")
        assert await repos.runs.find_stranded_waiting_all_tenants(older_than_s=60, limit=10) == []

    async def test_touch_only_bumps_a_run_still_in_the_given_status(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        await repos.runs.queue_alerts(TENANT_A, [alert_id])
        before = (await repos.runs.get(TENANT_A, alert_id)).updated_at
        assert not await repos.runs.touch(TENANT_A, alert_id, status="waiting_human")
        assert (await repos.runs.get(TENANT_A, alert_id)).updated_at == before
        assert await repos.runs.touch(TENANT_A, alert_id, status="queued")
        assert (await repos.runs.get(TENANT_A, alert_id)).updated_at > before
        assert not await repos.runs.touch(TENANT_B, alert_id, status="queued")  # other tenant

    async def test_latest_escalation_id_for_alert(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        assert await repos.escalations.latest_id_for_alert(TENANT_A, alert_id) is None
        esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r", related_alert_ids=["rel-1"])
        assert await repos.escalations.latest_id_for_alert(TENANT_A, alert_id) == esc.id
        assert await repos.escalations.latest_id_for_alert(TENANT_A, "rel-1") == esc.id
        assert await repos.escalations.latest_id_for_alert(TENANT_B, alert_id) is None

    async def test_workflow_approvals_count_only_workflow_owned_actions(self, repos: Repositories) -> None:
        alert_id = await make_alert(repos, TENANT_A)
        empty = await repos.actions.workflow_approvals(TENANT_A, alert_id)
        assert (empty.approved, empty.awaiting, empty.approver) == (0, 0, None)
        await repos.actions.propose(TENANT_A, alert_id, "isolate_host", "ws-1", "high", status="awaiting_approval")
        await repos.actions.propose(TENANT_A, alert_id, "block_ip", "203.0.113.9", "low", status="approved")
        await repos.actions.propose(
            TENANT_A, alert_id, "disable_user", "bob", "low", status="approved", execution_owner="scheduler"
        )
        counts = await repos.actions.workflow_approvals(TENANT_A, alert_id)
        assert (counts.approved, counts.awaiting, counts.approver) == (1, 1, None)
