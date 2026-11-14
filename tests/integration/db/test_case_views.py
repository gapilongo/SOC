"""The case page's lookups (``ViewsRepo.case_*``): bounded reads over the alerts of one case, tenant-scoped."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.views import MAX_CASE_ACTIONS, MAX_CASE_EVENTS_PER_ALERT, MAX_LOOKUP_IDS
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.asyncio


async def node(repos: Repositories, tenant_id: str, alert_id: str, name: str) -> None:
    await repos.alert_events.append(tenant_id, alert_id, "node.completed", node=name, actor_type="system", actor_id="workflow")


async def test_case_alerts_are_the_tenants_rows_without_the_raw_payload(repos: Repositories) -> None:
    mine = await make_alert(repos, TENANT_A, title="Beacon", severity="high", normalized={"entities": {"hosts": ["ws-1"]}})
    theirs = await make_alert(repos, TENANT_B, title="Other tenant")
    found = await repos.views.case_alerts(TENANT_A, [mine, theirs, "no-such-alert", mine])
    assert list(found) == [mine]
    row = found[mine]
    assert (row.title, row.severity, row.status, row.entities) == ("Beacon", "high", "new", {"hosts": ["ws-1"]})
    assert not hasattr(row, "raw") and not hasattr(row, "normalized")
    assert await repos.views.case_alerts(TENANT_A, []) == {}
    assert await repos.views.case_alerts(TENANT_B, [mine]) == {}


async def test_case_events_merge_the_timelines_oldest_first_without_the_skipped_steps(repos: Repositories) -> None:
    first = await make_alert(repos, TENANT_A)
    second = await make_alert(repos, TENANT_A)
    theirs = await make_alert(repos, TENANT_B)
    for alert_id, name in ((first, "triage"), (second, "decide"), (first, "close"), (second, "analysis"), (first, "decide")):
        await node(repos, TENANT_A, alert_id, name)
    await repos.alert_events.append(TENANT_A, second, "note", actor_type="user", actor_id="u-1", data={"text": "seen"})
    await node(repos, TENANT_B, theirs, "close")

    events = await repos.views.case_events(TENANT_A, [first, second, theirs], skip_nodes=("triage", "analysis"))
    assert [(e.alert_id, e.node or e.event_type) for e in events] == [
        (second, "decide"), (first, "close"), (first, "decide"), (second, "note"),
    ]
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    assert events[-1].actor_type == "user" and events[-1].actor_id == "u-1"
    # Each alert keeps its first events; nothing is skipped unless asked.
    capped = await repos.views.case_events(TENANT_A, [first, second], per_alert=1)
    assert [(e.alert_id, e.node) for e in capped] == [(first, "triage"), (second, "decide")]
    assert await repos.views.case_events(TENANT_A, []) == []
    with pytest.raises(ValueError):
        await repos.views.case_events(TENANT_A, [first], per_alert=MAX_CASE_EVENTS_PER_ALERT + 1)


async def test_case_actions_are_the_ledger_rows_of_the_alerts_oldest_first(repos: Repositories) -> None:
    first = await make_alert(repos, TENANT_A)
    second = await make_alert(repos, TENANT_A)
    other = await make_alert(repos, TENANT_A)
    theirs = await make_alert(repos, TENANT_B)
    a, _ = await repos.actions.propose(TENANT_A, first, "block_ip", "203.0.113.9", "low", status="awaiting_approval")
    b, _ = await repos.actions.propose(TENANT_A, second, "isolate_host", "ws-1", "high", status="blocked", blocked_reason="autonomy_disabled")
    await repos.actions.propose(TENANT_A, other, "block_ip", "203.0.113.10", "low")
    await repos.actions.propose(TENANT_B, theirs, "block_ip", "203.0.113.11", "low")

    found = await repos.views.case_actions(TENANT_A, [first, second, theirs])
    assert [(x.id, x.status) for x in found] == [(a.id, "awaiting_approval"), (b.id, "blocked")]
    assert [x.id for x in await repos.views.case_actions(TENANT_A, [first, second], limit=1)] == [a.id]
    assert await repos.views.case_actions(TENANT_A, []) == []
    with pytest.raises(ValueError):
        await repos.views.case_actions(TENANT_A, [first], limit=MAX_CASE_ACTIONS + 1)


async def test_case_audit_labels_say_which_alerts_were_sampled_and_how_they_were_labelled(repos: Repositories) -> None:
    labelled = await make_alert(repos, TENANT_A)
    pending = await make_alert(repos, TENANT_A)
    never = await make_alert(repos, TENANT_A)
    now = datetime.now(UTC)
    await repos.blind_audit.create_run(
        TENANT_A, since=now - timedelta(days=7), until=now, seed=1, sample_rate=None, min_sample=0, fixed_size=2,
        frame_size=2, items=[(labelled, 1, "benign"), (pending, 2, "benign")], trigger="cli", created_by="seed",
    )
    item = next(i for i in (await repos.blind_audit.list_items(TENANT_A)).items if i.alert_id == labelled)
    assert await repos.blind_audit.label(
        TENANT_A, item.id, label="malicious", notes=None, agreement=False, labelled_by=None, labelled_by_actor="seed",
        escalation_id=None, now=now,
    )
    labels = await repos.views.case_audit_labels(TENANT_A, [labelled, pending, never])
    assert set(labels) == {labelled, pending}
    assert (labels[labelled].label, labels[labelled].agreement, labels[labelled].labelled_at is not None) == ("malicious", False, True)
    assert (labels[pending].label, labels[pending].agreement, labels[pending].labelled_at) == (None, None, None)
    assert await repos.views.case_audit_labels(TENANT_B, [labelled]) == {}
    assert await repos.views.case_audit_labels(TENANT_A, []) == {}


async def test_every_case_lookup_is_bounded_by_its_ids(repos: Repositories) -> None:
    too_many = [f"alert-{i}" for i in range(MAX_LOOKUP_IDS + 1)]
    for lookup in (repos.views.case_alerts, repos.views.case_events, repos.views.case_actions, repos.views.case_audit_labels):
        with pytest.raises(ValueError):
            await lookup(TENANT_A, too_many)
