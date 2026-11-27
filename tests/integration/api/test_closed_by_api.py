"""Who or what closed an alert (PRD-2.9a): ``closed_by`` on ``GET /alerts`` with its filter, and the Overview's
split of the closes no person touched (``closed_without_human_by`` on ``GET /dashboard/summary``).

The five closers are the case page's: an analyst, the AI on approved evidence, the AI on the model's word, a
suppression rule, an earlier analyst verdict. A sample that waits for its blind-audit label names no closer and
matches no filter on it: who closed it is the AI's side.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.domain import closure
from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation.model import CLOSERS
from lg_sotf.domain.investigation.outcome import close_reasons_of, closer
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
NOW = datetime.now(UTC)


async def closed(
    api: ApiHarness, reason: Optional[str], *, tenant_id: str = TENANT_A, ingested_at: Optional[datetime] = None,
    **summary: Any,
) -> str:
    """An alert closed with ``reason`` as the workflow stores it (``summary.close_reason``)."""
    alert_id = await make_alert(api.repos, tenant_id, title=f"Closed: {reason}", ingested_at=ingested_at)
    for status in ("queued", "processing", "closed"):
        await api.repos.alerts.update_status(tenant_id, alert_id, status)
    body = {**({"close_reason": reason} if reason else {}), **summary}
    await api.repos.alerts.update(tenant_id, alert_id, disposition="benign", summary=body)  # type: ignore[arg-type]
    return alert_id


async def listed(api: ApiHarness, headers: Dict[str, str], query: str = "") -> Dict[str, Optional[str]]:
    response = await api.client.get(f"{API}/alerts?limit=100{query}", headers=headers)
    assert response.status_code == 200, response.text
    return {a["id"]: a["closed_by"] for a in response.json()["items"]}


def test_every_close_reason_has_one_closer_and_the_filter_matches_the_same_reasons() -> None:
    """One table decides both what an alert shows and what the filter matches."""
    by_closer = {kind: close_reasons_of([kind]) for kind in CLOSERS}
    assert sorted(reason for reasons in by_closer.values() for reason in reasons) == sorted(words.CLOSE_REASONS)
    assert by_closer["ai_audit"] == [closure.MODEL_CLOSE_REASON]
    assert set(by_closer["ai_evidence"]) == {"policy:close", "policy:response", "triage:false_positive"}
    assert set(by_closer["analyst"]) == {"analyst:true_positive", "analyst:false_positive", "analyst:benign_positive"}
    assert (closer("closed", "a reason of a newer release"), closer("closed", None), closer("queued", "policy:close")) == (None,) * 3


async def test_the_alerts_list_says_who_or_what_closed_each_alert_and_filters_by_it(api: ApiHarness) -> None:
    viewer = await api.login_headers(TENANT_A, "viewer")
    ids = {
        "analyst": await closed(api, "analyst:false_positive", analyst_decision="false_positive"),
        "ai_evidence": await closed(api, "policy:close"),
        "at_triage": await closed(api, "triage:false_positive"),
        "ai_audit": await closed(api, closure.MODEL_CLOSE_REASON),
        "suppression_rule": await closed(api, "suppression_rule"),
        "cached_verdict": await closed(api, "verdict_cache"),
        "unknown": await closed(api, "a reason of a newer release"),
        "open": await make_alert(api.repos, TENANT_A, title="Still open"),
    }
    theirs = await closed(api, closure.MODEL_CLOSE_REASON, tenant_id=TENANT_B)

    everything = await listed(api, viewer)
    assert {name: everything[alert_id] for name, alert_id in ids.items()} == {
        "analyst": "analyst", "ai_evidence": "ai_evidence", "at_triage": "ai_evidence", "ai_audit": "ai_audit",
        "suppression_rule": "suppression_rule", "cached_verdict": "cached_verdict", "unknown": None, "open": None,
    }
    assert theirs not in everything
    detail = await api.client.get(f"{API}/alerts/{ids['ai_audit']}", headers=viewer)
    assert detail.status_code == 200 and detail.json()["closed_by"] == "ai_audit"

    for kind, expected in (
        ("ai_audit", ["ai_audit"]), ("ai_evidence", ["ai_evidence", "at_triage"]), ("analyst", ["analyst"]),
        ("suppression_rule", ["suppression_rule"]), ("cached_verdict", ["cached_verdict"]),
    ):
        found = await listed(api, viewer, f"&closed_by={kind}")
        assert sorted(found) == sorted(ids[name] for name in expected), kind
        assert set(found.values()) == {kind}
    both = await listed(api, viewer, "&closed_by=ai_audit&closed_by=suppression_rule")
    assert sorted(both) == sorted([ids["ai_audit"], ids["suppression_rule"]])
    # The filter combines with the others, and the closed window still bounds it.
    window = f"&closed_by=ai_audit&closed_from={(NOW - timedelta(hours=1)).isoformat().replace('+00:00', 'Z')}"
    assert list(await listed(api, viewer, window)) == [ids["ai_audit"]]
    assert await listed(api, viewer, "&closed_by=ai_audit&severity=critical") == {}
    assert await listed(api, await api.login_headers(TENANT_B, "viewer"), "&closed_by=ai_audit") == {theirs: "ai_audit"}
    refused = await api.client.get(f"{API}/alerts?closed_by=the_ai", headers=viewer)
    assert refused.status_code == 422


async def test_a_sample_waiting_for_its_blind_audit_label_names_no_closer_and_matches_no_filter(api: ApiHarness) -> None:
    viewer = await api.login_headers(TENANT_A, "admin")
    sampled = await closed(api, closure.MODEL_CLOSE_REASON)
    other = await closed(api, closure.MODEL_CLOSE_REASON)
    await api.repos.blind_audit.create_run(
        TENANT_A, since=NOW - timedelta(days=7), until=datetime.now(UTC), seed=1, sample_rate=0.02, min_sample=0,
        fixed_size=None, frame_size=1, items=[(sampled, 1, "benign")], trigger="cli", created_by="seed",
    )
    hidden = await listed(api, viewer)
    assert (hidden[sampled], hidden[other]) == (None, "ai_audit")
    assert (await api.client.get(f"{API}/alerts/{sampled}", headers=viewer)).json()["closed_by"] is None
    for kind in CLOSERS:  # no filter finds it: matching one would say who closed it
        assert sampled not in await listed(api, viewer, f"&closed_by={kind}")

    item = (await api.repos.blind_audit.list_items(TENANT_A)).items[0]
    await api.repos.blind_audit.label(
        TENANT_A, item.id, label="benign", notes=None, agreement=True, labelled_by=None, labelled_by_actor="seed",
        escalation_id=None, now=datetime.now(UTC),
    )
    assert sorted(await listed(api, viewer, "&closed_by=ai_audit")) == sorted([sampled, other])


async def test_the_overview_splits_the_closes_without_a_person_by_who_or_what_closed_them(api: ApiHarness) -> None:
    """PRD-2.9a acceptance: the split is counted for the chosen window, and adds up to the closes it splits."""
    reasons: List[Optional[str]] = [
        closure.MODEL_CLOSE_REASON, closure.MODEL_CLOSE_REASON, "policy:close", "triage:false_positive", "policy:response",
        "suppression_rule", "verdict_cache", "a reason of a newer release", None,
    ]
    for reason in reasons:
        await closed(api, reason)
    await closed(api, "analyst:false_positive", analyst_decision="false_positive")  # a person decided: not in the split
    await make_alert(api.repos, TENANT_A, title="Still open")
    await closed(api, closure.MODEL_CLOSE_REASON, ingested_at=NOW - timedelta(days=3))  # before the 24-hour window
    await closed(api, closure.MODEL_CLOSE_REASON, tenant_id=TENANT_B)
    viewer = await api.login_headers(TENANT_A, "viewer")

    day = (await api.client.get(f"{API}/dashboard/summary?window_hours=24", headers=viewer)).json()
    assert day["closed_without_human_by"] == {
        "ai_evidence": 3, "ai_audit": 2, "suppression_rule": 1, "cached_verdict": 1, "other": 2,
    }
    assert sum(day["closed_without_human_by"].values()) == day["handled_without_human"] == 9
    assert day["needed_human"] == 1
    week = (await api.client.get(f"{API}/dashboard/summary?window_hours=168", headers=viewer)).json()
    assert week["closed_without_human_by"]["ai_audit"] == 3 and week["handled_without_human"] == 10
    theirs = (await api.client.get(f"{API}/dashboard/summary?window_hours=24", headers=await api.login_headers(TENANT_B, "viewer"))).json()
    assert theirs["closed_without_human_by"] == {
        "ai_evidence": 0, "ai_audit": 1, "suppression_rule": 0, "cached_verdict": 0, "other": 0,
    }
