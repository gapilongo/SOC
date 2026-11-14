"""A confirmed threat revokes the benign learning that would close the alert again (#343, M3).

Through the real API paths: an analyst's ``true_positive`` decision and a
blind-audit ``malicious`` label disable every enabled suppression rule that
matches the alert (audited ``suppression.revoked``) and tombstone its verdict
key and fingerprint in the verdict cache. A failure there is counted, not
swallowed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lg_sotf.core.verdict_cache import MALICIOUS_FIELD, VerdictCache
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.observability.metrics import REVOCATION_FAILURES
from tests.integration.api._blind_audit import API, alert_of, queue, sample, seed_frame
from tests.integration.api._support import TENANT_A, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

PROCESS = {"hosts": ["srv-app-02"], "processes": ["c:\\windows\\psexesvc.exe"]}


async def _revoked(api: ApiHarness, alert_id: str, rule_id: str, other_id: str) -> None:
    alert = await api.repos.alerts.get(TENANT_A, alert_id)
    assert (await api.repos.suppressions.get(TENANT_A, rule_id)).enabled is False
    assert (await api.repos.suppressions.get(TENANT_A, other_id)).enabled is True
    revoked = [e.resource_id for e in (await api.repos.audit.list(TENANT_A, action="suppression.revoked")).items]
    assert revoked == [rule_id]
    cache = VerdictCache(api.ctx.redis, api.ctx.prefix)
    assert await api.ctx.redis.hexists(cache.fingerprint_key(TENANT_A, alert.fingerprint), MALICIOUS_FIELD)
    key = verdict_key_of(alert)
    if key is not None:
        assert await api.ctx.redis.hexists(cache.key(TENANT_A, key), MALICIOUS_FIELD)


async def test_a_true_positive_decision_disables_matching_rules_and_tombstones_the_cache(api: ApiHarness) -> None:
    alert_id = await make_alert(api.repos, TENANT_A, title="New service", severity="low",
                                normalized={"entities": PROCESS, "mitre": {"techniques": ["T1569.002"]}})
    alert = await api.repos.alerts.get(TENANT_A, alert_id)
    assert verdict_key_of(alert) is not None
    rule = await api.repos.suppressions.create(
        TENANT_A, "suggested", {"verdict_key": verdict_key_of(alert), "severity": {"in": ["info", "low"]}}, enabled=True
    )
    other = await api.repos.suppressions.create(TENANT_A, "other host", {"entities.hosts": "db-9"}, enabled=True)
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_A, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    analyst = await api.login_headers(TENANT_A, "analyst")
    response = await api.client.post(
        f"/api/v1/escalations/{escalation.id}/decision",
        json={"decision": "true_positive", "version": escalation.version}, headers=analyst,
    )
    assert response.status_code == 200, response.text
    await _revoked(api, alert_id, rule.id, other.id)


async def test_a_malicious_blind_audit_label_disables_matching_rules_and_tombstones_the_cache(api: ApiHarness) -> None:
    await seed_frame(api.repos, n=1)
    rule = await api.repos.suppressions.create(TENANT_A, "ws-17 noise", {"entities.hosts": "ws-17"}, enabled=True)
    other = await api.repos.suppressions.create(TENANT_A, "other host", {"entities.hosts": "db-9"}, enabled=True)
    await sample(api, await api.login_headers(TENANT_A, "admin"), size=1)
    analyst = api.auth(await api.user(TENANT_A, "analyst"))
    [item] = await queue(api, analyst)
    alert_id = await alert_of(api, item)
    response = await api.client.post(
        f"{API}/blind-audit/items/{item['id']}/label", json={"label": "malicious"}, headers=analyst
    )
    assert response.status_code == 200, response.text
    await _revoked(api, alert_id, rule.id, other.id)


async def test_a_revocation_failure_is_counted_not_swallowed(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    from lg_sotf.api import common

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("redis is down")

    monkeypatch.setattr(common, "forget_benign_learning", broken)
    alert_id = await make_alert(api.repos, TENANT_A, title="x", normalized={"entities": PROCESS})
    before = REVOCATION_FAILURES.labels(path="api")._value.get()
    analyst = await api.user(TENANT_A, "analyst")
    from lg_sotf.audit.logger import Actor

    assert await common.invalidate_verdicts(api.ctx, TENANT_A, [alert_id], Actor("user", str(analyst.id))) == 1
    assert REVOCATION_FAILURES.labels(path="api")._value.get() == before + 1
