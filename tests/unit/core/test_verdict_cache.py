"""Verdict cache: only analyst-confirmed benign verdicts, tenant-scoped keys, 7-day TTL."""

from __future__ import annotations

import fakeredis.aioredis

from lg_sotf.core.verdict_cache import VERDICT_TTL_S, VerdictCache


async def test_only_benign_analyst_decisions_are_cached() -> None:
    redis = fakeredis.aioredis.FakeRedis()
    cache = VerdictCache(redis, "pfx")
    assert not await cache.put_analyst_benign("t1", "fp", decision="true_positive", alert_id="a", escalation_id=None)
    assert await cache.get("t1", "fp") is None
    assert await cache.put_analyst_benign("t1", "fp", decision="false_positive", alert_id="a", escalation_id="e")
    hit = await cache.get("t1", "fp")
    assert hit is not None and hit["decision"] == "false_positive"
    assert await cache.get("t2", "fp") is None
    assert cache.key("t1", "fp") == "pfx:t:t1:verdict:fp"
    assert 0 < await redis.ttl("pfx:t:t1:verdict:fp") <= VERDICT_TTL_S


async def test_garbage_values_are_ignored() -> None:
    redis = fakeredis.aioredis.FakeRedis()
    cache = VerdictCache(redis, "pfx")
    await redis.set(cache.key("t1", "fp"), "not json")
    assert await cache.get("t1", "fp") is None
    await redis.set(cache.key("t1", "fp"), '{"disposition": "malicious"}')
    assert await cache.get("t1", "fp") is None


async def test_cached_verdict_applies_only_at_or_below_the_decided_severity() -> None:
    """LLM-W6-02: a benign decision on a medium alert never closes a high repeat."""
    from lg_sotf.core.verdict_cache import cache_applies

    redis = fakeredis.aioredis.FakeRedis()
    cache = VerdictCache(redis, "pfx")
    await cache.put_analyst_benign("t1", "fp", decision="false_positive", alert_id="a", escalation_id="e", severity="medium")
    hit = await cache.get("t1", "fp")
    assert hit is not None
    assert cache_applies(hit, "low") and cache_applies(hit, "medium")
    assert not cache_applies(hit, "high") and not cache_applies(hit, "critical")
    assert not cache_applies({"disposition": "benign"}, "low")  # legacy entry without severity: fail closed


async def test_invalidate_and_clear_tenant() -> None:
    redis = fakeredis.aioredis.FakeRedis()
    cache = VerdictCache(redis, "pfx")
    for fp in ("a", "b", "c"):
        await cache.put_analyst_benign("t1", fp, decision="false_positive", alert_id="x", escalation_id=None, severity="low")
    await cache.put_analyst_benign("t2", "a", decision="false_positive", alert_id="x", escalation_id=None, severity="low")
    assert await cache.invalidate("t1", "a")
    assert await cache.clear_tenant("t1") == 2
    assert await cache.get("t1", "b") is None and await cache.get("t2", "a") is not None
