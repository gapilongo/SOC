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
