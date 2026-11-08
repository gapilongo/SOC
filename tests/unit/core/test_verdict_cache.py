"""Verdict cache: analyst-benign decisions only, two of them to close, none after a threat, tenant-scoped, 7 days."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import fakeredis.aioredis

from lg_sotf.core.verdict_cache import KEY_VERSION, MALICIOUS_FIELD, VERDICT_TTL_S, VerdictCache, closing_decisions

T0 = datetime(2026, 10, 1, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


def _cache() -> tuple[VerdictCache, fakeredis.aioredis.FakeRedis, Clock]:
    redis = fakeredis.aioredis.FakeRedis()
    clock = Clock()
    return VerdictCache(redis, "pfx", clock=clock), redis, clock


async def _benign(cache: VerdictCache, key: str, n: int, severity: str = "medium", tenant: str = "t1") -> None:
    for i in range(n):
        await cache.put_analyst_benign(tenant, key, decision="false_positive", alert_id=f"a{i}",
                                       escalation_id=f"e{i}", severity=severity)


async def test_only_benign_analyst_decisions_are_cached() -> None:
    cache, redis, _ = _cache()
    assert not await cache.put_analyst_benign("t1", "vk", decision="true_positive", alert_id="a", escalation_id=None)
    assert not await cache.put_analyst_benign("t1", None, decision="false_positive", alert_id="a", escalation_id="e")
    assert await cache.get("t1", "vk") is None
    assert await cache.put_analyst_benign("t1", "vk", decision="false_positive", alert_id="a", escalation_id="e",
                                          severity="low")
    record = await cache.get("t1", "vk")
    assert record is not None and [d["decision"] for d in record["decisions"]] == ["false_positive"]
    assert await cache.get("t2", "vk") is None
    assert cache.key("t1", "vk") == f"pfx:t:t1:verdict:v{KEY_VERSION}:vk"
    assert 0 < await redis.ttl(cache.key("t1", "vk")) <= VERDICT_TTL_S


async def test_one_analyst_decision_is_not_enough_two_distinct_ones_are() -> None:
    cache, _, _ = _cache()
    await cache.put_analyst_benign("t1", "vk", decision="false_positive", alert_id="a1", escalation_id="e1",
                                   severity="medium")
    assert await cache.closing_decision("t1", "vk", "medium") is None
    # Another alert closed by the same (group) decision counts once.
    await cache.put_analyst_benign("t1", "vk", decision="false_positive", alert_id="a2", escalation_id="e1",
                                   severity="medium")
    assert await cache.closing_decision("t1", "vk", "medium") is None
    await cache.put_analyst_benign("t1", "vk", decision="benign_positive", alert_id="a3", escalation_id="e2",
                                   severity="medium")
    hit = await cache.closing_decision("t1", "vk", "medium")
    assert hit is not None and hit["alert_id"] in {"a1", "a3"}
    assert await cache.closing_decision("t1", "other", "medium") is None


async def test_a_cached_verdict_closes_only_at_or_below_the_decided_severity_and_never_critical() -> None:
    """LLM-W6-02: benign medium decisions never close a high repeat."""
    cache, _, _ = _cache()
    await _benign(cache, "vk", 2, severity="medium")
    assert await cache.closing_decision("t1", "vk", "low") is not None
    assert await cache.closing_decision("t1", "vk", "medium") is not None
    assert await cache.closing_decision("t1", "vk", "high") is None
    await _benign(cache, "crit", 3, severity="critical")
    assert await cache.closing_decision("t1", "crit", "critical") is None
    # Only decisions at the alert's severity or above count towards the two.
    await cache.put_analyst_benign("t1", "mixed", decision="false_positive", alert_id="x", escalation_id="e1",
                                   severity="low")
    await cache.put_analyst_benign("t1", "mixed", decision="false_positive", alert_id="y", escalation_id="e2",
                                   severity="medium")
    assert await cache.closing_decision("t1", "mixed", "medium") is None
    assert await cache.closing_decision("t1", "mixed", "low") is not None


def test_closing_decisions_fail_closed() -> None:
    now = T0
    good = {"decision": "false_positive", "severity": "low", "confirmed_at": now.isoformat()}
    assert closing_decisions({"decisions": [good, good]}, "low", now)
    assert not closing_decisions({"decisions": [good, {**good, "severity": None}]}, "low", now)
    assert not closing_decisions({"decisions": [good, {**good, "confirmed_at": "yesterday"}]}, "low", now)
    assert not closing_decisions({"decisions": [good, {**good, "decision": "true_positive"}]}, "low", now)
    assert not closing_decisions({"decisions": [good, good], "threats": ["garbage"]}, "low", now)
    assert not closing_decisions({"decisions": [good, good]}, "unknown", now)
    assert not closing_decisions(None, "low", now)


async def test_decisions_expire_after_seven_days() -> None:
    cache, _, clock = _cache()
    await _benign(cache, "vk", 1)
    clock.now = T0 + timedelta(days=6)
    await cache.put_analyst_benign("t1", "vk", decision="false_positive", alert_id="b", escalation_id="eb",
                                   severity="medium")
    assert await cache.closing_decision("t1", "vk", "medium") is not None
    clock.now = T0 + timedelta(days=7, hours=1)
    assert await cache.closing_decision("t1", "vk", "medium") is None


async def test_a_threat_blocks_the_key_and_its_fingerprint_for_the_window() -> None:
    cache, redis, clock = _cache()
    await _benign(cache, "vk", 2)
    await _benign(cache, "sibling", 2)
    assert await cache.invalidate("t1", "vk", fingerprint="fp")
    assert await redis.hexists(cache.key("t1", "vk"), MALICIOUS_FIELD)
    assert await cache.closing_decision("t1", "vk", "medium", fingerprint="fp") is None
    # Benign decisions after the threat do not reopen the key within the window.
    clock.now = T0 + timedelta(days=1)
    await _benign(cache, "vk", 3)
    assert await cache.closing_decision("t1", "vk", "medium") is None
    # Another behaviour with the same fingerprint (same rule and host) is blocked too...
    assert await cache.closing_decision("t1", "sibling", "medium", fingerprint="fp") is None
    assert await cache.closing_decision("t1", "sibling", "medium", fingerprint="other-fp") is not None
    # ...until the window has passed.
    clock.now = T0 + timedelta(days=7, hours=1)
    await _benign(cache, "vk", 2)
    assert await cache.closing_decision("t1", "vk", "medium", fingerprint="fp") is not None


async def test_invalidate_without_keys_does_nothing() -> None:
    cache, redis, _ = _cache()
    assert not await cache.invalidate("t1", None)
    assert not await cache.invalidate("t1", "vk")  # nothing was cached; the threat is still marked
    assert await redis.hexists(cache.key("t1", "vk"), MALICIOUS_FIELD)
    assert await redis.keys("pfx:t:t1:verdict:v2:fp:*") == []


async def test_entries_of_the_fingerprint_keyed_cache_are_never_read() -> None:
    """Key version 1 (fingerprint only, one decision) must not match under the new semantics."""
    cache, redis, _ = _cache()
    legacy = {"disposition": "benign", "decision": "false_positive", "alert_id": "a", "severity": "low",
              "confirmed_at": T0.isoformat()}
    await redis.set("pfx:t:t1:verdict:fp", json.dumps(legacy))
    assert await cache.get("t1", "fp") is None
    assert await cache.closing_decision("t1", "fp", "low") is None
    assert await cache.clear_tenant("t1") == 1


async def test_garbage_fields_are_ignored() -> None:
    cache, redis, _ = _cache()
    await redis.hset(cache.key("t1", "vk"), "e:x", "not json")
    await redis.hset(cache.key("t1", "vk"), "e:y", "[1]")
    assert await cache.get("t1", "vk") is None
    await redis.hset(cache.fingerprint_key("t1", "fp"), MALICIOUS_FIELD, "not json")
    await _benign(cache, "vk", 2)
    assert await cache.closing_decision("t1", "vk", "medium") is not None
    assert await cache.closing_decision("t1", "vk", "medium", fingerprint="fp") is None


async def test_old_and_excess_decisions_are_pruned() -> None:
    cache, redis, clock = _cache()
    await _benign(cache, "vk", 1)
    clock.now = T0 + timedelta(days=8)
    await cache.put_analyst_benign("t1", "vk", decision="false_positive", alert_id="n", escalation_id="en",
                                   severity="medium")
    assert await redis.hkeys(cache.key("t1", "vk")) == [b"e:en"]
    await _benign(cache, "many", 25)
    assert await redis.hlen(cache.key("t1", "many")) == 20


async def test_invalidate_and_clear_tenant() -> None:
    cache, _, _ = _cache()
    for key in ("a", "b", "c"):
        await _benign(cache, key, 2, severity="low")
    await _benign(cache, "a", 2, severity="low", tenant="t2")
    assert await cache.invalidate("t1", "a", fingerprint="fp")
    assert await cache.clear_tenant("t1") == 4  # a (threat mark), b, c and the fingerprint's threat mark
    assert await cache.get("t1", "b") is None
    assert await cache.closing_decision("t2", "a", "low", fingerprint="fp") is not None
