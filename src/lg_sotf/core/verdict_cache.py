"""Redis cache of analyst-confirmed benign verdicts, keyed by verdict key.

The key is the alert's verdict key (:mod:`lg_sotf.domain.verdict_key`): its
fingerprint refined with the process, command line, service, user and parent
process of the event, so a malicious service or command on a host never
matches the benign one an analyst closed there. Each key holds a Redis hash
with one field per analyst (``decided_by``): the latest benign decision of
that analyst on the key. One analyst's decisions, however many alerts or
escalations they close at once (a group decision, a bulk close), count once.

Only verdicts an analyst confirmed as benign (``false_positive`` or
``benign_positive``) are written, with the severity of the alert decided.
The gate closes an alert from the cache (:func:`closing_decisions`) only when,
within :data:`VERDICT_TTL_S` (7 days):

* at least :data:`MIN_ANALYSTS` different analysts decided the key benign,
  each at the alert's severity or above (decisions without a known analyst,
  such as an MSSP operator's under a grant, count as one unknown analyst);
* no threat was confirmed on the key, nor on any alert with its fingerprint
  (the same rule on the same hosts, users and indicators);
* the alert is not critical (critical alerts always go through the workflow).

:meth:`VerdictCache.invalidate` drops the key's decisions and writes a
``!malicious`` tombstone on the key and on the fingerprint: the workflow
calls it when a response is planned or an alert closes malicious, the API
when an analyst decides ``true_positive`` or a blind audit finds a threat.
Admins clear a tenant's whole cache with ``DELETE /tenant/verdict-cache``.
Keys carry :data:`KEY_VERSION`: entries written under an older key recipe
(version 1 was keyed by fingerprint alone) are never read and expire with
their TTL.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from redis.asyncio import Redis

from lg_sotf.models.vocabulary import BENIGN_DECISIONS, SEVERITY_RANK
from lg_sotf.security.shadow import REFUSE, egress, sink

VERDICT_TTL_S = 7 * 24 * 3600
MAX_KEY_CHARS = 256
KEY_VERSION = 3
# Two different analysts: one analyst's mistake, or one bulk close, never teaches the cache alone. The
# corpus_v1 analyst-oracle replay (tests/unit/core/test_verdict_cache_replay.py) closes no attack even at 1.
MIN_ANALYSTS = 2
UNKNOWN_ANALYST = "?"
MAX_DECISIONS = 20
MALICIOUS_FIELD = "!malicious"


def _time(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _text(value: Any) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def closing_decisions(record: Optional[Mapping[str, Any]], severity: str, now: datetime) -> List[Dict[str, Any]]:
    """The analyst decisions that let a cached verdict close an alert of ``severity``, latest first (empty: it may not).

    ``record`` is :meth:`VerdictCache.get`'s value. Fails closed: a threat
    with an unreadable time blocks the key, and a decision without a readable
    time or a severity never counts.
    """
    if not record or severity == "critical" or severity not in SEVERITY_RANK:
        return []
    window = timedelta(seconds=VERDICT_TTL_S)
    for threat in record.get("threats", []):
        threat_at = _time(threat)
        if threat_at is None or now - threat_at <= window:
            return []
    supporting: List[Dict[str, Any]] = []
    for decision in record.get("decisions", []):
        decided_at = _time(decision.get("confirmed_at"))
        decided = decision.get("severity")
        if decided_at is None or now - decided_at > window or decision.get("decision") not in BENIGN_DECISIONS:
            continue
        if decided in SEVERITY_RANK and SEVERITY_RANK[str(decided)] >= SEVERITY_RANK[severity]:
            supporting.append(decision)
    supporting.sort(key=lambda d: str(d.get("confirmed_at")), reverse=True)
    return supporting if len(supporting) >= MIN_ANALYSTS else []


def _stale_fields(fields: Mapping[Any, Any], cutoff: datetime) -> List[str]:
    """Decision fields older than ``cutoff`` or unreadable, then the oldest beyond :data:`MAX_DECISIONS`."""
    decided: List[Tuple[str, Optional[datetime]]] = []
    for name, raw in fields.items():
        if _text(name) == MALICIOUS_FIELD:
            continue
        try:
            decided.append((_text(name), _time(json.loads(raw).get("confirmed_at"))))
        except (ValueError, AttributeError):
            decided.append((_text(name), None))
    decided.sort(key=lambda f: f[1] or cutoff, reverse=True)
    return [name for i, (name, at) in enumerate(decided) if at is None or at < cutoff or i >= MAX_DECISIONS]


def _now() -> datetime:
    return datetime.now(UTC)


class VerdictCache:
    def __init__(
        self, redis: Redis, prefix: str, *, ttl_s: int = VERDICT_TTL_S, clock: Callable[[], datetime] = _now
    ) -> None:
        self._redis = redis
        self._prefix = prefix
        self._ttl_s = ttl_s
        self._clock = clock

    @property
    def redis(self) -> Redis:
        return self._redis

    def with_redis(self, redis: Redis) -> VerdictCache:
        """The same cache read through another client (a shadow run's write-refusing one)."""
        return VerdictCache(redis, self._prefix, ttl_s=self._ttl_s, clock=self._clock)

    def key(self, tenant_id: str, verdict_key: str) -> str:
        return f"{self._prefix}:t:{tenant_id}:verdict:v{KEY_VERSION}:{verdict_key[:MAX_KEY_CHARS]}"

    def fingerprint_key(self, tenant_id: str, fingerprint: str) -> str:
        """Where threats on a fingerprint are marked (verdict keys are hex, so ``fp:`` never collides)."""
        return self.key(tenant_id, f"fp:{fingerprint}")

    async def get(
        self, tenant_id: str, verdict_key: Optional[str], *, fingerprint: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """``{"decisions": [...], "threats": [iso...]}`` for the key (and fingerprint), or ``None`` when empty."""
        if not verdict_key:
            return None
        record: Dict[str, Any] = {"decisions": [], "threats": []}
        for name, raw in (await self._redis.hgetall(self.key(tenant_id, verdict_key)) or {}).items():
            try:
                value = json.loads(raw)
            except ValueError:
                continue
            if isinstance(value, dict) and _text(name) == MALICIOUS_FIELD:
                record["threats"].append(value.get("at"))
            elif isinstance(value, dict):
                record["decisions"].append(value)
        if fingerprint:
            threat = await self._redis.hget(self.fingerprint_key(tenant_id, fingerprint), MALICIOUS_FIELD)
            if threat is not None:
                try:
                    record["threats"].append(json.loads(threat).get("at"))
                except (ValueError, AttributeError):
                    record["threats"].append(None)  # unreadable: blocks the key (fail closed)
        return record if record["decisions"] or record["threats"] else None

    async def closing_decision(
        self, tenant_id: str, verdict_key: Optional[str], severity: str, *, fingerprint: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """The latest analyst decision of a cached verdict that closes an alert of ``severity``, or ``None``."""
        record = await self.get(tenant_id, verdict_key, fingerprint=fingerprint)
        supporting = closing_decisions(record, severity, self._clock())
        return supporting[0] if supporting else None

    @egress("verdict_cache", sink(lambda a: False))
    async def put_analyst_benign(
        self,
        tenant_id: str,
        verdict_key: Optional[str],
        *,
        decision: str,
        alert_id: str,
        escalation_id: Optional[str],
        decided_by: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> bool:
        """Record an analyst-confirmed benign decision. Returns False (and writes nothing) for other decisions.

        The decision replaces the same analyst's earlier one on the key, so
        what counts towards a close is the number of analysts, not of alerts.
        """
        if decision not in BENIGN_DECISIONS or not verdict_key:
            return False
        key = self.key(tenant_id, verdict_key)
        value = {
            "decision": decision,
            "alert_id": alert_id,
            "escalation_id": escalation_id,
            "decided_by": decided_by,
            "severity": severity,
            "confirmed_at": self._clock().isoformat(),
        }
        await self._redis.hset(key, f"u:{decided_by or UNKNOWN_ANALYST}", json.dumps(value))
        stale = _stale_fields(await self._redis.hgetall(key) or {}, self._clock() - timedelta(seconds=self._ttl_s))
        if stale:
            await self._redis.hdel(key, *stale)
        await self._redis.expire(key, self._ttl_s)
        return True

    @egress("verdict_cache", sink(lambda a: False))
    async def invalidate(self, tenant_id: str, verdict_key: Optional[str], *, fingerprint: Optional[str] = None) -> bool:
        """Drop the key's decisions and mark the key and the fingerprint malicious; True when decisions existed."""
        keys = ([self.key(tenant_id, verdict_key)] if verdict_key else []) + (
            [self.fingerprint_key(tenant_id, fingerprint)] if fingerprint else []
        )
        if not keys:
            return False
        threat = json.dumps({"at": self._clock().isoformat()})
        async with self._redis.pipeline(transaction=True) as pipe:
            if verdict_key:
                pipe.hkeys(keys[0])
                pipe.delete(keys[0])
            for key in keys:
                pipe.hset(key, MALICIOUS_FIELD, threat)
                pipe.expire(key, self._ttl_s)
            results = await pipe.execute()
        names = {_text(n) for n in results[0]} if verdict_key else set()
        return bool(names - {MALICIOUS_FIELD})

    @egress("verdict_cache", REFUSE)
    async def clear_tenant(self, tenant_id: str) -> int:
        """Remove every cached verdict and threat mark of the tenant (any key version); returns the keys removed."""
        pattern = f"{self._prefix}:t:{tenant_id}:verdict:*".replace("[", "\\[").replace("]", "\\]")
        removed = 0
        batch: list[Any] = []
        async for key in self._redis.scan_iter(match=pattern, count=500):
            batch.append(key)
            if len(batch) >= 500:
                removed += int(await self._redis.delete(*batch))
                batch = []
        if batch:
            removed += int(await self._redis.delete(*batch))
        return removed
