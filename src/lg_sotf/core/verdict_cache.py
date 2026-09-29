"""Redis cache of analyst-confirmed benign verdicts, keyed by alert fingerprint.

Only verdicts an analyst confirmed as benign (``false_positive`` or
``benign_positive``) are written, together with the severity of the alert
the analyst decided. The gate uses a hit to close repeats of the same benign
alert at the same or a lower severity (:func:`cache_applies`, the rule
``own_review_reason`` applies to grouped alerts); critical alerts always go
through the workflow. :meth:`VerdictCache.invalidate` removes a verdict:
the workflow calls it when a response is planned for the fingerprint or an
alert with it closes malicious, the API when an analyst decides
``true_positive``; admins clear a tenant's whole cache with
``DELETE /tenant/verdict-cache``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from redis.asyncio import Redis

VERDICT_TTL_S = 7 * 24 * 3600
BENIGN_DECISIONS = frozenset({"false_positive", "benign_positive"})
MAX_FINGERPRINT_CHARS = 256
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def cache_applies(cached: Dict[str, Any], severity: str) -> bool:
    """Whether a cached benign verdict may close an alert of ``severity``.

    Only at the severity the analyst decided or below, never for critical,
    and never from an entry that did not record its severity (fail closed).
    """
    decided = cached.get("severity")
    if severity == "critical" or decided not in SEVERITY_RANK or severity not in SEVERITY_RANK:
        return False
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[str(decided)]


class VerdictCache:
    def __init__(self, redis: Redis, prefix: str, *, ttl_s: int = VERDICT_TTL_S) -> None:
        self._redis = redis
        self._prefix = prefix
        self._ttl_s = ttl_s

    def key(self, tenant_id: str, fingerprint: str) -> str:
        return f"{self._prefix}:t:{tenant_id}:verdict:{fingerprint[:MAX_FINGERPRINT_CHARS]}"

    async def get(self, tenant_id: str, fingerprint: str) -> Optional[Dict[str, Any]]:
        if not fingerprint:
            return None
        raw = await self._redis.get(self.key(tenant_id, fingerprint))
        if raw is None:
            return None
        text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        try:
            value = json.loads(text)
        except ValueError:
            return None
        if not isinstance(value, dict) or value.get("disposition") != "benign":
            return None
        return value

    async def put_analyst_benign(
        self,
        tenant_id: str,
        fingerprint: str,
        *,
        decision: str,
        alert_id: str,
        escalation_id: Optional[str],
        severity: Optional[str] = None,
    ) -> bool:
        """Store an analyst-confirmed benign verdict. Returns False (and writes nothing) for other decisions."""
        if decision not in BENIGN_DECISIONS or not fingerprint:
            return False
        value = {
            "disposition": "benign",
            "decision": decision,
            "alert_id": alert_id,
            "escalation_id": escalation_id,
            "severity": severity,
            "confirmed_at": datetime.now(UTC).isoformat(),
        }
        await self._redis.set(self.key(tenant_id, fingerprint), json.dumps(value), ex=self._ttl_s)
        return True

    async def invalidate(self, tenant_id: str, fingerprint: str) -> bool:
        """Remove the cached verdict for ``fingerprint``; True when one existed."""
        if not fingerprint:
            return False
        return bool(await self._redis.delete(self.key(tenant_id, fingerprint)))

    async def clear_tenant(self, tenant_id: str) -> int:
        """Remove every cached verdict of the tenant; returns how many were removed."""
        pattern = self.key(tenant_id, "*").replace("[", "\\[").replace("]", "\\]")
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
