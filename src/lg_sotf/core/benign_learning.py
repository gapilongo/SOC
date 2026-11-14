"""Forget what analysts taught automation about an alert once a threat is confirmed on it.

Two mechanisms close alerts from earlier analyst decisions: the verdict cache
(:mod:`lg_sotf.core.verdict_cache`) and suppression rules suggested from
false positives and enabled by an admin. When an analyst decides
``true_positive``, a blind audit labels an alert malicious, the workflow plans a
response or an alert closes malicious, :func:`forget_benign_learning` drops the
alert's cached decisions, blocks its verdict key and fingerprint for the cache
window, and disables every active suppression rule that would close it
(audited ``suppression.revoked``).
"""

from __future__ import annotations

from typing import Any, List

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.suppression import stored_alert_view
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.services.suppressions import disable_rules_matching


async def forget_benign_learning(
    repos: Repositories, verdicts: VerdictCache, tenant_id: str, alert: Any, *, actor: Actor
) -> List[str]:
    """Invalidate the cache for ``alert`` (a stored alert) and disable the rules matching it; the rule ids."""
    await verdicts.invalidate(tenant_id, verdict_key_of(alert), fingerprint=alert.fingerprint or None)
    return await disable_rules_matching(
        repos, AuditLogger(repos), tenant_id, stored_alert_view(alert), actor=actor, alert_id=alert.id
    )
