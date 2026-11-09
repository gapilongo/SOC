"""The analyst oracle (``lg-sotf eval --oracle``): every escalation decided at once, from the ground truth.

An evaluation normally leaves an escalated alert waiting: the harness never
invents an analyst decision, so the mechanisms that learn from analysts (the
verdict cache, the tenant's entity history, suppression proposals) never see
one and cannot be measured. The oracle answers the question "how much would
automation close if analysts decided every escalation correctly and at
once?".

It is a labelled measurement mode, never a default. For each item, after the
run stops at an interrupt, a simulated analyst (a user created in the
evaluation tenant) acts through the real decision path, the one the API uses:

* an analyst escalation is decided with :meth:`ReviewService.decide
  <lg_sotf.services.review.ReviewService.decide>`: ``false_positive`` for an
  expected-benign item, ``true_positive`` for an expected-malicious one (and,
  as ``POST /escalations/{id}/decision`` does, the alert's cached benign
  verdicts are dropped and the suppression rules matching it disabled). The run is then resumed with the decision, so the close
  node writes the verdict cache and the history provider sees an analyst's
  outcome. A ``false_positive`` creates the disabled suppression suggestion the
  tenant's review policy asks for; with ``accept_suppressions`` the oracle
  also enables it, as an admin who approves every suggestion would;
* response actions waiting for approval are rejected (an evaluation never
  executes a response); the run then closes (analyst-confirmed threat) or
  comes back as an escalation, which is decided as above.

Items without a ground-truth disposition (``inconclusive``) are left waiting.
The item's ``status`` keeps what automation did before the oracle acted;
``oracle_decisions`` and ``final_status`` record the oracle's part. Items run
one at a time in event-time order (:func:`lg_sotf.eval.closure.event_time_order`),
so an alert only benefits from decisions on alerts that happened before it.
The verdict cache keeps its wall-clock lifetime (seven days), which a replay of
a few days never reaches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.benign_learning import forget_benign_learning
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.eval.results import REVIEW_ORACLE, ItemResult
from lg_sotf.services.review import ResumeRequest, ReviewService
from lg_sotf.services.suppressions import update_rule

if TYPE_CHECKING:
    from lg_sotf.core.workflow import RunOutcome, WorkflowEngine
    from lg_sotf.db.repos import Repositories
    from lg_sotf.eval.dataset import EvalItem

ORACLE_EMAIL = "analyst-oracle@eval.example.com"
ORACLE_ROLE = "admin"  # decides escalations, rejects actions of any risk, enables suggested suppressions
ORACLE_NOTES = "Analyst oracle: decided from the evaluation dataset's ground truth."
MAX_ORACLE_STEPS = 6
DECISION_FOR: Dict[str, str] = {"benign": "false_positive", "malicious": "true_positive"}
REJECT_ACTIONS = "reject_actions"


@dataclass
class AnalystOracle:
    """Decides each waiting run of one evaluation from the item's expected disposition."""

    repos: Repositories
    engine: WorkflowEngine
    review: ReviewService
    accept_suppressions: bool = False
    suppressions_enabled: int = 0
    _users: Dict[str, UUID] = field(default_factory=dict, init=False, repr=False)

    async def user(self, tenant_id: str) -> UUID:
        """The oracle's account in ``tenant_id`` (created on first use)."""
        if tenant_id not in self._users:
            existing = await self.repos.users.get_by_email(tenant_id, ORACLE_EMAIL)
            account = existing or await self.repos.users.create(tenant_id, ORACLE_EMAIL, ORACLE_ROLE)
            self._users[tenant_id] = account.id
        return self._users[tenant_id]

    async def settle(self, tenant_id: str, item: EvalItem, result: ItemResult, outcome: RunOutcome) -> None:
        """Decide ``item``'s waiting run until it stops waiting (at most :data:`MAX_ORACLE_STEPS` decisions)."""
        decision = DECISION_FOR.get(item.expected.disposition)
        if decision is None or result.alert_id is None or outcome.status == "completed":
            return
        alert_id = result.alert_id
        user = await self.user(tenant_id)
        result.review = REVIEW_ORACLE
        current: Optional[RunOutcome] = outcome
        for _ in range(MAX_ORACLE_STEPS):
            if current is None or current.status == "completed":
                break
            pending: Mapping[str, Any] = current.interrupt or {}
            if current.status == "waiting_human" and pending.get("escalation_id"):
                requests = await self._decide(tenant_id, str(pending["escalation_id"]), decision, user)
                result.oracle_decisions.append(decision)
            elif current.status == "waiting_approval" and pending.get("action_ids"):
                requests = await self.review.reject_actions(
                    tenant_id, list(pending["action_ids"]), user, ORACLE_ROLE, reject_remaining=True
                )
                result.oracle_decisions.append(REJECT_ACTIONS)
            else:
                break
            current = await self._resume(tenant_id, alert_id, requests)
        result.final_status = (await self.repos.alerts.get(tenant_id, alert_id)).status

    async def _decide(self, tenant_id: str, escalation_id: str, decision: str, user: UUID) -> List[ResumeRequest]:
        escalation = await self.repos.escalations.get(tenant_id, escalation_id)
        decided = await self.review.decide(
            tenant_id, escalation_id, user, ORACLE_ROLE, decision, ORACLE_NOTES, [], escalation.version
        )
        if decision == "true_positive":
            alert = await self.repos.alerts.get(tenant_id, decided.escalation.alert_id)
            await forget_benign_learning(self.repos, self._verdicts, tenant_id, alert, actor=Actor("user", str(user)))
        if self.accept_suppressions and decided.suppression_suggestion_id:
            actor = Actor("user", str(user))
            await update_rule(
                self.repos, AuditLogger(self.repos), tenant_id, actor, decided.suppression_suggestion_id,
                {"enabled": True}, fields=["enabled"],
            )
            self.suppressions_enabled += 1
        return list(decided)

    @property
    def _verdicts(self) -> VerdictCache:
        return self.engine.node_deps.verdicts

    async def _resume(self, tenant_id: str, alert_id: str, requests: Sequence[ResumeRequest]) -> Optional[RunOutcome]:
        """Resume every run the decision released; the outcome of ``alert_id``'s run (None when it was not one)."""
        own: Optional[RunOutcome] = None
        for request in requests:
            resumed = await self.engine.resume(tenant_id, request.alert_id, request.payload)
            if request.alert_id == alert_id:
                own = resumed
        return own


def oracle_info(oracle: Optional[AnalystOracle]) -> Dict[str, Any]:
    """``report.run.oracle`` of a run with the oracle (empty without)."""
    if oracle is None:
        return {}
    return {
        "oracle": {
            "decisions": dict(DECISION_FOR),
            "accept_suppressions": oracle.accept_suppressions,
            "suppressions_enabled": oracle.suppressions_enabled,
            "order": "event_time",
        }
    }
