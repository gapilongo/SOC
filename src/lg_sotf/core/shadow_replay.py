"""Shadow replay (AI-E1.5b): a candidate's verdict beside production's on alerts production decided.

:class:`ShadowReplay` runs each alert through a :class:`~lg_sotf.core.shadow.ShadowRunner`
built with the candidate, reads what production decided on the same alert,
and stores the pair in ``shadow_verdicts`` under one report id, one row per
alert. A candidate run that fails is stored with its error type and no
verdict; the replay goes on with the next alert. Each row is written after
its shadow run has left shadow mode, like the run's ``shadow_effects``.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Sequence, Tuple
from uuid import uuid4

from lg_sotf.core.shadow import ShadowOutcome, ShadowRunner
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.shadow_agreement import MAX_ACTIONS, Comparison, Verdict
from lg_sotf.models.vocabulary import DISPOSITIONS, ROUTES
from lg_sotf.observability.logging import get_logger, log_failure

log = get_logger(__name__)

REPORT_PREFIX = "shr_"
Progress = Callable[[int, int, Comparison], None]


def new_report_id() -> str:
    return REPORT_PREFIX + uuid4().hex


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def candidate_verdict(outcome: ShadowOutcome) -> Verdict:
    """What the candidate decided: its routing decision, else ``close`` when it closed before deciding.

    A run closes before ``decide`` when the gate suppressed the alert or triage closed it as a false positive.
    """
    state = outcome.state
    decision = _mapping(state.get("decision"))
    if decision.get("route") in ROUTES:
        route, disposition = decision.get("route"), decision.get("disposition")
    elif state.get("disposition") is not None or _mapping(state.get("gate")).get("suppressed"):
        route, disposition = "close", state.get("disposition")
    else:
        route, disposition = None, None
    plan = next((e for e in outcome.effects if e.boundary == "response_plan"), None)
    actions = sorted({str(a) for a in plan.detail.get("actions") or ()}) if plan is not None else []
    confidence = state.get("confidence")
    return Verdict(
        route=route,
        disposition=disposition if disposition in DISPOSITIONS else None,
        confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
        actions=tuple(actions[:MAX_ACTIONS]),
        tokens=outcome.llm_tokens,
        cost_usd=outcome.llm_cost_usd,
        latency_ms=sum(int(getattr(step, "latency_ms", 0) or 0) for step in outcome.trace),
    )


class ShadowReplay:
    """Replays alerts through ``runner`` (the candidate ``candidate``) and stores each comparison."""

    def __init__(self, runner: ShadowRunner, repos: Repositories, *, candidate: str) -> None:
        self._runner = runner
        self._repos = repos
        self.candidate = candidate

    async def run(
        self, tenant_id: str, alert_ids: Sequence[str], *, report_id: Optional[str] = None,
        progress: Optional[Progress] = None,
    ) -> str:
        """Replay ``alert_ids`` (those that still exist) into ``report_id`` (new by default); returns the id."""
        report_id = report_id or new_report_id()
        production = await self._repos.shadow_verdicts.production_verdicts(tenant_id, alert_ids)
        todo = [production[a] for a in alert_ids if a in production]
        for done, base in enumerate(todo, start=1):
            row, run_id = await self._compare(tenant_id, base)
            await self._repos.shadow_verdicts.append(tenant_id, report_id, self.candidate, row, run_id=run_id)
            if progress is not None:
                progress(done, len(todo), row)
        log.info("shadow.replay_completed", tenant_id=tenant_id, report_id=report_id, alerts=len(todo))
        return report_id

    async def _compare(self, tenant_id: str, base: Comparison) -> Tuple[Comparison, Optional[str]]:
        try:
            outcome = await self._runner.run(tenant_id, base.alert_id)
        except Exception as exc:  # noqa: BLE001 - one failed candidate run is a row of the report, not the end of it
            log_failure(log, "shadow.replay_alert_failed", exc, level="warning", alert_id=base.alert_id)
            return base.model_copy(update={"candidate": Verdict(error=type(exc).__name__)}), None
        return base.model_copy(update={"candidate": candidate_verdict(outcome)}), outcome.run_id
