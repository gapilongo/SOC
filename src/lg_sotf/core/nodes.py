"""Workflow node implementations and the wrapper every non-interrupt node runs in.

The wrapper applies the node timeout, binds the logging context, observes
``lgsotf_node_seconds``, appends a ``node.completed`` alert event with the
node's small digest and publishes ``alert.updated``. Nodes return LangGraph
state updates; the optional ``_event`` key carries the digest and never
reaches graph state.

Side-effecting nodes (``escalate``, ``plan_response``, ``execute_actions``,
``close``) are idempotent because LangGraph re-runs a node whose checkpoint
was not written.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, cast

from langgraph.types import interrupt

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.registry import AgentSet
from lg_sotf.core.benign_learning import forget_benign_learning
from lg_sotf.core.graph import WorkflowState
from lg_sotf.core.state import (
    AlertSummary,
    AnalystInput,
    DecisionDigest,
    EscalationSummary,
    GateDigest,
    ResponseSummary,
    RoutingDigest,
    SuppressedBy,
)
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain import closure, routing
from lg_sotf.domain.events import EventPublisher, publish_event
from lg_sotf.domain.routing import BENIGN_DECISIONS, RoutingThresholds
from lg_sotf.domain.suppression import alert_match_view, fingerprint_suggestion, first_matching_rule
from lg_sotf.errors import NodeTimeout
from lg_sotf.llm import USE_DEFAULT, TokenBudget
from lg_sotf.observability.logging import bound_context, get_logger, log_failure
from lg_sotf.observability.metrics import observe_node
from lg_sotf.security.shadow import shadow_run_id
from lg_sotf.services.escalation import WORKFLOW_ACTOR, EscalationService
from lg_sotf.services.plan_context import plan_context
from lg_sotf.services.response import ResponseService
from lg_sotf.settings import Settings

log = get_logger(__name__)

NodeFn = Callable[[WorkflowState], Awaitable[Dict[str, Any]]]
AGENT_NODES = frozenset({"triage", "correlation", "analysis"})
EVENT_KEY = "_event"
MAX_EVENT_KEYS = 20


@dataclass
class NodeDeps:
    settings: Settings
    repos: Repositories
    agents: AgentSet
    escalations: EscalationService
    responses: ResponseService
    verdicts: VerdictCache
    thresholds: RoutingThresholds
    events: Optional[EventPublisher] = None
    budget: Optional[TokenBudget] = None


def _small(data: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in list(data.items())[:MAX_EVENT_KEYS]:
        if isinstance(value, str):
            out[key] = value[:300]
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            out[key] = [v if isinstance(v, (int, float, bool)) else str(v)[:120] for v in list(value)[:10]]
        elif isinstance(value, Mapping):
            out[key] = {str(k)[:64]: v for k, v in list(value.items())[:10] if isinstance(v, (str, int, float, bool))}
    return out


def _escalation_summary(state: WorkflowState, routing_digest: RoutingDigest) -> EscalationSummary:
    """What an escalation shows the analyst about this alert (small; no raw alert data)."""
    analysis = state.get("analysis") or {}
    confidence = float(state.get("confidence", 50))
    return {
        "title": str(state["alert"].get("title", ""))[:300],
        "severity": state["severity"],
        "confidence": confidence,
        "threat_score": analysis.get("threat_score"),
        "verdict": analysis.get("verdict"),
        "conclusion": str(analysis.get("conclusion") or "")[:1_000],
        "simulated_evidence": bool(analysis.get("simulated_evidence")),
        "recommended_actions": list(analysis.get("recommended_actions") or [])[:10],
        # Whether ``conclusion`` was written by the model (else by the rules); unknown without an analysis.
        "llm_used": analysis["llm_used"] if isinstance(analysis.get("llm_used"), bool) else None,
        "routing": routing_digest,
    }


class WorkflowNodes:
    def __init__(self, deps: NodeDeps) -> None:
        self.deps = deps
        self._impl: Dict[str, NodeFn] = {
            "gate": self.gate,
            "triage": self.triage,
            "correlation": self.correlation,
            "analysis": self.analysis,
            "decide": self.decide,
            "escalate": self.escalate,
            "await_analyst": self.await_analyst,
            "plan_response": self.plan_response,
            "await_approval": self.await_approval,
            "execute_actions": self.execute_actions,
            "close": self.close,
        }

    def node(self, name: str) -> NodeFn:
        fn = self._impl[name]
        if name.startswith("await_"):
            return fn
        worker = self.deps.settings.worker
        timeout_s = worker.analysis_timeout_s if name == "analysis" else worker.node_timeout_s
        return self._wrap(name, fn, timeout_s)

    def _wrap(self, name: str, fn: NodeFn, timeout_s: float) -> NodeFn:
        repos = self.deps.repos
        events = self.deps.events
        actor_type = "agent" if name in AGENT_NODES else "system"

        async def run_node(state: WorkflowState) -> Dict[str, Any]:
            tenant_id, alert_id = state["tenant_id"], state["alert_id"]
            started = time.perf_counter()
            with bound_context(
                tenant_id=tenant_id, alert_id=alert_id, thread_id=thread_id_for(tenant_id, alert_id), node=name
            ):
                try:
                    budget = asyncio.timeout(timeout_s)
                    try:
                        async with budget:
                            update = await fn(state)
                    except TimeoutError as exc:
                        if budget.expired():
                            raise NodeTimeout(name, timeout_s) from exc
                        raise
                    digest = _small(update.pop(EVENT_KEY, {}))
                    await repos.alert_events.append(
                        tenant_id,
                        alert_id,
                        "node.completed",
                        node=name,
                        actor_type=actor_type,
                        actor_id=name if actor_type == "agent" else "workflow",
                        data=digest,
                    )
                except Exception as exc:
                    log_failure(log, "workflow.node_failed", exc, level="warning", error_type=type(exc).__name__)
                    raise
                finally:
                    observe_node(name, time.perf_counter() - started)
                log.info("workflow.node_completed", duration_ms=round((time.perf_counter() - started) * 1000))
            await publish_event(events, "alert.updated", tenant_id, alert_id, {"node": name, **digest})
            return update

        run_node.__name__ = f"node_{name}"
        return run_node

    def _ctx(self, state: WorkflowState) -> AgentContext:
        limit = state.get("llm_budget_limit")
        return AgentContext(
            tenant_id=state["tenant_id"],
            alert_id=state["alert_id"],
            settings=self.deps.settings,
            repos=self.deps.repos,
            budget=self.deps.budget,
            budget_limit=limit if isinstance(limit, int) else USE_DEFAULT,
            llm_budget_exceeded=bool(state.get("llm_budget_exceeded")),
            run_id=shadow_run_id(),
        )

    async def gate(self, state: WorkflowState) -> Dict[str, Any]:
        tenant_id, alert = state["tenant_id"], state["alert"]
        raw_flags = alert.get("flags")
        # An LLM-normalised alert's fields were chosen by a model from attacker-shaped text: no suppression
        # rule and no cached verdict closes it.
        if "llm_normalized" in (raw_flags if isinstance(raw_flags, list) else []):
            return {"gate": {"suppressed": False}, EVENT_KEY: {"suppressed": False}}
        view = alert_match_view(
            title=str(alert.get("title", "")),
            severity=state["severity"],
            category=alert.get("category"),
            source_id=str(alert.get("source_id", "")),
            source_alert_id=str(alert.get("source_alert_id", "")),
            fingerprint=state.get("fingerprint", ""),
            normalized=alert,
            verdict_key=state.get("verdict_key"),
        )
        # Suggestions written before verdict keys matched a fingerprint alone; migration 0016 disabled them.
        rules = [r for r in await self.deps.repos.suppressions.list_active(tenant_id) if not fingerprint_suggestion(r)]
        match = first_matching_rule(rules, view)
        if match is not None:
            await self.deps.repos.suppressions.record_hit(tenant_id, match.rule_id)
            by: SuppressedBy = {"type": "suppression_rule", "rule_id": match.rule_id, "name": match.name[:200]}
            return {"gate": {"suppressed": True, "suppressed_by": by}, EVENT_KEY: {"suppressed": True, "rule_id": match.rule_id}}
        if state["severity"] != "critical":
            cached = await self.deps.verdicts.closing_decision(
                tenant_id, state.get("verdict_key"), state["severity"], fingerprint=state.get("fingerprint")
            )
            if cached is not None:
                cache_hit: SuppressedBy = {
                    "type": "verdict_cache",
                    "decision": cached.get("decision"),
                    "source_alert_id": cached.get("alert_id"),
                }
                return {
                    "gate": {"suppressed": True, "suppressed_by": cache_hit},
                    EVENT_KEY: {"suppressed": True, "verdict_cache": True},
                }
        return {"gate": {"suppressed": False}, EVENT_KEY: {"suppressed": False}}

    async def triage(self, state: WorkflowState) -> Dict[str, Any]:
        ctx = self._ctx(state)
        result = await self.deps.agents.triage.run(ctx, state["alert"])
        digest = result.digest()
        await self.deps.repos.alerts.update(
            ctx.tenant_id, ctx.alert_id, confidence=result.confidence, priority=result.priority, summary={"triage": digest}
        )
        return {
            "triage": digest,
            "confidence": result.confidence,
            "llm_budget_exceeded": ctx.llm_budget_exceeded,
            "notes": result.notes,
            EVENT_KEY: {
                "confidence": result.confidence,
                "rule_confidence": result.rule_confidence,
                "priority": result.priority,
                "rule_fp": len(result.rule_fp),
                "rule_tp": len(result.rule_tp),
                "llm_used": result.llm_used,
            },
        }

    async def correlation(self, state: WorkflowState) -> Dict[str, Any]:
        ctx = self._ctx(state)
        result = await self.deps.agents.correlation.run(
            ctx, state["alert"], base_confidence=float(state.get("confidence", 50))
        )
        digest = result.digest()
        await self.deps.repos.alerts.update(
            ctx.tenant_id, ctx.alert_id, confidence=result.confidence, summary={"correlation": digest}
        )
        return {
            "correlation": digest,
            "confidence": result.confidence,
            "llm_budget_exceeded": ctx.llm_budget_exceeded,
            "notes": result.notes,
            EVENT_KEY: {
                "score": result.score,
                "related_count": result.related_count,
                "indicators": result.indicator_count,
                "burst": result.burst,
                "llm_used": result.llm_used,
            },
        }

    async def analysis(self, state: WorkflowState) -> Dict[str, Any]:
        ctx = self._ctx(state)
        analyst = state.get("analyst") or {}
        loops = int(state.get("more_info_loops", 0))
        notes: Optional[str] = None
        if analyst.get("decision") == "needs_more_info":
            loops += 1
            notes = str(analyst.get("notes") or "") or "analyst requested more information"
        result = await self.deps.agents.analysis.run(
            ctx,
            state["alert"],
            triage=state.get("triage") or {},
            correlation=state.get("correlation") or {},
            analyst_notes=notes,
        )
        summary: AlertSummary = {"analysis": result.summary()}
        if ctx.llm_budget_exceeded:
            summary["llm_budget_exceeded"] = True
        await self.deps.repos.alerts.update(
            ctx.tenant_id, ctx.alert_id, threat_score=result.threat_score, summary=summary
        )
        return {
            "analysis": result.digest(),
            "analysis_runs": int(state.get("analysis_runs", 0)) + 1,
            "more_info_loops": loops,
            "llm_budget_exceeded": ctx.llm_budget_exceeded,
            "notes": result.notes,
            EVENT_KEY: {
                "threat_score": result.threat_score,
                "rule_threat_score": result.rule_threat_score,
                "verdict": result.verdict,
                "llm_used": result.llm_used,
                "tool_steps": result.tool_steps,
                "simulated_evidence": result.simulated_evidence,
            },
        }

    async def decide(self, state: WorkflowState) -> Dict[str, Any]:
        """Route on the analysed alert, with the tenant's model-led closure tier as it is now (``off`` if unset)."""
        tenant = await self.deps.repos.tenants.get(state["tenant_id"])
        tier = closure.autonomy_tier(tenant.settings)
        decision = routing.decide(state, self.deps.thresholds, tier).as_dict()
        return {"decision": decision, EVENT_KEY: {**decision, "autonomy_tier": tier}}

    async def escalate(self, state: WorkflowState) -> Dict[str, Any]:
        tenant_id, alert_id = state["tenant_id"], state["alert_id"]
        decision = dict(state.get("decision") or {})
        analysis = state.get("analysis") or {}
        correlation = state.get("correlation") or {}
        confidence = float(state.get("confidence", 50))
        if decision.get("route") == "plan_response" and not state.get("analyst"):
            if "failed" in (state.get("executed") or {}).values():
                decision["reason"] = "an automatic response action failed"
            else:
                decision["reason"] = "automatic response left the threat without a human or a completed action"
            decision["code"] = "response_review"
        code = str(decision.get("code") or "inconclusive")
        ticket = await self.deps.escalations.open_or_attach(
            tenant_id,
            alert_id,
            severity=state["severity"],
            confidence=confidence,
            threat_score=float(analysis.get("threat_score", confidence)),
            reason=str(decision.get("reason") or "analyst review required"),
            reason_code=code,
            summary=_escalation_summary(
                state, routing.routing_digest(code, routing.assessed_threat(state), self.deps.thresholds)
            ),
            correlated_alert_ids=list(correlation.get("related_alert_ids") or []),
            fingerprint=state.get("fingerprint") or None,
        )
        await self.deps.repos.alerts.update(
            tenant_id, alert_id, summary={"escalation_id": ticket.id, "escalation_attached": ticket.attached}
        )
        return {
            "escalation_id": ticket.id,
            EVENT_KEY: {
                "escalation_id": ticket.id,
                "level": ticket.level,
                "priority": ticket.priority,
                "created": ticket.created,
                "attached": ticket.attached,
            },
        }

    async def await_analyst(self, state: WorkflowState) -> Dict[str, Any]:
        """Wait for the analyst decision on the escalation this alert waits on.

        A decision on a grouped escalation's parent alert is *inherited* by an
        attached alert (:meth:`EscalationService.decision_scope`): it is
        marked ``inherited_from`` and stripped of pre-approved actions, so it
        never authorises containment of this alert's assets. A benign group
        decision that does not fit this alert (another detection, or more
        severe) is not applied: the alert gets its own escalation and the run
        waits again, on that escalation (a second interrupt in this node).
        LangGraph re-runs the node from the top on every resume, so the
        lookups and the detach are idempotent.
        """
        tenant_id, alert_id = state["tenant_id"], state["alert_id"]
        waiting_on = state.get("escalation_id")
        decision = dict(interrupt({"type": "analyst_decision", "escalation_id": waiting_on}))
        if not waiting_on:
            return {"analyst": decision}
        scope = await self.deps.escalations.decision_scope(
            tenant_id,
            alert_id,
            str(waiting_on),
            decision=str(decision.get("decision")),
            verdict_key=state.get("verdict_key"),
            severity=state["severity"],
        )
        if not scope.inherited:
            return {"analyst": decision}
        if scope.own_review_reason is None:
            return {"analyst": {**decision, "approved_actions": [], "inherited_from": scope.parent_alert_id}}
        analysis = state.get("analysis") or {}
        confidence = float(state.get("confidence", 50))
        ticket = await self.deps.escalations.open_detached(
            tenant_id,
            alert_id,
            scope.escalation,
            reason_code=scope.own_review_reason,
            decision=str(decision.get("decision")),
            severity=state["severity"],
            confidence=confidence,
            threat_score=float(analysis.get("threat_score", confidence)),
            summary=_escalation_summary(
                state, routing.routing_digest("group_review", confidence, self.deps.thresholds)
            ),
        )
        if ticket.created:
            await self.deps.repos.alerts.update(
                tenant_id,
                alert_id,
                summary={"escalation_id": ticket.id, "escalation_attached": False, "detached_from": scope.escalation.id},
            )
            await self.deps.repos.alert_events.append(
                tenant_id,
                alert_id,
                "escalation.detached",
                node="await_analyst",
                actor_type="system",
                actor_id="workflow",
                data={
                    "escalation_id": ticket.id,
                    "detached_from": scope.escalation.id,
                    "group_decision": str(decision.get("decision")),
                    "reason": scope.own_review_reason,
                },
            )
        own = interrupt({"type": "analyst_decision", "escalation_id": ticket.id})
        return {"analyst": dict(own), "escalation_id": ticket.id}

    async def _forget_benign_learning(self, state: WorkflowState) -> None:
        """A threat on this alert: no cached verdict or suppression rule may close it, or its repeats, again."""
        alert = await self.deps.repos.alerts.get(state["tenant_id"], state["alert_id"])
        await forget_benign_learning(self.deps.repos, self.deps.verdicts, state["tenant_id"], alert, actor=WORKFLOW_ACTOR)

    def _evidence(self, state: WorkflowState) -> str:
        """What authorises containment for this plan: ``analyst``, ``rules`` or ``llm_only``.

        ``rules`` only when the analysis agent found corroborating rule
        evidence (``rule_corroborated``: threat intel, analyst-confirmed
        history, specific indicators; never severity or field presence).
        Without an analysis (correlation went straight to ``decide``) the
        evidence is ``llm_only``: triage rules read text an attacker can
        shape and never corroborate containment. Digests written before
        ``rule_corroborated`` existed fall back to the capped rule score.
        """
        analyst = state.get("analyst") or {}
        if analyst.get("decision") == "true_positive" and not analyst.get("inherited_from"):
            return "analyst"
        analysis = state.get("analysis") or {}
        if not analysis:
            return "llm_only"
        corroborated = analysis.get("rule_corroborated")
        if isinstance(corroborated, bool):
            return "rules" if corroborated else "llm_only"
        rule_score = float(analysis.get("rule_threat_score", 0))
        return "rules" if rule_score >= self.deps.thresholds.response_threshold else "llm_only"

    async def plan_response(self, state: WorkflowState) -> Dict[str, Any]:
        tenant_id, alert_id, alert = state["tenant_id"], state["alert_id"], state["alert"]
        analysis = state.get("analysis") or {}
        triage = state.get("triage") or {}
        analyst = state.get("analyst") or {}
        # An inherited group decision (attached alert) never pre-approves this alert's actions.
        is_tp = analyst.get("decision") == "true_positive" and not analyst.get("inherited_from")
        ctx = plan_context(
            alert,
            severity=state["severity"],
            evidence=self._evidence(state),  # type: ignore[arg-type]
            analysis=analysis,
            triage=triage,
            approved_actions=list(analyst.get("approved_actions") or []) if is_tp else [],
            approved_by=str(analyst.get("decided_by")) if is_tp and analyst.get("decided_by") else None,
            approver_role=analyst.get("approver_role") if is_tp else None,
        )
        # A response for this detection contradicts any cached "benign" verdict for it.
        await self._forget_benign_learning(state)
        plan = await self.deps.responses.plan(tenant_id, alert_id, ctx)
        response: ResponseSummary = {
            "threat_type": plan.threat_type,
            "evidence": ctx.evidence,
            "auto": len(plan.auto),
            "awaiting": len(plan.awaiting),
            "blocked": len(plan.blocked),
            "done": len(plan.done),
        }
        await self.deps.repos.alerts.update(tenant_id, alert_id, summary={"response": response})
        return {
            "plan": plan.as_dict(),
            "awaiting_actions": list(plan.awaiting),
            "approval": None,
            EVENT_KEY: dict(response),
        }

    async def await_approval(self, state: WorkflowState) -> Dict[str, Any]:
        decision = interrupt({"type": "approval", "action_ids": list(state.get("awaiting_actions") or [])})
        return {"approval": decision}

    async def execute_actions(self, state: WorkflowState) -> Dict[str, Any]:
        """Apply the pending approval decision (if any), run every approved action, re-read what still waits.

        A decision changes only the actions it names unless it sets
        ``reject_remaining``; actions still awaiting approval afterwards send
        the run back to ``await_approval`` with a fresh interrupt. Every
        execution pass of one node run shares one execution budget.

        Approvals commit through the API whenever the analyst clicks, also
        while this node runs, and their resume messages cannot reach a run
        that is not waiting. So the node keeps executing until one execute
        pass over the pending work finds nothing approved: every action is
        then either finished or was still ``awaiting_approval`` when that
        pass read it, in which case it stays in ``awaiting_actions`` and its
        approval's resume message continues the run at ``await_approval``.
        """
        tenant_id, alert_id = state["tenant_id"], state["alert_id"]
        plan = state.get("plan") or {}
        approval = state.get("approval")
        awaiting = list(state.get("awaiting_actions") or [])
        approvals: Dict[str, str] = {}
        if approval is not None and awaiting:
            approvals = await self.deps.responses.apply_approval(
                tenant_id,
                alert_id,
                pending_ids=awaiting,
                approved_ids=list(approval.get("approved_action_ids") or []),
                rejected_ids=list(approval.get("rejected_action_ids") or []),
                decided_by=str(approval.get("decided_by") or "unknown"),
                reject_remaining=bool(approval.get("reject_remaining")),
            )
        candidates = list(
            dict.fromkeys(
                [*(plan.get("auto") or []), *(plan.get("awaiting") or []), *(plan.get("done") or []), *awaiting]
            )
        )
        # One execution budget for the whole node run, however many passes it takes: each pass gets what is left.
        loop = asyncio.get_running_loop()
        ends_at = loop.time() + self.deps.responses.execution_budget_s

        def remaining() -> float:
            return max(0.0, ends_at - loop.time())

        results = await self.deps.responses.execute(tenant_id, alert_id, candidates, budget_s=remaining())
        still_waiting = await self.deps.responses.awaiting(tenant_id, alert_id, candidates)
        for _ in range(len(candidates) + 1):
            if not still_waiting:
                break
            again = await self.deps.responses.execute(tenant_id, alert_id, still_waiting, budget_s=remaining())
            results.update(again)
            if all(status == "awaiting_approval" for status in again.values()):
                still_waiting = [i for i in still_waiting if again.get(i) == "awaiting_approval"]
                break
            still_waiting = await self.deps.responses.awaiting(tenant_id, alert_id, candidates)
        executed = {**(state.get("executed") or {}), **approvals, **results}
        statuses: Dict[str, int] = {}
        for status in executed.values():
            statuses[status] = statuses.get(status, 0) + 1
        return {
            "executed": executed,
            "awaiting_actions": still_waiting,
            "approval": None,
            EVENT_KEY: {
                "statuses": statuses,
                "approval_applied": approval is not None,
                "still_awaiting": len(still_waiting),
            },
        }

    @staticmethod
    def outcome(state: Mapping[str, Any]) -> tuple[str, str]:
        """(disposition, close reason) for the path that reached ``close``."""
        analyst = cast(AnalystInput, state.get("analyst") or {})
        decision = analyst.get("decision")
        if decision in BENIGN_DECISIONS:
            return "benign", f"analyst:{decision}"
        if decision == "true_positive":
            return "malicious", "analyst:true_positive"
        gate = cast(GateDigest, state.get("gate") or {})
        if gate.get("suppressed"):
            return "benign", str((gate.get("suppressed_by") or {}).get("type") or "suppressed")
        decided = cast(DecisionDigest, state.get("decision") or {})
        route = decided.get("route")
        if route == "close":
            model_led = decided.get("code") == closure.MODEL_CLOSED
            return str(decided.get("disposition") or "benign"), closure.MODEL_CLOSE_REASON if model_led else "policy:close"
        if route == "plan_response":
            return "malicious", "policy:response"
        return "benign", "triage:false_positive"

    async def close(self, state: WorkflowState) -> Dict[str, Any]:
        tenant_id, alert_id = state["tenant_id"], state["alert_id"]
        disposition, reason = self.outcome(state)
        analysis = state.get("analysis") or {}
        analyst = state.get("analyst") or {}
        executed = state.get("executed") or {}
        statuses: Dict[str, int] = {}
        for status in executed.values():
            statuses[status] = statuses.get(status, 0) + 1
        summary: AlertSummary = {
            "verdict": disposition,
            "close_reason": reason,
            "confidence": state.get("confidence"),
            "threat_score": analysis.get("threat_score"),
            "decision": state.get("decision") or None,
            "analyst_decision": analyst.get("decision"),
            "escalation_id": state.get("escalation_id"),
            "actions": statuses,
            "dry_run": statuses.get("dry_run", 0) > 0,
            "simulated_evidence": bool(analysis.get("simulated_evidence")),
            "llm_budget_exceeded": bool(state.get("llm_budget_exceeded")),
        }
        gate = state.get("gate") or {}
        if gate.get("suppressed"):
            summary["suppressed_by"] = gate.get("suppressed_by")
        threat = analysis.get("threat_score")
        async with self.deps.repos.db.tenant_tx(tenant_id) as conn:
            await self.deps.repos.alerts.update(
                tenant_id,
                alert_id,
                disposition=disposition,
                confidence=float(state.get("confidence", 50)),
                threat_score=float(threat) if threat is not None else None,
                summary=summary,
                conn=conn,
            )
            await self.deps.repos.alerts.update_status(tenant_id, alert_id, "closed", conn=conn)
        if analyst.get("decision") in BENIGN_DECISIONS:
            await self.deps.verdicts.put_analyst_benign(
                tenant_id,
                state.get("verdict_key"),
                decision=str(analyst["decision"]),
                alert_id=alert_id,
                escalation_id=state.get("escalation_id"),
                decided_by=str(analyst.get("decided_by") or "") or None,
                severity=state["severity"],
            )
        elif disposition == "malicious":
            await self._forget_benign_learning(state)
        return {
            "disposition": disposition,
            "close_reason": reason,
            EVENT_KEY: {"status": "closed", "disposition": disposition, "close_reason": reason},
        }
