"""
Human-in-the-Loop Agent for LG-SOTF.

This agent handles:
- Escalating alerts for human review
- Collecting analyst feedback
- Managing escalation queues and SLAs
- Providing feedback to learning agent
"""

import asyncio
from typing import Dict, Any, Optional

from lg_sotf.agents.base import BaseAgent
from lg_sotf.core.state.manager import StateManager
from lg_sotf.storage.redis import RedisStorage
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.agents.human_loop.escalation import (
    EscalationManager,
    EscalationReason,
    Escalation,
)
from lg_sotf.agents.human_loop.feedback import FeedbackHandler, AnalystDecision


class HumanLoopAgent(BaseAgent):
    """Agent for human-in-the-loop decision making.

    This agent:
    1. Creates escalations for alerts requiring human review
    2. Manages escalation queue with priority and SLA tracking
    3. Collects analyst feedback for learning
    4. Provides feedback data to learning agent
    """

    def __init__(
        self,
        state_manager: StateManager,
        redis_storage: RedisStorage,
        audit_logger: AuditLogger,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize Human-in-the-Loop agent.

        Args:
            state_manager: State manager for persistence
            redis_storage: Redis storage for queue
            audit_logger: Audit logger
            config: Agent configuration
        """
        # Initialize parent BaseAgent
        super().__init__(config or {})

        self.state_manager = state_manager
        self.redis_storage = redis_storage
        self.audit_logger = audit_logger

        # Initialize managers
        self.escalation_manager = EscalationManager(
            state_manager=state_manager,
            redis_storage=redis_storage,
            audit_logger=audit_logger,
        )
        self.feedback_handler = FeedbackHandler(
            state_manager=state_manager,
            redis_storage=redis_storage,
            audit_logger=audit_logger,
        )

        # Configuration
        self.auto_escalate_enabled = self.config.get("auto_escalate_enabled", True)
        self.sla_check_interval = self.config.get("sla_check_interval", 300)  # 5 minutes

        # Background task
        self._sla_checker_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """Initialize the agent (called by workflow engine)."""
        await self.start()

    async def start(self) -> None:
        """Start the agent and background tasks."""
        if self.auto_escalate_enabled:
            self._sla_checker_task = asyncio.create_task(self._sla_checker_loop())

    async def stop(self) -> None:
        """Stop the agent and background tasks."""
        if self._sla_checker_task:
            self._sla_checker_task.cancel()
            try:
                await self._sla_checker_task
            except asyncio.CancelledError:
                pass

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Human-in-the-Loop logic for workflow.

        This is called by LangGraph workflow when alert needs human review.

        Args:
            state: Workflow state

        Returns:
            Updated state with escalation created
        """
        alert_id = state["alert_id"]
        workflow_instance_id = state.get("workflow_instance_id", "unknown")

        # Determine escalation reason
        reason = self._determine_escalation_reason(state)

        # Prepare context for analyst
        alert_summary = self._create_alert_summary(state)

        # Get metrics
        triage_confidence = state.get("confidence_score", 50.0)
        threat_score = state.get("threat_score", 0.0)
        correlations = state.get("correlations", [])
        correlations_count = len(correlations)

        # Create escalation
        escalation = await self.escalation_manager.create_escalation(
            alert_id=alert_id,
            workflow_instance_id=workflow_instance_id,
            reason=reason,
            alert_summary=alert_summary,
            triage_confidence=triage_confidence,
            threat_score=threat_score,
            correlations_count=correlations_count,
            enrichment_data=state.get("enriched_data", {}),
            analysis_notes=state.get("analysis_conclusion"),
        )

        # Update state
        state["escalation_id"] = escalation.escalation_id
        state["escalation_level"] = escalation.level.value
        state["escalation_priority"] = escalation.priority
        state["escalation_sla_deadline"] = escalation.sla_deadline.isoformat()

        # Add to processing notes
        processing_notes = state.get("processing_notes", [])
        processing_notes.append(
            f"Escalated to {escalation.level.value} for human review "
            f"(Priority: {escalation.priority}, Reason: {reason.value})"
        )
        state["processing_notes"] = processing_notes

        return state

    def _determine_escalation_reason(self, state: Dict[str, Any]) -> EscalationReason:
        """Determine reason for escalation based on state.

        Args:
            state: Workflow state

        Returns:
            Escalation reason
        """
        confidence = state.get("confidence_score", 50.0)
        threat_score = state.get("threat_score", 0.0)
        analysis_conclusion = state.get("analysis_conclusion", "")

        # Check for specific conditions
        if "high-risk" in analysis_conclusion.lower() or "critical" in analysis_conclusion.lower():
            return EscalationReason.HIGH_RISK

        if "complex" in analysis_conclusion.lower() or "multi-stage" in analysis_conclusion.lower():
            return EscalationReason.COMPLEX_ATTACK

        if "conflicting" in analysis_conclusion.lower() or "contradictory" in analysis_conclusion.lower():
            return EscalationReason.CONFLICTING_EVIDENCE

        if "inconclusive" in analysis_conclusion.lower() or "uncertain" in analysis_conclusion.lower():
            return EscalationReason.INCONCLUSIVE

        # Check confidence thresholds (grey zone)
        if 20 <= confidence <= 60:
            return EscalationReason.GREY_ZONE

        # Check if marked as potential FP
        if state.get("triage_status") == "potential_fp":
            return EscalationReason.FALSE_POSITIVE_REVIEW

        # Default to grey zone
        return EscalationReason.GREY_ZONE

    def _create_alert_summary(self, state: Dict[str, Any]) -> str:
        """Create concise alert summary for analyst.

        Args:
            state: Workflow state

        Returns:
            Alert summary text
        """
        raw_alert = state.get("raw_alert", {})
        enriched_data = state.get("enriched_data", {})
        triage_status = state.get("triage_status", "unknown")
        confidence = state.get("confidence_score", 0)
        threat_score = state.get("threat_score", 0)
        correlations = state.get("correlations", [])
        analysis_conclusion = state.get("analysis_conclusion", "")

        # Extract basic alert fields
        alert_id = state.get("alert_id", "unknown")
        alert_type = raw_alert.get("category") or raw_alert.get("alert_type", "unknown")
        severity = raw_alert.get("severity", "unknown")
        title = raw_alert.get("title", "No title")
        description = raw_alert.get("description", "")

        # Extract entities/IOCs
        source = raw_alert.get("source_ip") or raw_alert.get("source_user") or raw_alert.get("source", "unknown")
        target = raw_alert.get("destination_ip") or raw_alert.get("target_user") or raw_alert.get("target", "unknown")
        entities = raw_alert.get("entities", [])

        # Extract LLM insights
        llm_insights = enriched_data.get("llm_insights", {})
        threat_assessment = llm_insights.get("threat_assessment", "unknown")
        threat_categories = llm_insights.get("threat_categories", [])
        reasoning = llm_insights.get("analysis_reasoning", "")
        recommended_actions = llm_insights.get("recommended_actions", [])

        # Build comprehensive summary
        summary_parts = [
            f"🎯 ALERT: {title}",
            f"ID: {alert_id} | Category: {alert_type} | Severity: {severity}",
            ""
        ]

        # Add source/target if meaningful
        if source != "unknown" or target != "unknown":
            summary_parts.append(f"📍 Source: {source} → Target: {target}")
            summary_parts.append("")

        # Add entities if present
        if entities:
            entity_str = ", ".join([f"{e.get('type', 'unknown')}: {e.get('value', 'N/A')}" for e in entities[:3]])
            summary_parts.append(f"🔍 Key Entities: {entity_str}")
            if len(entities) > 3:
                summary_parts.append(f"   (+{len(entities) - 3} more)")
            summary_parts.append("")

        # Add triage assessment
        summary_parts.append(f"⚖️ TRIAGE ASSESSMENT")
        summary_parts.append(f"Status: {triage_status} | Confidence: {confidence:.1f}%")
        summary_parts.append(f"Threat Score: {threat_score:.1f} | LLM Assessment: {threat_assessment}")
        if threat_categories:
            summary_parts.append(f"Threat Categories: {', '.join(threat_categories)}")
        summary_parts.append("")

        # Add correlation info
        if correlations:
            summary_parts.append(f"🔗 CORRELATIONS: {len(correlations)} related alerts found")
            summary_parts.append("")

        # Add LLM reasoning (full text)
        if reasoning:
            summary_parts.append(f"🤔 ANALYSIS REASONING:")
            summary_parts.append(reasoning)
            summary_parts.append("")

        # Add analysis conclusion if present (full text)
        if analysis_conclusion:
            summary_parts.append(f"📊 DEEP ANALYSIS:")
            summary_parts.append(analysis_conclusion)
            summary_parts.append("")

        # Add all recommended actions
        if recommended_actions:
            summary_parts.append(f"💡 RECOMMENDED ACTIONS:")
            for i, action in enumerate(recommended_actions, 1):
                summary_parts.append(f"{i}. {action}")
            summary_parts.append("")

        return "\n".join(summary_parts)

    async def _sla_checker_loop(self) -> None:
        """Background task to check SLA violations and auto-escalate."""
        while True:
            try:
                await asyncio.sleep(self.sla_check_interval)

                # Check for SLA violations
                escalated = await self.escalation_manager.check_sla_violations()

            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Log errors silently

    async def get_pending_escalations(
        self,
        level: Optional[str] = None,
        limit: int = 50,
    ) -> list:
        """Get pending escalations for analyst assignment.

        Args:
            level: Filter by level (L1, L2, L3)
            limit: Maximum number to return

        Returns:
            List of pending escalations
        """
        from lg_sotf.agents.human_loop.escalation import EscalationLevel

        escalation_level = None
        if level:
            escalation_level = EscalationLevel(level)

        escalations = await self.escalation_manager.get_pending_escalations(
            level=escalation_level,
            limit=limit,
        )

        # Convert to dict for API response
        return [
            {
                "escalation_id": e.escalation_id,
                "alert_id": e.alert_id,
                "level": e.level.value,
                "status": e.status.value,
                "priority": e.priority,
                "reason": e.reason.value,
                "alert_summary": e.alert_summary,
                "threat_score": e.threat_score,
                "correlations_count": e.correlations_count,
                "created_at": e.created_at.isoformat(),
                "assigned_to": e.assigned_to,
                "assigned_at": e.assigned_at.isoformat() if e.assigned_at else None,
                "sla_deadline": e.sla_deadline.isoformat() if e.sla_deadline else None,
            }
            for e in escalations
        ]

    async def assign_escalation(
        self,
        escalation_id: str,
        analyst_username: str,
    ) -> Dict[str, Any]:
        """Assign escalation to analyst.

        Args:
            escalation_id: Escalation ID
            analyst_username: Analyst username

        Returns:
            Updated escalation data
        """
        escalation = await self.escalation_manager.assign_escalation(
            escalation_id=escalation_id,
            analyst_username=analyst_username,
        )

        return {
            "escalation_id": escalation.escalation_id,
            "alert_id": escalation.alert_id,
            "assigned_to": escalation.assigned_to,
            "assigned_at": escalation.assigned_at.isoformat() if escalation.assigned_at else None,
            "status": escalation.status.value,
        }

    async def submit_feedback(
        self,
        escalation_id: str,
        analyst_username: str,
        decision: str,
        confidence: int,
        notes: str,
        actions_taken: Optional[list] = None,
        actions_recommended: Optional[list] = None,
        triage_correct: Optional[bool] = None,
        correlation_helpful: Optional[bool] = None,
        analysis_accurate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Submit analyst feedback for escalation.

        Args:
            escalation_id: Escalation ID
            analyst_username: Analyst username
            decision: Analyst decision (true_positive, false_positive, etc.)
            confidence: Confidence in decision (1-10)
            notes: Analyst notes
            actions_taken: Actions already taken
            actions_recommended: Actions recommended
            triage_correct: Was triage correct?
            correlation_helpful: Were correlations helpful?
            analysis_accurate: Was analysis accurate?

        Returns:
            Feedback data
        """
        from lg_sotf.agents.human_loop.feedback import ResponseAction

        # Load escalation
        escalation = await self.escalation_manager._load_escalation(escalation_id)
        if not escalation:
            raise ValueError(f"Escalation {escalation_id} not found")

        # Convert decision string to enum
        analyst_decision = AnalystDecision(decision)

        # Convert actions
        actions_taken_enum = [ResponseAction(a) for a in (actions_taken or [])]
        actions_recommended_enum = [ResponseAction(a) for a in (actions_recommended or [])]

        # Record feedback
        feedback = await self.feedback_handler.record_feedback(
            escalation=escalation,
            analyst_username=analyst_username,
            decision=analyst_decision,
            confidence=confidence,
            notes=notes,
            actions_taken=actions_taken_enum,
            actions_recommended=actions_recommended_enum,
            triage_correct=triage_correct,
            correlation_helpful=correlation_helpful,
            analysis_accurate=analysis_accurate,
        )

        return {
            "feedback_id": feedback.feedback_id,
            "escalation_id": feedback.escalation_id,
            "alert_id": feedback.alert_id,
            "decision": feedback.decision.value,
            "confidence": feedback.confidence,
            "created_at": feedback.created_at.isoformat(),
        }

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get escalation queue statistics.

        Returns:
            Queue stats by level
        """
        return await self.escalation_manager.get_queue_stats()

    async def get_decision_stats(self) -> Dict[str, Any]:
        """Get analyst decision statistics.

        Returns:
            Decision statistics
        """
        return await self.feedback_handler.get_decision_stats()

    async def get_triage_accuracy(self) -> Dict[str, Any]:
        """Get triage accuracy from analyst feedback.

        Returns:
            Triage accuracy stats
        """
        return await self.feedback_handler.get_triage_accuracy()

    async def health_check(self) -> bool:
        """Perform health check on Human-in-the-Loop agent.

        Returns:
            True if healthy, False otherwise
        """
        try:
            # Check queue access
            await self.escalation_manager.get_queue_stats()

            # Check background task if enabled
            if self.auto_escalate_enabled:
                if self._sla_checker_task is None or self._sla_checker_task.done():
                    return False

            return True
        except Exception:
            return False

    async def cleanup(self) -> None:
        """Cleanup resources when shutting down."""
        await self.stop()
