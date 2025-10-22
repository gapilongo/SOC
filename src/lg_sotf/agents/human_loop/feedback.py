"""
Feedback Handler for Human-in-the-Loop Agent.

This module handles:
- Analyst decision recording and validation
- Feedback storage for learning agent
- Action tracking and execution status
- Decision patterns analysis
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from lg_sotf.core.state.manager import StateManager
from lg_sotf.storage.redis import RedisStorage
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.agents.human_loop.escalation import Escalation, EscalationStatus


class AnalystDecision(str, Enum):
    """Analyst decision on alert."""
    TRUE_POSITIVE = "true_positive"         # Confirmed threat
    FALSE_POSITIVE = "false_positive"       # Benign activity
    NEEDS_RESPONSE = "needs_response"       # Requires containment
    NEEDS_INVESTIGATION = "needs_investigation"  # More analysis needed
    BENIGN_ANOMALY = "benign_anomaly"      # Unusual but safe
    POLICY_VIOLATION = "policy_violation"   # Policy breach, not security threat


class ResponseAction(str, Enum):
    """Available response actions."""
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_IP = "block_ip"
    BLOCK_HASH = "block_hash"
    RESET_PASSWORD = "reset_password"
    QUARANTINE_EMAIL = "quarantine_email"
    TERMINATE_PROCESS = "terminate_process"
    NO_ACTION = "no_action"


@dataclass
class AnalystFeedback:
    """Feedback from analyst on alert review."""

    feedback_id: str
    escalation_id: str
    alert_id: str
    analyst_username: str

    # Decision
    decision: AnalystDecision
    confidence: int  # 1-10, analyst's confidence in decision
    notes: str

    # Actions
    actions_taken: List[ResponseAction] = field(default_factory=list)
    actions_recommended: List[ResponseAction] = field(default_factory=list)

    # Context
    review_duration_seconds: Optional[int] = None
    additional_context: Dict[str, Any] = field(default_factory=dict)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Learning signals
    triage_correct: Optional[bool] = None  # Did triage get it right?
    correlation_helpful: Optional[bool] = None  # Were correlations useful?
    analysis_accurate: Optional[bool] = None  # Was analysis conclusion correct?


class FeedbackHandler:
    """Handles analyst feedback collection and storage."""

    def __init__(
        self,
        state_manager: StateManager,
        redis_storage: RedisStorage,
        audit_logger: AuditLogger,
    ):
        """Initialize feedback handler.

        Args:
            state_manager: State manager for persistence
            redis_storage: Redis for cache and stats
            audit_logger: Audit logger for tracking
        """
        self.state_manager = state_manager
        self.redis_storage = redis_storage
        self.audit_logger = audit_logger

    async def record_feedback(
        self,
        escalation: Escalation,
        analyst_username: str,
        decision: AnalystDecision,
        confidence: int,
        notes: str,
        actions_taken: Optional[List[ResponseAction]] = None,
        actions_recommended: Optional[List[ResponseAction]] = None,
        review_duration_seconds: Optional[int] = None,
        additional_context: Optional[Dict[str, Any]] = None,
        triage_correct: Optional[bool] = None,
        correlation_helpful: Optional[bool] = None,
        analysis_accurate: Optional[bool] = None,
    ) -> AnalystFeedback:
        """Record analyst feedback for alert.

        Args:
            escalation: Escalation being reviewed
            analyst_username: Analyst providing feedback
            decision: Analyst's decision
            confidence: Confidence in decision (1-10)
            notes: Analyst's notes
            actions_taken: Actions already executed
            actions_recommended: Actions recommended for future
            review_duration_seconds: Time spent reviewing
            additional_context: Additional metadata
            triage_correct: Was triage assessment correct?
            correlation_helpful: Were correlations useful?
            analysis_accurate: Was analysis conclusion accurate?

        Returns:
            Created AnalystFeedback object
        """
        # Generate feedback ID
        feedback_id = f"fb-{escalation.escalation_id}"

        # Create feedback record
        feedback = AnalystFeedback(
            feedback_id=feedback_id,
            escalation_id=escalation.escalation_id,
            alert_id=escalation.alert_id,
            analyst_username=analyst_username,
            decision=decision,
            confidence=confidence,
            notes=notes,
            actions_taken=actions_taken or [],
            actions_recommended=actions_recommended or [],
            review_duration_seconds=review_duration_seconds,
            additional_context=additional_context or {},
            triage_correct=triage_correct,
            correlation_helpful=correlation_helpful,
            analysis_accurate=analysis_accurate,
        )

        # Store in PostgreSQL
        await self._persist_feedback(feedback)

        # Update escalation status
        escalation.status = EscalationStatus.DECIDED
        escalation.decided_at = datetime.utcnow()
        escalation.analyst_decision = decision.value
        escalation.analyst_notes = notes

        # Persist escalation status update to database
        from lg_sotf.agents.human_loop.escalation import EscalationManager
        escalation_manager = EscalationManager(
            state_manager=self.state_manager,
            redis_storage=self.redis_storage,
            audit_logger=self.audit_logger
        )
        await escalation_manager._update_escalation_status(escalation)

        # Remove from Redis queue (it's been decided)
        queue_key = f"escalation_queue:{escalation.level.value}"
        await self.redis_storage.redis_client.zrem(queue_key, escalation.escalation_id)

        # Cache decision in Redis for quick access
        await self._cache_decision(feedback)

        # Update decision statistics
        await self._update_decision_stats(feedback)

        return feedback

    async def _persist_feedback(self, feedback: AnalystFeedback) -> None:
        """Persist feedback to PostgreSQL.

        Args:
            feedback: Feedback to persist
        """
        query = """
        INSERT INTO analyst_feedback (
            feedback_id, escalation_id, alert_id, analyst_username,
            decision, confidence, notes,
            actions_taken, actions_recommended,
            review_duration_seconds,
            triage_correct, correlation_helpful, analysis_accurate,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        """

        await self.state_manager.storage.pool.execute(
            query,
            feedback.feedback_id,
            feedback.escalation_id,
            feedback.alert_id,
            feedback.analyst_username,
            feedback.decision.value,
            feedback.confidence,
            feedback.notes,
            [a.value for a in feedback.actions_taken],
            [a.value for a in feedback.actions_recommended],
            feedback.review_duration_seconds,
            feedback.triage_correct,
            feedback.correlation_helpful,
            feedback.analysis_accurate,
            feedback.created_at,
        )

    async def _cache_decision(self, feedback: AnalystFeedback) -> None:
        """Cache analyst decision in Redis for quick lookup.

        Args:
            feedback: Feedback to cache
        """
        # Store decision for this alert
        decision_key = f"alert:{feedback.alert_id}:decision"
        await self.redis_storage.redis_client.hset(
            decision_key,
            mapping={
                "decision": feedback.decision.value,
                "analyst": feedback.analyst_username,
                "confidence": str(feedback.confidence),
                "timestamp": feedback.created_at.isoformat(),
            },
        )
        await self.redis_storage.redis_client.expire(decision_key, 2592000)  # 30 days

    async def _update_decision_stats(self, feedback: AnalystFeedback) -> None:
        """Update decision statistics in Redis.

        Args:
            feedback: Feedback to track
        """
        # Track decision distribution
        stats_key = "analyst_decisions:stats"
        await self.redis_storage.redis_client.hincrby(
            stats_key,
            feedback.decision.value,
            1,
        )

        # Track per-analyst stats
        analyst_key = f"analyst:{feedback.analyst_username}:stats"
        await self.redis_storage.redis_client.hincrby(
            analyst_key,
            "total_reviews",
            1,
        )
        await self.redis_storage.redis_client.hincrby(
            analyst_key,
            f"decision_{feedback.decision.value}",
            1,
        )

        # Track triage accuracy if provided
        if feedback.triage_correct is not None:
            triage_key = "triage_accuracy"
            field = "correct" if feedback.triage_correct else "incorrect"
            await self.redis_storage.redis_client.hincrby(triage_key, field, 1)

        # Track correlation usefulness if provided
        if feedback.correlation_helpful is not None:
            corr_key = "correlation_usefulness"
            field = "helpful" if feedback.correlation_helpful else "not_helpful"
            await self.redis_storage.redis_client.hincrby(corr_key, field, 1)

        # Track analysis accuracy if provided
        if feedback.analysis_accurate is not None:
            analysis_key = "analysis_accuracy"
            field = "accurate" if feedback.analysis_accurate else "inaccurate"
            await self.redis_storage.redis_client.hincrby(analysis_key, field, 1)

    async def get_feedback_by_alert(self, alert_id: str) -> Optional[AnalystFeedback]:
        """Get feedback for specific alert.

        Args:
            alert_id: Alert ID

        Returns:
            AnalystFeedback or None if not found
        """
        query = """
        SELECT
            feedback_id, escalation_id, alert_id, analyst_username,
            decision, confidence, notes,
            actions_taken, actions_recommended,
            review_duration_seconds,
            triage_correct, correlation_helpful, analysis_accurate,
            created_at
        FROM analyst_feedback
        WHERE alert_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        """

        row = await self.state_manager.storage.pool.fetchrow(query, alert_id)

        if not row:
            return None

        return AnalystFeedback(
            feedback_id=row["feedback_id"],
            escalation_id=row["escalation_id"],
            alert_id=row["alert_id"],
            analyst_username=row["analyst_username"],
            decision=AnalystDecision(row["decision"]),
            confidence=row["confidence"],
            notes=row["notes"],
            actions_taken=[ResponseAction(a) for a in row["actions_taken"]],
            actions_recommended=[ResponseAction(a) for a in row["actions_recommended"]],
            review_duration_seconds=row["review_duration_seconds"],
            additional_context={},
            triage_correct=row["triage_correct"],
            correlation_helpful=row["correlation_helpful"],
            analysis_accurate=row["analysis_accurate"],
            created_at=row["created_at"],
        )

    async def get_decision_stats(self) -> Dict[str, Any]:
        """Get overall decision statistics.

        Returns:
            Decision statistics
        """
        stats_key = "analyst_decisions:stats"
        decision_counts_raw = await self.redis_storage.redis_client.hgetall(stats_key)

        # Decode and convert
        decision_counts = {}
        total = 0
        for decision_bytes, count_bytes in decision_counts_raw.items():
            decision = decision_bytes.decode('utf-8')
            count = int(count_bytes.decode('utf-8'))
            decision_counts[decision] = count
            total += count

        # Calculate percentages
        decision_percentages = {}
        if total > 0:
            for decision, count in decision_counts.items():
                decision_percentages[decision] = round((count / total) * 100, 2)

        return {
            "total_decisions": total,
            "decision_counts": decision_counts,
            "decision_percentages": decision_percentages,
        }

    async def get_triage_accuracy(self) -> Dict[str, Any]:
        """Get triage accuracy statistics.

        Returns:
            Triage accuracy stats
        """
        triage_key = "triage_accuracy"
        stats_raw = await self.redis_storage.redis_client.hgetall(triage_key)

        correct = 0
        incorrect = 0

        for field_bytes, count_bytes in stats_raw.items():
            field = field_bytes.decode('utf-8')
            count = int(count_bytes.decode('utf-8'))
            if field == "correct":
                correct = count
            elif field == "incorrect":
                incorrect = count

        total = correct + incorrect
        accuracy = round((correct / total) * 100, 2) if total > 0 else 0

        return {
            "total_assessments": total,
            "correct": correct,
            "incorrect": incorrect,
            "accuracy_percentage": accuracy,
        }

    async def get_analyst_performance(self, analyst_username: str) -> Dict[str, Any]:
        """Get performance stats for specific analyst.

        Args:
            analyst_username: Analyst username

        Returns:
            Analyst performance statistics
        """
        analyst_key = f"analyst:{analyst_username}:stats"
        stats_raw = await self.redis_storage.redis_client.hgetall(analyst_key)

        if not stats_raw:
            return {
                "analyst": analyst_username,
                "total_reviews": 0,
                "decisions": {},
            }

        stats = {}
        for field_bytes, count_bytes in stats_raw.items():
            field = field_bytes.decode('utf-8')
            count = int(count_bytes.decode('utf-8'))
            stats[field] = count

        total_reviews = stats.get("total_reviews", 0)

        # Extract decision breakdown
        decisions = {}
        for key, value in stats.items():
            if key.startswith("decision_"):
                decision_type = key.replace("decision_", "")
                decisions[decision_type] = value

        return {
            "analyst": analyst_username,
            "total_reviews": total_reviews,
            "decisions": decisions,
        }

    async def get_learning_signals(
        self,
        limit: int = 100,
        min_confidence: int = 7,
    ) -> List[Dict[str, Any]]:
        """Get feedback data for learning agent.

        Retrieves high-confidence analyst decisions to train ML models.

        Args:
            limit: Maximum number of signals to return
            min_confidence: Minimum analyst confidence (1-10)

        Returns:
            List of learning signals
        """
        query = """
        SELECT
            af.alert_id,
            af.decision,
            af.confidence,
            af.triage_correct,
            af.correlation_helpful,
            af.analysis_accurate,
            af.created_at,
            s.raw_alert,
            s.enriched_data,
            s.triage_status,
            s.confidence_score as triage_confidence,
            s.threat_score,
            s.analysis_conclusion
        FROM analyst_feedback af
        JOIN states s ON af.alert_id = s.alert_id
        WHERE af.confidence >= $1
        ORDER BY af.created_at DESC
        LIMIT $2
        """

        rows = await self.state_manager.storage.pool.fetch(query, min_confidence, limit)

        signals = []
        for row in rows:
            signals.append({
                "alert_id": row["alert_id"],
                "analyst_decision": row["decision"],
                "analyst_confidence": row["confidence"],
                "triage_status": row["triage_status"],
                "triage_confidence": row["triage_confidence"],
                "threat_score": row["threat_score"],
                "analysis_conclusion": row["analysis_conclusion"],
                "triage_correct": row["triage_correct"],
                "correlation_helpful": row["correlation_helpful"],
                "analysis_accurate": row["analysis_accurate"],
                "raw_alert": row["raw_alert"],
                "enriched_data": row["enriched_data"],
                "timestamp": row["created_at"].isoformat(),
            })

        return signals
