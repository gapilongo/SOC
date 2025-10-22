"""
Escalation Management for Human-in-the-Loop Agent.

This module handles:
- Escalation queue management with priority-based assignment
- SLA tracking with timeout enforcement
- Multi-tier escalation (L1 → L2 → L3)
- Escalation status lifecycle management
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

from lg_sotf.core.state.manager import StateManager
from lg_sotf.storage.redis import RedisStorage
from lg_sotf.audit.logger import AuditLogger


class EscalationLevel(str, Enum):
    """Escalation tier levels."""
    L1 = "L1"  # Junior Analyst
    L2 = "L2"  # Senior Analyst
    L3 = "L3"  # Security Architect/Manager


class EscalationStatus(str, Enum):
    """Escalation lifecycle status."""
    PENDING = "pending"              # Waiting for analyst assignment
    ASSIGNED = "assigned"            # Assigned to analyst
    IN_REVIEW = "in_review"          # Analyst actively reviewing
    DECIDED = "decided"              # Decision made by analyst
    EXPIRED = "expired"              # SLA timeout exceeded
    ESCALATED = "escalated"          # Escalated to higher tier


class EscalationReason(str, Enum):
    """Reason for escalation to human analyst."""
    GREY_ZONE = "grey_zone"                    # Confidence in grey zone (20-60%)
    HIGH_RISK = "high_risk"                    # High-risk asset/user involved
    INCONCLUSIVE = "inconclusive"              # Analysis agent couldn't conclude
    CONFLICTING_EVIDENCE = "conflicting_evidence"  # Contradictory indicators
    COMPLEX_ATTACK = "complex_attack"          # Multi-stage/sophisticated attack
    POLICY_EXCEPTION = "policy_exception"      # Requires policy judgment
    FALSE_POSITIVE_REVIEW = "false_positive_review"  # Potential FP needs review
    REGULATORY_COMPLIANCE = "regulatory_compliance"  # Compliance requirement


@dataclass
class Escalation:
    """Escalation record for human review."""

    escalation_id: str
    alert_id: str
    workflow_instance_id: str

    # Escalation metadata
    level: EscalationLevel
    status: EscalationStatus
    reason: EscalationReason
    priority: int  # 1-10, higher = more urgent

    # Context for analyst
    alert_summary: str
    triage_confidence: float
    threat_score: float
    correlations_count: int
    enrichment_data: Dict[str, Any]
    analysis_notes: Optional[str] = None

    # SLA tracking
    created_at: datetime = field(default_factory=datetime.utcnow)
    assigned_at: Optional[datetime] = None
    reviewed_at: Optional[datetime] = None
    decided_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None

    # Assignment
    assigned_to: Optional[str] = None  # Analyst username
    assigned_tier: Optional[EscalationLevel] = None

    # Decision
    analyst_decision: Optional[str] = None  # "true_positive", "false_positive", "needs_response"
    analyst_notes: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)

    # Escalation chain
    escalated_from: Optional[str] = None  # Previous escalation_id if escalated up
    escalation_count: int = 0  # Number of times escalated


class EscalationManager:
    """Manages escalation queue, SLA tracking, and tier escalation."""

    # SLA deadlines by level (in minutes)
    SLA_DEADLINES = {
        EscalationLevel.L1: 30,   # 30 minutes for L1
        EscalationLevel.L2: 60,   # 1 hour for L2
        EscalationLevel.L3: 120,  # 2 hours for L3
    }

    # Auto-escalation thresholds
    HIGH_PRIORITY_THRESHOLD = 8  # Priority >= 8 starts at L2
    CRITICAL_PRIORITY_THRESHOLD = 9  # Priority >= 9 starts at L3

    def __init__(
        self,
        state_manager: StateManager,
        redis_storage: RedisStorage,
        audit_logger: AuditLogger,
    ):
        """Initialize escalation manager.

        Args:
            state_manager: State manager for persistence
            redis_storage: Redis for queue and cache
            audit_logger: Audit logger for tracking
        """
        self.state_manager = state_manager
        self.redis_storage = redis_storage
        self.audit_logger = audit_logger

    async def create_escalation(
        self,
        alert_id: str,
        workflow_instance_id: str,
        reason: EscalationReason,
        alert_summary: str,
        triage_confidence: float,
        threat_score: float,
        correlations_count: int,
        enrichment_data: Dict[str, Any],
        analysis_notes: Optional[str] = None,
    ) -> Escalation:
        """Create new escalation for human review.

        Args:
            alert_id: Alert identifier
            workflow_instance_id: Workflow instance ID
            reason: Reason for escalation
            alert_summary: Brief summary for analyst
            triage_confidence: Confidence score from triage
            threat_score: Threat score from analysis
            correlations_count: Number of correlations found
            enrichment_data: Enrichment data for context
            analysis_notes: Notes from analysis agent

        Returns:
            Created Escalation object
        """
        escalation_id = f"esc-{uuid4().hex[:12]}"

        # Calculate priority based on threat score, confidence, and correlations
        priority = self._calculate_priority(
            threat_score=threat_score,
            triage_confidence=triage_confidence,
            correlations_count=correlations_count,
            reason=reason,
        )

        # Determine initial escalation level
        level = self._determine_initial_level(priority, threat_score, reason)

        # Calculate SLA deadline
        sla_minutes = self.SLA_DEADLINES[level]
        sla_deadline = datetime.utcnow() + timedelta(minutes=sla_minutes)

        escalation = Escalation(
            escalation_id=escalation_id,
            alert_id=alert_id,
            workflow_instance_id=workflow_instance_id,
            level=level,
            status=EscalationStatus.PENDING,
            reason=reason,
            priority=priority,
            alert_summary=alert_summary,
            triage_confidence=triage_confidence,
            threat_score=threat_score,
            correlations_count=correlations_count,
            enrichment_data=enrichment_data,
            analysis_notes=analysis_notes,
            sla_deadline=sla_deadline,
        )

        # Add to Redis queue (sorted by priority)
        await self._add_to_queue(escalation)

        # Store in PostgreSQL for persistence
        await self._persist_escalation(escalation)

        return escalation

    def _calculate_priority(
        self,
        threat_score: float,
        triage_confidence: float,
        correlations_count: int,
        reason: EscalationReason,
    ) -> int:
        """Calculate escalation priority (1-10).

        Args:
            threat_score: Threat score (0-100)
            triage_confidence: Confidence score (0-100)
            correlations_count: Number of correlations
            reason: Escalation reason

        Returns:
            Priority score (1-10)
        """
        # Base priority from threat score
        base_priority = int(threat_score / 10)  # 0-100 → 0-10

        # Adjust based on confidence uncertainty
        # Low confidence = higher priority (needs human judgment)
        confidence_factor = 0
        if triage_confidence < 30:
            confidence_factor = 2
        elif triage_confidence < 50:
            confidence_factor = 1

        # Adjust based on correlations
        correlation_factor = 0
        if correlations_count >= 10:
            correlation_factor = 2
        elif correlations_count >= 5:
            correlation_factor = 1

        # Adjust based on reason
        reason_factor = {
            EscalationReason.HIGH_RISK: 3,
            EscalationReason.COMPLEX_ATTACK: 2,
            EscalationReason.REGULATORY_COMPLIANCE: 2,
            EscalationReason.CONFLICTING_EVIDENCE: 1,
            EscalationReason.GREY_ZONE: 1,
            EscalationReason.INCONCLUSIVE: 1,
            EscalationReason.POLICY_EXCEPTION: 1,
            EscalationReason.FALSE_POSITIVE_REVIEW: 0,
        }.get(reason, 0)

        # Calculate final priority
        priority = base_priority + confidence_factor + correlation_factor + reason_factor

        # Clamp to 1-10 range
        return max(1, min(10, priority))

    def _determine_initial_level(
        self,
        priority: int,
        threat_score: float,
        reason: EscalationReason,
    ) -> EscalationLevel:
        """Determine initial escalation level.

        Args:
            priority: Calculated priority (1-10)
            threat_score: Threat score (0-100)
            reason: Escalation reason

        Returns:
            Initial escalation level
        """
        # Critical priority → L3 directly
        if priority >= self.CRITICAL_PRIORITY_THRESHOLD:
            return EscalationLevel.L3

        # High priority → L2
        if priority >= self.HIGH_PRIORITY_THRESHOLD:
            return EscalationLevel.L2

        # Certain reasons always go to L2+
        if reason in [
            EscalationReason.REGULATORY_COMPLIANCE,
            EscalationReason.COMPLEX_ATTACK,
        ]:
            return EscalationLevel.L2

        # High threat score → L2
        if threat_score >= 80:
            return EscalationLevel.L2

        # Default to L1
        return EscalationLevel.L1

    async def _add_to_queue(self, escalation: Escalation) -> None:
        """Add escalation to Redis queue (sorted by priority).

        Args:
            escalation: Escalation to queue
        """
        queue_key = f"escalation_queue:{escalation.level.value}"

        # Use sorted set with priority as score (higher = more urgent)
        await self.redis_storage.redis_client.zadd(
            queue_key,
            {escalation.escalation_id: escalation.priority},
        )

        # Store escalation data
        escalation_key = f"escalation:{escalation.escalation_id}"
        await self.redis_storage.redis_client.hset(
            escalation_key,
            mapping={
                "alert_id": escalation.alert_id,
                "workflow_instance_id": escalation.workflow_instance_id,
                "level": escalation.level.value,
                "status": escalation.status.value,
                "reason": escalation.reason.value,
                "priority": str(escalation.priority),
                "created_at": escalation.created_at.isoformat(),
                "sla_deadline": escalation.sla_deadline.isoformat() if escalation.sla_deadline else "",
            },
        )

        # Set TTL (7 days)
        await self.redis_storage.redis_client.expire(escalation_key, 604800)

    async def _persist_escalation(self, escalation: Escalation) -> None:
        """Persist escalation to PostgreSQL.

        Args:
            escalation: Escalation to persist
        """
        # Store in escalations table (will be created in migration)
        query = """
        INSERT INTO escalations (
            escalation_id, alert_id, workflow_instance_id,
            level, status, reason, priority,
            alert_summary, triage_confidence, threat_score,
            correlations_count, analysis_notes,
            created_at, sla_deadline
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        """

        await self.state_manager.storage.pool.execute(
            query,
            escalation.escalation_id,
            escalation.alert_id,
            escalation.workflow_instance_id,
            escalation.level.value,
            escalation.status.value,
            escalation.reason.value,
            escalation.priority,
            escalation.alert_summary,
            escalation.triage_confidence,
            escalation.threat_score,
            escalation.correlations_count,
            escalation.analysis_notes,
            escalation.created_at,
            escalation.sla_deadline,
        )

    async def get_pending_escalations(
        self,
        level: Optional[EscalationLevel] = None,
        limit: int = 50,
    ) -> List[Escalation]:
        """Get pending escalations from queue.

        Args:
            level: Filter by escalation level (None = all levels)
            limit: Maximum number to return

        Returns:
            List of pending escalations (sorted by priority descending)
        """
        if level:
            levels = [level]
        else:
            levels = [EscalationLevel.L1, EscalationLevel.L2, EscalationLevel.L3]

        escalations = []

        for lvl in levels:
            queue_key = f"escalation_queue:{lvl.value}"

            # Get top N escalation IDs from queue (highest priority first)
            escalation_ids = await self.redis_storage.redis_client.zrevrange(
                queue_key, 0, limit - 1
            )

            for esc_id_bytes in escalation_ids:
                esc_id = esc_id_bytes.decode('utf-8')
                escalation = await self._load_escalation(esc_id)
                if escalation and escalation.status == EscalationStatus.PENDING:
                    escalations.append(escalation)

        # Sort by priority descending
        escalations.sort(key=lambda e: e.priority, reverse=True)

        return escalations[:limit]

    async def _load_escalation(self, escalation_id: str) -> Optional[Escalation]:
        """Load escalation from PostgreSQL.

        Args:
            escalation_id: Escalation ID

        Returns:
            Escalation object or None if not found
        """
        query = """
        SELECT
            escalation_id, alert_id, workflow_instance_id,
            level, status, reason, priority,
            alert_summary, triage_confidence, threat_score,
            correlations_count, analysis_notes,
            created_at, assigned_at, reviewed_at, decided_at, sla_deadline,
            assigned_to, assigned_tier,
            analyst_decision, analyst_notes,
            escalated_from, escalation_count
        FROM escalations
        WHERE escalation_id = $1
        """

        row = await self.state_manager.storage.pool.fetchrow(query, escalation_id)

        if not row:
            return None

        return Escalation(
            escalation_id=row["escalation_id"],
            alert_id=row["alert_id"],
            workflow_instance_id=row["workflow_instance_id"],
            level=EscalationLevel(row["level"]),
            status=EscalationStatus(row["status"]),
            reason=EscalationReason(row["reason"]),
            priority=row["priority"],
            alert_summary=row["alert_summary"],
            triage_confidence=row["triage_confidence"],
            threat_score=row["threat_score"],
            correlations_count=row["correlations_count"],
            enrichment_data={},  # Load separately if needed
            analysis_notes=row["analysis_notes"],
            created_at=row["created_at"],
            assigned_at=row["assigned_at"],
            reviewed_at=row["reviewed_at"],
            decided_at=row["decided_at"],
            sla_deadline=row["sla_deadline"],
            assigned_to=row["assigned_to"],
            assigned_tier=EscalationLevel(row["assigned_tier"]) if row["assigned_tier"] else None,
            analyst_decision=row["analyst_decision"],
            analyst_notes=row["analyst_notes"],
            escalated_from=row["escalated_from"],
            escalation_count=row["escalation_count"],
        )

    async def assign_escalation(
        self,
        escalation_id: str,
        analyst_username: str,
    ) -> Escalation:
        """Assign escalation to analyst.

        Args:
            escalation_id: Escalation ID
            analyst_username: Analyst username

        Returns:
            Updated Escalation
        """
        escalation = await self._load_escalation(escalation_id)
        if not escalation:
            raise ValueError(f"Escalation {escalation_id} not found")

        escalation.status = EscalationStatus.ASSIGNED
        escalation.assigned_to = analyst_username
        escalation.assigned_tier = escalation.level
        escalation.assigned_at = datetime.utcnow()

        # Update in database
        await self._update_escalation_status(escalation)

        return escalation

    async def _update_escalation_status(self, escalation: Escalation) -> None:
        """Update escalation status in database.

        Args:
            escalation: Escalation with updated fields
        """
        query = """
        UPDATE escalations
        SET status = $1, assigned_to = $2, assigned_tier = $3,
            assigned_at = $4, reviewed_at = $5, decided_at = $6,
            analyst_decision = $7, analyst_notes = $8
        WHERE escalation_id = $9
        """

        await self.state_manager.storage.pool.execute(
            query,
            escalation.status.value,
            escalation.assigned_to,
            escalation.assigned_tier.value if escalation.assigned_tier else None,
            escalation.assigned_at,
            escalation.reviewed_at,
            escalation.decided_at,
            escalation.analyst_decision,
            escalation.analyst_notes,
            escalation.escalation_id,
        )

    async def check_sla_violations(self) -> List[Escalation]:
        """Check for SLA violations and auto-escalate if needed.

        Returns:
            List of escalations that were auto-escalated
        """
        escalated = []

        # Check all pending/assigned escalations
        query = """
        SELECT escalation_id FROM escalations
        WHERE status IN ('pending', 'assigned')
        AND sla_deadline < NOW()
        """

        rows = await self.state_manager.storage.pool.fetch(query)

        for row in rows:
            escalation = await self._load_escalation(row["escalation_id"])
            if escalation:
                # Auto-escalate to next tier
                if escalation.level == EscalationLevel.L1:
                    await self._escalate_to_tier(escalation, EscalationLevel.L2)
                    escalated.append(escalation)
                elif escalation.level == EscalationLevel.L2:
                    await self._escalate_to_tier(escalation, EscalationLevel.L3)
                    escalated.append(escalation)
                else:
                    # L3 timeout → mark as expired
                    escalation.status = EscalationStatus.EXPIRED
                    await self._update_escalation_status(escalation)

        return escalated

    async def _escalate_to_tier(
        self,
        escalation: Escalation,
        new_tier: EscalationLevel,
    ) -> None:
        """Escalate to higher tier.

        Args:
            escalation: Current escalation
            new_tier: New tier level
        """
        old_tier = escalation.level

        # Update escalation
        escalation.level = new_tier
        escalation.status = EscalationStatus.ESCALATED
        escalation.escalation_count += 1

        # Calculate new SLA
        sla_minutes = self.SLA_DEADLINES[new_tier]
        escalation.sla_deadline = datetime.utcnow() + timedelta(minutes=sla_minutes)

        # Create new escalation record for new tier
        new_escalation_id = f"esc-{uuid4().hex[:12]}"
        new_escalation = Escalation(
            escalation_id=new_escalation_id,
            alert_id=escalation.alert_id,
            workflow_instance_id=escalation.workflow_instance_id,
            level=new_tier,
            status=EscalationStatus.PENDING,
            reason=escalation.reason,
            priority=min(10, escalation.priority + 1),  # Increase priority
            alert_summary=escalation.alert_summary,
            triage_confidence=escalation.triage_confidence,
            threat_score=escalation.threat_score,
            correlations_count=escalation.correlations_count,
            enrichment_data=escalation.enrichment_data,
            analysis_notes=escalation.analysis_notes,
            sla_deadline=escalation.sla_deadline,
            escalated_from=escalation.escalation_id,
            escalation_count=escalation.escalation_count,
        )

        # Add to queue
        await self._add_to_queue(new_escalation)
        await self._persist_escalation(new_escalation)

        # Update old escalation
        await self._update_escalation_status(escalation)

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics.

        Returns:
            Queue stats by level
        """
        stats = {}

        for level in [EscalationLevel.L1, EscalationLevel.L2, EscalationLevel.L3]:
            queue_key = f"escalation_queue:{level.value}"
            count = await self.redis_storage.redis_client.zcard(queue_key)

            stats[level.value] = {
                "pending_count": count,
                "sla_minutes": self.SLA_DEADLINES[level],
            }

        return stats
