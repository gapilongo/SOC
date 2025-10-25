"""Escalation and human-in-the-loop endpoints."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.dependencies import get_lg_sotf_app
from lg_sotf.api.models.workflows import FeedbackRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/escalations", tags=["escalations"])


@router.get("")
async def get_pending_escalations(
    level: Optional[str] = None,
    limit: int = 50,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get pending escalations from queue."""
    try:
        human_loop_agent = lg_sotf_app.workflow_engine.agents.get("human_loop")
        if not human_loop_agent:
            raise HTTPException(status_code=503, detail="Human loop agent not available")

        escalations = await human_loop_agent.get_pending_escalations(level=level, limit=limit)
        return {"escalations": escalations, "count": len(escalations)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Escalation retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{escalation_id}/assign")
async def assign_escalation(
    escalation_id: str,
    analyst_username: str,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Assign escalation to analyst."""
    try:
        human_loop_agent = lg_sotf_app.workflow_engine.agents.get("human_loop")
        if not human_loop_agent:
            raise HTTPException(status_code=503, detail="Human loop agent not available")

        result = await human_loop_agent.assign_escalation(
            escalation_id=escalation_id,
            analyst_username=analyst_username
        )
        return result

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Escalation assignment failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{escalation_id}/feedback")
async def submit_feedback(
    escalation_id: str,
    feedback: FeedbackRequest,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Submit analyst feedback for escalation."""
    try:
        human_loop_agent = lg_sotf_app.workflow_engine.agents.get("human_loop")
        if not human_loop_agent:
            raise HTTPException(status_code=503, detail="Human loop agent not available")

        result = await human_loop_agent.submit_feedback(
            escalation_id=escalation_id,
            analyst_username=feedback.analyst_username,
            decision=feedback.decision,
            confidence=feedback.confidence,
            notes=feedback.notes,
            actions_taken=feedback.actions_taken,
            actions_recommended=feedback.actions_recommended,
            triage_correct=feedback.triage_correct,
            correlation_helpful=feedback.correlation_helpful,
            analysis_accurate=feedback.analysis_accurate
        )
        return result

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Feedback submission failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_escalation_stats(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get escalation queue statistics."""
    try:
        human_loop_agent = lg_sotf_app.workflow_engine.agents.get("human_loop")
        if not human_loop_agent:
            raise HTTPException(status_code=503, detail="Human loop agent not available")

        # Get queue stats from PostgreSQL
        queue_stats = await human_loop_agent.get_queue_stats()

        # Try to get decision stats and accuracy, but don't fail if not available
        try:
            decision_stats = await human_loop_agent.get_decision_stats()
            triage_accuracy = await human_loop_agent.get_triage_accuracy()
            if triage_accuracy and 'accuracy_rate' in triage_accuracy:
                queue_stats['accuracy_rate'] = triage_accuracy['accuracy_rate']
        except Exception as e:
            logger.warning(f"Could not get decision stats: {e}")

        return queue_stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Escalation stats retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
