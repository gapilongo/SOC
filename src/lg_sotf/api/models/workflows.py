"""Workflow-related Pydantic models."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class WorkflowStatusResponse(BaseModel):
    alert_id: str
    workflow_instance_id: str
    current_node: str
    triage_status: str
    confidence_score: int
    threat_score: Optional[int] = 0
    processing_notes: List[str]
    enriched_data: Optional[Dict[str, Any]] = {}
    escalation_info: Optional[Dict[str, Any]] = None
    response_execution: Optional[Dict[str, Any]] = None
    fp_indicators: Optional[List[str]] = []
    tp_indicators: Optional[List[str]] = []
    correlations: Optional[List[Dict[str, Any]]] = []
    correlation_score: Optional[int] = 0
    analysis_conclusion: Optional[str] = None
    recommended_actions: Optional[List[str]] = []
    last_updated: str
    progress_percentage: int

class CorrelationResponse(BaseModel):
    alert_id: str
    correlations: List[Dict[str, Any]]
    correlation_score: int
    attack_campaign_indicators: List[str]
    threat_actor_patterns: List[str]

class FeedbackRequest(BaseModel):
    analyst_username: str
    decision: str
    confidence: int
    notes: str
    actions_taken: Optional[List[str]] = None
    actions_recommended: Optional[List[str]] = None
    triage_correct: Optional[bool] = None
    correlation_helpful: Optional[bool] = None
    analysis_accurate: Optional[bool] = None
