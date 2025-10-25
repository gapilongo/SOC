"""Metrics and health-related Pydantic models."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class MetricsResponse(BaseModel):
    timestamp: str
    alerts_processed_today: int
    alerts_in_progress: int
    average_processing_time: float
    success_rate: float
    agent_health: Dict[str, bool]
    system_health: bool

class DashboardStatsResponse(BaseModel):
    total_alerts_today: int
    high_priority_alerts: int
    alerts_by_status: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    top_threat_indicators: List[Dict[str, Any]]
    recent_escalations: List[Dict[str, Any]]
    processing_time_avg: float

class AgentStatusResponse(BaseModel):
    agent_name: str
    status: str
    last_execution: Optional[str]
    success_rate: float
    average_execution_time: float
    error_count: int
