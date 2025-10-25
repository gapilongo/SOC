"""Alert-related Pydantic models."""

from typing import Any, Dict, Optional
from pydantic import BaseModel


class AlertRequest(BaseModel):
    """Request model for processing a new alert."""
    alert_data: Dict[str, Any]
    priority: Optional[str] = "normal"


class AlertResponse(BaseModel):
    """Response model for alert processing."""
    alert_id: str
    status: str
    workflow_instance_id: str
    processing_started: bool
    estimated_completion: Optional[str] = None
