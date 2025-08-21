"""
State data models for LG-SOTF.

This module defines the data models used throughout the framework for
managing alert state, workflow execution, and system configuration.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class TriageStatus(str, Enum):
    """Triage status enumeration."""
    NEW = "new"
    INGESTED = "ingested"
    TRIAGED = "triaged"
    CORRELATED = "correlated"
    ANALYZED = "analyzed"
    ESCALATED = "escalated"
    RESPONDED = "responded"
    CLOSED = "closed"


class AgentExecutionStatus(str, Enum):
    """Agent execution status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class StateVersion(BaseModel):
    """State version information."""
    version: int = Field(..., description="State version number")
    timestamp: datetime = Field(..., description="Timestamp of state update")
    author_type: str = Field(..., description="Type of author (agent/human)")
    author_id: str = Field(..., description="ID of author")
    changes_summary: str = Field(..., description="Summary of changes made")


class AgentExecution(BaseModel):
    """Agent execution record."""
    agent_name: str = Field(..., description="Name of the agent")
    execution_id: str = Field(..., description="Unique execution ID")
    start_time: datetime = Field(..., description="Execution start time")
    end_time: Optional[datetime] = Field(None, description="Execution end time")
    status: AgentExecutionStatus = Field(..., description="Execution status")
    inputs: Dict[str, Any] = Field(default_factory=dict, description="Agent inputs")
    outputs: Dict[str, Any] = Field(default_factory=dict, description="Agent outputs")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Execution metrics")
    errors: List[str] = Field(default_factory=list, description="Execution errors")
    
    @validator('execution_id')
    def validate_execution_id(cls, v):
        """Validate execution ID."""
        if not v:
            raise ValueError("Execution ID cannot be empty")
        return v


class WorkflowNodeHistory(BaseModel):
    """Workflow node execution history."""
    node_name: str = Field(..., description="Name of the workflow node")
    execution_time: datetime = Field(..., description="Time of execution")
    execution_duration_ms: int = Field(..., description="Execution duration in milliseconds")
    input_state_hash: str = Field(..., description="Hash of input state")
    output_state_hash: str = Field(..., description="Hash of output state")
    decision: str = Field(..., description="Decision made")
    decision_rationale: str = Field(..., description="Rationale for decision")


class HumanFeedback(BaseModel):
    """Human feedback record."""
    feedback_id: str = Field(..., description="Unique feedback ID")
    analyst_id: str = Field(..., description="ID of the analyst")
    timestamp: datetime = Field(..., description="Feedback timestamp")
    feedback_type: str = Field(..., description="Type of feedback (FP/TP/other)")
    classification: str = Field(..., description="Classification provided")
    confidence_score: int = Field(..., ge=0, le=100, description="Analyst confidence score")
    comments: str = Field(..., description="Analyst comments")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SOCState(BaseModel):
    """Main SOC state object."""
    # Core fields
    alert_id: str = Field(..., description="Unique alert identifier")
    raw_alert: Dict[str, Any] = Field(..., description="Raw alert data")
    enriched_data: Dict[str, Any] = Field(default_factory=dict, description="Enriched alert data")
    triage_status: TriageStatus = Field(default=TriageStatus.NEW, description="Current triage status")
    
    # Confidence and indicators
    confidence_score: int = Field(default=0, ge=0, le=100, description="Confidence score (0-100)")
    fp_indicators: List[str] = Field(default_factory=list, description="False positive indicators")
    tp_indicators: List[str] = Field(default_factory=list, description="True positive indicators")
    
    # Workflow tracking
    workflow_instance_id: str = Field(..., description="Unique workflow instance ID")
    current_node: str = Field(..., description="Current workflow node")
    next_nodes: List[str] = Field(default_factory=list, description="Next possible nodes")
    
    # Versioning and history
    state_version: int = Field(default=1, description="Current state version")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="State creation timestamp")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    version_history: List[StateVersion] = Field(default_factory=list, description="State version history")
    
    # Agent execution tracking
    agent_executions: List[AgentExecution] = Field(default_factory=list, description="Agent execution history")
    workflow_history: List[WorkflowNodeHistory] = Field(default_factory=list, description="Workflow node history")
    
    # Human interaction
    human_feedback: Optional[HumanFeedback] = Field(None, description="Human feedback")
    escalation_level: int = Field(default=0, description="Current escalation level")
    assigned_analyst: Optional[str] = Field(None, description="ID of assigned analyst")
    
    # Response and actions
    response_actions: List[Dict[str, Any]] = Field(default_factory=list, description="Response actions taken")
    playbook_executed: Optional[str] = Field(None, description="Playbook executed for response")
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    tags: List[str] = Field(default_factory=list, description="Alert tags")
    priority_level: int = Field(default=3, ge=1, le=5, description="Priority level (1-5)")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        validate_assignment = True
    
    @validator('alert_id')
    def validate_alert_id(cls, v):
        """Validate alert ID."""
        if not v:
            raise ValueError("Alert ID cannot be empty")
        return v
    
    @validator('workflow_instance_id')
    def validate_workflow_instance_id(cls, v):
        """Validate workflow instance ID."""
        if not v:
            raise ValueError("Workflow instance ID cannot be empty")
        return v
    
    @validator('current_node')
    def validate_current_node(cls, v):
        """Validate current node."""
        if not v:
            raise ValueError("Current node cannot be empty")
        return v
    
    def add_agent_execution(self, execution: AgentExecution) -> None:
        """Add agent execution record."""
        self.agent_executions.append(execution)
        self.last_updated = datetime.utcnow()
    
    def add_workflow_history(self, history: WorkflowNodeHistory) -> None:
        """Add workflow history record."""
        self.workflow_history.append(history)
        self.last_updated = datetime.utcnow()
    
    def add_version(self, version: StateVersion) -> None:
        """Add state version record."""
        self.version_history.append(version)
        self.state_version += 1
        self.last_updated = datetime.utcnow()
    
    def update_triage_status(self, status: TriageStatus) -> None:
        """Update triage status."""
        self.triage_status = status
        self.last_updated = datetime.utcnow()
    
    def update_confidence_score(self, score: int) -> None:
        """Update confidence score."""
        self.confidence_score = max(0, min(100, score))
        self.last_updated = datetime.utcnow()