"""
LangGraph workflow graph construction and routing logic.

This module defines the graph structure, state schema, and routing decisions
for the SOC alert processing workflow.
"""

import operator
from typing import Any, Dict, List, Literal, TypedDict, Annotated

from pydantic import BaseModel, Field
from langgraph.graph import END, START, StateGraph

from lg_sotf.core.config.manager import ConfigManager


class ExecutionContextData(TypedDict):
    """Typed execution context for state."""
    execution_id: str
    started_at: str
    last_node: str
    executed_nodes: List[str]
    execution_time: str


class RoutingDecision(BaseModel):
    """Structured LLM routing decision following LangGraph best practices."""
    next_step: Literal["correlation", "analysis", "response", "human_loop", "close"] = Field(
        description="The next processing step for the alert"
    )
    confidence: int = Field(ge=0, le=100, description="Confidence in this routing decision")
    reasoning: str = Field(description="Brief reasoning for this routing choice")


class WorkflowState(TypedDict):
    """State schema for LangGraph workflow with proper reducers."""
    # Core identification
    alert_id: str
    workflow_instance_id: str
    execution_context: ExecutionContextData

    # Alert data
    raw_alert: Dict[str, Any]
    enriched_data: Dict[str, Any]

    # Status and scoring
    triage_status: str
    confidence_score: int
    current_node: str
    priority_level: int

    # Indicators - WITH REDUCERS for accumulation
    fp_indicators: Annotated[List[str], operator.add]
    tp_indicators: Annotated[List[str], operator.add]

    # Correlation data - WITH REDUCER
    correlations: Annotated[List[Dict[str, Any]], operator.add]
    correlation_score: int

    # Analysis data
    analysis_conclusion: str
    threat_score: int
    recommended_actions: Annotated[List[str], operator.add]
    analysis_reasoning: Annotated[List[Dict[str, Any]], operator.add]
    tool_results: Dict[str, Dict[str, Any]]

    # Processing tracking - WITH REDUCER
    processing_notes: Annotated[List[str], operator.add]
    last_updated: str

    # Execution guards
    agent_executions: Dict[str, Dict[str, Any]]  # Track agent execution state
    state_version: int  # State versioning for conflict detection


class WorkflowGraphBuilder:
    """Builder for constructing the LangGraph workflow graph."""

    def __init__(self, config_manager: ConfigManager):
        """Initialize graph builder with configuration."""
        self.config = config_manager
        self.routing_config = {
            'max_alert_age_hours': config_manager.get('routing.max_alert_age_hours', 72),
            'correlation_grey_zone_min': config_manager.get('routing.correlation_grey_zone_min', 30),
            'correlation_grey_zone_max': config_manager.get('routing.correlation_grey_zone_max', 70),
            'analysis_threshold': config_manager.get('routing.analysis_threshold', 40),
            'human_review_min': config_manager.get('routing.human_review_min', 20),
            'human_review_max': config_manager.get('routing.human_review_max', 60),
            'response_threshold': config_manager.get('routing.response_threshold', 80),
        }

    def build_graph(self, node_executors: Dict[str, Any]) -> StateGraph:
        """Build the LangGraph workflow graph.

        Args:
            node_executors: Dictionary mapping node names to executor functions

        Returns:
            Compiled StateGraph ready for execution
        """
        workflow = StateGraph(WorkflowState)

        # Add nodes with execution wrappers
        for node_name, executor in node_executors.items():
            workflow.add_node(node_name, executor)

        # Set entry point
        workflow.add_edge(START, "ingestion")

        # Add conditional edges with routing
        workflow.add_conditional_edges(
            "ingestion",
            self.route_after_ingestion,
            {"triage": "triage", "close": "close"},
        )

        workflow.add_conditional_edges(
            "triage",
            self.route_after_triage,
            {
                "correlation": "correlation",
                "analysis": "analysis",
                "human_loop": "human_loop",
                "response": "response",
                "close": "close",
            },
        )

        workflow.add_conditional_edges(
            "correlation",
            self.route_after_correlation,
            {
                "analysis": "analysis",
                "response": "response",
                "human_loop": "human_loop",
                "close": "close",
            },
        )

        workflow.add_conditional_edges(
            "analysis",
            self.route_after_analysis,
            {"human_loop": "human_loop", "response": "response", "close": "close"},
        )

        workflow.add_conditional_edges(
            "human_loop",
            self.route_after_human_loop,
            {"analysis": "analysis", "response": "response", "close": "close"},
        )

        workflow.add_conditional_edges(
            "response",
            self.route_after_response,
            {"learning": "learning", "close": "close"},
        )

        workflow.add_edge("learning", "close")
        workflow.add_edge("close", END)

        # Validate graph structure
        self._validate_graph(workflow)

        return workflow

    def _validate_graph(self, workflow: StateGraph):
        """Validate graph structure before compilation.

        Args:
            workflow: StateGraph to validate

        Raises:
            ValueError: If graph structure is invalid
        """
        # LangGraph will do most validation on compile(),
        # but we can add custom checks here
        if not hasattr(workflow, 'nodes') or len(workflow.nodes) == 0:
            raise ValueError("Graph has no nodes defined")

    # ===============================
    # ROUTING METHODS
    # ===============================

    async def route_after_triage(
        self,
        state: WorkflowState
    ) -> Literal["correlation", "analysis", "response", "human_loop", "close"]:
        """Intelligent async routing after triage.

        Following LangGraph best practices:
        - ALWAYS route through correlation for threat intelligence building
        - Fast-track obvious FPs to close
        - All other alerts go through correlation
        """
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])

        # ONLY obvious false positives skip correlation and go directly to close
        if confidence <= 10 and fp_count >= 2:
            return "close"

        if fp_count > tp_count and fp_count >= 3 and confidence <= 20:
            return "close"

        # ALL other alerts MUST go through correlation first to build threat intelligence
        return "correlation"

    def route_after_correlation(self, state: WorkflowState) -> str:
        """Routing after correlation."""
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        confidence = state["confidence_score"]

        # Strong correlations → direct response
        if correlation_score > 85 and len(correlations) >= 5:
            return "response"

        # Moderate correlations → analysis
        if correlation_score > 60 or len(correlations) >= 3:
            return "analysis"

        # Weak correlations → human review
        if correlation_score > 20 and confidence > 50:
            return "human_loop"

        # No meaningful correlations → close
        return "close"

    def route_after_analysis(self, state: WorkflowState) -> str:
        """Routing after analysis."""
        threat_score = state.get("threat_score", 0)
        confidence = state["confidence_score"]
        conclusion = state.get("analysis_conclusion", "").lower()

        # High threat → response
        if threat_score >= 80 or (threat_score >= 60 and confidence >= 80):
            return "response"

        # Uncertain analysis → human review
        if "uncertain" in conclusion or (30 <= confidence <= 70):
            return "human_loop"

        # Low threat → close
        return "close"

    def route_after_ingestion(self, state: WorkflowState) -> str:
        """Routing logic after ingestion."""
        return "triage" if state["raw_alert"] else "close"

    def route_after_human_loop(self, state: WorkflowState) -> str:
        """Routing logic after human loop."""
        confidence = state["confidence_score"]
        return "response" if confidence >= 75 else "close"

    def route_after_response(self, state: WorkflowState) -> str:
        """Routing logic after response."""
        return "learning" if self._should_learn(state) else "close"

    # ===============================
    # ROUTING HELPER METHODS
    # ===============================

    def _needs_correlation(self, state: WorkflowState) -> bool:
        """Determine if alert needs correlation based on indicators."""
        enriched_data = state.get("enriched_data", {})
        raw_alert = state.get("raw_alert", {})

        # Check for network indicators
        has_network_indicators = any([
            enriched_data.get("source_ip"),
            enriched_data.get("destination_ip"),
            enriched_data.get("domain"),
            enriched_data.get("url"),
            raw_alert.get("source_ip"),
            raw_alert.get("destination_ip"),
            raw_alert.get("domain")
        ])

        # Check for user indicators
        has_user_indicators = any([
            enriched_data.get("user"),
            enriched_data.get("username"),
            raw_alert.get("user"),
            raw_alert.get("username")
        ])

        # Check for file/hash indicators
        has_file_indicators = any([
            enriched_data.get("file_hash"),
            enriched_data.get("file_name"),
            raw_alert.get("file_hash"),
            raw_alert.get("sha256"),
            raw_alert.get("md5")
        ])

        return has_network_indicators or has_user_indicators or has_file_indicators

    def _needs_analysis(self, state: WorkflowState) -> bool:
        """Determine if alert needs deep analysis."""
        confidence = state.get("confidence_score", 0)
        fp_count = len(state.get("fp_indicators", []))
        tp_count = len(state.get("tp_indicators", []))
        category = state.get("enriched_data", {}).get("category", "").lower()

        # Low confidence with mixed signals
        if confidence < 40 and fp_count > 0 and tp_count > 0:
            return True

        # Complex attack categories that need investigation
        complex_categories = [
            "lateral_movement",
            "privilege_escalation",
            "persistence",
            "command_and_control",
            "exfiltration",
            "malware"
        ]
        if any(cat in category for cat in complex_categories):
            return True

        # Alerts with tool results need deeper analysis
        tool_results = state.get("tool_results", [])
        if tool_results:
            return True

        return False

    def _should_learn(self, state: WorkflowState) -> bool:
        """Check if learning is beneficial."""
        return (state.get("human_feedback") or
                any("unusual" in note.lower() for note in state["processing_notes"]))

    # ===============================
    # FALLBACK ROUTING (when LLM unavailable)
    # ===============================

    def fallback_routing(
        self,
        state: WorkflowState,
        after_node: str
    ) -> Literal["correlation", "analysis", "response", "human_loop", "close"]:
        """Fallback routing logic when LLM is unavailable or fails."""
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])

        if after_node == "triage":
            # Fallback rules following SOC best practices
            # Close obvious false positives
            if confidence <= 10 and fp_count >= 2:
                return "close"

            # Fast-track high-confidence threats to response
            if confidence >= 85 and tp_count >= 3:
                return "response"

            # Prefer correlation first for grey-zone cases (gather context)
            if self._needs_correlation(state) or 20 <= confidence <= 80:
                return "correlation"

            # Analysis for lower confidence that needs investigation
            if confidence < 70:
                return "analysis"

            # Medium-high confidence (70-84%) → analyze to confirm
            if confidence < 85:
                return "analysis"

            # Default fallback: correlation (safest, gathers context)
            return "correlation"

        # For other nodes, conservative default
        return "close"
