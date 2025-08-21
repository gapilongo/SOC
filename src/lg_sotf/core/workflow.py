from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import StateError, WorkflowError
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.state.model import SOCState, TriageStatus


class WorkflowState(TypedDict):
    """State schema for LangGraph workflow."""
    alert_id: str
    workflow_instance_id: str
    raw_alert: Dict[str, Any]
    triage_status: str
    confidence_score: int
    current_node: str
    fp_indicators: List[str]
    tp_indicators: List[str]
    last_updated: str
    priority_level: int
    enriched_data: Dict[str, Any]
    processing_notes: List[str]


class WorkflowEngine:
    """Workflow engine with proper state integration."""
    
    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.graph = self._build_workflow_graph()
        self.compiled_graph = self.graph.compile()
    
    def _workflow_to_soc_state(self, workflow_state: WorkflowState) -> SOCState:
        """Convert WorkflowState to SOCState for persistence."""
        return SOCState(
            alert_id=workflow_state["alert_id"],
            raw_alert=workflow_state["raw_alert"],
            enriched_data=workflow_state.get("enriched_data", {}),
            triage_status=TriageStatus(workflow_state["triage_status"]),
            confidence_score=workflow_state["confidence_score"],
            fp_indicators=workflow_state.get("fp_indicators", []),
            tp_indicators=workflow_state.get("tp_indicators", []),
            workflow_instance_id=workflow_state["workflow_instance_id"],
            current_node=workflow_state["current_node"],
            priority_level=workflow_state.get("priority_level", 3),
            metadata={"processing_notes": workflow_state.get("processing_notes", [])}
        )
    
    def _soc_to_workflow_state(self, soc_state: SOCState) -> WorkflowState:
        """Convert SOCState to WorkflowState for LangGraph."""
        return WorkflowState(
            alert_id=soc_state.alert_id,
            workflow_instance_id=soc_state.workflow_instance_id,
            raw_alert=soc_state.raw_alert,
            triage_status=soc_state.triage_status.value,
            confidence_score=soc_state.confidence_score,
            current_node=soc_state.current_node,
            fp_indicators=soc_state.fp_indicators,
            tp_indicators=soc_state.tp_indicators,
            last_updated=soc_state.last_updated.isoformat() if hasattr(soc_state.last_updated, 'isoformat') else str(soc_state.last_updated),
            priority_level=soc_state.priority_level,
            enriched_data=soc_state.enriched_data,
            processing_notes=soc_state.metadata.get("processing_notes", [])
        )
    
    async def initialize(self):
        """Initialize the workflow engine."""
        try:
            # Compile the graph if not already compiled
            if not hasattr(self, 'compiled_graph') or self.compiled_graph is None:
                self.compiled_graph = self.graph.compile()
            
            import logging
            logging.info("WorkflowEngine initialized successfully")
            
        except Exception as e:
            import logging
            logging.error(f"Failed to initialize WorkflowEngine: {e}")
            raise
    
    async def execute_workflow(self, alert_id: str, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the workflow with proper state management."""
        try:
            # Create workflow instance ID
            workflow_instance_id = f"{alert_id}_{self._generate_workflow_id()}"
            
            # Create SOCState for persistence
            soc_state = await self.state_manager.create_state(
                alert_id=alert_id,
                raw_alert=initial_state,
                workflow_instance_id=workflow_instance_id,
                initial_node="ingestion",
                author_type="system",
                author_id="workflow_engine"
            )
            
            # Convert to WorkflowState for LangGraph
            workflow_state = self._soc_to_workflow_state(soc_state)
            
            # Execute workflow through LangGraph
            result_state = await self.compiled_graph.ainvoke(workflow_state)
            
            # Convert back to SOCState and update persistence
            final_soc_state = self._workflow_to_soc_state(result_state)
            
            # Update the persisted state
            updated_soc_state = await self.state_manager.update_state(
                soc_state,
                final_soc_state.dict(exclude={'alert_id', 'workflow_instance_id'}),
                author_type="system",
                author_id="workflow_engine",
                changes_summary="Workflow execution completed"
            )
            
            # Return the final state as dict
            return result_state
            
        except Exception as e:
            import traceback
            print(f"Workflow error details: {traceback.format_exc()}")
            raise WorkflowError(f"Workflow execution failed: {str(e)}")
    
    def _build_workflow_graph(self) -> StateGraph:
        """Build the LangGraph workflow graph."""
        workflow = StateGraph(WorkflowState)
        
        # Add nodes
        workflow.add_node("ingestion", self._execute_ingestion)
        workflow.add_node("triage", self._execute_triage)
        workflow.add_node("correlation", self._execute_correlation)
        workflow.add_node("analysis", self._execute_analysis)
        workflow.add_node("human_loop", self._execute_human_loop)
        workflow.add_node("response", self._execute_response)
        workflow.add_node("learning", self._execute_learning)
        workflow.add_node("close", self._execute_close)
        
        # Set entry point
        workflow.add_edge(START, "ingestion")
        
        # Add conditional edges with simplified routing
        workflow.add_conditional_edges(
            "ingestion",
            self._route_after_ingestion,
            {
                "triage": "triage",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "triage",
            self._route_after_triage,
            {
                "correlation": "correlation",
                "analysis": "analysis",
                "human_loop": "human_loop",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "correlation",
            self._route_after_correlation,
            {
                "analysis": "analysis",
                "human_loop": "human_loop",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "analysis",
            self._route_after_analysis,
            {
                "human_loop": "human_loop",
                "response": "response",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "human_loop",
            self._route_after_human_loop,
            {
                "analysis": "analysis",
                "response": "response",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "response",
            self._route_after_response,
            {
                "learning": "learning",
                "close": "close"
            }
        )
        
        workflow.add_edge("learning", "close")
        workflow.add_edge("close", END)
        
        return workflow
    
    # Node implementations remain the same but work with WorkflowState
    async def _execute_ingestion(self, state: WorkflowState) -> WorkflowState:
        """Execute ingestion."""
        try:
            if not state["raw_alert"]:
                raise ValueError("Empty alert data")
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            
            state["processing_notes"].append(f"Ingested at {datetime.utcnow().isoformat()}")
            state["current_node"] = "ingestion"
            state["triage_status"] = "ingested"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Ingestion error: {str(e)}")
            return state
    
    async def _execute_triage(self, state: WorkflowState) -> WorkflowState:
        """Execute triage."""
        try:
            alert = state["raw_alert"]
            
            confidence_score = self._calculate_basic_confidence(alert)
            fp_indicators, tp_indicators = self._analyze_indicators(alert)
            
            state["confidence_score"] = confidence_score
            state["fp_indicators"] = fp_indicators
            state["tp_indicators"] = tp_indicators
            state["current_node"] = "triage"
            state["triage_status"] = "triaged"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Triaged with confidence {confidence_score}")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Triage error: {str(e)}")
            return state
    
    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """Execute correlation."""
        try:
            if "enriched_data" not in state:
                state["enriched_data"] = {}
            
            state["enriched_data"]["related_events"] = []
            state["enriched_data"]["correlation_score"] = 0.5
            
            state["current_node"] = "correlation"
            state["triage_status"] = "correlated"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append("Correlation completed")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Correlation error: {str(e)}")
            return state
    
    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """Execute analysis."""
        try:
            confidence_adjustment = 10 if len(state.get("tp_indicators", [])) > len(state.get("fp_indicators", [])) else -10
            current_confidence = state.get("confidence_score", 50)
            state["confidence_score"] = max(0, min(100, current_confidence + confidence_adjustment))
            
            if "enriched_data" not in state:
                state["enriched_data"] = {}
            
            state["enriched_data"]["analysis_results"] = {
                "threats_found": len(state.get("tp_indicators", [])),
                "false_positives": len(state.get("fp_indicators", []))
            }
            
            state["current_node"] = "analysis"
            state["triage_status"] = "analyzed"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append("Analysis completed")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Analysis error: {str(e)}")
            return state
    
    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """Execute human loop."""
        try:
            if "enriched_data" not in state:
                state["enriched_data"] = {}
            
            state["enriched_data"]["human_review_requested"] = True
            state["enriched_data"]["escalation_level"] = 1
            
            state["current_node"] = "human_loop"
            state["triage_status"] = "escalated"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append("Escalated for human review")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Human loop error: {str(e)}")
            return state
    
    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """Execute response."""
        try:
            if "enriched_data" not in state:
                state["enriched_data"] = {}
            
            state["enriched_data"]["response_actions"] = ["quarantine_file", "block_ip"]
            
            state["current_node"] = "response"
            state["triage_status"] = "responded"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append("Response actions executed")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Response error: {str(e)}")
            return state
    
    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """Execute learning."""
        try:
            if "enriched_data" not in state:
                state["enriched_data"] = {}
            
            state["enriched_data"]["learning_data"] = {
                "patterns_learned": 1,
                "model_updated": True
            }
            
            state["current_node"] = "learning"
            state["last_updated"] = datetime.utcnow().isoformat()
            
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append("Learning completed")
            
            return state
            
        except Exception as e:
            if "processing_notes" not in state:
                state["processing_notes"] = []
            state["processing_notes"].append(f"Learning error: {str(e)}")
            return state
    
    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """Close the alert."""
        state["current_node"] = "close"
        state["triage_status"] = "closed"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        if "processing_notes" not in state:
            state["processing_notes"] = []
        state["processing_notes"].append("Alert closed")
        
        return state
    
    # Routing methods
    def _route_after_ingestion(self, state: WorkflowState) -> str:
        """Route after ingestion."""
        if not state["raw_alert"]:
            return "close"
        return "triage"
    
    def _route_after_triage(self, state: WorkflowState) -> str:
        """Route after triage."""
        confidence = state["confidence_score"]
        
        if confidence < 20:
            return "close"
        elif confidence > 80:
            return "response"
        elif confidence < 50:
            return "human_loop"
        else:
            return "analysis"
    
    def _route_after_correlation(self, state: WorkflowState) -> str:
        """Route after correlation."""
        return "analysis"
    
    def _route_after_analysis(self, state: WorkflowState) -> str:
        """Route after analysis."""
        confidence = state["confidence_score"]
        
        if confidence > 80:
            return "response"
        elif confidence < 30:
            return "close"
        else:
            return "human_loop"
    
    def _route_after_human_loop(self, state: WorkflowState) -> str:
        """Route after human loop."""
        return "close"
    
    def _route_after_response(self, state: WorkflowState) -> str:
        """Route after response."""
        return "learning"
    
    # Helper methods
    def _calculate_basic_confidence(self, alert: Dict[str, Any]) -> int:
        """Calculate basic confidence score."""
        score = 50
        
        severity = alert.get('severity', '').lower()
        if severity == 'high':
            score += 20
        elif severity == 'critical':
            score += 30
        elif severity == 'low':
            score -= 20
        
        content = str(alert).lower()
        if 'malware' in content:
            score += 25
        if 'test' in content:
            score -= 30
        
        return max(0, min(100, score))
    
    def _analyze_indicators(self, alert: Dict[str, Any]) -> tuple:
        """Analyze alert for FP/TP indicators."""
        fp_indicators = []
        tp_indicators = []
        
        content = str(alert).lower()
        
        if 'test' in content:
            fp_indicators.append('test_environment')
        if 'scheduled' in content:
            fp_indicators.append('scheduled_activity')
        
        if 'malware' in content:
            tp_indicators.append('malware_detected')
        if 'suspicious' in content:
            tp_indicators.append('suspicious_activity')
        
        return fp_indicators, tp_indicators
    
    def _generate_workflow_id(self) -> str:
        """Generate unique workflow instance ID."""
        import uuid
        return str(uuid.uuid4())[:8]