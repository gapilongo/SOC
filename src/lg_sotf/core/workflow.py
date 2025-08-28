"""
Simplified WorkflowEngine using agents consistently.
"""

from datetime import datetime
from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, START, StateGraph

from lg_sotf.agents.registry import agent_registry
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import WorkflowError
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
    """Simplified workflow engine using agents consistently."""
    
    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.agents = {}
        self.graph = self._build_workflow_graph()
        self.compiled_graph = None
    
    async def initialize(self):
        """Initialize the workflow engine and agents."""
        try:
            # Setup all agents
            await self._setup_agents()
            
            # Compile the graph
            self.compiled_graph = self.graph.compile()
            
            import logging
            logging.info("WorkflowEngine initialized successfully")
            
        except Exception as e:
            import logging
            logging.error(f"Failed to initialize WorkflowEngine: {e}")
            raise WorkflowError(f"Initialization failed: {e}")
    
    async def _setup_agents(self):
        """Setup all required agents."""


        # Register and create triage agent
        if "triage" not in agent_registry.list_agent_types():
            agent_registry.register_agent_type(
                "triage", TriageAgent, self.config.get_agent_config("triage")
            )
        
        if "triage_instance" not in agent_registry.list_agent_instances():
            agent_registry.create_agent(
                "triage_instance", "triage", self.config.get_agent_config("triage")
            )
        
        # Initialize and store agent references
        self.agents['triage'] = agent_registry.get_agent("triage_instance")
        await self.agents['triage'].initialize()
        
        # TODO: Add other agents (correlation, analysis, etc.) when implemented
        # For now, we'll use placeholder agents for non-implemented nodes
    
    async def execute_workflow(self, alert_id: str, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the workflow."""
        try:
            # Create workflow instance ID
            workflow_instance_id = f"{alert_id}_{self._generate_workflow_id()}"
            
            # Create initial workflow state
            workflow_state = WorkflowState(
                alert_id=alert_id,
                workflow_instance_id=workflow_instance_id,
                raw_alert=initial_state,
                triage_status="new",
                confidence_score=0,
                current_node="ingestion",
                fp_indicators=[],
                tp_indicators=[],
                last_updated=datetime.utcnow().isoformat(),
                priority_level=3,
                enriched_data={},
                processing_notes=[]
            )
            
            # Execute through LangGraph
            result_state = await self.compiled_graph.ainvoke(workflow_state)
            
            # Persist final state
            await self._persist_final_state(result_state)
            
            return result_state
            
        except Exception as e:
            import traceback
            print(f"Workflow error: {traceback.format_exc()}")
            raise WorkflowError(f"Workflow execution failed: {str(e)}")
    
    async def _persist_final_state(self, workflow_state: WorkflowState):
        """Persist the final workflow state."""
        try:
            # Convert to SOCState for persistence
            soc_state = SOCState(
                alert_id=workflow_state["alert_id"],
                raw_alert=workflow_state["raw_alert"],
                enriched_data=workflow_state["enriched_data"],
                triage_status=TriageStatus(workflow_state["triage_status"]),
                confidence_score=workflow_state["confidence_score"],
                fp_indicators=workflow_state["fp_indicators"],
                tp_indicators=workflow_state["tp_indicators"],
                workflow_instance_id=workflow_state["workflow_instance_id"],
                current_node=workflow_state["current_node"],
                priority_level=workflow_state["priority_level"],
                metadata={"processing_notes": workflow_state["processing_notes"]}
            )
            
            # Create or update in state manager
            try:
                existing_state = await self.state_manager.get_state(
                    workflow_state["alert_id"], 
                    workflow_state["workflow_instance_id"]
                )
                
                if existing_state:
                    # Update existing state
                    await self.state_manager.update_state(
                        existing_state,
                        soc_state.dict(exclude={'alert_id', 'workflow_instance_id'}),
                        author_type="system",
                        author_id="workflow_engine",
                        changes_summary="Workflow execution completed"
                    )
                else:
                    # Create new state
                    await self.state_manager.create_state(
                        alert_id=workflow_state["alert_id"],
                        raw_alert=workflow_state["raw_alert"],
                        workflow_instance_id=workflow_state["workflow_instance_id"],
                        initial_node="ingestion",
                        author_type="system",
                        author_id="workflow_engine"
                    )
            except Exception as persist_error:
                import logging
                logging.warning(f"Failed to persist state: {persist_error}")
            
        except Exception as e:
            import logging
            logging.error(f"Error persisting final state: {e}")
    
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
        
        # Add conditional edges
        workflow.add_conditional_edges(
            "ingestion",
            self._route_after_ingestion,
            {"triage": "triage", "close": "close"}
        )
        
        workflow.add_conditional_edges(
            "triage",
            self._route_after_triage,
            {
                "correlation": "correlation",
                "analysis": "analysis", 
                "human_loop": "human_loop",
                "response": "response",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "correlation",
            self._route_after_correlation,
            {"analysis": "analysis", "human_loop": "human_loop", "close": "close"}
        )
        
        workflow.add_conditional_edges(
            "analysis", 
            self._route_after_analysis,
            {"human_loop": "human_loop", "response": "response", "close": "close"}
        )
        
        workflow.add_conditional_edges(
            "human_loop",
            self._route_after_human_loop,
            {"analysis": "analysis", "response": "response", "close": "close"}
        )
        
        workflow.add_conditional_edges(
            "response",
            self._route_after_response,
            {"learning": "learning", "close": "close"}
        )
        
        workflow.add_edge("learning", "close")
        workflow.add_edge("close", END)
        
        return workflow
    
    # Node implementations
    async def _execute_ingestion(self, state: WorkflowState) -> WorkflowState:
        """Execute ingestion - simple validation."""
        if not state["raw_alert"]:
            state["processing_notes"].append("Ingestion failed: empty alert")
            return state
        
        state["triage_status"] = "ingested"
        state["current_node"] = "ingestion"
        state["last_updated"] = datetime.utcnow().isoformat()
        state["processing_notes"].append("Alert ingested successfully")
        
        return state
    
    async def _execute_triage(self, state: WorkflowState) -> WorkflowState:
        """Execute triage using the triage agent."""
        try:
            if 'triage' not in self.agents:
                raise ValueError("Triage agent not available")
            
            # Convert state to agent format
            agent_input = {
                'alert_id': state['alert_id'],
                'raw_alert': state['raw_alert'],
                'triage_status': state['triage_status'],
                'confidence_score': state['confidence_score'],
                'fp_indicators': state['fp_indicators'],
                'tp_indicators': state['tp_indicators'],
                'priority_level': state['priority_level'],
                'enriched_data': state['enriched_data'],
                'metadata': {'processing_notes': state['processing_notes']}
            }
            
            # Execute agent
            agent_result = await self.agents['triage'].execute(agent_input)
            
            # Update state with agent results
            state['confidence_score'] = agent_result.get('confidence_score', state['confidence_score'])
            state['fp_indicators'] = agent_result.get('fp_indicators', state['fp_indicators'])
            state['tp_indicators'] = agent_result.get('tp_indicators', state['tp_indicators'])
            state['priority_level'] = agent_result.get('priority_level', state['priority_level'])
            state['triage_status'] = agent_result.get('triage_status', 'triaged')
            state['enriched_data'].update(agent_result.get('enriched_data', {}))
            
            # Add agent processing notes
            agent_notes = agent_result.get('metadata', {}).get('processing_notes', [])
            state['processing_notes'].extend(agent_notes)
            
            state['current_node'] = "triage"
            state['last_updated'] = datetime.utcnow().isoformat()
            
            return state
            
        except Exception as e:
            state['processing_notes'].append(f"Triage error: {str(e)}")
            state['current_node'] = "triage"
            state['last_updated'] = datetime.utcnow().isoformat()
            return state
    
    # Placeholder implementations for other nodes
    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """Execute correlation - placeholder."""
        state['enriched_data']['correlation_score'] = 0.5
        state['current_node'] = "correlation"
        state['triage_status'] = "correlated"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Correlation completed (placeholder)")
        return state
    
    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """Execute analysis - placeholder."""
        # Simple confidence adjustment
        if len(state['tp_indicators']) > len(state['fp_indicators']):
            state['confidence_score'] = min(100, state['confidence_score'] + 10)
        else:
            state['confidence_score'] = max(0, state['confidence_score'] - 10)
        
        state['current_node'] = "analysis"
        state['triage_status'] = "analyzed"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Analysis completed (placeholder)")
        return state
    
    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """Execute human loop - placeholder."""
        state['enriched_data']['human_review_requested'] = True
        state['current_node'] = "human_loop"
        state['triage_status'] = "escalated"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Escalated for human review (placeholder)")
        return state
    
    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """Execute response - placeholder."""
        state['enriched_data']['response_actions'] = ["quarantine", "block_ip"]
        state['current_node'] = "response"
        state['triage_status'] = "responded"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Response actions executed (placeholder)")
        return state
    
    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """Execute learning - placeholder."""
        state['enriched_data']['learning_completed'] = True
        state['current_node'] = "learning"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Learning completed (placeholder)")
        return state
    
    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """Close the alert."""
        state['current_node'] = "close"
        state['triage_status'] = "closed"
        state['last_updated'] = datetime.utcnow().isoformat()
        state['processing_notes'].append("Alert closed")
        return state
    
    # Routing methods (unchanged)
    def _route_after_ingestion(self, state: WorkflowState) -> str:
        return "close" if not state["raw_alert"] else "triage"
    
    def _route_after_triage(self, state: WorkflowState) -> str:
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
        return "analysis"
    
    def _route_after_analysis(self, state: WorkflowState) -> str:
        confidence = state["confidence_score"]
        if confidence > 80:
            return "response"
        elif confidence < 30:
            return "close"
        else:
            return "human_loop"
    
    def _route_after_human_loop(self, state: WorkflowState) -> str:
        return "close"
    
    def _route_after_response(self, state: WorkflowState) -> str:
        return "learning"
    
    def _generate_workflow_id(self) -> str:
        """Generate unique workflow instance ID."""
        import uuid
        return str(uuid.uuid4())[:8]