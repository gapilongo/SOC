"""
Workflow orchestration engine using LangGraph.

This module provides the main workflow engine that orchestrates the entire
SOC alert processing pipeline using LangGraph for stateful workflow execution.
"""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from ..agents.registry import agent_registry
from .config.manager import ConfigManager
from .edges.router import EdgeRouter
from .exceptions import StateError, WorkflowError
from .state.manager import StateManager


class WorkflowState(TypedDict):
    """State schema for the workflow."""
    alert_id: str
    workflow_instance_id: str
    triage_status: str
    last_updated: str
    raw_alert: Dict[str, Any]
    processed_data: Dict[str, Any]
    current_node: str
    author_type: str
    author_id: str
    messages: Annotated[List[Dict], add_messages]


class WorkflowEngine:
    """Main workflow engine for SOC alert processing."""
    
    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.edge_router = EdgeRouter(config_manager)
        self.graph = self._build_workflow_graph()
        self.compiled_graph = self.graph.compile()
        
    def _build_workflow_graph(self) -> StateGraph:
        """Build the LangGraph workflow graph."""
        workflow = StateGraph(WorkflowState)
        
        # Add nodes (agents)
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
            self.edge_router.route_after_ingestion,
            {
                "triage": "triage",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "triage",
            self.edge_router.route_after_triage,
            {
                "correlation": "correlation",
                "analysis": "analysis",
                "human_loop": "human_loop",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "correlation",
            self.edge_router.route_after_correlation,
            {
                "analysis": "analysis",
                "human_loop": "human_loop",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "analysis",
            self.edge_router.route_after_analysis,
            {
                "human_loop": "human_loop",
                "response": "response",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "human_loop",
            self.edge_router.route_after_human_loop,
            {
                "analysis": "analysis",
                "response": "response",
                "close": "close"
            }
        )
        
        workflow.add_conditional_edges(
            "response",
            self.edge_router.route_after_response,
            {
                "learning": "learning",
                "close": "close"
            }
        )
        
        workflow.add_edge("learning", "close")
        workflow.add_edge("close", END)
        
        return workflow
    
    async def execute_workflow(self, alert_id: str, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the workflow for a given alert."""
        try:
            # Create workflow instance ID
            workflow_instance_id = f"{alert_id}_{self._generate_workflow_id()}"
            
            # Initialize state according to WorkflowState schema
            initial_workflow_state = {
                "alert_id": alert_id,
                "workflow_instance_id": workflow_instance_id,
                "triage_status": "initiated",
                "last_updated": datetime.utcnow().isoformat(),
                "raw_alert": initial_state,
                "processed_data": {},
                "current_node": "ingestion",
                "author_type": "system",
                "author_id": "workflow_engine",
                "messages": []
            }
            
            # Create state using state manager
            state = await self.state_manager.create_state(
                alert_id=alert_id,
                raw_alert=initial_state,
                workflow_instance_id=workflow_instance_id,
                initial_node="ingestion",
                author_type="system",
                author_id="workflow_engine"
            )
            
            # Update with additional fields for workflow state
            workflow_state = {**state.dict(), **initial_workflow_state}
            
            # Execute workflow
            result = await self.compiled_graph.ainvoke(workflow_state)
            
            return result
            
        except Exception as e:
            raise WorkflowError(f"Workflow execution failed: {str(e)}")
    
    async def _execute_ingestion(self, state: WorkflowState) -> WorkflowState:
        """Execute ingestion agent."""
        agent = agent_registry.get_agent("ingestion")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "ingestion"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_triage(self, state: WorkflowState) -> WorkflowState:
        """Execute triage agent."""
        agent = agent_registry.get_agent("triage")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "triage"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """Execute correlation agent."""
        agent = agent_registry.get_agent("correlation")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "correlation"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """Execute analysis agent."""
        agent = agent_registry.get_agent("analysis")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "analysis"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """Execute human loop agent."""
        agent = agent_registry.get_agent("human_loop")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "human_loop"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """Execute response agent."""
        agent = agent_registry.get_agent("response")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "response"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """Execute learning agent."""
        agent = agent_registry.get_agent("learning")
        result = await agent.execute(dict(state))
        
        # Update state
        state.update(result)
        state["current_node"] = "learning"
        state["last_updated"] = datetime.utcnow().isoformat()
        
        return state
    
    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """Execute close agent."""
        # Final state validation and cleanup
        state["triage_status"] = "closed"
        state["current_node"] = "close"
        state["last_updated"] = datetime.utcnow().isoformat()
        return state
    
    def _generate_workflow_id(self) -> str:
        """Generate unique workflow instance ID."""
        import uuid
        return str(uuid.uuid4())