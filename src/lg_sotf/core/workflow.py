"""
 WorkflowEngine with atomic state management and proper agent coordination.
Fixes the state corruption and duplicate execution issues.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, START, StateGraph

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.ingestion.base import IngestionAgent
from lg_sotf.agents.registry import agent_registry
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import WorkflowError
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.state.model import SOCState, TriageStatus


@dataclass
class ExecutionContext:
    """Execution context to prevent duplicate executions."""
    execution_id: str
    started_at: datetime
    node_executions: Dict[str, bool]  # Track which nodes have executed
    locks: Dict[str, asyncio.Lock]    # Per-node locks


class WorkflowState(TypedDict):
    """ state schema for LangGraph workflow."""
    # Core identification
    alert_id: str
    workflow_instance_id: str
    execution_context: Dict[str, Any]  # NEW: Execution tracking
    
    # Alert data
    raw_alert: Dict[str, Any]
    enriched_data: Dict[str, Any]
    
    # Status and scoring
    triage_status: str
    confidence_score: int
    current_node: str
    priority_level: int
    
    # Indicators
    fp_indicators: List[str]
    tp_indicators: List[str]
    
    # Correlation data
    correlations: List[Dict[str, Any]]
    correlation_score: int
    
    # Analysis data  
    analysis_conclusion: str
    threat_score: int
    recommended_actions: List[str]
    analysis_reasoning: List[Dict[str, Any]]
    tool_results: Dict[str, Dict[str, Any]]
    
    # Processing tracking
    processing_notes: List[str]
    last_updated: str
    
    # Execution guards (NEW)
    agent_executions: Dict[str, Dict[str, Any]]  # Track agent execution state
    state_version: int  # State versioning for conflict detection


class WorkflowEngine:
    """ workflow engine with atomic state management."""

    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.agents = {}
        self.logger = logging.getLogger(__name__)
        
        # Synchronization primitives
        self._state_lock = RLock()  # Protects state updates
        self._execution_contexts = {}  # Track active executions
        self._agent_locks = {}  # Per-agent execution locks
        
        # Routing configuration
        self.routing_config = {
            'max_alert_age_hours': config_manager.get('routing.max_alert_age_hours', 72),
            'correlation_grey_zone_min': config_manager.get('routing.correlation_grey_zone_min', 30),
            'correlation_grey_zone_max': config_manager.get('routing.correlation_grey_zone_max', 70),
            'analysis_threshold': config_manager.get('routing.analysis_threshold', 40),
            'human_review_min': config_manager.get('routing.human_review_min', 20),
            'human_review_max': config_manager.get('routing.human_review_max', 60),
            'response_threshold': config_manager.get('routing.response_threshold', 80),
        }
        
        self.graph = self._build_workflow_graph()
        self.compiled_graph = None

    async def initialize(self):
        """Initialize the  workflow engine."""
        try:
            await self._setup_agents()
            self.compiled_graph = self.graph.compile()
            self.logger.info(" WorkflowEngine initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize  WorkflowEngine: {e}")
            raise WorkflowError(f"Initialization failed: {e}")

    async def _setup_agents(self):
        """Setup all required agents with proper synchronization."""
        agents_config = [
            ("ingestion", IngestionAgent, "ingestion_instance"),
            ("triage", TriageAgent, "triage_instance"),
            ("correlation", CorrelationAgent, "correlation_instance"),
            ("analysis", AnalysisAgent, "analysis_instance"),
        ]
        
        for agent_type, agent_class, instance_name in agents_config:
            # Register agent type if not exists
            if agent_type not in agent_registry.list_agent_types():
                agent_registry.register_agent_type(
                    agent_type, agent_class, self.config.get_agent_config(agent_type)
                )
            
            # Create instance if not exists
            if instance_name not in agent_registry.list_agent_instances():
                agent_registry.create_agent(
                    instance_name, agent_type, self.config.get_agent_config(agent_type)
                )
            
            # Get and initialize agent
            agent = agent_registry.get_agent(instance_name)
            await agent.initialize()
            
            # Store reference and create lock
            self.agents[agent_type] = agent
            self._agent_locks[agent_type] = asyncio.Lock()
        
        self.logger.info(f"Initialized {len(self.agents)} agents with synchronization")

    def _create_execution_context(self, alert_id: str) -> ExecutionContext:
        """Create execution context with proper tracking."""
        execution_id = f"{alert_id}_{datetime.utcnow().strftime('%H%M%S_%f')}"
        
        context = ExecutionContext(
            execution_id=execution_id,
            started_at=datetime.utcnow(),
            node_executions={},
            locks={node: asyncio.Lock() for node in 
                   ['ingestion', 'triage', 'correlation', 'analysis', 'human_loop', 'response', 'learning']}
        )
        
        self._execution_contexts[alert_id] = context
        return context

    def _build_workflow_graph(self) -> StateGraph:
        """Build the  LangGraph workflow."""
        workflow = StateGraph(WorkflowState)

        # Add nodes with synchronization wrappers
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

        # Add conditional edges with  routing
        workflow.add_conditional_edges(
            "ingestion",
            self._route_after_ingestion,
            {"triage": "triage", "close": "close"},
        )

        workflow.add_conditional_edges(
            "triage",
            self._route_after_triage,
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
            self._route_after_correlation,
            {
                "analysis": "analysis",
                "response": "response",
                "human_loop": "human_loop", 
                "close": "close",
            },
        )

        workflow.add_conditional_edges(
            "analysis",
            self._route_after_analysis,
            {"human_loop": "human_loop", "response": "response", "close": "close"},
        )

        workflow.add_conditional_edges(
            "human_loop",
            self._route_after_human_loop,
            {"analysis": "analysis", "response": "response", "close": "close"},
        )

        workflow.add_conditional_edges(
            "response",
            self._route_after_response,
            {"learning": "learning", "close": "close"},
        )

        workflow.add_edge("learning", "close")
        workflow.add_edge("close", END)

        return workflow

    # ===============================
    #  EXECUTION WRAPPERS
    # ===============================

    async def _execute_ingestion(self, state: WorkflowState) -> WorkflowState:
        """ ingestion execution."""
        return await self._execute_with("ingestion", self._execute_ingestion, state)

    async def _execute_triage(self, state: WorkflowState) -> WorkflowState:
        """ triage execution.""" 
        return await self._execute_with("triage", self._execute_triage, state)

    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """ correlation execution."""
        return await self._execute_with("correlation", self._execute_correlation, state)

    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """ analysis execution."""
        return await self._execute_with("analysis", self._execute_analysis, state)

    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """ human loop execution."""
        return await self._execute_with("human_loop", self._execute_human_loop, state)

    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """ response execution."""
        return await self._execute_with("response", self._execute_response, state)

    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """ learning execution."""
        return await self._execute_with("learning", self._execute_learning, state)

    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """ close execution."""
        return await self._execute_with("close", self._execute_close, state)

    async def _execute_with(self, node_name: str, executor_func, state: WorkflowState) -> WorkflowState:
        """Execute node with full synchronization and duplicate prevention."""
        alert_id = state["alert_id"]
        execution_context = self._execution_contexts.get(alert_id)
        
        if not execution_context:
            self.logger.error(f"No execution context for alert {alert_id}")
            return state
        
        # Check if this node already executed
        with self._state_lock:
            if execution_context.node_executions.get(node_name, False):
                self.logger.warning(f"Node {node_name} already executed for {alert_id}, skipping")
                return state
        
        # Acquire node-specific lock
        async with execution_context.locks[node_name]:
            # Double-check after acquiring lock
            with self._state_lock:
                if execution_context.node_executions.get(node_name, False):
                    self.logger.warning(f"Node {node_name} executed during lock wait for {alert_id}")
                    return state
                
                # Mark as executing
                execution_context.node_executions[node_name] = True
                state["state_version"] += 1
                
                self.logger.info(f"🔒 Executing {node_name} for {alert_id} (version {state['state_version']})")
            
            try:
                # Execute the actual node logic
                result_state = await executor_func(state)
                
                # Atomic state update
                with self._state_lock:
                    result_state["execution_context"] = {
                        "execution_id": execution_context.execution_id,
                        "last_node": node_name,
                        "executed_nodes": list(execution_context.node_executions.keys()),
                        "execution_time": datetime.utcnow().isoformat()
                    }
                    result_state["last_updated"] = datetime.utcnow().isoformat()
                    result_state["processing_notes"].append(f"✅ {node_name} completed (v{result_state['state_version']})")
                
                self.logger.info(f"✅ {node_name} completed for {alert_id}")
                return result_state
                
            except Exception as e:
                # Mark as failed but don't re-execute
                self.logger.error(f"❌ {node_name} failed for {alert_id}: {e}")
                state["processing_notes"].append(f"❌ {node_name} failed: {str(e)}")
                return state

    # ===============================
    #  ROUTING METHODS
    # ===============================

    def _route_after_ingestion(self, state: WorkflowState) -> str:
        """ routing after ingestion."""
        with self._state_lock:
            return self._route_after_ingestion(state)

    def _route_after_triage(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after triage."""
        with self._state_lock:
            return self._route_after_triage_logic(state)

    def _route_after_triage_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after triage."""
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])
        
        self.logger.info(f"🛤️ Routing after triage: confidence={confidence}%, FP={fp_count}, TP={tp_count}")
        
        # Close conditions
        if confidence <= 10 and fp_count >= 2:
            state["processing_notes"].append(f"Routing: Close (low confidence {confidence}% + {fp_count} FP indicators)")
            return "close"
        
        if fp_count > tp_count and confidence <= 30:
            state["processing_notes"].append(f"Routing: Close (more FP {fp_count} than TP {tp_count})")
            return "close"
        
        # High confidence direct response
        if confidence >= 85 and tp_count >= 3:
            state["processing_notes"].append(f"Routing: Response (high confidence {confidence}% + {tp_count} TP indicators)")
            return "response"
        
        # Correlation needed
        if self._needs_correlation(state):
            state["processing_notes"].append("Routing: Correlation (network/user indicators detected)")
            return "correlation"
        
        # Analysis needed
        if confidence < 60 or self._needs_analysis(state):
            state["processing_notes"].append(f"Routing: Analysis (confidence {confidence}% needs investigation)")
            return "analysis"
        
        # Default to human review
        state["processing_notes"].append(f"Routing: Human review (uncertain case)")
        return "human_loop"

    # Apply the same pattern to all routing methods:

    def _route_after_correlation(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after correlation.""" 
        with self._state_lock:
            return self._route_after_correlation_logic(state)

    def _route_after_correlation_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after correlation."""
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        confidence = state["confidence_score"]
        
        self.logger.info(f"🛤️ Routing after correlation: correlations={len(correlations)}, score={correlation_score}%, confidence={confidence}%")
        
        # Strong correlations → direct response
        if correlation_score > 85 and len(correlations) >= 5:
            state["processing_notes"].append(f"Routing: Response (strong correlations score={correlation_score}%)")
            return "response"
        
        # Moderate correlations → analysis
        if correlation_score > 60 or len(correlations) >= 3:
            state["processing_notes"].append(f"Routing: Analysis (moderate correlations for deep dive)")
            return "analysis"
        
        # Weak correlations → human review 
        if correlation_score > 20 and confidence > 50:
            state["processing_notes"].append(f"Routing: Human review (weak correlations need manual assessment)")
            return "human_loop"
        
        # No meaningful correlations → close
        state["processing_notes"].append(f"Routing: Close (insufficient correlations)")
        return "close"

    def _route_after_analysis(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after analysis."""
        with self._state_lock:
            return self._route_after_analysis_logic(state)

    def _route_after_analysis_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after analysis."""
        threat_score = state.get("threat_score", 0)
        confidence = state["confidence_score"]
        conclusion = state.get("analysis_conclusion", "").lower()
        
        self.logger.info(f"🛤️ Routing after analysis: threat_score={threat_score}%, confidence={confidence}%")
        
        # High threat → response
        if threat_score >= 80 or (threat_score >= 60 and confidence >= 80):
            state["processing_notes"].append(f"Routing: Response (threat_score={threat_score}%)")
            return "response"
        
        # Uncertain analysis → human review
        if "uncertain" in conclusion or (30 <= confidence <= 70):
            state["processing_notes"].append(f"Routing: Human review (uncertain analysis)")
            return "human_loop"
        
        # Low threat → close
        state["processing_notes"].append(f"Routing: Close (low threat_score={threat_score}%)")
        return "close"

    # Also fix the other routing methods similarly:

    def _route_after_ingestion(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after ingestion."""
        with self._state_lock:
            return self._route_after_ingestion_logic(state)

    def _route_after_ingestion_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after ingestion."""
        return "triage" if state["raw_alert"] else "close"

    def _route_after_human_loop(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after human loop."""
        with self._state_lock:
            return self._route_after_human_loop_logic(state)

    def _route_after_human_loop_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after human loop."""
        confidence = state["confidence_score"]
        if confidence >= 75:
            return "response"
        else:
            return "close"

    def _route_after_response(self, state: WorkflowState) -> str:
        """Thread-safe routing wrapper after response."""
        with self._state_lock:
            return self._route_after_response_logic(state)

    def _route_after_response_logic(self, state: WorkflowState) -> str:
        """Actual routing logic after response."""
        return "learning" if self._should_learn(state) else "close"

    # ===============================
    # IMPROVED AGENT EXECUTION METHODS
    # ===============================

    async def _execute_triage(self, state: WorkflowState) -> WorkflowState:
        """Execute triage with proper state management."""
        try:
            # Prevent duplicate execution with agent-specific lock
            async with self._agent_locks['triage']:
                agent_exec_key = f"triage_{state['alert_id']}"
                
                # Check if already executed in this workflow
                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Triage already executed for {state['alert_id']}")
                    return state
                
                self.logger.info(f"🎯 Executing triage for {state['alert_id']}")
                
                # Convert state to agent format (immutable)
                agent_input = self._convert_to_agent_format(state)
                
                # Execute agent
                agent_result = await self.agents["triage"].execute(agent_input)
                
                # Atomic state update
                with self._state_lock:
                    # Update core fields
                    state["confidence_score"] = agent_result.get("confidence_score", state["confidence_score"])
                    state["fp_indicators"] = agent_result.get("fp_indicators", state["fp_indicators"])
                    state["tp_indicators"] = agent_result.get("tp_indicators", state["tp_indicators"])
                    state["priority_level"] = agent_result.get("priority_level", state["priority_level"])
                    state["triage_status"] = agent_result.get("triage_status", "triaged")
                    
                    # Merge enriched data safely
                    state["enriched_data"].update(agent_result.get("enriched_data", {}))
                    
                    # Track execution
                    if "agent_executions" not in state:
                        state["agent_executions"] = {}
                    state["agent_executions"][agent_exec_key] = {
                        "executed_at": datetime.utcnow().isoformat(),
                        "confidence_score": state["confidence_score"],
                        "status": "completed"
                    }
                    
                    state["current_node"] = "triage"
                    state["processing_notes"].append(f"Triage: confidence={state['confidence_score']}%, FP={len(state['fp_indicators'])}, TP={len(state['tp_indicators'])}")
                
                return state

        except Exception as e:
            self.logger.error(f"Triage execution failed: {e}")
            state["processing_notes"].append(f"Triage error: {str(e)}")
            state["current_node"] = "triage"
            return state

    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """Execute correlation with proper state management."""
        try:
            async with self._agent_locks['correlation']:
                agent_exec_key = f"correlation_{state['alert_id']}"
                
                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Correlation already executed for {state['alert_id']}")
                    return state
                
                self.logger.info(f"🔗 Executing correlation for {state['alert_id']}")
                
                # Convert state to agent format
                agent_input = self._convert_to_agent_format(state)
                
                # Execute agent
                agent_result = await self.agents["correlation"].execute(agent_input)
                
                # Atomic state update
                with self._state_lock:
                    # Update correlation-specific fields
                    state["confidence_score"] = agent_result.get("confidence_score", state["confidence_score"])
                    state["triage_status"] = agent_result.get("triage_status", "correlated")
                    state["correlations"] = agent_result.get("correlations", [])
                    state["correlation_score"] = agent_result.get("correlation_score", 0)
                    
                    # Merge enriched data
                    state["enriched_data"].update(agent_result.get("enriched_data", {}))
                    
                    # Track execution
                    if "agent_executions" not in state:
                        state["agent_executions"] = {}
                    state["agent_executions"][agent_exec_key] = {
                        "executed_at": datetime.utcnow().isoformat(),
                        "correlations_found": len(state["correlations"]),
                        "correlation_score": state["correlation_score"],
                        "status": "completed"
                    }
                    
                    state["current_node"] = "correlation"
                    state["processing_notes"].append(f"Correlation: found {len(state['correlations'])} correlations (score: {state['correlation_score']}%)")
                
                return state

        except Exception as e:
            self.logger.error(f"Correlation execution failed: {e}")
            state["processing_notes"].append(f"Correlation error: {str(e)}")
            state["current_node"] = "correlation"
            # Ensure fields exist even on error
            if "correlations" not in state:
                state["correlations"] = []
            if "correlation_score" not in state:
                state["correlation_score"] = 0
            return state

    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """Execute analysis with proper state management."""
        try:
            async with self._agent_locks['analysis']:
                agent_exec_key = f"analysis_{state['alert_id']}"
                
                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Analysis already executed for {state['alert_id']}")
                    return state
                
                self.logger.info(f"🧠 Executing analysis for {state['alert_id']}")
                
                # Convert state to agent format
                agent_input = self._convert_to_agent_format(state)
                
                # Execute agent  
                agent_result = await self.agents["analysis"].execute(agent_input)
                
                # Atomic state update
                with self._state_lock:
                    # Update analysis-specific fields
                    state["confidence_score"] = agent_result.get("confidence_score", state["confidence_score"])
                    state["triage_status"] = agent_result.get("triage_status", "analyzed")
                    state["analysis_conclusion"] = agent_result.get("analysis_conclusion", "")
                    state["threat_score"] = agent_result.get("threat_score", 0)
                    state["recommended_actions"] = agent_result.get("recommended_actions", [])
                    state["analysis_reasoning"] = agent_result.get("analysis_reasoning", [])
                    state["tool_results"] = agent_result.get("tool_results", {})
                    
                    # Merge enriched data
                    state["enriched_data"].update(agent_result.get("enriched_data", {}))
                    
                    # Track execution
                    if "agent_executions" not in state:
                        state["agent_executions"] = {}
                    state["agent_executions"][agent_exec_key] = {
                        "executed_at": datetime.utcnow().isoformat(),
                        "threat_score": state["threat_score"],
                        "reasoning_steps": len(state["analysis_reasoning"]),
                        "tools_used": len(state["tool_results"]),
                        "status": "completed"
                    }
                    
                    state["current_node"] = "analysis"
                    state["processing_notes"].append(f"Analysis: threat_score={state['threat_score']}%, reasoning_steps={len(state['analysis_reasoning'])}")
                
                return state

        except Exception as e:
            self.logger.error(f"Analysis execution failed: {e}")
            state["processing_notes"].append(f"Analysis error: {str(e)}")
            state["current_node"] = "analysis"
            # Ensure fields exist
            for field in ["analysis_conclusion", "threat_score", "recommended_actions", "analysis_reasoning", "tool_results"]:
                if field not in state:
                    state[field] = [] if "actions" in field or "reasoning" in field or "results" in field else ("" if "conclusion" in field else 0)
            return state

    # ===============================
    # HELPER METHODS
    # ===============================

    def _convert_to_agent_format(self, state: WorkflowState) -> Dict[str, Any]:
        """Convert workflow state to agent input format."""
        return {
            "alert_id": state["alert_id"],
            "raw_alert": state["raw_alert"].copy(),  # Immutable copy
            "triage_status": state["triage_status"],
            "confidence_score": state["confidence_score"],
            "fp_indicators": state["fp_indicators"].copy(),
            "tp_indicators": state["tp_indicators"].copy(),
            "priority_level": state["priority_level"],
            "enriched_data": state["enriched_data"].copy(),
            "correlations": state.get("correlations", []).copy(),
            "correlation_score": state.get("correlation_score", 0),
            "analysis_reasoning": state.get("analysis_reasoning", []).copy(),
            "tool_results": state.get("tool_results", {}).copy(),
            "metadata": {
                "processing_notes": state["processing_notes"].copy(),
                "execution_context": state.get("execution_context", {}),
                "state_version": state["state_version"]
            }
        }

    # ===============================
    # ROUTING METHODS (Improved)
    # ===============================

    def _route_after_triage(self, state: WorkflowState) -> str:
        """Improved routing after triage with detailed logging."""
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])
        
        self.logger.info(f"🛤️ Routing after triage: confidence={confidence}%, FP={fp_count}, TP={tp_count}")
        
        # Close conditions
        if confidence <= 10 and fp_count >= 2:
            state["processing_notes"].append(f"Routing: Close (low confidence {confidence}% + {fp_count} FP indicators)")
            return "close"
        
        if fp_count > tp_count and confidence <= 30:
            state["processing_notes"].append(f"Routing: Close (more FP {fp_count} than TP {tp_count})")
            return "close"
        
        # High confidence direct response
        if confidence >= 85 and tp_count >= 3:
            state["processing_notes"].append(f"Routing: Response (high confidence {confidence}% + {tp_count} TP indicators)")
            return "response"
        
        # Correlation needed
        if self._needs_correlation(state):
            state["processing_notes"].append("Routing: Correlation (network/user indicators detected)")
            return "correlation"
        
        # Analysis needed
        if confidence < 60 or self._needs_analysis(state):
            state["processing_notes"].append(f"Routing: Analysis (confidence {confidence}% needs investigation)")
            return "analysis"
        
        # Default to human review
        state["processing_notes"].append(f"Routing: Human review (uncertain case)")
        return "human_loop"

    def _route_after_correlation(self, state: WorkflowState) -> str:
        """Improved routing after correlation."""
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        confidence = state["confidence_score"]
        
        self.logger.info(f"🛤️ Routing after correlation: correlations={len(correlations)}, score={correlation_score}%, confidence={confidence}%")
        
        # Strong correlations → direct response
        if correlation_score > 85 and len(correlations) >= 5:
            state["processing_notes"].append(f"Routing: Response (strong correlations score={correlation_score}%)")
            return "response"
        
        # Moderate correlations → analysis
        if correlation_score > 60 or len(correlations) >= 3:
            state["processing_notes"].append(f"Routing: Analysis (moderate correlations for deep dive)")
            return "analysis"
        
        # Weak correlations → human review 
        if correlation_score > 20 and confidence > 50:
            state["processing_notes"].append(f"Routing: Human review (weak correlations need manual assessment)")
            return "human_loop"
        
        # No meaningful correlations → close
        state["processing_notes"].append(f"Routing: Close (insufficient correlations)")
        return "close"

    def _route_after_analysis(self, state: WorkflowState) -> str:
        """Improved routing after analysis."""
        threat_score = state.get("threat_score", 0)
        confidence = state["confidence_score"]
        conclusion = state.get("analysis_conclusion", "").lower()
        
        self.logger.info(f"🛤️ Routing after analysis: threat_score={threat_score}%, confidence={confidence}%")
        
        # High threat → response
        if threat_score >= 80 or (threat_score >= 60 and confidence >= 80):
            state["processing_notes"].append(f"Routing: Response (threat_score={threat_score}%)")
            return "response"
        
        # Uncertain analysis → human review
        if "uncertain" in conclusion or (30 <= confidence <= 70):
            state["processing_notes"].append(f"Routing: Human review (uncertain analysis)")
            return "human_loop"
        
        # Low threat → close
        state["processing_notes"].append(f"Routing: Close (low threat_score={threat_score}%)")
        return "close"

    # ===============================
    # WORKFLOW EXECUTION
    # ===============================

    async def execute_workflow(self, alert_id: str, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the workflow."""
        try:
            # Create execution context
            execution_context = self._create_execution_context(alert_id)
            workflow_instance_id = f"{alert_id}_{execution_context.execution_id}"

            # ✅ CREATE INITIAL STATE IN DATABASE FIRST
            await self.state_manager.create_state(
                alert_id=alert_id,
                raw_alert=initial_state,
                workflow_instance_id=workflow_instance_id,
                initial_node="ingestion",
                author_type="system",
                author_id="workflow_engine"
            )
            
            self.logger.info(f"Created initial state in database for {alert_id}")

            # Create initial workflow state for LangGraph
            workflow_state = WorkflowState(
                alert_id=alert_id,
                workflow_instance_id=workflow_instance_id,
                execution_context={
                    "execution_id": execution_context.execution_id,
                    "started_at": execution_context.started_at.isoformat()
                },
                raw_alert=initial_state,
                enriched_data={},
                triage_status="new",
                confidence_score=0,
                current_node="ingestion",
                priority_level=3,
                fp_indicators=[],
                tp_indicators=[],
                correlations=[],
                correlation_score=0,
                analysis_conclusion="",
                threat_score=0,
                recommended_actions=[],
                analysis_reasoning=[],
                tool_results={},
                processing_notes=["🔄 workflow started"],
                last_updated=datetime.utcnow().isoformat(),
                agent_executions={},
                state_version=1
            )

            # Execute through LangGraph
            self.logger.info(f"🚀 Starting workflow for {alert_id}")
            result_state = await self.compiled_graph.ainvoke(workflow_state)

            # Cleanup execution context
            if alert_id in self._execution_contexts:
                del self._execution_contexts[alert_id]

            # ✅ UPDATE final state (now it exists!)
            await self._persist_final_state(result_state)

            self.logger.info(f"✅ workflow completed for {alert_id}")
            return result_state

        except Exception as e:
            self.logger.error(f"❌ workflow failed for {alert_id}: {e}")
            if alert_id in self._execution_contexts:
                del self._execution_contexts[alert_id]
            raise WorkflowError(f"workflow execution failed: {str(e)}")

    # Placeholder methods for completeness
    async def _execute_ingestion(self, state: WorkflowState) -> WorkflowState:
        """Execute ingestion using the IngestionAgent."""
        try:
            # Get ingestion agent
            if "ingestion" not in self.agents:
                # Register and initialize ingestion agent if not exists

                
                if "ingestion" not in agent_registry.list_agent_types():
                    agent_registry.register_agent_type(
                        "ingestion",
                        IngestionAgent,
                        self.config.get_agent_config("ingestion")
                    )
                
                if "ingestion_instance" not in agent_registry.list_agent_instances():
                    agent_registry.create_agent(
                        "ingestion_instance",
                        "ingestion",
                        self.config.get_agent_config("ingestion")
                    )
                
                ingestion_agent = agent_registry.get_agent("ingestion_instance")
                await ingestion_agent.initialize()
                self.agents["ingestion"] = ingestion_agent
                self._agent_locks["ingestion"] = asyncio.Lock()
            
            # Execute ingestion
            async with self._agent_locks['ingestion']:
                agent_exec_key = f"ingestion_{state['alert_id']}"
                
                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Ingestion already executed for {state['alert_id']}")
                    return state
                
                self.logger.info(f"🔍 Executing ingestion for {state['alert_id']}")
                
                # Convert state to agent format
                agent_input = {
                    "alert_id": state["alert_id"],
                    "raw_alert": state.get("raw_alert", {}),
                    "source": state.get("raw_alert", {}).get("source", "unknown"),
                    "workflow_instance_id": state["workflow_instance_id"]
                }
                
                # Execute ingestion agent
                agent_result = await self.agents["ingestion"].execute(agent_input)
                
                # Update state with ingestion results
                with self._state_lock:
                    # Update raw_alert with normalized version
                    if agent_result.get("ingestion_status") == "success":
                        state["raw_alert"] = agent_result.get("raw_alert", state["raw_alert"])
                        state["triage_status"] = "ingested"
                    elif agent_result.get("ingestion_status") == "duplicate":
                        state["triage_status"] = "duplicate"
                        state["processing_notes"].append("Alert is a duplicate, skipping processing")
                    else:
                        state["triage_status"] = "ingestion_error"
                    
                    # Merge enriched data
                    state["enriched_data"].update(agent_result.get("enriched_data", {}))
                    
                    # Track execution
                    if "agent_executions" not in state:
                        state["agent_executions"] = {}
                    state["agent_executions"][agent_exec_key] = {
                        "executed_at": datetime.utcnow().isoformat(),
                        "status": agent_result.get("ingestion_status", "unknown"),
                        "source": agent_result.get("raw_alert", {}).get("source", "unknown")
                    }
                    
                    state["current_node"] = "ingestion"
                    state["processing_notes"].append(
                        f"Ingestion: status={agent_result.get('ingestion_status')}, "
                        f"source={agent_result.get('raw_alert', {}).get('source', 'unknown')}"
                    )
                
                return state
                
        except Exception as e:
            self.logger.error(f"Ingestion execution failed: {e}")
            state["processing_notes"].append(f"Ingestion error: {str(e)}")
            state["current_node"] = "ingestion"
            state["triage_status"] = "ingestion_error"
            return state

    def _route_after_ingestion(self, state: WorkflowState) -> str:
        return "triage" if state["raw_alert"] else "close"

    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """Execute human loop - placeholder."""
        state["triage_status"] = "escalated"
        state["current_node"] = "human_loop"
        return state

    def _route_after_human_loop(self, state: WorkflowState) -> str:
        """Routing after human loop."""
        confidence = state["confidence_score"]
        if confidence >= 75:
            return "response"
        else:
            return "close"

    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """Execute response - placeholder."""
        state["enriched_data"]["response_actions"] = ["quarantine", "block_ip"]
        state["current_node"] = "response"
        state["triage_status"] = "responded"
        return state

    def _route_after_response(self, state: WorkflowState) -> str:
        """Routing after response."""
        return "learning" if self._should_learn(state) else "close"

    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """Execute learning - placeholder."""
        state["enriched_data"]["learning_completed"] = True
        state["current_node"] = "learning"
        return state

    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """Close the alert."""
        state["current_node"] = "close"
        state["triage_status"] = "closed"
        return state

    def _needs_correlation(self, state: WorkflowState) -> bool:
        """Check if correlation is needed."""
        raw_data = state["raw_alert"].get("raw_data", {})
        return any(field in raw_data for field in 
                  ["source_ip", "destination_ip", "user", "username", "account"])

    def _needs_analysis(self, state: WorkflowState) -> bool:
        """Check if analysis is needed."""
        raw_data = state["raw_alert"].get("raw_data", {})
        return any(field in raw_data for field in 
                  ["file_hash", "process_name", "command_line", "pid"])

    def _should_learn(self, state: WorkflowState) -> bool:
        """Check if learning is beneficial."""
        return (state.get("human_feedback") or 
                any("unusual" in note.lower() for note in state["processing_notes"]))

    async def _persist_final_state(self, workflow_state: WorkflowState):
        """Persist the final workflow state."""
        try:
            # Get existing state (should always exist now)
            existing_state = await self.state_manager.get_state(
                workflow_state["alert_id"], 
                workflow_state["workflow_instance_id"]
            )
            
            if not existing_state:
                self.logger.error(f"No existing state found for {workflow_state['alert_id']} - this should not happen!")
                return
            
            # Prepare updates with all workflow results
            updates = {
                "triage_status": workflow_state["triage_status"],
                "confidence_score": workflow_state["confidence_score"],
                "current_node": workflow_state["current_node"],
                "fp_indicators": workflow_state["fp_indicators"],
                "tp_indicators": workflow_state["tp_indicators"],
                "priority_level": workflow_state["priority_level"],
                "enriched_data": workflow_state["enriched_data"],
                "metadata": {
                    "processing_notes": workflow_state["processing_notes"],
                    "correlations": workflow_state.get("correlations", []),
                    "correlation_score": workflow_state.get("correlation_score", 0),
                    "analysis_conclusion": workflow_state.get("analysis_conclusion", ""),
                    "threat_score": workflow_state.get("threat_score", 0),
                    "recommended_actions": workflow_state.get("recommended_actions", []),
                    "analysis_reasoning": workflow_state.get("analysis_reasoning", []),
                    "tool_results": workflow_state.get("tool_results", {}),
                    "agent_executions": workflow_state.get("agent_executions", {}),
                    "execution_context": workflow_state.get("execution_context", {}),
                    "state_version": workflow_state["state_version"]
                }
            }
            
            # Update the existing state
            await self.state_manager.update_state(
                existing_state,
                updates,
                author_type="system",
                author_id="workflow_engine",
                changes_summary=f"Workflow completed: {workflow_state['current_node']} (confidence: {workflow_state['confidence_score']}%)"
            )
            
            self.logger.info(f"✅ Persisted final state for {workflow_state['alert_id']}: confidence={workflow_state['confidence_score']}%, status={workflow_state['triage_status']}")
                
        except Exception as e:
            self.logger.error(f"Error persisting final state: {e}", exc_info=True)

    def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get  workflow metrics."""
        return {
            "active_executions": len(self._execution_contexts),
            "total_agents": len(self.agents),
            "agent_locks": len(self._agent_locks),
            "synchronization_enabled": True,
            "workflow_type": ""
        }