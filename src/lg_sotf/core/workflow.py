"""
WorkflowEngine for orchestrating multi-agent SOC alert processing.

This module handles workflow execution, agent coordination, and state management.
The graph structure and routing logic are defined in graph.py.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Dict, List, Literal
import json

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.human_loop.base import HumanLoopAgent
from lg_sotf.agents.ingestion.base import IngestionAgent
from lg_sotf.agents.registry import agent_registry
from lg_sotf.agents.response.base import ResponseAgent
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import WorkflowError
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.state.model import SOCState, TriageStatus
from lg_sotf.utils.llm import get_llm_client

# Import graph components
from lg_sotf.core.graph import (
    WorkflowState,
    WorkflowGraphBuilder,
    RoutingDecision
)


@dataclass
class ExecutionContext:
    """Execution context to prevent duplicate executions."""
    execution_id: str
    started_at: datetime
    node_executions: Dict[str, bool]  # Track which nodes have executed
    locks: Dict[str, asyncio.Lock]    # Per-node locks


class WorkflowEngine:
    """Workflow engine with atomic state management."""

    def __init__(self, config_manager: ConfigManager, state_manager: StateManager, redis_storage=None, tool_orchestrator=None):
        self.config = config_manager
        self.state_manager = state_manager
        self.redis_storage = redis_storage
        self.tool_orchestrator = tool_orchestrator
        self.agents = {}
        self.logger = logging.getLogger(__name__)

        # LLM client for intelligent routing
        self.llm_client = None
        self.enable_llm_routing = config_manager.get('workflow.enable_llm_routing', True)
        try:
            if self.enable_llm_routing:
                self.llm_client = get_llm_client(config_manager)
                self.logger.info("LLM client initialized for intelligent routing")
        except Exception as e:
            self.logger.warning(f"LLM routing disabled: {e}")
            self.enable_llm_routing = False

        # Synchronization primitives
        self._state_lock = RLock()  # Protects state updates
        self._execution_contexts = {}  # Track active executions
        self._agent_locks = {}  # Per-agent execution locks

        # Graph builder
        self.graph_builder = WorkflowGraphBuilder(config_manager)
        self.compiled_graph = None

        # Recursion limit for safety (prevents infinite loops)
        self.recursion_limit = config_manager.get('workflow.recursion_limit', 50)

    async def initialize(self):
        """Initialize the workflow engine."""
        try:
            await self._setup_agents()

            # Build node executors map for graph construction
            node_executors = {
                "ingestion": self._execute_ingestion,
                "triage": self._execute_triage,
                "correlation": self._execute_correlation,
                "analysis": self._execute_analysis,
                "human_loop": self._execute_human_loop,
                "response": self._execute_response,
                "learning": self._execute_learning,
                "close": self._execute_close,
            }

            # Build and compile graph using WorkflowGraphBuilder
            graph = self.graph_builder.build_graph(node_executors)
            self.compiled_graph = graph.compile()

            self.logger.info("WorkflowEngine initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize WorkflowEngine: {e}")
            raise WorkflowError(f"Initialization failed: {e}")

    async def _setup_agents(self):
        """Setup all required agents with proper synchronization."""
        agents_config = [
            ("ingestion", IngestionAgent, "ingestion_instance"),
            ("triage", TriageAgent, "triage_instance"),
            ("correlation", CorrelationAgent, "correlation_instance"),
            ("analysis", AnalysisAgent, "analysis_instance"),
            ("human_loop", HumanLoopAgent, "human_loop_instance"),
            ("response", ResponseAgent, "response_instance"),
        ]

        for agent_type, agent_class, instance_name in agents_config:
            # Register agent type if not exists
            if agent_type not in agent_registry.list_agent_types():
                agent_registry.register_agent_type(
                    agent_type, agent_class, self.config.get_agent_config(agent_type)
                )

            # Create instance with special handling for agents needing dependencies
            if instance_name not in agent_registry.list_agent_instances():
                if agent_type == "correlation":
                    # Create correlation agent with dependencies
                    config = self.config.get_agent_config(agent_type)
                    agent_instance = CorrelationAgent(
                        config,
                        state_manager=self.state_manager,
                        redis_storage=self._get_redis_storage(),
                        tool_orchestrator=self._get_tool_orchestrator()
                    )
                    # Register the instance manually
                    agent_registry._agent_instances[instance_name] = agent_instance
                    self.logger.info(f"Created correlation agent with dependencies")
                elif agent_type == "human_loop":
                    # Create human loop agent with dependencies
                    from lg_sotf.audit.logger import AuditLogger
                    config = self.config.get_agent_config(agent_type)
                    audit_logger = AuditLogger()  # AuditLogger takes no arguments
                    agent_instance = HumanLoopAgent(
                        state_manager=self.state_manager,
                        redis_storage=self._get_redis_storage(),
                        audit_logger=audit_logger,
                        config=config
                    )
                    # Register the instance manually
                    agent_registry._agent_instances[instance_name] = agent_instance
                    self.logger.info(f"Created human loop agent with dependencies")
                elif agent_type == "response":
                    # Create response agent with tool orchestrator dependency
                    config = self.config.get_agent_config(agent_type)
                    agent_instance = ResponseAgent(
                        config=config,
                        tool_orchestrator=self._get_tool_orchestrator()
                    )
                    # Register the instance manually
                    agent_registry._agent_instances[instance_name] = agent_instance
                    self.logger.info(f"Created response agent with tool orchestrator")
                else:
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

    def _get_redis_storage(self):
        """Get Redis storage instance from application context."""
        if self.redis_storage:
            return self.redis_storage
        else:
            self.logger.warning("Redis storage not available for correlation agent")
            return None

    def _get_tool_orchestrator(self):
        """Get Tool orchestrator instance."""
        if self.tool_orchestrator:
            return self.tool_orchestrator
        else:
            # Try to create tool orchestrator if not exists
            try:
                from lg_sotf.tools.orchestrator import ToolOrchestrator
                self.tool_orchestrator = ToolOrchestrator(self.config)
                return self.tool_orchestrator
            except Exception as e:
                self.logger.warning(f"Could not create tool orchestrator: {e}")
                return None

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

    # Graph building is now handled by WorkflowGraphBuilder in graph.py

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

    async def _execute_with(self, node_name: str, executor_func, state: WorkflowState) -> Dict[str, Any]:
        """Execute node with full synchronization and duplicate prevention.

        Returns only state updates, following LangGraph best practices.
        """
        alert_id = state["alert_id"]
        execution_context = self._execution_contexts.get(alert_id)

        # ✅ IMPROVEMENT: Return informative updates instead of empty dict
        if not execution_context:
            self.logger.error(f"No execution context for alert {alert_id}")
            return {
                "processing_notes": [f"⚠️ Missing execution context for {node_name}"]
            }

        # Check if this node already executed
        with self._state_lock:
            if execution_context.node_executions.get(node_name, False):
                self.logger.warning(f"Node {node_name} already executed for {alert_id}, skipping")
                return {
                    "processing_notes": [f"⏭️ Skipped {node_name} (already executed)"]
                }

        # Acquire node-specific lock
        async with execution_context.locks[node_name]:
            # Double-check after acquiring lock
            with self._state_lock:
                if execution_context.node_executions.get(node_name, False):
                    self.logger.warning(f"Node {node_name} executed during lock wait for {alert_id}")
                    return {
                        "processing_notes": [f"⏭️ Skipped {node_name} (executed during lock wait)"]
                    }

                # Mark as executing
                execution_context.node_executions[node_name] = True
                current_version = state["state_version"]

                self.logger.info(f"🔒 Executing {node_name} for {alert_id} (version {current_version})")

            try:
                # Execute the actual node logic - returns updates dict
                updates = await executor_func(state)

                # Build final updates (no mutation)
                final_updates = {
                    **updates,
                    "execution_context": {
                        "execution_id": execution_context.execution_id,
                        "started_at": execution_context.started_at.isoformat(),
                        "last_node": node_name,
                        "executed_nodes": list(execution_context.node_executions.keys()),
                        "execution_time": datetime.utcnow().isoformat()
                    },
                    "last_updated": datetime.utcnow().isoformat(),
                    "processing_notes": [f"✅ {node_name} completed (v{current_version + 1})"],
                    "state_version": current_version + 1
                }

                self.logger.info(f"✅ {node_name} completed for {alert_id}")
                return final_updates

            except Exception as e:
                # Return error updates only
                self.logger.error(f"❌ {node_name} failed for {alert_id}: {e}")
                return {
                    "processing_notes": [f"❌ {node_name} failed: {str(e)}"]
                }

    # ===============================
    #  ROUTING METHODS
    # ===============================

    def _route_after_triage(self, state: WorkflowState) -> str:
        """Routing logic after triage."""
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])

        self.logger.info(f"🛤️ Routing after triage: confidence={confidence}%, FP={fp_count}, TP={tp_count}")

        # Close conditions
        if confidence <= 10 and fp_count >= 2:
            return "close"

        if fp_count > tp_count and confidence <= 30:
            return "close"

        # High confidence direct response
        if confidence >= 85 and tp_count >= 3:
            return "response"

        # Correlation needed
        if self._needs_correlation(state):
            return "correlation"

        # Analysis needed
        if confidence < 60 or self._needs_analysis(state):
            return "analysis"

        # Default to human review
        return "human_loop"

    def _route_after_correlation(self, state: WorkflowState) -> str:
        """Routing logic after correlation (following SOC best practices)."""
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        confidence = state["confidence_score"]

        self.logger.info(f"🛤️ Routing after correlation: correlations={len(correlations)}, score={correlation_score}%, confidence={confidence}%")

        # Strong correlations → direct response
        if correlation_score > 85 and len(correlations) >= 5:
            return "response"

        # Moderate-high correlations OR found multiple related alerts → deep analysis
        if correlation_score > 50 or len(correlations) >= 2:
            return "analysis"

        # Low correlations but medium confidence → still analyze (don't give up yet)
        if confidence >= 40:
            return "analysis"

        # Very low confidence and no correlations → close as likely FP
        if confidence < 30 and correlation_score < 20:
            return "close"

        # Edge case: escalate only if truly uncertain after correlation
        if 30 <= confidence <= 60 and correlation_score < 30:
            return "human_loop"

        # Default: analyze (prefer AI investigation over human escalation)
        return "analysis"

    def _route_after_analysis(self, state: WorkflowState) -> str:
        """Routing logic after analysis (following SOC best practices)."""
        threat_score = state.get("threat_score", 0)
        confidence = state["confidence_score"]
        conclusion = state.get("analysis_conclusion", "").lower()
        tp_count = len(state.get("tp_indicators", []))

        self.logger.info(f"🛤️ Routing after analysis: threat_score={threat_score}%, confidence={confidence}%")

        # High threat → automated response
        if threat_score >= 70 or (threat_score >= 50 and confidence >= 80):
            return "response"

        # Medium threat with evidence → response
        if threat_score >= 50 and tp_count >= 3:
            return "response"

        # Analysis found low/no threat → close
        if threat_score < 30 and confidence < 40:
            return "close"

        # Analysis is uncertain OR complex case → escalate to human (this is appropriate AFTER analysis)
        if "uncertain" in conclusion or "needs human" in conclusion:
            return "human_loop"

        # Medium threat, medium confidence → escalate for human judgment (after AI tried)
        if 40 <= threat_score < 70 and 40 <= confidence < 75:
            return "human_loop"

        # Default: close (analysis didn't find significant threat)
        return "close"

    def _route_after_ingestion(self, state: WorkflowState) -> str:
        """Routing logic after ingestion."""
        return "triage" if state["raw_alert"] else "close"

    def _route_after_human_loop(self, state: WorkflowState) -> str:
        """Routing logic after human loop."""
        confidence = state["confidence_score"]
        return "response" if confidence >= 75 else "close"

    def _route_after_response(self, state: WorkflowState) -> str:
        """Routing logic after response."""
        return "learning" if self._should_learn(state) else "close"

    # ===============================
    # IMPROVED AGENT EXECUTION METHODS
    # ===============================

    async def _execute_triage(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute triage with proper state management.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            # Prevent duplicate execution with agent-specific lock
            async with self._agent_locks['triage']:
                agent_exec_key = f"triage_{state['alert_id']}"

                # Check if already executed in this workflow
                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Triage already executed for {state['alert_id']}")
                    return {}

                self.logger.info(f"🎯 Executing triage for {state['alert_id']}")

                # Convert state to agent format (immutable)
                agent_input = self._convert_to_agent_format(state)

                # Execute agent
                agent_result = await self.agents["triage"].execute(agent_input)

                # Build updates dict (no mutation)
                confidence_score = agent_result.get("confidence_score", state["confidence_score"])
                fp_indicators = agent_result.get("fp_indicators", [])
                tp_indicators = agent_result.get("tp_indicators", [])

                updates = {
                    "confidence_score": confidence_score,
                    "fp_indicators": fp_indicators,  # Will append via reducer
                    "tp_indicators": tp_indicators,  # Will append via reducer
                    "priority_level": agent_result.get("priority_level", state["priority_level"]),
                    "triage_status": agent_result.get("triage_status", "triaged"),
                    "enriched_data": {**state["enriched_data"], **agent_result.get("enriched_data", {})},
                    "agent_executions": {
                        **state.get("agent_executions", {}),
                        agent_exec_key: {
                            "executed_at": datetime.utcnow().isoformat(),
                            "confidence_score": confidence_score,
                            "status": "completed"
                        }
                    },
                    "current_node": "triage",
                    "processing_notes": [f"Triage: confidence={confidence_score}%, FP={len(fp_indicators)}, TP={len(tp_indicators)}"]
                }

                return updates

        except Exception as e:
            self.logger.error(f"Triage execution failed: {e}")
            return {
                "processing_notes": [f"Triage error: {str(e)}"],
                "current_node": "triage"
            }

    async def _execute_correlation(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute correlation with proper state management.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            async with self._agent_locks['correlation']:
                agent_exec_key = f"correlation_{state['alert_id']}"

                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Correlation already executed for {state['alert_id']}")
                    return {}

                self.logger.info(f"🔗 Executing correlation for {state['alert_id']}")

                # Convert state to agent format
                agent_input = self._convert_to_agent_format(state)

                # Execute agent
                agent_result = await self.agents["correlation"].execute(agent_input)

                # Build updates dict (no mutation)
                correlations = agent_result.get("correlations", [])
                correlation_score = agent_result.get("correlation_score", 0)

                updates = {
                    "confidence_score": agent_result.get("confidence_score", state["confidence_score"]),
                    "triage_status": agent_result.get("triage_status", "correlated"),
                    "correlations": correlations,  # Will append via reducer
                    "correlation_score": correlation_score,
                    "enriched_data": {**state["enriched_data"], **agent_result.get("enriched_data", {})},
                    "agent_executions": {
                        **state.get("agent_executions", {}),
                        agent_exec_key: {
                            "executed_at": datetime.utcnow().isoformat(),
                            "correlations_found": len(correlations),
                            "correlation_score": correlation_score,
                            "status": "completed"
                        }
                    },
                    "current_node": "correlation",
                    "processing_notes": [f"Correlation: found {len(correlations)} correlations (score: {correlation_score}%)"]
                }

                return updates

        except Exception as e:
            self.logger.error(f"Correlation execution failed: {e}")
            return {
                "processing_notes": [f"Correlation error: {str(e)}"],
                "current_node": "correlation",
                "correlations": [],
                "correlation_score": 0
            }

    async def _execute_analysis(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute analysis with proper state management.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            async with self._agent_locks['analysis']:
                agent_exec_key = f"analysis_{state['alert_id']}"

                if agent_exec_key in state.get("agent_executions", {}):
                    self.logger.warning(f"Analysis already executed for {state['alert_id']}")
                    return {}

                self.logger.info(f"🧠 Executing analysis for {state['alert_id']}")

                # Convert state to agent format
                agent_input = self._convert_to_agent_format(state)

                # Execute agent
                agent_result = await self.agents["analysis"].execute(agent_input)

                # Build updates dict (no mutation)
                threat_score = agent_result.get("threat_score", 0)
                recommended_actions = agent_result.get("recommended_actions", [])
                analysis_reasoning = agent_result.get("analysis_reasoning", [])
                tool_results = agent_result.get("tool_results", {})

                updates = {
                    "confidence_score": agent_result.get("confidence_score", state["confidence_score"]),
                    "triage_status": agent_result.get("triage_status", "analyzed"),
                    "analysis_conclusion": agent_result.get("analysis_conclusion", ""),
                    "threat_score": threat_score,
                    "recommended_actions": recommended_actions,  # Will append via reducer
                    "analysis_reasoning": analysis_reasoning,  # Will append via reducer
                    "tool_results": {**state.get("tool_results", {}), **tool_results},
                    "enriched_data": {**state["enriched_data"], **agent_result.get("enriched_data", {})},
                    "agent_executions": {
                        **state.get("agent_executions", {}),
                        agent_exec_key: {
                            "executed_at": datetime.utcnow().isoformat(),
                            "threat_score": threat_score,
                            "reasoning_steps": len(analysis_reasoning),
                            "tools_used": len(tool_results),
                            "status": "completed"
                        }
                    },
                    "current_node": "analysis",
                    "processing_notes": [f"Analysis: threat_score={threat_score}%, reasoning_steps={len(analysis_reasoning)}"]
                }

                return updates

        except Exception as e:
            self.logger.error(f"Analysis execution failed: {e}")
            return {
                "processing_notes": [f"Analysis error: {str(e)}"],
                "current_node": "analysis",
                "analysis_conclusion": "",
                "threat_score": 0,
                "recommended_actions": [],
                "analysis_reasoning": [],
                "tool_results": {}
            }

    # ===============================
    # HELPER METHODS
    # ===============================

    def _convert_to_agent_format(self, state: WorkflowState) -> Dict[str, Any]:
        """Convert workflow state to agent input format."""
        import copy
        return {
            "alert_id": state["alert_id"],
            "raw_alert": copy.deepcopy(state["raw_alert"]),  # Deep copy to preserve nested dicts like raw_data
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
    # ROUTING METHODS (Async with LLM - LangGraph Best Practices)
    # ===============================

    async def _route_after_triage(
        self,
        state: WorkflowState
    ) -> Literal["correlation", "analysis", "response", "human_loop", "close"]:
        """Intelligent async routing after triage with optional LLM enhancement.

        Following LangGraph best practices:
        - Async function for LLM calls
        - Literal type hints for graph visualization
        - ALWAYS route through correlation for threat intelligence building
        - Fast-track obvious FPs to close
        - All other alerts go through correlation

        IMPORTANT: Correlation MUST run for ALL non-FP alerts to:
        - Populate Redis with threat indicators
        - Build threat intelligence over time
        - Enable "Top Threats" dashboard
        - Support future alert correlation
        """
        confidence = state["confidence_score"]
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])

        self.logger.info(f"🛤️ Routing after triage: confidence={confidence}%, FP={fp_count}, TP={tp_count}")

        # ONLY obvious false positives skip correlation and go directly to close
        if confidence <= 10 and fp_count >= 2:
            self.logger.info("Rule-based routing: close (obvious FP: low confidence + multiple FP indicators)")
            return "close"

        if fp_count > tp_count and fp_count >= 3 and confidence <= 20:
            self.logger.info("Rule-based routing: close (obvious FP: more FP than TP + very low confidence)")
            return "close"

        # ALL other alerts MUST go through correlation first to build threat intelligence
        # Correlation agent will then route to appropriate next step (analysis/response/human_loop)
        self.logger.info(
            "Routing to correlation (builds threat intel + enriches alert with historical context)"
        )
        return "correlation"

    def _route_after_correlation(self, state: WorkflowState) -> str:
        """Routing after correlation."""
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        confidence = state["confidence_score"]

        self.logger.info(f"🛤️ Routing after correlation: correlations={len(correlations)}, score={correlation_score}%, confidence={confidence}%")

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

    def _route_after_analysis(self, state: WorkflowState) -> str:
        """Routing after analysis."""
        threat_score = state.get("threat_score", 0)
        confidence = state["confidence_score"]
        conclusion = state.get("analysis_conclusion", "").lower()

        self.logger.info(f"🛤️ Routing after analysis: threat_score={threat_score}%, confidence={confidence}%")

        # High threat → response
        if threat_score >= 80 or (threat_score >= 60 and confidence >= 80):
            return "response"

        # Uncertain analysis → human review
        if "uncertain" in conclusion or (30 <= confidence <= 70):
            return "human_loop"

        # Low threat → close
        return "close"

    # ===============================
    # ROUTING HELPER METHODS (Fallback Logic)
    # ===============================

    def _needs_correlation(self, state: WorkflowState) -> bool:
        """Determine if alert needs correlation based on indicators.

        Returns True if alert has network or user-related indicators
        that would benefit from historical correlation analysis.
        """
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
        """Determine if alert needs deep analysis.

        Returns True if alert is complex, has ambiguous indicators,
        or requires tool-based investigation.
        """
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

    # ===============================
    # WORKFLOW EXECUTION
    # ===============================

    async def execute_workflow(self, alert_id: str, initial_state: Dict[str, Any], skip_ingestion: bool = False) -> Dict[str, Any]:
        """Execute the workflow.

        Args:
            alert_id: Alert identifier
            initial_state: Initial alert data
            skip_ingestion: If True, skip ingestion node (alert already ingested)
        """
        try:
            # Create execution context
            execution_context = self._create_execution_context(alert_id)
            workflow_instance_id = f"{alert_id}_{execution_context.execution_id}"

            # Determine initial node based on whether ingestion was already done
            initial_node = "triage" if skip_ingestion else "ingestion"

            # ✅ CREATE INITIAL STATE IN DATABASE FIRST
            await self.state_manager.create_state(
                alert_id=alert_id,
                raw_alert=initial_state,
                workflow_instance_id=workflow_instance_id,
                initial_node=initial_node,
                author_type="system",
                author_id="workflow_engine"
            )

            self.logger.info(f"Created initial state in database for {alert_id} (starting at: {initial_node})")

            # Mark ingestion as already executed if skipping
            if skip_ingestion:
                execution_context.node_executions["ingestion"] = True
                agent_executions = {
                    "ingestion_" + alert_id: {
                        "executed_at": datetime.utcnow().isoformat(),
                        "status": "skipped",
                        "note": "Alert already ingested by polling loop"
                    }
                }
                processing_notes = ["🔄 workflow started", "⏭️ Ingestion skipped (already done by polling)"]
                current_node = "triage"
                triage_status = "ingested"
            else:
                agent_executions = {}
                processing_notes = ["🔄 workflow started"]
                current_node = "ingestion"
                triage_status = "new"

            # Create initial workflow state for LangGraph
            workflow_state: WorkflowState = {
                "alert_id": alert_id,
                "workflow_instance_id": workflow_instance_id,
                "execution_context": {
                    "execution_id": execution_context.execution_id,
                    "started_at": execution_context.started_at.isoformat(),
                    "last_node": "start",
                    "executed_nodes": ["ingestion"] if skip_ingestion else [],
                    "execution_time": datetime.utcnow().isoformat()
                },
                "raw_alert": initial_state,
                "enriched_data": {},
                "triage_status": triage_status,
                "confidence_score": 0,
                "current_node": current_node,
                "priority_level": 3,
                "fp_indicators": [],
                "tp_indicators": [],
                "correlations": [],
                "correlation_score": 0,
                "analysis_conclusion": "",
                "threat_score": 0,
                "recommended_actions": [],
                "analysis_reasoning": [],
                "tool_results": {},
                "processing_notes": processing_notes,
                "last_updated": datetime.utcnow().isoformat(),
                "agent_executions": agent_executions,
                "state_version": 1
            }

            # Execute through LangGraph with recursion limit for safety
            # ✅ IMPROVEMENT: Add recursion_limit to prevent infinite loops
            config = {
                "recursion_limit": self.recursion_limit
            }
            self.logger.info(f"🚀 Starting workflow for {alert_id} (recursion_limit={self.recursion_limit})")
            result_state = await self.compiled_graph.ainvoke(workflow_state, config)

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
    async def _execute_ingestion(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute ingestion using the IngestionAgent.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            # Check if ingestion was already done (by polling loop)
            agent_exec_key = f"ingestion_{state['alert_id']}"
            if agent_exec_key in state.get("agent_executions", {}):
                existing_exec = state["agent_executions"][agent_exec_key]
                if existing_exec.get("status") == "skipped":
                    self.logger.info(f"⏭️ Ingestion already done for {state['alert_id']}, skipping workflow ingestion node")
                    return {}  # Return empty updates, proceed to next node

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
                    return {}

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

                # Build updates dict (no mutation)
                ingestion_status = agent_result.get("ingestion_status", "unknown")
                updates = {
                    "enriched_data": {**state["enriched_data"], **agent_result.get("enriched_data", {})},
                    "agent_executions": {
                        **state.get("agent_executions", {}),
                        agent_exec_key: {
                            "executed_at": datetime.utcnow().isoformat(),
                            "status": ingestion_status,
                            "source": agent_result.get("raw_alert", {}).get("source", "unknown")
                        }
                    },
                    "current_node": "ingestion",
                    "processing_notes": [
                        f"Ingestion: status={ingestion_status}, "
                        f"source={agent_result.get('raw_alert', {}).get('source', 'unknown')}"
                    ]
                }

                # Update based on ingestion status
                if ingestion_status == "success":
                    updates["raw_alert"] = agent_result.get("raw_alert", state["raw_alert"])
                    updates["triage_status"] = "ingested"
                elif ingestion_status == "duplicate":
                    updates["triage_status"] = "duplicate"
                    updates["processing_notes"] = ["Alert is a duplicate, skipping processing"]
                else:
                    updates["triage_status"] = "ingestion_error"

                return updates

        except Exception as e:
            self.logger.error(f"Ingestion execution failed: {e}")
            return {
                "processing_notes": [f"Ingestion error: {str(e)}"],
                "current_node": "ingestion",
                "triage_status": "ingestion_error"
            }

    async def _execute_human_loop(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute human loop agent - escalate for analyst review.

        Returns only state updates, following LangGraph best practices.
        """
        human_loop_agent = self.agents.get("human_loop")
        if not human_loop_agent:
            self.logger.warning("Human loop agent not available, skipping escalation")
            return {
                "current_node": "human_loop",
                "triage_status": "escalated"
            }

        try:
            # Execute human loop agent
            agent_result = await human_loop_agent.execute(state)

            self.logger.info(
                f"Alert {state['alert_id']} escalated to {agent_result.get('escalation_level', 'unknown')} "
                f"(Priority: {agent_result.get('escalation_priority', 'unknown')})"
            )

            # Return only updates
            return {
                **agent_result,
                "current_node": "human_loop",
                "triage_status": "escalated"
            }

        except Exception as e:
            self.logger.error(f"Human loop execution failed: {e}", exc_info=True)
            return {
                "processing_notes": [f"Human loop escalation failed: {str(e)}"],
                "current_node": "human_loop",
                "triage_status": "escalated"  # Still escalated even if process failed
            }

    async def _execute_response(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute automated response actions.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            # Prevent duplicate execution with agent-specific lock
            async with self._agent_locks['response']:
                agent_exec_key = f"response_{state['alert_id']}"

                # Check if already executed in this workflow
                if state.get("agent_executions", {}).get(agent_exec_key, {}).get("status") == "completed":
                    self.logger.info(f"Response already executed for {state['alert_id']}")
                    return {}

                # Execute response agent
                agent = self.agents.get("response")
                if not agent:
                    self.logger.warning("Response agent not available")
                    return {
                        "processing_notes": ["Response agent not available"],
                        "current_node": "response",
                        "triage_status": "response_skipped"
                    }

                # Convert state to agent format
                agent_input = self._convert_to_agent_format(state)

                # Execute agent
                agent_result = await agent.execute(agent_input)

                # Return updates with execution tracking
                return {
                    **agent_result,
                    "agent_executions": {
                        **state.get("agent_executions", {}),
                        agent_exec_key: {
                            "executed_at": datetime.utcnow().isoformat(),
                            "status": "completed"
                        }
                    }
                }

        except Exception as e:
            self.logger.error(f"Response execution failed: {e}", exc_info=True)
            return {
                "processing_notes": [f"Response execution failed: {str(e)}"],
                "current_node": "response",
                "triage_status": "escalated"  # Escalate for manual intervention
            }

    async def _execute_learning(self, state: WorkflowState) -> Dict[str, Any]:
        """Execute learning - placeholder.

        Returns only state updates, following LangGraph best practices.
        """
        return {
            "enriched_data": {
                **state["enriched_data"],
                "learning_completed": True
            },
            "current_node": "learning"
        }

    async def _execute_close(self, state: WorkflowState) -> Dict[str, Any]:
        """Close the alert.

        Returns only state updates, following LangGraph best practices.
        """
        # Preserve important statuses - don't overwrite with generic "closed"
        current_status = state.get("triage_status", "unknown")

        # Preserve these statuses (meaningful outcomes):
        # - responded: Response actions were taken
        # - escalated: Alert is waiting for human review or manual intervention
        preserved_statuses = [
            "responded",
            "escalated"
        ]

        if current_status in preserved_statuses:
            final_status = current_status
        else:
            # Only set "closed" for truly closed alerts (FP, low confidence, etc.)
            final_status = "closed"

        return {
            "current_node": "close",
            "triage_status": final_status
        }

    async def _llm_decide_routing(
        self,
        state: WorkflowState,
        after_node: str
    ) -> Literal["correlation", "analysis", "response", "human_loop", "close"]:
        """Use LLM with structured output for intelligent routing decisions.

        Following LangGraph best practices:
        - Uses structured output with Pydantic model
        - Provides rich context to LLM
        - Returns typed Literal for safety
        - Handles errors gracefully
        """
        if not self.enable_llm_routing or not self.llm_client:
            return self._fallback_routing(state, after_node)

        try:
            # Create LLM with structured output (LangGraph best practice)
            router_llm = self.llm_client.with_structured_output(RoutingDecision)

            # Prepare rich context for LLM
            alert_context = {
                "alert_id": state["alert_id"],
                "confidence": state["confidence_score"],
                "fp_indicators": len(state["fp_indicators"]),
                "tp_indicators": len(state["tp_indicators"]),
                "severity": state["raw_alert"].get("severity", "unknown"),
                "category": state["raw_alert"].get("category", "unknown"),
                "title": state["raw_alert"].get("title", "unknown"),
                "has_network_indicators": bool(
                    state["raw_alert"].get("raw_data", {}).get("source_ip") or
                    state["raw_alert"].get("raw_data", {}).get("destination_ip")
                ),
                "has_user_indicators": bool(
                    state["raw_alert"].get("raw_data", {}).get("user") or
                    state["raw_alert"].get("raw_data", {}).get("username")
                ),
                "has_file_indicators": bool(
                    state["raw_alert"].get("raw_data", {}).get("file_hash") or
                    state["raw_alert"].get("raw_data", {}).get("file_name")
                ),
            }

            # Create intelligent routing prompt following SOC best practices
            prompt = f"""You are a SOC routing AI. Analyze this alert after {after_node} and decide the optimal next step.

Alert Context:
{json.dumps(alert_context, indent=2)}

Available Next Steps (follow SOC best practices - minimize human escalation):
- **correlation**: Find related alerts, historical patterns, connections
  → PREFER THIS for: Grey-zone confidence (20-80%), network/user/file indicators, pattern detection needed
  → Goal: Gather context before deep analysis

- **analysis**: Deep investigation with automated tools and AI reasoning
  → Use when: After correlation, suspicious activity needs investigation, complex threats
  → Goal: Let AI investigate thoroughly before bothering analysts

- **response**: Take immediate automated containment/remediation action
  → Use when: CONFIRMED high threat (>85% confidence with 3+ TP indicators)
  → Goal: Fast automated response for clear threats

- **human_loop**: Escalate to security analyst for manual review
  → Use SPARINGLY: Only when correlation + analysis would STILL be uncertain
  → Use when: Critical business impact requiring human judgment, policy violations, compliance issues
  → Goal: Minimize analyst alert fatigue

- **close**: Close alert as false positive or benign
  → Use when: Very low confidence (<15%) with 2+ FP indicators, obvious false positive

IMPORTANT: Following SOC best practices, prefer correlation → analysis → response over human escalation.
Human escalation should be LAST RESORT for cases requiring human judgment after automated processing.

Provide your decision with:
1. next_step: The chosen step
2. confidence: Your confidence in this decision (0-100)
3. reasoning: Brief explanation (1-2 sentences)"""

            # Get structured LLM decision
            decision = await router_llm.ainvoke(prompt)

            # Log for observability
            self.logger.info(
                f"🤖 LLM Routing for {state['alert_id']}: {decision.next_step} "
                f"(LLM confidence: {decision.confidence}%) - {decision.reasoning}"
            )

            return decision.next_step

        except Exception as e:
            self.logger.error(f"LLM routing failed: {e}, using rule-based fallback")
            return self._fallback_routing(state, after_node)

    def _fallback_routing(
        self,
        state: WorkflowState,
        after_node: str
    ) -> Literal["correlation", "analysis", "response", "human_loop", "close"]:
        """Fallback routing logic when LLM is unavailable or fails.

        Returns properly typed Literal for LangGraph compatibility.
        """
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