"""
 WorkflowEngine with integrated smart routing logic.
Combines the simplicity of workflow-based routing with intelligent decision-making.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, START, StateGraph

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.correlation.base import CorrelationAgent
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
    correlations: List[Dict[str, Any]]
    correlation_score: int
    analysis_conclusion: str
    threat_score: int
    recommended_actions: List[str]


class WorkflowEngine:
    """ workflow engine with integrated smart routing logic."""

    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.agents = {}
        
        # Routing configuration (extracted from edge policies)
        self.routing_config = {
            'max_alert_age_hours': config_manager.get('routing.max_alert_age_hours', 72),
            'correlation_grey_zone_min': config_manager.get('routing.correlation_grey_zone_min', 30),
            'correlation_grey_zone_max': config_manager.get('routing.correlation_grey_zone_max', 70),
            'analysis_threshold': config_manager.get('routing.analysis_threshold', 40),
            'human_review_min': config_manager.get('routing.human_review_min', 20),
            'human_review_max': config_manager.get('routing.human_review_max', 60),
            'response_threshold': config_manager.get('routing.response_threshold', 80),
            'escalation_off_hours': config_manager.get('routing.escalation_off_hours', True),
            'critical_escalation_threshold': config_manager.get('routing.critical_escalation_threshold', 90),
        }
        
        self.graph = self._build_workflow_graph()
        self.compiled_graph = None

    async def initialize(self):
        """Initialize the workflow engine and agents."""
        try:
            await self._setup_agents()
            self.compiled_graph = self.graph.compile()
            
            import logging
            logging.info(" WorkflowEngine initialized with smart routing")

        except Exception as e:
            import logging
            logging.error(f"Failed to initialize  WorkflowEngine: {e}")
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

        # Register and create correlation agent
        if "correlation" not in agent_registry.list_agent_types():
            agent_registry.register_agent_type(
                "correlation", CorrelationAgent, self.config.get_agent_config("correlation")
            )
        
        if "correlation_instance" not in agent_registry.list_agent_instances():
            agent_registry.create_agent(
                "correlation_instance", "correlation", self.config.get_agent_config("correlation")
            )

        # Register and create analysis agent
        if "analysis" not in agent_registry.list_agent_types():
            agent_registry.register_agent_type(
                "analysis", AnalysisAgent, self.config.get_agent_config("analysis")
            )
        
        if "analysis_instance" not in agent_registry.list_agent_instances():
            agent_registry.create_agent(
                "analysis_instance", "analysis", self.config.get_agent_config("analysis")
            )
        
        # Initialize and store agent references
        self.agents['triage'] = agent_registry.get_agent("triage_instance")
        await self.agents['triage'].initialize()
        
        self.agents['correlation'] = agent_registry.get_agent("correlation_instance")
        await self.agents['correlation'].initialize()
        
        self.agents['analysis'] = agent_registry.get_agent("analysis_instance")
        await self.agents['analysis'].initialize()

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

        #  conditional edges with smart routing
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
    # SMART ROUTING METHODS
    # ===============================

    def _route_after_ingestion(self, state: WorkflowState) -> str:
        """Smart routing after ingestion."""
        # Basic validation
        if not state["raw_alert"]:
            state["processing_notes"].append("Ingestion failed: empty alert - closing")
            return "close"
        
        # Check for obviously malformed alerts
        raw_alert = state["raw_alert"]
        if not raw_alert.get("id") and not raw_alert.get("timestamp"):
            state["processing_notes"].append("Ingestion failed: malformed alert - closing")
            return "close"
        
        return "triage"

    def _route_after_triage(self, state: WorkflowState) -> str:
        """ routing after triage with intelligent decision-making."""
        
        # 1. Smart close detection (from conditions.py logic)
        if self._should_close_alert(state):
            return "close"
        
        # 2. Critical escalation (time + severity + indicators)
        if self._needs_immediate_escalation(state):
            state["processing_notes"].append("Critical escalation triggered - routing to human review")
            return "human_loop"
        
        # 3. High-confidence direct response
        if self._should_direct_response(state):
            state["processing_notes"].append("High confidence threat - routing directly to response")
            return "response"
        
        # 4. Smart correlation detection
        if self._needs_correlation(state):
            state["processing_notes"].append("Correlation needed - routing to correlation analysis")
            return "correlation"
        
        # 5. Smart analysis detection
        if self._needs_analysis(state):
            state["processing_notes"].append("Deep analysis needed - routing to analysis")
            return "analysis"
        
        # 6. Default to human review for uncertain cases
        state["processing_notes"].append("Uncertain case - routing to human review")
        return "human_loop"

    def _route_after_correlation(self, state: WorkflowState) -> str:
        """ routing after correlation."""
        
        # 1. Check if we should close after correlation
        if self._should_close_alert(state):
            return "close"
        
        # 2. High-confidence correlations → direct response
        correlations = state.get("correlations", [])
        correlation_score = state.get("correlation_score", 0)
        
        if correlation_score > 85 and len(correlations) >= 5:
            high_conf_correlations = [c for c in correlations if c.get("confidence", 0) > 80]
            if len(high_conf_correlations) >= 3:
                state["processing_notes"].append("Strong correlations found - routing to response")
                return "response"
        
        # 3. Medium correlations → analysis
        if correlation_score > 60 or len(correlations) >= 3:
            state["processing_notes"].append("Moderate correlations - routing to analysis")
            return "analysis"
        
        # 4. Weak correlations but still needs human review
        if correlation_score > 20 or len(correlations) >= 1:
            state["processing_notes"].append("Weak correlations - routing to human review")
            return "human_loop"
        
        # 5. No meaningful correlations
        state["processing_notes"].append("No significant correlations - closing alert")
        return "close"

    def _route_after_analysis(self, state: WorkflowState) -> str:
        """ routing after analysis."""
        
        # 1. Check if we should close after analysis
        if self._should_close_alert(state):
            return "close"
        
        # 2. High threat score → response
        threat_score = state.get("threat_score", 0)
        confidence = state.get("confidence_score", 0)
        
        if threat_score >= 80 or (threat_score >= 60 and confidence >= 80):
            state["processing_notes"].append(f"High threat detected (score: {threat_score}) - routing to response")
            return "response"
        
        # 3. Uncertain analysis → human review
        analysis_conclusion = state.get("analysis_conclusion", "")
        if "uncertain" in analysis_conclusion.lower() or (30 <= confidence <= 70):
            state["processing_notes"].append("Analysis inconclusive - routing to human review")
            return "human_loop"
        
        # 4. Low threat → close
        if threat_score <= 30 or confidence <= 25:
            state["processing_notes"].append(f"Low threat (score: {threat_score}) - closing")
            return "close"
        
        # 5. Default to human review
        return "human_loop"

    def _route_after_human_loop(self, state: WorkflowState) -> str:
        """Routing after human review."""
        # For now, simple logic - in real implementation would check human feedback
        confidence = state.get("confidence_score", 0)
        
        if confidence >= 75:
            return "response"
        else:
            return "close"

    def _route_after_response(self, state: WorkflowState) -> str:
        """Routing after response actions."""
        # Check if learning is enabled and beneficial
        if self._should_learn(state):
            return "learning"
        else:
            return "close"

    # ===============================
    # SMART DECISION-MAKING METHODS
    # ===============================

    def _should_close_alert(self, state: WorkflowState) -> bool:
        """Smart alert closure detection."""
        
        # 1. Already closed
        if state["triage_status"] == "closed":
            state["processing_notes"].append("Alert already closed")
            return True
        
        # 2. Very low confidence with strong FP indicators
        confidence = state["confidence_score"]
        fp_indicators = state["fp_indicators"]
        tp_indicators = state["tp_indicators"]
        
        if confidence <= 10 and len(fp_indicators) >= 2:
            state["processing_notes"].append(f"Low confidence ({confidence}%) with {len(fp_indicators)} FP indicators")
            return True
        
        # 3. More FP than TP indicators with low confidence
        if len(fp_indicators) > len(tp_indicators) and confidence <= 30:
            state["processing_notes"].append(f"More FP ({len(fp_indicators)}) than TP ({len(tp_indicators)}) indicators")
            return True
        
        # 4. Alert age check
        alert_age_hours = self._calculate_alert_age(state)
        max_age = self.routing_config['max_alert_age_hours']
        
        if alert_age_hours > max_age:
            state["processing_notes"].append(f"Alert too old ({alert_age_hours:.1f}h > {max_age}h)")
            return True
        
        # 5. Test environment alerts with low severity
        raw_alert = state["raw_alert"]
        source = raw_alert.get("source", "").lower()
        severity = raw_alert.get("severity", "").lower()
        
        if any(env in source for env in ["test", "dev", "staging"]) and severity in ["low", "info"]:
            state["processing_notes"].append("Test environment + low severity")
            return True
        
        return False

    def _needs_immediate_escalation(self, state: WorkflowState) -> bool:
        """Check if alert needs immediate escalation."""
        
        # 1. Critical severity alerts
        raw_alert = state["raw_alert"]
        severity = raw_alert.get("severity", "").lower()
        
        if severity == "critical":
            state["processing_notes"].append("Critical severity detected")
            return True
        
        # 2. High confidence + critical indicators
        confidence = state["confidence_score"]
        if confidence >= self.routing_config['critical_escalation_threshold']:
            critical_indicators = self._has_critical_indicators(state)
            if critical_indicators:
                state["processing_notes"].append(f"High confidence ({confidence}%) + critical indicators")
                return True
        
        # 3. Off-hours + high severity + privileged user
        if self.routing_config['escalation_off_hours']:
            is_off_hours = self._is_off_hours(raw_alert.get("timestamp", ""))
            is_privileged = self._has_privileged_user(raw_alert)
            
            if is_off_hours and severity == "high" and is_privileged:
                state["processing_notes"].append("Off-hours + high severity + privileged user")
                return True
        
        # 4. Multiple high-confidence TP indicators
        tp_indicators = state["tp_indicators"]
        high_value_indicators = ["malware", "trojan", "backdoor", "exploit", "breach", "c2_communication"]
        
        critical_tp_count = sum(1 for indicator in tp_indicators 
                               if any(keyword in indicator.lower() for keyword in high_value_indicators))
        
        if critical_tp_count >= 2:
            state["processing_notes"].append(f"Multiple critical TP indicators ({critical_tp_count})")
            return True
        
        return False

    def _should_direct_response(self, state: WorkflowState) -> bool:
        """Check if alert should go directly to response (skip human review)."""
        
        confidence = state["confidence_score"]
        
        # 1. Very high confidence
        if confidence >= 95:
            return True
        
        # 2. Known malware hash + high confidence
        raw_alert = state["raw_alert"]
        raw_data = raw_alert.get("raw_data", {})
        
        if raw_data.get("file_hash") and confidence >= 85:
            tp_indicators = state["tp_indicators"]
            if any("malware" in indicator.lower() or "hash" in indicator.lower() for indicator in tp_indicators):
                return True
        
        # 3. Known C2 communication patterns
        if confidence >= 80:
            if any("c2" in indicator.lower() or "command_control" in indicator.lower() 
                   for indicator in state["tp_indicators"]):
                return True
        
        return False

    def _needs_correlation(self, state: WorkflowState) -> bool:
        """Smart correlation detection."""
        
        confidence = state["confidence_score"]
        
        # 1. Already correlated
        if state["triage_status"] in ["correlated", "analyzed", "escalated"]:
            return False
        
        # 2. Confidence in grey zone
        grey_min = self.routing_config['correlation_grey_zone_min']
        grey_max = self.routing_config['correlation_grey_zone_max']
        
        if grey_min <= confidence <= grey_max:
            return True
        
        # 3. Network indicators present
        if self._has_network_indicators(state["raw_alert"]):
            return True
        
        # 4. User-related indicators
        if self._has_user_indicators(state["raw_alert"]):
            return True
        
        # 5. Multiple indicators of different types (might be campaign)
        tp_indicators = state["tp_indicators"]
        indicator_types = set()
        for indicator in tp_indicators:
            if any(net in indicator.lower() for net in ["ip", "network", "connection"]):
                indicator_types.add("network")
            elif any(file_kw in indicator.lower() for file_kw in ["file", "hash", "executable"]):
                indicator_types.add("file")
            elif any(user_kw in indicator.lower() for user_kw in ["user", "account", "login"]):
                indicator_types.add("user")
        
        if len(indicator_types) >= 2:
            return True
        
        return False

    def _needs_analysis(self, state: WorkflowState) -> bool:
        """Smart analysis detection."""
        
        confidence = state["confidence_score"]
        
        # 1. Already analyzed
        if state["triage_status"] in ["analyzed", "escalated"]:
            return False
        
        # 2. Low confidence
        analysis_threshold = self.routing_config['analysis_threshold']
        if confidence < analysis_threshold:
            return True
        
        # 3. File-related indicators
        if self._has_file_indicators(state["raw_alert"]):
            return True
        
        # 4. Process-related indicators
        if self._has_process_indicators(state["raw_alert"]):
            return True
        
        # 5. Conflicting indicators (both FP and TP)
        fp_count = len(state["fp_indicators"])
        tp_count = len(state["tp_indicators"])
        
        if fp_count > 0 and tp_count > 0 and abs(fp_count - tp_count) <= 1:
            return True  # Need deeper analysis to resolve conflict
        
        return False

    def _should_learn(self, state: WorkflowState) -> bool:
        """Check if learning phase would be beneficial."""
        
        # 1. Human feedback present
        if state.get("human_feedback"):
            return True
        
        # 2. Unusual patterns detected
        if any("unusual" in note.lower() for note in state["processing_notes"]):
            return True
        
        # 3. Low confidence with mixed indicators (learning opportunity)
        confidence = state["confidence_score"]
        if confidence < 60 and len(state["fp_indicators"]) > 0 and len(state["tp_indicators"]) > 0:
            return True
        
        return False

    # ===============================
    # HELPER METHODS
    # ===============================

    def _calculate_alert_age(self, state: WorkflowState) -> float:
        """Calculate alert age in hours."""
        try:
            raw_alert = state["raw_alert"]
            timestamp_str = raw_alert.get("timestamp", "")
            
            if not timestamp_str:
                return 0.0
            
            # Parse timestamp
            alert_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            now = datetime.utcnow()
            
            age_seconds = (now - alert_time).total_seconds()
            return age_seconds / 3600  # Convert to hours
            
        except Exception:
            return 0.0

    def _is_off_hours(self, timestamp_str: str) -> bool:
        """Check if timestamp is during off-hours."""
        try:
            if not timestamp_str:
                return False
            
            alert_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            hour = alert_time.hour
            
            # Off-hours: before 6 AM or after 6 PM
            return hour < 6 or hour >= 18
            
        except Exception:
            return False

    def _has_network_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has network-related indicators."""
        raw_data = raw_alert.get("raw_data", {})
        
        network_fields = ["source_ip", "destination_ip", "destination_port", "network", "connection", "dns"]
        return any(field in raw_data for field in network_fields)

    def _has_user_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has user-related indicators."""
        raw_data = raw_alert.get("raw_data", {})
        
        user_fields = ["user", "username", "account", "login", "authentication"]
        return any(field in raw_data for field in user_fields)

    def _has_file_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has file-related indicators."""
        raw_data = raw_alert.get("raw_data", {})
        
        file_fields = ["file_hash", "file_path", "file_name", "executable", "binary"]
        return any(field in raw_data for field in file_fields)

    def _has_process_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has process-related indicators."""
        raw_data = raw_alert.get("raw_data", {})
        
        process_fields = ["process_name", "pid", "parent_process", "command_line"]
        return any(field in raw_data for field in process_fields)

    def _has_privileged_user(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert involves privileged user."""
        raw_data = raw_alert.get("raw_data", {})
        user = raw_data.get("user", "").lower()
        
        privileged_users = ["administrator", "admin", "root", "system"]
        return user in privileged_users

    def _has_critical_indicators(self, state: WorkflowState) -> bool:
        """Check if alert has critical threat indicators."""
        
        # 1. Check priority level
        if state["priority_level"] <= 1:  # Critical priority
            return True
        
        # 2. Check TP indicators for critical keywords
        tp_indicators = state["tp_indicators"]
        critical_keywords = ["malware", "trojan", "backdoor", "exploit", "breach", "ransomware", "apt"]
        
        return any(
            any(keyword in indicator.lower() for keyword in critical_keywords)
            for indicator in tp_indicators
        )

    # ===============================
    # NODE EXECUTION METHODS (Unchanged)
    # ===============================

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
            if "triage" not in self.agents:
                raise ValueError("Triage agent not available")

            # Convert state to agent format
            agent_input = {
                "alert_id": state["alert_id"],
                "raw_alert": state["raw_alert"],
                "triage_status": state["triage_status"],
                "confidence_score": state["confidence_score"],
                "fp_indicators": state["fp_indicators"],
                "tp_indicators": state["tp_indicators"],
                "priority_level": state["priority_level"],
                "enriched_data": state["enriched_data"],
                "metadata": {"processing_notes": state["processing_notes"]},
            }

            # Execute agent
            agent_result = await self.agents["triage"].execute(agent_input)

            # Update state with agent results
            state["confidence_score"] = agent_result.get(
                "confidence_score", state["confidence_score"]
            )
            state["fp_indicators"] = agent_result.get(
                "fp_indicators", state["fp_indicators"]
            )
            state["tp_indicators"] = agent_result.get(
                "tp_indicators", state["tp_indicators"]
            )
            state["priority_level"] = agent_result.get(
                "priority_level", state["priority_level"]
            )
            state["triage_status"] = agent_result.get("triage_status", "triaged")
            state["enriched_data"].update(agent_result.get("enriched_data", {}))

            # Add agent processing notes
            agent_notes = agent_result.get("metadata", {}).get("processing_notes", [])
            state["processing_notes"].extend(agent_notes)

            state["current_node"] = "triage"
            state["last_updated"] = datetime.utcnow().isoformat()

            return state

        except Exception as e:
            state["processing_notes"].append(f"Triage error: {str(e)}")
            state["current_node"] = "triage"
            state["last_updated"] = datetime.utcnow().isoformat()
            return state

    async def _execute_correlation(self, state: WorkflowState) -> WorkflowState:
        """Execute correlation using the correlation agent."""
        try:
            if "correlation" not in self.agents:
                # Fallback to placeholder if agent not available
                state["enriched_data"]["correlation_score"] = 0.5
                state["current_node"] = "correlation"
                state["triage_status"] = "correlated"
                state["last_updated"] = datetime.utcnow().isoformat()
                state["processing_notes"].append(
                    "Correlation completed (placeholder - agent not available)"
                )
                if "correlations" not in state:
                    state["correlations"] = []
                if "correlation_score" not in state:
                    state["correlation_score"] = 0
                return state

            # Convert state to agent format
            agent_input = {
                "alert_id": state["alert_id"],
                "raw_alert": state["raw_alert"],
                "triage_status": state["triage_status"],
                "confidence_score": state["confidence_score"],
                "fp_indicators": state["fp_indicators"],
                "tp_indicators": state["tp_indicators"],
                "priority_level": state["priority_level"],
                "enriched_data": state["enriched_data"],
                "metadata": {"processing_notes": state["processing_notes"]},
            }

            # Execute correlation agent
            agent_result = await self.agents["correlation"].execute(agent_input)

            # Update state with correlation results
            state["confidence_score"] = agent_result.get(
                "confidence_score", state["confidence_score"]
            )
            state["triage_status"] = agent_result.get("triage_status", "correlated")
            state["enriched_data"].update(agent_result.get("enriched_data", {}))

            # Properly transfer correlation data
            state["correlations"] = agent_result.get("correlations", [])
            state["correlation_score"] = agent_result.get("correlation_score", 0)

            # Add agent processing notes
            agent_notes = agent_result.get("metadata", {}).get("processing_notes", [])
            state["processing_notes"].extend(agent_notes)

            state["current_node"] = "correlation"
            state["last_updated"] = datetime.utcnow().isoformat()

            # Add summary note with correlation details
            correlation_count = len(state["correlations"])
            correlation_score = state["correlation_score"]
            state["processing_notes"].append(
                f"Correlation completed - found {correlation_count} correlations (score: {correlation_score}%)"
            )

            return state

        except Exception as e:
            state["processing_notes"].append(f"Correlation error: {str(e)}")
            state["current_node"] = "correlation"
            state["triage_status"] = "correlation_failed"
            state["last_updated"] = datetime.utcnow().isoformat()
            # Ensure correlations fields exist even on error
            if "correlations" not in state:
                state["correlations"] = []
            if "correlation_score" not in state:
                state["correlation_score"] = 0
            return state

    async def _execute_analysis(self, state: WorkflowState) -> WorkflowState:
        """Execute analysis using the analysis agent."""
        try:
            if 'analysis' not in self.agents:
                # Fallback to placeholder if agent not available
                state['confidence_score'] = min(100, state['confidence_score'] + 10)
                state['current_node'] = "analysis"
                state['triage_status'] = "analyzed"
                state['last_updated'] = datetime.utcnow().isoformat()
                state['processing_notes'].append("Analysis completed (placeholder - agent not available)")
                return state
            
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
                'correlations': state.get('correlations', []),
                'correlation_score': state.get('correlation_score', 0),
                'metadata': {'processing_notes': state['processing_notes']}
            }
            
            # Execute analysis agent
            agent_result = await self.agents['analysis'].execute(agent_input)
            
            # Update state with analysis results
            state['confidence_score'] = agent_result.get('confidence_score', state['confidence_score'])
            state['triage_status'] = agent_result.get('triage_status', 'analyzed')
            state['enriched_data'].update(agent_result.get('enriched_data', {}))
            
            # Add analysis-specific data
            state['analysis_conclusion'] = agent_result.get('analysis_conclusion', '')
            state['threat_score'] = agent_result.get('threat_score', 0)
            state['recommended_actions'] = agent_result.get('recommended_actions', [])
            
            # Add agent processing notes
            agent_notes = agent_result.get('metadata', {}).get('processing_notes', [])
            state['processing_notes'].extend(agent_notes)
            
            state['current_node'] = "analysis"
            state['last_updated'] = datetime.utcnow().isoformat()
            
            # Add summary note
            analysis_iterations = agent_result.get('metadata', {}).get('analysis_iterations', 0)
            final_confidence = state['confidence_score']
            state['processing_notes'].append(
                f"Analysis completed - {analysis_iterations} reasoning iterations, final confidence: {final_confidence}%"
            )
            
            return state
            
        except Exception as e:
            state['processing_notes'].append(f"Analysis error: {str(e)}")
            state['current_node'] = "analysis"
            state['triage_status'] = "analysis_failed"
            state['last_updated'] = datetime.utcnow().isoformat()
            return state

    async def _execute_human_loop(self, state: WorkflowState) -> WorkflowState:
        """Execute human loop - placeholder."""
        state["enriched_data"]["human_review_requested"] = True
        state["current_node"] = "human_loop"
        state["triage_status"] = "escalated"
        state["last_updated"] = datetime.utcnow().isoformat()
        state["processing_notes"].append("Escalated for human review (placeholder)")
        return state

    async def _execute_response(self, state: WorkflowState) -> WorkflowState:
        """Execute response - placeholder."""
        state["enriched_data"]["response_actions"] = ["quarantine", "block_ip"]
        state["current_node"] = "response"
        state["triage_status"] = "responded"
        state["last_updated"] = datetime.utcnow().isoformat()
        state["processing_notes"].append("Response actions executed (placeholder)")
        return state

    async def _execute_learning(self, state: WorkflowState) -> WorkflowState:
        """Execute learning - placeholder."""
        state["enriched_data"]["learning_completed"] = True
        state["current_node"] = "learning"
        state["last_updated"] = datetime.utcnow().isoformat()
        state["processing_notes"].append("Learning completed (placeholder)")
        return state

    async def _execute_close(self, state: WorkflowState) -> WorkflowState:
        """Close the alert."""
        state["current_node"] = "close"
        state["triage_status"] = "closed"
        state["last_updated"] = datetime.utcnow().isoformat()
        state["processing_notes"].append("Alert closed")
        return state

    # ===============================
    # WORKFLOW EXECUTION (Unchanged)
    # ===============================

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
                processing_notes=["Smart workflow execution started"],
                correlations=[],
                correlation_score=0,
                analysis_conclusion="",
                threat_score=0,
                recommended_actions=[]
            )

            # Execute through LangGraph
            result_state = await self.compiled_graph.ainvoke(workflow_state)

            # Persist final state
            await self._persist_final_state(result_state)

            return result_state

        except Exception as e:
            import traceback
            print(f" workflow error: {traceback.format_exc()}")
            raise WorkflowError(f" workflow execution failed: {str(e)}")

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
                metadata={
                    "processing_notes": workflow_state["processing_notes"],
                    "correlations": workflow_state.get("correlations", []),
                    "correlation_score": workflow_state.get("correlation_score", 0),
                    "analysis_conclusion": workflow_state.get("analysis_conclusion", ""),
                    "threat_score": workflow_state.get("threat_score", 0),
                    "recommended_actions": workflow_state.get("recommended_actions", []),
                    "routing_system": "integrated_smart_routing"
                },
            )

            try:
                existing_state = await self.state_manager.get_state(
                    workflow_state["alert_id"], workflow_state["workflow_instance_id"]
                )

                if existing_state:
                    await self.state_manager.update_state(
                        existing_state,
                        soc_state.dict(exclude={"alert_id", "workflow_instance_id"}),
                        author_type="system",
                        author_id="_workflow_engine",
                        changes_summary=" workflow execution completed",
                    )
                else:
                    await self.state_manager.create_state(
                        alert_id=workflow_state["alert_id"],
                        raw_alert=workflow_state["raw_alert"],
                        workflow_instance_id=workflow_state["workflow_instance_id"],
                        initial_node="ingestion",
                        author_type="system",
                        author_id="_workflow_engine",
                    )
            except Exception as persist_error:
                import logging
                logging.warning(f"Failed to persist state: {persist_error}")

        except Exception as e:
            import logging
            logging.error(f"Error persisting final state: {e}")

    def _generate_workflow_id(self) -> str:
        """Generate unique workflow instance ID."""
        import uuid
        return str(uuid.uuid4())[:8]