"""
Analysis Agent implementation with ReAct integration.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from lg_sotf.agents.analysis.react import ReActReasoner
from lg_sotf.agents.analysis.tools import (
    HashAnalysisTool,
    IPAnalysisTool,
    NetworkAnalysisTool,
    ProcessAnalysisTool,
    TemporalAnalysisTool,
)
from lg_sotf.agents.base import BaseAgent
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.tools.orchestrator import ToolOrchestrator
from lg_sotf.utils.llm import get_llm_client


class AnalysisAgent(BaseAgent):
    """Analysis agent implementing ReAct reasoning pattern"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the analysis agent."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Core analysis configuration
        self.max_iterations = self.get_config("max_iterations", 5)
        self.min_confidence_threshold = self.get_config("min_confidence_threshold", 60)
        self.max_confidence_threshold = self.get_config("max_confidence_threshold", 90)
        self.enable_tool_orchestration = self.get_config(
            "enable_tool_orchestration", True
        )
        self.enable_llm_reasoning = self.get_config("enable_llm_reasoning", True)

        # ReAct configuration
        self.react_temperature = self.get_config("react_temperature", 0.3)
        self.max_reasoning_tokens = self.get_config("max_reasoning_tokens", 1000)

        # Tool configuration
        self.parallel_tool_execution = self.get_config("parallel_tool_execution", True)
        self.max_parallel_tools = self.get_config("max_parallel_tools", 3)
        self.tool_timeout = self.get_config("tool_timeout", 30)

        # PRODUCTION HARDENING: Enhanced resilience settings
        self.enable_fallback_analysis = self.get_config(
            "enable_fallback_analysis", True
        )
        self.max_tool_failures = self.get_config("max_tool_failures", 3)
        self.tool_retry_attempts = self.get_config("tool_retry_attempts", 2)
        self.react_resilience_mode = self.get_config("react_resilience_mode", True)

        # Components
        self.llm_client = None
        self.tool_orchestrator = None
        self.react_reasoner = None

        # Analysis state
        self.current_iteration = 0
        self.reasoning_history = []
        self.tool_results = {}
        self.confidence_progression = []
        self.tool_failure_count = 0

    async def initialize(self):
        """Initialize the analysis agent."""
        try:
            self.logger.info("Initializing analysis agent")

            # Initialize LLM client
            if self.enable_llm_reasoning:
                await self._initialize_llm_client()

            # Initialize tool orchestrator with resilience
            if self.enable_tool_orchestration:
                await self._initialize_tool_orchestrator_resilient()

            # Initialize ReAct reasoner with production config
            await self._initialize_react_reasoner()

            # Load analysis models and rules
            await self._load_analysis_rules()

            self.initialized = True
            self.logger.info("Analysis agent initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize analysis agent: {e}")
            # Don't raise, continue with degraded mode
            self.logger.warning(
                "Continuing in degraded mode with limited functionality"
            )
            self.initialized = True
            self.enable_tool_orchestration = False
            self.enable_llm_reasoning = False

    async def _initialize_llm_client(self):
        """Initialize LLM client for ReAct reasoning."""
        try:
            config_manager = ConfigManager()
            self.llm_client = get_llm_client(config_manager)
            self.logger.info("LLM client initialized for ReAct reasoning")
        except Exception as e:
            self.logger.warning(
                f"LLM client initialization failed: {e}, falling back to rule-based analysis"
            )
            self.enable_llm_reasoning = False

    async def _initialize_tool_orchestrator_resilient(self):
        """Initialize tool orchestrator with resilience."""
        try:
            config_manager = ConfigManager()
            self.tool_orchestrator = ToolOrchestrator(config_manager)

            # Register available analysis tools with error handling
            await self._register_analysis_tools_safe()

            self.logger.info("Tool orchestrator initialized with resilience")
        except Exception as e:
            self.logger.warning(f"Tool orchestrator initialization failed: {e}")
            # Create minimal fallback orchestrator
            self.tool_orchestrator = self._create_fallback_orchestrator()
            self.logger.info("Using fallback tool orchestrator")

    async def _initialize_react_reasoner(self):
        """Initialize ReAct reasoner"""
        try:
            # Enhanced ReAct config for production
            react_config = {
                **self.config,
                "max_action_retries": self.tool_retry_attempts,
                "enable_fallback_analysis": self.enable_fallback_analysis,
                "min_iterations_before_stop": 2,
                "confidence_stop_threshold": 95,
            }

            self.react_reasoner = ReActReasoner(react_config)
            await self.react_reasoner.initialize()
            self.logger.info("ReAct reasoner initialized")
        except Exception as e:
            self.logger.warning(f"ReAct reasoner initialization failed: {e}")
            # Continue without ReAct - will use rule-based analysis
            self.react_reasoner = None
            self.enable_llm_reasoning = False

    async def _register_analysis_tools_safe(self):
        """Register analysis tools with error handling."""
        tools_to_register = [
            ("ip_analysis", IPAnalysisTool),
            ("hash_analysis", HashAnalysisTool),
            ("process_analysis", ProcessAnalysisTool),
            ("network_analysis", NetworkAnalysisTool),
            ("temporal_analysis", TemporalAnalysisTool),
        ]

        registered_count = 0
        for tool_name, tool_class in tools_to_register:
            try:
                self.tool_orchestrator.register_tool(tool_name, tool_class, {})
                registered_count += 1
            except Exception as e:
                self.logger.warning(f"Failed to register {tool_name}: {e}")

        self.logger.info(
            f"Successfully registered {registered_count}/{len(tools_to_register)} analysis tools"
        )

    def _create_fallback_orchestrator(self):
        """Create minimal fallback orchestrator."""

        class FallbackOrchestrator:
            def __init__(self):
                self.tools = [
                    "rule_based_analysis",
                    "confidence_assessment",
                    "pattern_matching",
                ]

            def list_tools(self):
                return self.tools

            async def execute_tool(
                self,
                tool_name: str,
                tool_args: Dict[str, Any],
                context: Dict[str, Any] = None,
            ):
                # Simple rule-based fallback analysis
                return {
                    "success": True,
                    "tool": tool_name,
                    "result": "fallback_analysis_completed",
                    "confidence": 50,
                    "fallback": True,
                }

        return FallbackOrchestrator()

    async def _load_analysis_rules(self):
        """Load analysis rules and patterns."""
        self.analysis_rules = {
            "malware_patterns": [
                {
                    "pattern": "process_from_temp",
                    "weight": 0.8,
                    "description": "Process executing from temp directory",
                },
                {
                    "pattern": "unsigned_executable",
                    "weight": 0.6,
                    "description": "Unsigned executable",
                },
                {
                    "pattern": "network_beacon",
                    "weight": 0.9,
                    "description": "Regular network beaconing pattern",
                },
                {
                    "pattern": "privilege_escalation",
                    "weight": 0.85,
                    "description": "Evidence of privilege escalation",
                },
            ],
            "network_patterns": [
                {
                    "pattern": "c2_communication",
                    "weight": 0.9,
                    "description": "Command and control communication",
                },
                {
                    "pattern": "data_exfiltration",
                    "weight": 0.8,
                    "description": "Large data transfer to external IP",
                },
                {
                    "pattern": "port_scanning",
                    "weight": 0.7,
                    "description": "Port scanning activity",
                },
            ],
            "behavioral_patterns": [
                {
                    "pattern": "lateral_movement",
                    "weight": 0.85,
                    "description": "Lateral movement indicators",
                },
                {
                    "pattern": "persistence_mechanism",
                    "weight": 0.8,
                    "description": "Persistence establishment",
                },
                {
                    "pattern": "defense_evasion",
                    "weight": 0.75,
                    "description": "Defense evasion techniques",
                },
            ],
        }

        self.logger.info("Analysis rules loaded")

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis using ReAct reasoning pattern.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            self.logger.info(
                f"Executing analysis for alert {state.get('alert_id', 'unknown')}"
            )

            # Validate input
            if not await self.validate_input(state):
                raise ValueError("Invalid input state for analysis")

            # Initialize analysis state
            self._reset_analysis_state()

            # Extract relevant data
            alert = state.get("raw_alert", {})
            correlations = state.get("correlations", [])
            enriched_data = state.get("enriched_data", {})

            # Perform analysis with multiple fallback strategies
            analysis_result = await self._perform_analysis_with_fallbacks(
                alert, correlations, enriched_data, state
            )

            # Build updates dict (return only changes, not full state)
            updates = {
                "confidence_score": analysis_result["confidence_score"],
                "analysis_conclusion": analysis_result["conclusion"],
                "analysis_reasoning": analysis_result["reasoning_history"],
                "tool_results": analysis_result["tool_results"],
                "threat_score": analysis_result["threat_score"],
                "recommended_actions": analysis_result["recommended_actions"],
                "triage_status": "analyzed",
                "last_updated": datetime.utcnow().isoformat(),
                "enriched_data": {
                    "analysis_metadata": analysis_result["metadata"]
                },
                "metadata": {
                    "analysis_iterations": self.current_iteration,
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "analysis_agent_version": "1.0.0",
                    "analysis_method": analysis_result.get("method", "unknown"),
                    "tool_failures": self.tool_failure_count,
                }
            }

            # Validate output
            if not await self.validate_output({**state, **updates}):
                self.logger.warning("Output validation failed, using fallback result")
                fallback = await self._create_fallback_result(state)
                # Extract only updates from fallback
                return {k: v for k, v in fallback.items() if k not in ["alert_id", "workflow_instance_id", "raw_alert"]}

            self.logger.info(
                f"Analysis completed for alert {state.get('alert_id')} "
                f"after {self.current_iteration} iterations with "
                f"{analysis_result['confidence_score']}% confidence"
            )

            return updates

        except Exception as e:
            self.logger.error(f"Analysis execution failed: {e}")
            # Return graceful fallback instead of error state
            fallback = await self._create_fallback_result(state, error=str(e))
            # Extract only updates from fallback
            return {k: v for k, v in fallback.items() if k not in ["alert_id", "workflow_instance_id", "raw_alert"]}

    async def _perform_analysis_with_fallbacks(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        enriched_data: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Perform analysis with multiple fallback strategies."""

        # Strategy 1: Full ReAct analysis (preferred)
        if self.enable_llm_reasoning and self.react_reasoner and self.tool_orchestrator:
            try:
                result = await self._perform_react_analysis_resilient(
                    alert, correlations, enriched_data, state
                )
                result["method"] = "react_analysis"
                return result
            except Exception as e:
                self.logger.warning(
                    f"ReAct analysis failed: {e}, trying hybrid approach"
                )
                self.tool_failure_count += 1

        # Strategy 2: Hybrid analysis (ReAct reasoning + rule-based tools)
        if self.enable_llm_reasoning and self.react_reasoner:
            try:
                result = await self._perform_hybrid_analysis(
                    alert, correlations, enriched_data, state
                )
                result["method"] = "hybrid_analysis"
                return result
            except Exception as e:
                self.logger.warning(
                    f"Hybrid analysis failed: {e}, falling back to rule-based"
                )
                self.tool_failure_count += 1

        # Strategy 3: Enhanced rule-based analysis (fallback)
        result = await self._perform_enhanced_rule_based_analysis(
            alert, correlations, enriched_data, state
        )
        result["method"] = "enhanced_rule_based"
        return result

    async def _perform_react_analysis_resilient(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        enriched_data: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Perform ReAct analysis with resilience enhancements."""

        # Initial assessment
        initial_confidence = state.get("confidence_score", 50)
        self.confidence_progression.append(
            {
                "iteration": 0,
                "confidence": initial_confidence,
                "reason": "Initial state",
            }
        )

        # Prepare context for ReAct
        context = {
            "alert": alert,
            "correlations": correlations,
            "enriched_data": enriched_data,
            "state": state,
            "confidence_score": initial_confidence,
        }

        # Get available tools with fallback
        available_tools = await self._get_available_tools_resilient()

        # Run ReAct reasoning with resilience
        react_result = await self.react_reasoner.reason_and_act(
            context,
            available_tools,
            execute_action_callback=self._execute_single_action_resilient,
        )

        # Validate and enhance ReAct results
        validated_result = await self._validate_and_enhance_react_result(
            react_result, initial_confidence, context
        )

        return validated_result

    async def _get_available_tools_resilient(self) -> List[str]:
        """Get available tools with fallback."""
        try:
            if self.tool_orchestrator:
                tools = self.tool_orchestrator.list_tools()
                if tools:
                    return tools
        except Exception as e:
            self.logger.warning(f"Failed to retrieve tools from orchestrator: {e}")

        # Fallback to built-in tool list
        return [
            "ip_analysis",
            "hash_analysis",
            "process_analysis",
            "network_analysis",
            "temporal_analysis",
            "rule_based_analysis",
        ]

    async def _execute_single_action_resilient(
        self, action: Dict[str, str], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single analysis action with resilience."""

        tool_name = action.get("tool", "unknown")
        target = action.get("target", "default")
        analysis_type = action.get("type", "general")

        # Prepare tool arguments
        tool_args = {
            "target": target,
            "analysis_type": analysis_type,
            "alert_context": alert,
            "state_context": state,
        }

        # Execute with multiple fallback strategies
        for attempt in range(self.tool_retry_attempts + 1):
            try:
                # Try tool orchestrator first
                if self.tool_orchestrator and hasattr(
                    self.tool_orchestrator, "execute_tool"
                ):
                    result = await asyncio.wait_for(
                        self.tool_orchestrator.execute_tool(
                            tool_name,
                            tool_args,
                            {"analysis_iteration": self.current_iteration},
                        ),
                        timeout=self.tool_timeout,
                    )

                    if result and result.get("success"):
                        return result

                # Fallback to direct tool execution
                result = await self._execute_tool_direct(
                    tool_name, tool_args, alert, state
                )
                if result and result.get("success"):
                    return result

            except asyncio.TimeoutError:
                self.logger.warning(
                    f"Tool {tool_name} timed out (attempt {attempt + 1})"
                )
            except Exception as e:
                self.logger.warning(
                    f"Tool {tool_name} failed (attempt {attempt + 1}): {e}"
                )

            # Short delay before retry
            if attempt < self.tool_retry_attempts:
                await asyncio.sleep(0.5 * (attempt + 1))

        # All attempts failed - return graceful fallback
        self.tool_failure_count += 1
        return await self._create_tool_fallback_result(tool_name, target, analysis_type)

    async def _execute_tool_direct(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        alert: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Direct tool execution fallback."""

        # Map tool names to direct implementations
        tool_map = {
            "ip_analysis": self._analyze_ip_direct,
            "hash_analysis": self._analyze_hash_direct,
            "process_analysis": self._analyze_process_direct,
            "network_analysis": self._analyze_network_direct,
            "temporal_analysis": self._analyze_temporal_direct,
            "rule_based_analysis": self._analyze_rule_based_direct,
        }

        if tool_name in tool_map:
            try:
                return await tool_map[tool_name](tool_args, alert, state)
            except Exception as e:
                self.logger.warning(f"Direct {tool_name} execution failed: {e}")

        return {"success": False, "error": f"Tool {tool_name} not available"}

    async def _create_tool_fallback_result(
        self, tool_name: str, target: str, analysis_type: str
    ) -> Dict[str, Any]:
        """Create fallback result when tool execution fails."""
        return {
            "success": True,
            "tool": tool_name,
            "target": target,
            "analysis_type": analysis_type,
            "fallback": True,
            "confidence": 25,  # Low confidence for fallback
            "result": f"Tool {tool_name} unavailable - using fallback analysis",
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _validate_and_enhance_react_result(
        self,
        react_result: Dict[str, Any],
        initial_confidence: int,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Validate and enhance ReAct results."""

        # Sync iteration count
        self.current_iteration = max(
            self.current_iteration, react_result.get("iterations_completed", 0)
        )

        # Extract and validate reasoning
        self.reasoning_history = react_result.get("thoughts", [])
        self.tool_results = react_result.get("action_results", {})

        # Calculate enhanced confidence
        updated_confidence = await self._calculate_enhanced_confidence(
            initial_confidence, self.tool_results, react_result
        )

        self.confidence_progression.append(
            {
                "iteration": self.current_iteration,
                "confidence": updated_confidence,
                "reason": f"Enhanced calculation from {len(self.tool_results)} tool results",
            }
        )

        # Generate final analysis
        final_result = await self._synthesize_final_analysis_enhanced(
            context["alert"],
            context["correlations"],
            context["enriched_data"],
            context["state"],
        )

        return final_result

    async def _calculate_enhanced_confidence(
        self,
        base_confidence: int,
        tool_results: Dict[str, Dict[str, Any]],
        react_result: Dict[str, Any],
    ) -> int:
        """Enhanced confidence calculation."""

        if not tool_results:
            return base_confidence

        confidence_adjustment = 0
        successful_tools = 0
        failed_tools = 0

        for result in tool_results.values():
            if not isinstance(result, dict):
                continue

            if result.get("success", False):
                successful_tools += 1

                # Positive indicators
                if (
                    result.get("is_malicious", False)
                    or result.get("reputation") == "malicious"
                ):
                    confidence_adjustment += 25
                elif (
                    result.get("is_suspicious", False)
                    or result.get("reputation") == "suspicious"
                ):
                    confidence_adjustment += 15
                elif result.get("reputation") == "clean":
                    confidence_adjustment -= 5  # Slight reduction for clean indicators

                # Tool-specific adjustments
                if "high_confidence" in result.get("result", "").lower():
                    confidence_adjustment += 10

            else:
                failed_tools += 1
                confidence_adjustment -= 2  # Small penalty for failed tools

        # Factor in ReAct performance
        iterations_completed = react_result.get("iterations_completed", 1)
        successful_iterations = react_result.get("successful_iterations", 0)

        if successful_iterations > 0 and iterations_completed > 0:
            success_rate = successful_iterations / iterations_completed
            confidence_adjustment += int(success_rate * 10)

        # Apply bounds and return
        final_confidence = max(0, min(100, base_confidence + confidence_adjustment))

        self.logger.debug(
            f"Enhanced confidence: base={base_confidence}, adjustment=+{confidence_adjustment}, "
            f"final={final_confidence}, successful_tools={successful_tools}, failed_tools={failed_tools}"
        )

        return final_confidence

    async def _perform_hybrid_analysis(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        enriched_data: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Hybrid analysis using ReAct reasoning with rule-based tool execution."""

        # Use ReAct for reasoning but rule-based tools for execution
        context = {
            "alert": alert,
            "correlations": correlations,
            "enriched_data": enriched_data,
            "state": state,
        }

        # Simplified tool list for hybrid mode
        available_tools = [
            "rule_based_analysis",
            "confidence_assessment",
            "pattern_matching",
        ]

        # Run ReAct with rule-based execution
        react_result = await self.react_reasoner.reason_and_act(
            context,
            available_tools,
            execute_action_callback=self._execute_rule_based_action,
        )

        # Enhance with rule-based analysis
        rule_results = await self._perform_enhanced_rule_based_analysis(
            alert, correlations, enriched_data, state
        )

        # Combine results
        return {
            "confidence_score": max(
                rule_results["confidence_score"], 60
            ),  # Boost for hybrid
            "conclusion": rule_results["conclusion"],
            "reasoning_history": react_result.get("thoughts", []),
            "tool_results": react_result.get("action_results", {}),
            "threat_score": rule_results["threat_score"],
            "recommended_actions": rule_results["recommended_actions"],
            "metadata": {
                **rule_results["metadata"],
                "react_iterations": react_result.get("iterations_completed", 0),
                "hybrid_mode": True,
            },
        }

    async def _execute_rule_based_action(
        self, action: Dict[str, str], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute rule-based action for hybrid mode."""

        tool_name = action.get("tool", "rule_based_analysis")

        if tool_name == "rule_based_analysis":
            return await self._analyze_rule_based_direct({}, alert, state)
        elif tool_name == "confidence_assessment":
            return await self._assess_confidence_direct({}, alert, state)
        elif tool_name == "pattern_matching":
            return await self._match_patterns_direct({}, alert, state)

        return {
            "success": True,
            "result": "Rule-based action completed",
            "confidence": 50,
        }

    async def _perform_enhanced_rule_based_analysis(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        enriched_data: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enhanced rule-based analysis as ultimate fallback."""

        initial_confidence = state.get("confidence_score", 50)

        # Perform comprehensive rule-based analysis
        threat_indicators = await self._analyze_threat_indicators_comprehensive(
            alert, correlations
        )
        confidence_score = await self._calculate_rule_based_confidence(
            alert, correlations, threat_indicators
        )
        threat_score = await self._calculate_threat_score_comprehensive(
            confidence_score, correlations, threat_indicators
        )

        # Generate conclusion and actions
        conclusion = await self._generate_rule_based_conclusion(
            confidence_score, threat_score
        )
        recommended_actions = await self._generate_rule_based_actions(
            confidence_score, threat_score, alert
        )

        return {
            "confidence_score": confidence_score,
            "conclusion": conclusion,
            "reasoning_history": [
                {"iteration": 1, "thought": "Rule-based analysis completed"}
            ],
            "tool_results": {
                "rule_analysis": {"success": True, "indicators": threat_indicators}
            },
            "threat_score": threat_score,
            "recommended_actions": recommended_actions,
            "metadata": {
                "analysis_method": "enhanced_rule_based",
                "threat_indicators_count": len(threat_indicators),
                "fallback_mode": True,
                "analysis_timestamp": datetime.utcnow().isoformat(),
            },
        }

    # Direct tool implementation methods (fallbacks)
    async def _analyze_ip_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct IP analysis implementation."""
        raw_data = alert.get("raw_data", {})
        ip = (
            tool_args.get("target")
            or raw_data.get("source_ip")
            or raw_data.get("destination_ip")
        )

        if not ip:
            return {"success": False, "error": "No IP address found"}

        # Simple IP classification
        is_private = any(
            ip.startswith(prefix) for prefix in ["10.", "172.16.", "192.168.", "127."]
        )
        is_suspicious = any(ip.startswith(prefix) for prefix in ["185.220.", "45.133."])

        return {
            "success": True,
            "ip": ip,
            "is_private": is_private,
            "is_suspicious": is_suspicious,
            "reputation": "suspicious"
            if is_suspicious
            else "clean"
            if is_private
            else "unknown",
            "analysis_type": "direct_ip_analysis",
            "confidence": 70 if is_suspicious else 85 if is_private else 50,
        }

    async def _analyze_hash_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct hash analysis implementation."""
        raw_data = alert.get("raw_data", {})
        file_hash = tool_args.get("target") or raw_data.get("file_hash")

        if not file_hash:
            return {"success": False, "error": "No file hash found"}

        # Simple hash reputation check
        known_malicious = ["a1b2c3d4e5f6789", "d41d8cd98f00b204e9800998ecf8427e"]
        is_malicious = file_hash in known_malicious

        return {
            "success": True,
            "hash": file_hash,
            "is_malicious": is_malicious,
            "reputation": "malicious" if is_malicious else "unknown",
            "analysis_type": "direct_hash_analysis",
            "confidence": 90 if is_malicious else 50,
        }

    async def _analyze_process_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct process analysis implementation."""
        raw_data = alert.get("raw_data", {})
        process = tool_args.get("target") or raw_data.get("process_name")

        if not process:
            return {"success": False, "error": "No process name found"}

        suspicious_processes = ["update.exe", "svchost.exe", "powershell.exe"]
        is_suspicious = process.lower() in [p.lower() for p in suspicious_processes]

        return {
            "success": True,
            "process": process,
            "is_suspicious": is_suspicious,
            "analysis_type": "direct_process_analysis",
            "confidence": 75 if is_suspicious else 60,
        }

    async def _analyze_network_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct network analysis implementation."""
        raw_data = alert.get("raw_data", {})

        port = raw_data.get("destination_port")
        suspicious_ports = [4444, 6666, 31337]
        is_suspicious_port = port in suspicious_ports if port else False

        bytes_transferred = raw_data.get("bytes_transferred", 0)
        is_large_transfer = bytes_transferred > 1000000  # > 1MB

        return {
            "success": True,
            "port": port,
            "is_suspicious_port": is_suspicious_port,
            "bytes_transferred": bytes_transferred,
            "is_large_transfer": is_large_transfer,
            "analysis_type": "direct_network_analysis",
            "confidence": 80 if is_suspicious_port else 65,
        }

    async def _analyze_temporal_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct temporal analysis implementation."""
        timestamp = alert.get("timestamp")

        if not timestamp:
            return {"success": False, "error": "No timestamp found"}

        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            is_business_hours = 6 <= hour < 18
            is_weekend = dt.weekday() >= 5

            return {
                "success": True,
                "timestamp": timestamp,
                "hour": hour,
                "is_business_hours": is_business_hours,
                "is_weekend": is_weekend,
                "temporal_risk": "low"
                if is_business_hours and not is_weekend
                else "medium",
                "analysis_type": "direct_temporal_analysis",
                "confidence": 85,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _analyze_rule_based_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct rule-based analysis implementation."""

        indicators = []
        confidence_factors = []

        # Analyze severity
        severity = alert.get("severity", "").lower()
        if severity in ["critical", "high"]:
            indicators.append(f"high_severity_{severity}")
            confidence_factors.append(15)

        # Analyze description for keywords
        description = alert.get("description", "").lower()
        threat_keywords = ["malware", "trojan", "suspicious", "attack", "threat"]
        for keyword in threat_keywords:
            if keyword in description:
                indicators.append(f"threat_keyword_{keyword}")
                confidence_factors.append(10)

        # Calculate confidence
        base_confidence = 50
        confidence_boost = sum(confidence_factors[:5])  # Limit boost
        final_confidence = min(95, base_confidence + confidence_boost)

        return {
            "success": True,
            "indicators": indicators,
            "confidence": final_confidence,
            "analysis_type": "direct_rule_based_analysis",
            "threat_keywords_found": len(
                [i for i in indicators if "threat_keyword" in i]
            ),
            "severity_assessment": severity,
        }

    async def _assess_confidence_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct confidence assessment implementation."""

        current_confidence = state.get("confidence_score", 50)
        correlations = state.get("correlations", [])

        # Assess confidence factors
        factors = []
        if current_confidence > 80:
            factors.append("high_initial_confidence")
        if len(correlations) > 3:
            factors.append("multiple_correlations")

        severity = alert.get("severity", "").lower()
        if severity in ["critical", "high"]:
            factors.append("high_severity")

        assessment_confidence = min(90, current_confidence + len(factors) * 5)

        return {
            "success": True,
            "current_confidence": current_confidence,
            "assessment_confidence": assessment_confidence,
            "confidence_factors": factors,
            "analysis_type": "direct_confidence_assessment",
        }

    async def _match_patterns_direct(
        self, tool_args: Dict[str, Any], alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Direct pattern matching implementation."""

        patterns_found = []
        raw_data = alert.get("raw_data", {})

        # Pattern matching logic
        if raw_data.get("process_name") and raw_data.get("file_path"):
            if "temp" in raw_data.get("file_path", "").lower():
                patterns_found.append("process_from_temp")

        if raw_data.get("destination_port") in [4444, 6666, 31337]:
            patterns_found.append("suspicious_port")

        if raw_data.get("user") in ["administrator", "system"]:
            patterns_found.append("privileged_user")

        return {
            "success": True,
            "patterns_found": patterns_found,
            "pattern_count": len(patterns_found),
            "analysis_type": "direct_pattern_matching",
            "confidence": min(85, 40 + len(patterns_found) * 15),
        }

    async def _analyze_threat_indicators_comprehensive(
        self, alert: Dict[str, Any], correlations: List[Dict[str, Any]]
    ) -> List[str]:
        """Comprehensive threat indicator analysis."""

        indicators = []
        raw_data = alert.get("raw_data", {})

        # File-based indicators
        if raw_data.get("file_hash"):
            indicators.append("file_hash_present")
        if raw_data.get("process_name"):
            indicators.append("process_execution")
        if (
            raw_data.get("file_path")
            and "temp" in raw_data.get("file_path", "").lower()
        ):
            indicators.append("temp_directory_execution")

        # Network indicators
        if raw_data.get("destination_ip"):
            indicators.append("network_communication")
        if raw_data.get("destination_port") in [4444, 6666, 31337, 8080]:
            indicators.append("suspicious_port_usage")

        # User indicators
        if raw_data.get("user") in ["administrator", "system"]:
            indicators.append("privileged_account_usage")

        # Correlation indicators
        if correlations:
            high_confidence_corr = [
                c for c in correlations if c.get("confidence", 0) > 80
            ]
            if high_confidence_corr:
                indicators.append("high_confidence_correlations")

            threat_levels = [c.get("threat_level") for c in correlations]
            if "high" in threat_levels or "critical" in threat_levels:
                indicators.append("high_threat_correlations")

        # Behavioral indicators
        description = alert.get("description", "").lower()
        behavioral_keywords = ["persistence", "lateral", "escalation", "exfiltration"]
        for keyword in behavioral_keywords:
            if keyword in description:
                indicators.append(f"behavioral_{keyword}")

        return indicators

    async def _calculate_rule_based_confidence(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        threat_indicators: List[str],
    ) -> int:
        """Calculate confidence based on rule-based analysis."""

        base_confidence = 50

        # Severity factor
        severity = alert.get("severity", "").lower()
        severity_boost = {
            "critical": 25,
            "high": 20,
            "medium": 10,
            "low": 0,
            "info": -10,
        }.get(severity, 0)

        # Indicator factor
        indicator_boost = min(30, len(threat_indicators) * 3)

        # Correlation factor
        correlation_boost = 0
        if correlations:
            high_conf_corr = [c for c in correlations if c.get("confidence", 0) > 80]
            correlation_boost = min(20, len(high_conf_corr) * 5 + len(correlations) * 2)

        # Source reliability
        source = alert.get("source", "").lower()
        source_penalty = -15 if any(env in source for env in ["test", "dev"]) else 0

        final_confidence = max(
            0,
            min(
                100,
                base_confidence
                + severity_boost
                + indicator_boost
                + correlation_boost
                + source_penalty,
            ),
        )

        self.logger.debug(
            f"Rule-based confidence: base={base_confidence}, severity=+{severity_boost}, "
            f"indicators=+{indicator_boost}, correlations=+{correlation_boost}, "
            f"source={source_penalty}, final={final_confidence}"
        )

        return final_confidence

    async def _calculate_threat_score_comprehensive(
        self,
        confidence: int,
        correlations: List[Dict[str, Any]],
        threat_indicators: List[str],
    ) -> int:
        """Calculate comprehensive threat score."""

        threat_score = confidence

        # Correlation impact
        if correlations:
            critical_correlations = [
                c for c in correlations if c.get("threat_level") == "critical"
            ]
            high_correlations = [
                c for c in correlations if c.get("threat_level") == "high"
            ]

            threat_score += len(critical_correlations) * 10
            threat_score += len(high_correlations) * 5

        # Indicator impact
        critical_indicators = [
            i
            for i in threat_indicators
            if any(
                critical in i
                for critical in [
                    "suspicious_port",
                    "temp_directory",
                    "privileged_account",
                ]
            )
        ]
        threat_score += len(critical_indicators) * 8

        return max(0, min(100, threat_score))

    async def _generate_rule_based_conclusion(
        self, confidence: int, threat_score: int
    ) -> str:
        """Generate rule-based analysis conclusion."""

        if threat_score >= 85:
            return "CRITICAL THREAT: Multiple high-confidence indicators suggest active malicious activity requiring immediate response"
        elif threat_score >= 70:
            return "HIGH THREAT: Strong evidence indicates potential security incident, investigation and response recommended"
        elif threat_score >= 55:
            return "MODERATE THREAT: Suspicious activity detected with multiple indicators, enhanced monitoring advised"
        elif threat_score >= 40:
            return "LOW THREAT: Some concerning indicators present, routine investigation recommended"
        else:
            return "MINIMAL THREAT: Limited indicators suggest benign activity or potential false positive"

    async def _generate_rule_based_actions(
        self, confidence: int, threat_score: int, alert: Dict[str, Any]
    ) -> List[str]:
        """Generate rule-based recommended actions."""

        actions = []

        if threat_score >= 85:
            actions.extend(
                [
                    "Immediate isolation of affected systems",
                    "Escalate to incident response team",
                    "Block suspicious network indicators",
                    "Initiate forensic collection",
                    "Notify CISO/Security leadership",
                ]
            )
        elif threat_score >= 70:
            actions.extend(
                [
                    "Enhanced monitoring of affected systems",
                    "Block suspicious indicators as precaution",
                    "Schedule detailed investigation within 2 hours",
                    "Notify security team lead",
                    "Document findings for pattern analysis",
                ]
            )
        elif threat_score >= 55:
            actions.extend(
                [
                    "Add systems to enhanced monitoring",
                    "Review similar alerts for patterns",
                    "Schedule investigation within 8 hours",
                    "Update threat hunting queries",
                ]
            )
        elif threat_score >= 40:
            actions.extend(
                [
                    "Add to watchlist for monitoring",
                    "Review for false positive patterns",
                    "Document for trend analysis",
                ]
            )
        else:
            actions.extend(
                [
                    "Close as likely false positive",
                    "Update detection rules if needed",
                    "Document for tuning purposes",
                ]
            )

        # Add context-specific actions
        raw_data = alert.get("raw_data", {})
        if raw_data.get("file_hash"):
            actions.append(f"Add hash {raw_data['file_hash']} to threat intelligence")
        if raw_data.get("source_ip") and not any(
            raw_data["source_ip"].startswith(p) for p in ["10.", "172.16.", "192.168."]
        ):
            actions.append(f"Consider blocking IP {raw_data['source_ip']}")

        return actions

    async def _synthesize_final_analysis_enhanced(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        enriched_data: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Synthesize enhanced final analysis results."""

        # Calculate final confidence from progression
        final_confidence = (
            self.confidence_progression[-1]["confidence"]
            if self.confidence_progression
            else 50
        )

        # Calculate enhanced threat score
        threat_score = await self._calculate_threat_score_comprehensive(
            final_confidence, correlations, []
        )

        # Generate enhanced conclusion
        conclusion = await self._generate_enhanced_conclusion(
            final_confidence, threat_score, self.reasoning_history
        )

        # Generate comprehensive recommended actions
        recommended_actions = await self._generate_enhanced_actions(
            final_confidence, threat_score, alert, self.tool_results
        )

        # Build comprehensive metadata
        metadata = {
            "analysis_iterations": self.current_iteration,
            "final_confidence": final_confidence,
            "threat_score": threat_score,
            "tools_attempted": len(self.tool_results),
            "tools_successful": len(
                [r for r in self.tool_results.values() if r.get("success", False)]
            ),
            "tool_failures": self.tool_failure_count,
            "reasoning_steps": len(self.reasoning_history),
            "confidence_progression": self.confidence_progression,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "agent_version": "1.0.0",
        }

        return {
            "confidence_score": final_confidence,
            "threat_score": threat_score,
            "conclusion": conclusion,
            "reasoning_history": self.reasoning_history,
            "tool_results": self.tool_results,
            "recommended_actions": recommended_actions,
            "metadata": metadata,
        }

    async def _generate_enhanced_conclusion(
        self,
        confidence: int,
        threat_score: int,
        reasoning_history: List[Dict[str, Any]],
    ) -> str:
        """Generate enhanced analysis conclusion."""

        base_conclusion = await self._generate_rule_based_conclusion(
            confidence, threat_score
        )

        # Add reasoning context if available
        if reasoning_history:
            reasoning_quality = len(
                [r for r in reasoning_history if len(r.get("thought", "")) > 50]
            )
            if reasoning_quality >= 2:
                base_conclusion += f" (Analysis supported by {reasoning_quality} detailed reasoning steps)"

        return base_conclusion

    async def _generate_enhanced_actions(
        self,
        confidence: int,
        threat_score: int,
        alert: Dict[str, Any],
        tool_results: Dict[str, Dict[str, Any]],
    ) -> List[str]:
        """Generate enhanced recommended actions."""

        actions = await self._generate_rule_based_actions(
            confidence, threat_score, alert
        )

        # Add tool-specific actions
        for tool_result in tool_results.values():
            if not tool_result.get("success", False):
                continue

            if tool_result.get("is_malicious") and "hash" in str(tool_result):
                actions.append("Add identified hash to global blacklist")
            elif tool_result.get("reputation") == "suspicious" and "ip" in str(
                tool_result
            ):
                actions.append("Consider temporary IP blocking pending investigation")

        # Deduplicate actions
        return list(dict.fromkeys(actions))

    async def _create_fallback_result(
        self, state: Dict[str, Any], error: str = None
    ) -> Dict[str, Any]:
        """Create graceful fallback result."""

        fallback_confidence = max(30, state.get("confidence_score", 50) - 20)

        result_state = state.copy()
        result_state.update(
            {
                "confidence_score": fallback_confidence,
                "analysis_conclusion": "Analysis completed with limited capabilities due to system constraints",
                "analysis_reasoning": [
                    {"iteration": 1, "thought": "Fallback analysis mode activated"}
                ],
                "tool_results": {"fallback": {"success": True, "mode": "degraded"}},
                "threat_score": fallback_confidence,
                "recommended_actions": [
                    "Manual review recommended due to analysis limitations"
                ],
                "triage_status": "analyzed",
                "last_updated": datetime.utcnow().isoformat(),
                "metadata": {
                    **state.get("metadata", {}),
                    "analysis_method": "fallback",
                    "analysis_error": error,
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "degraded_mode": True,
                },
            }
        )

        return result_state

    def _reset_analysis_state(self):
        """Reset analysis state for new execution."""
        self.current_iteration = 0
        self.reasoning_history = []
        self.tool_results = {}
        self.confidence_progression = []
        self.tool_failure_count = 0

    # Keep all existing validation and helper methods unchanged
    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state."""
        try:
            required_fields = ["alert_id", "raw_alert", "confidence_score"]
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing required field: {field}")
                    return False

            if not isinstance(state.get("confidence_score"), (int, float)):
                self.logger.error("Invalid confidence_score type")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating input: {e}")
            return False

    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state."""
        try:
            required_fields = [
                "confidence_score",
                "analysis_conclusion",
                "triage_status",
            ]
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing output field: {field}")
                    return False

            confidence = state.get("confidence_score", 0)
            if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 100:
                self.logger.error(f"Invalid confidence score: {confidence}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating output: {e}")
            return False

    async def cleanup(self):
        """Cleanup analysis agent resources."""
        try:
            self.logger.info("Cleaning up analysis agent")

            if self.tool_orchestrator:
                # Tool orchestrator cleanup if needed
                pass

            if self.llm_client:
                self.llm_client = None

            if self.react_reasoner:
                # ReAct reasoner cleanup if needed
                pass

            self.logger.info("Analysis agent cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during analysis agent cleanup: {e}")

    async def health_check(self) -> bool:
        """Enhanced health check for production environment."""
        try:
            if not self.initialized:
                return False

            # Check core components
            health_checks = {
                "llm_client": self.llm_client is not None
                if self.enable_llm_reasoning
                else True,
                "tool_orchestrator": self.tool_orchestrator is not None
                if self.enable_tool_orchestration
                else True,
                "react_reasoner": self.react_reasoner is not None
                if self.enable_llm_reasoning
                else True,
            }

            # Run basic functionality test
            test_state = {
                "alert_id": "health_check",
                "raw_alert": {"id": "test", "severity": "low"},
                "confidence_score": 50,
            }

            if not await self.validate_input(test_state):
                health_checks["input_validation"] = False
            else:
                health_checks["input_validation"] = True

            # Overall health
            overall_health = all(health_checks.values())

            if not overall_health:
                self.logger.warning(
                    f"Health check issues: {[k for k, v in health_checks.items() if not v]}"
                )

            return overall_health

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get enhanced production metrics."""
        base_metrics = super().get_metrics()

        analysis_metrics = {
            "max_iterations": self.max_iterations,
            "min_confidence_threshold": self.min_confidence_threshold,
            "max_confidence_threshold": self.max_confidence_threshold,
            "tool_orchestration_enabled": self.enable_tool_orchestration,
            "llm_reasoning_enabled": self.enable_llm_reasoning,
            "react_resilience_mode": self.react_resilience_mode,
            "current_iteration": self.current_iteration,
            "reasoning_steps_completed": len(self.reasoning_history),
            "tools_executed": len(self.tool_results),
            "tool_failure_count": self.tool_failure_count,
            "confidence_progression_steps": len(self.confidence_progression),
            "production": True,
            "fallback_analysis_enabled": self.enable_fallback_analysis,
        }

        base_metrics.update(analysis_metrics)
        return base_metrics
