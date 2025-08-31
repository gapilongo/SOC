"""
Production-grade Analysis Agent implementation with ReAct reasoning and tool orchestration.
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
    """Production-grade analysis agent implementing ReAct reasoning pattern."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the analysis agent."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Core analysis configuration
        self.max_iterations = self.get_config("max_iterations", 5)
        self.min_confidence_threshold = self.get_config("min_confidence_threshold", 60)
        self.max_confidence_threshold = self.get_config("max_confidence_threshold", 90)
        self.enable_tool_orchestration = self.get_config("enable_tool_orchestration", True)
        self.enable_llm_reasoning = self.get_config("enable_llm_reasoning", True)

        # ReAct configuration
        self.react_temperature = self.get_config("react_temperature", 0.3)
        self.max_reasoning_tokens = self.get_config("max_reasoning_tokens", 1000)
        
        # Tool configuration
        self.parallel_tool_execution = self.get_config("parallel_tool_execution", True)
        self.max_parallel_tools = self.get_config("max_parallel_tools", 3)
        self.tool_timeout = self.get_config("tool_timeout", 30)

        # Components
        self.llm_client = None
        self.tool_orchestrator = None
        self.react_reasoner = ReActReasoner(config)
        
        # Analysis state
        self.current_iteration = 0
        self.reasoning_history = []
        self.tool_results = {}
        self.confidence_progression = []

    async def initialize(self):
        """Initialize the analysis agent."""
        try:
            self.logger.info("Initializing analysis agent")

            # Initialize LLM client
            if self.enable_llm_reasoning:
                await self._initialize_llm_client()

            # Initialize tool orchestrator
            if self.enable_tool_orchestration:
                await self._initialize_tool_orchestrator()
                
            # Initialize ReAct reasoner
            await self.react_reasoner.initialize()

            # Load analysis models and rules
            await self._load_analysis_rules()

            self.initialized = True
            self.logger.info("Analysis agent initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize analysis agent: {e}")
            raise

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

    async def _initialize_tool_orchestrator(self):
        """Initialize tool orchestrator."""
        try:
            
            config_manager = ConfigManager()
            self.tool_orchestrator = ToolOrchestrator(config_manager)
            
            # Register available analysis tools
            await self._register_analysis_tools()
            
            self.logger.info("Tool orchestrator initialized")
        except Exception as e:
            self.logger.warning(f"Tool orchestrator initialization failed: {e}")
            self.enable_tool_orchestration = False

    async def _register_analysis_tools(self):
        """Register analysis tools with the orchestrator."""
        # Register basic analysis tools that we can implement without external dependencies
        
        self.tool_orchestrator.register_tool("ip_analysis", IPAnalysisTool, {})
        self.tool_orchestrator.register_tool("hash_analysis", HashAnalysisTool, {})
        self.tool_orchestrator.register_tool("process_analysis", ProcessAnalysisTool, {})
        self.tool_orchestrator.register_tool("network_analysis", NetworkAnalysisTool, {})
        self.tool_orchestrator.register_tool("temporal_analysis", TemporalAnalysisTool, {})
        
        self.logger.info("Analysis tools registered successfully")

    async def _load_analysis_rules(self):
        """Load analysis rules and patterns."""
        # Production implementation would load from configuration files
        # For now, define core analysis patterns inline
        
        self.analysis_rules = {
            "malware_patterns": [
                {"pattern": "process_from_temp", "weight": 0.8, "description": "Process executing from temp directory"},
                {"pattern": "unsigned_executable", "weight": 0.6, "description": "Unsigned executable"},
                {"pattern": "network_beacon", "weight": 0.9, "description": "Regular network beaconing pattern"},
                {"pattern": "privilege_escalation", "weight": 0.85, "description": "Evidence of privilege escalation"},
            ],
            "network_patterns": [
                {"pattern": "c2_communication", "weight": 0.9, "description": "Command and control communication"},
                {"pattern": "data_exfiltration", "weight": 0.8, "description": "Large data transfer to external IP"},
                {"pattern": "port_scanning", "weight": 0.7, "description": "Port scanning activity"},
            ],
            "behavioral_patterns": [
                {"pattern": "lateral_movement", "weight": 0.85, "description": "Lateral movement indicators"},
                {"pattern": "persistence_mechanism", "weight": 0.8, "description": "Persistence establishment"},
                {"pattern": "defense_evasion", "weight": 0.75, "description": "Defense evasion techniques"},
            ]
        }
        
        self.logger.info("Analysis rules loaded")

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis using ReAct reasoning pattern."""
        try:
            self.logger.info(f"Executing analysis for alert {state.get('alert_id', 'unknown')}")

            # Validate input
            if not await self.validate_input(state):
                raise ValueError("Invalid input state for analysis")

            # Initialize analysis state
            self._reset_analysis_state()
            
            # Extract relevant data
            alert = state.get("raw_alert", {})
            correlations = state.get("correlations", [])
            enriched_data = state.get("enriched_data", {})

            # Perform ReAct analysis
            analysis_result = await self._perform_react_analysis(alert, correlations, enriched_data, state)

            # Build result state
            result_state = state.copy()
            result_state.update({
                "confidence_score": analysis_result["confidence_score"],
                "analysis_conclusion": analysis_result["conclusion"],
                "analysis_reasoning": analysis_result["reasoning_history"],
                "tool_results": analysis_result["tool_results"],
                "threat_score": analysis_result["threat_score"],
                "recommended_actions": analysis_result["recommended_actions"],
                "triage_status": "analyzed",
                "last_updated": datetime.utcnow().isoformat(),
                "enriched_data": {
                    **state.get("enriched_data", {}),
                    "analysis_metadata": analysis_result["metadata"]
                },
                "metadata": {
                    **state.get("metadata", {}),
                    "analysis_iterations": self.current_iteration,
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "analysis_agent_version": "1.0.0",
                }
            })

            # Validate output
            if not await self.validate_output(result_state):
                raise ValueError("Invalid output state from analysis")

            self.logger.info(
                f"Analysis completed for alert {state.get('alert_id')} "
                f"after {self.current_iteration} iterations with "
                f"{analysis_result['confidence_score']}% confidence"
            )

            return result_state

        except Exception as e:
            self.logger.error(f"Analysis execution failed: {e}")
            # Return state with error information
            error_state = state.copy()
            error_state.update({
                "triage_status": "analysis_failed",
                "last_updated": datetime.utcnow().isoformat(),
                "metadata": {
                    **state.get("metadata", {}),
                    "analysis_error": str(e),
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                }
            })
            return error_state

    def _reset_analysis_state(self):
        """Reset analysis state for new execution."""
        self.current_iteration = 0
        self.reasoning_history = []
        self.tool_results = {}
        self.confidence_progression = []

    async def _perform_react_analysis(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                                    enriched_data: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Perform ReAct analysis using the integrated ReActReasoner."""
        
        # Initial assessment
        initial_confidence = state.get("confidence_score", 50)
        self.confidence_progression.append({
            "iteration": 0,
            "confidence": initial_confidence,
            "reason": "Initial state"
        })
        
        # Prepare context for ReAct
        context = {
            "alert": alert,
            "correlations": correlations,
            "enriched_data": enriched_data,
            "state": state
        }
        
        # Get available tools
        available_tools = []
        if self.tool_orchestrator:
            try:
                available_tools = self.tool_orchestrator.list_tools()
            except Exception as e:
                self.logger.warning(f"Failed to retrieve tools: {e}, using empty toolset")
        else:
            self.logger.warning("Tool orchestrator not initialized; empty toolset")
        
        # Run ReAct reasoning
        react_result = await self.react_reasoner.reason_and_act(
            context, available_tools, execute_action_callback=self._execute_single_action
        )
        
        # Sync iteration count with ReAct result
        self.current_iteration = max(
            self.current_iteration, react_result.get("iterations_completed", 0)
        )
        
        # Extract from ReAct result
        self.reasoning_history = react_result["thoughts"]
        self.tool_results = react_result.get("action_results", {})
        
        # Update confidence based on results
        updated_confidence = await self._update_confidence(
            initial_confidence, self.tool_results, "", ""
        )
        
        self.confidence_progression.append({
            "iteration": self.current_iteration,
            "confidence": updated_confidence,
            "reason": f"Updated based on {len(self.tool_results)} tool results"
        })
        
        # Check termination conditions
        if await self._should_terminate_analysis(updated_confidence, self.current_iteration):
            self.logger.info(
                f"Terminating analysis early at iteration {self.current_iteration} "
                f"with {updated_confidence}% confidence"
            )
        
        # Final synthesis
        final_result = await self._synthesize_final_analysis(
            alert, correlations, enriched_data, state
        )
        
        return final_result


    async def _reason_about_evidence(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                                   enriched_data: Dict[str, Any], state: Dict[str, Any]) -> str:
        """Reason about current evidence using LLM or rule-based approach."""
        
        if self.enable_llm_reasoning and self.llm_client:
            return await self._llm_reasoning(alert, correlations, enriched_data, state)
        else:
            return await self._rule_based_reasoning(alert, correlations, enriched_data, state)

    async def _llm_reasoning(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                           enriched_data: Dict[str, Any], state: Dict[str, Any]) -> str:
        """Use LLM for reasoning step."""
        try:
            prompt = self._build_reasoning_prompt(alert, correlations, enriched_data, state)
            
            start_time = time.time()
            response = await self.llm_client.ainvoke(prompt)
            reasoning_time = time.time() - start_time
            
            self.logger.debug(f"LLM reasoning completed in {reasoning_time:.2f}s")
            
            return response.content.strip()
            
        except Exception as e:
            self.logger.warning(f"LLM reasoning failed: {e}, falling back to rule-based")
            return await self._rule_based_reasoning(alert, correlations, enriched_data, state)

    def _build_reasoning_prompt(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                              enriched_data: Dict[str, Any], state: Dict[str, Any]) -> str:
        """Build reasoning prompt for LLM."""
        
        # Previous reasoning context
        previous_reasoning = ""
        if self.reasoning_history:
            previous_reasoning = "\n\nPREVIOUS REASONING:\n"
            for entry in self.reasoning_history[-2:]:  # Last 2 iterations
                previous_reasoning += f"Iteration {entry['iteration']}: {entry['reasoning']}\n"
                if 'observation' in entry:
                    previous_reasoning += f"Observation: {entry['observation']}\n"

        return f"""You are a cybersecurity analyst performing deep threat analysis. Based on the current evidence, reason about what this alert represents and what additional investigation is needed.

CURRENT ALERT:
{json.dumps(alert, indent=2)}

CORRELATIONS FOUND ({len(correlations)}):
{json.dumps(correlations, indent=2) if correlations else "None"}

ENRICHED DATA:
{json.dumps(enriched_data, indent=2)}

CURRENT STATE:
- Confidence Score: {state.get('confidence_score', 0)}%
- TP Indicators: {state.get('tp_indicators', [])}
- FP Indicators: {state.get('fp_indicators', [])}
- Analysis Iteration: {self.current_iteration}/{self.max_iterations}

{previous_reasoning}

TOOL RESULTS FROM THIS ANALYSIS:
{json.dumps(self.tool_results, indent=2) if self.tool_results else "None yet"}

Based on all available evidence, provide your reasoning about:
1. What type of threat this likely represents
2. Key evidence supporting or refuting the threat hypothesis
3. What additional information would help confirm or deny the threat
4. Confidence level in current assessment

Keep your reasoning concise but thorough. Focus on evidence-based analysis."""

    async def _rule_based_reasoning(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                                  enriched_data: Dict[str, Any], state: Dict[str, Any]) -> str:
        """Rule-based reasoning fallback."""
        
        reasoning_points = []
        
        # Analyze alert severity and type
        severity = alert.get("severity", "unknown").lower()
        event_type = alert.get("raw_data", {}).get("event_type", "unknown")
        
        reasoning_points.append(f"Alert severity: {severity}, event type: {event_type}")
        
        # Analyze correlations
        if correlations:
            high_confidence_corr = [c for c in correlations if c.get("confidence", 0) > 80]
            reasoning_points.append(f"Found {len(correlations)} correlations, {len(high_confidence_corr)} high-confidence")
            
            threat_levels = set(c.get("threat_level", "unknown") for c in correlations)
            if "high" in threat_levels or "critical" in threat_levels:
                reasoning_points.append("High or critical threat indicators present in correlations")
        
        # Analyze confidence progression
        current_confidence = state.get("confidence_score", 0)
        if current_confidence > 80:
            reasoning_points.append("High confidence in threat assessment")
        elif current_confidence < 30:
            reasoning_points.append("Low confidence suggests potential false positive")
        else:
            reasoning_points.append("Medium confidence requires additional investigation")
        
        # Analyze indicators
        tp_count = len(state.get("tp_indicators", []))
        fp_count = len(state.get("fp_indicators", []))
        reasoning_points.append(f"Evidence balance: {tp_count} TP indicators vs {fp_count} FP indicators")
        
        return "; ".join(reasoning_points)

    async def _determine_actions(self, reasoning: str, alert: Dict[str, Any], 
                               correlations: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Determine what analysis actions/tools to use based on reasoning."""
        
        actions = []
        raw_data = alert.get("raw_data", {})
        
        # IP analysis if IPs are present
        if raw_data.get("source_ip") or raw_data.get("destination_ip"):
            actions.append({
                "tool": "ip_analysis",
                "target": raw_data.get("source_ip") or raw_data.get("destination_ip"),
                "type": "ip_reputation"
            })
        
        # Hash analysis if file hash is present
        if raw_data.get("file_hash"):
            actions.append({
                "tool": "hash_analysis", 
                "target": raw_data.get("file_hash"),
                "type": "malware_analysis"
            })
        
        # Process analysis if process information is available
        if raw_data.get("process_name"):
            actions.append({
                "tool": "process_analysis",
                "target": raw_data.get("process_name"),
                "type": "behavior_analysis"
            })
        
        # Network analysis if network indicators are present
        if (raw_data.get("destination_ip") and raw_data.get("destination_port")) or raw_data.get("bytes_transferred"):
            actions.append({
                "tool": "network_analysis",
                "target": f"{raw_data.get('destination_ip', '')}:{raw_data.get('destination_port', '')}",
                "type": "network_behavior"
            })
        
        # Temporal analysis for timing patterns
        if alert.get("timestamp"):
            actions.append({
                "tool": "temporal_analysis",
                "target": alert.get("timestamp"),
                "type": "timing_analysis"
            })
        
        # Limit actions based on iteration and configuration
        max_actions = min(self.max_parallel_tools, len(actions))
        return actions[:max_actions]

    async def _execute_actions(self, actions: List[Dict[str, str]], alert: Dict[str, Any], 
                             state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Execute analysis actions using tool orchestrator."""
        
        if not self.enable_tool_orchestration or not self.tool_orchestrator:
            return await self._execute_actions_fallback(actions, alert, state)
        
        results = {}
        
        if self.parallel_tool_execution:
            # Execute tools in parallel
            tasks = []
            for i, action in enumerate(actions):
                task = self._execute_single_action(action, alert, state)
                tasks.append((f"action_{i}", task))
            
            # Wait for all tasks to complete
            for action_id, task in tasks:
                try:
                    result = await asyncio.wait_for(task, timeout=self.tool_timeout)
                    results[action_id] = result
                except asyncio.TimeoutError:
                    results[action_id] = {"error": "Tool execution timeout", "success": False}
                except Exception as e:
                    results[action_id] = {"error": str(e), "success": False}
        else:
            # Execute tools sequentially
            for i, action in enumerate(actions):
                action_id = f"action_{i}"
                try:
                    result = await asyncio.wait_for(
                        self._execute_single_action(action, alert, state),
                        timeout=self.tool_timeout
                    )
                    results[action_id] = result
                except Exception as e:
                    results[action_id] = {"error": str(e), "success": False}
        
        return results

    async def _execute_single_action(self, action: Dict[str, str], alert: Dict[str, Any], 
                                   state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single analysis action."""
        
        tool_name = action["tool"]
        target = action["target"]
        analysis_type = action["type"]
        
        # Prepare tool arguments
        tool_args = {
            "target": target,
            "analysis_type": analysis_type,
            "alert_context": alert,
            "state_context": state
        }
        
        # Execute tool through orchestrator
        result = await self.tool_orchestrator.execute_tool(
            tool_name, tool_args, {"analysis_iteration": self.current_iteration}
        )
        
        return result

    async def _execute_actions_fallback(self, actions: List[Dict[str, str]], alert: Dict[str, Any], 
                                      state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Fallback action execution without tool orchestrator."""
        
        results = {}
        
        for i, action in enumerate(actions):
            action_id = f"action_{i}"
            
            # Simple rule-based analysis as fallback
            if action["tool"] == "ip_analysis":
                results[action_id] = await self._simple_ip_analysis(action["target"])
            elif action["tool"] == "hash_analysis":
                results[action_id] = await self._simple_hash_analysis(action["target"])
            elif action["tool"] == "process_analysis":
                results[action_id] = await self._simple_process_analysis(action["target"])
            elif action["tool"] == "network_analysis":
                results[action_id] = await self._simple_network_analysis(action["target"])
            elif action["tool"] == "temporal_analysis":
                results[action_id] = await self._simple_temporal_analysis(action["target"])
            else:
                results[action_id] = {"error": f"Unknown tool: {action['tool']}", "success": False}
        
        return results

    # Simple analysis methods for fallback
    async def _simple_ip_analysis(self, ip: str) -> Dict[str, Any]:
        """Simple IP analysis fallback."""
        # Basic IP classification
        is_private = any(ip.startswith(prefix) for prefix in ["10.", "172.16.", "192.168.", "127."])
        is_suspicious = any(ip.startswith(prefix) for prefix in ["185.220.", "45.133."])
        
        return {
            "success": True,
            "ip": ip,
            "is_private": is_private,
            "is_suspicious": is_suspicious,
            "reputation": "suspicious" if is_suspicious else "clean" if is_private else "unknown",
            "analysis_type": "basic_classification"
        }

    async def _simple_hash_analysis(self, file_hash: str) -> Dict[str, Any]:
        """Simple hash analysis fallback."""
        # Basic hash pattern analysis
        known_bad = ["a1b2c3d4e5f6789", "d41d8cd98f00b204e9800998ecf8427e"]
        is_malicious = file_hash in known_bad
        
        return {
            "success": True,
            "hash": file_hash,
            "is_malicious": is_malicious,
            "detection_ratio": "5/70" if is_malicious else "0/70",
            "analysis_type": "hash_lookup"
        }

    async def _simple_process_analysis(self, process: str) -> Dict[str, Any]:
        """Simple process analysis fallback."""
        suspicious_processes = ["update.exe", "svchost.exe", "powershell.exe"]
        is_suspicious = process.lower() in [p.lower() for p in suspicious_processes]
        
        return {
            "success": True,
            "process": process,
            "is_suspicious": is_suspicious,
            "common_locations": ["C:\\Windows\\System32", "C:\\temp"] if is_suspicious else [],
            "analysis_type": "process_reputation"
        }

    async def _simple_network_analysis(self, target: str) -> Dict[str, Any]:
        """Simple network analysis fallback."""
        # Parse IP:port
        parts = target.split(":")
        ip = parts[0] if parts else target
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        
        suspicious_ports = [4444, 6666, 31337, 8080]
        is_suspicious_port = port in suspicious_ports if port else False
        
        return {
            "success": True,
            "ip": ip,
            "port": port,
            "is_suspicious_port": is_suspicious_port,
            "port_reputation": "suspicious" if is_suspicious_port else "normal",
            "analysis_type": "network_classification"
        }

    async def _simple_temporal_analysis(self, timestamp: str) -> Dict[str, Any]:
        """Simple temporal analysis fallback."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            is_business_hours = 6 <= hour < 18
            is_weekend = dt.weekday() >= 5
            
            return {
                "success": True,
                "timestamp": timestamp,
                "hour": hour,
                "is_business_hours": is_business_hours,
                "is_weekend": is_weekend,
                "temporal_risk": "low" if is_business_hours and not is_weekend else "medium",
                "analysis_type": "temporal_classification"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis_type": "temporal_classification"
            }

    async def _observe_results(self, action_results: Dict[str, Dict[str, Any]], reasoning: str) -> str:
        """Observe and summarize action results."""
        
        observations = []
        
        for action_id, result in action_results.items():
            if result.get("success", False):
                if "ip" in result:
                    rep = result.get("reputation", "unknown")
                    observations.append(f"IP {result['ip']} has {rep} reputation")
                elif "hash" in result:
                    if result.get("is_malicious", False):
                        observations.append(f"Hash {result['hash']} detected as malicious")
                    else:
                        observations.append(f"Hash {result['hash']} appears clean")
                elif "process" in result:
                    if result.get("is_suspicious", False):
                        observations.append(f"Process {result['process']} flagged as suspicious")
                elif "port" in result:
                    if result.get("is_suspicious_port", False):
                        observations.append(f"Port {result['port']} is commonly used for malicious purposes")
                elif "temporal_risk" in result:
                    risk = result.get("temporal_risk", "unknown")
                    observations.append(f"Temporal analysis shows {risk} risk timing")
            else:
                observations.append(f"Tool execution failed: {result.get('error', 'Unknown error')}")
        
        return "; ".join(observations) if observations else "No significant findings from tool execution"

    async def _update_confidence(self, base_confidence: int, action_results: Dict[str, Dict[str, Any]], 
                               reasoning: str, observation: str) -> int:
        """Update confidence score based on analysis results."""
        
        confidence_adjustment = 0
        
        # Analyze results for confidence impact
        for result in action_results.values():
            if not result.get("success", False):
                continue
                
            # IP reputation impact
            if "reputation" in result:
                if result["reputation"] == "suspicious":
                    confidence_adjustment += 15
                elif result["reputation"] == "malicious":
                    confidence_adjustment += 25
                elif result["reputation"] == "clean":
                    confidence_adjustment -= 10
            
            # Hash analysis impact
            if result.get("is_malicious", False):
                confidence_adjustment += 30
            elif "hash" in result and not result.get("is_malicious", True):
                confidence_adjustment -= 15
            
            # Process analysis impact
            if result.get("is_suspicious", False):
                confidence_adjustment += 10
            
            # Network analysis impact
            if result.get("is_suspicious_port", False):
                confidence_adjustment += 15
            
            # Temporal analysis impact
            temporal_risk = result.get("temporal_risk")
            if temporal_risk == "high":
                confidence_adjustment += 10
            elif temporal_risk == "low":
                confidence_adjustment -= 5
        
        # Apply adjustment with bounds
        updated_confidence = max(0, min(100, base_confidence + confidence_adjustment))
        
        self.logger.debug(
            f"Confidence update: {base_confidence} + {confidence_adjustment} = {updated_confidence}"
        )
        
        return updated_confidence

    async def _should_terminate_analysis(self, confidence: int, iteration: int) -> bool:
        """Determine if analysis should terminate."""
        
        # Terminate if we've reached max iterations
        if iteration >= self.max_iterations:
            return True
        
        # Terminate if confidence is very high or very low
        if confidence >= self.max_confidence_threshold or confidence <= 20:
            return True
        
        # Terminate if confidence hasn't changed significantly in last 2 iterations
        if len(self.confidence_progression) >= 3:
            recent_changes = [
                abs(self.confidence_progression[i]["confidence"] - self.confidence_progression[i-1]["confidence"])
                for i in range(-2, 0)
            ]
            if all(change < 5 for change in recent_changes):
                self.logger.info("Terminating analysis due to confidence plateau")
                return True
        
        return False

    async def _synthesize_final_analysis(self, alert: Dict[str, Any], correlations: List[Dict[str, Any]], 
                                       enriched_data: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize final analysis results."""
        
        # Calculate final confidence
        final_confidence = self.confidence_progression[-1]["confidence"] if self.confidence_progression else 50
        
        # Determine threat score based on multiple factors
        threat_score = await self._calculate_threat_score(final_confidence, correlations, self.tool_results)
        
        # Generate conclusion
        conclusion = await self._generate_conclusion(final_confidence, threat_score, self.reasoning_history)
        
        # Generate recommended actions
        recommended_actions = await self._generate_recommended_actions(
            final_confidence, threat_score, alert, self.tool_results
        )
        
        # Build metadata
        metadata = {
            "analysis_iterations": self.current_iteration,
            "final_confidence": final_confidence,
            "threat_score": threat_score,
            "tools_used": list(set(result.get("analysis_type", "unknown") for result in self.tool_results.values())),
            "reasoning_steps": len(self.reasoning_history),
            "analysis_duration": time.time() - (self.reasoning_history[0].get("start_time", time.time()) if self.reasoning_history else time.time()),
            "confidence_progression": self.confidence_progression
        }
        
        return {
            "confidence_score": final_confidence,
            "threat_score": threat_score,
            "conclusion": conclusion,
            "reasoning_history": self.reasoning_history,
            "tool_results": self.tool_results,
            "recommended_actions": recommended_actions,
            "metadata": metadata
        }

    async def _calculate_threat_score(self, confidence: int, correlations: List[Dict[str, Any]], 
                                    tool_results: Dict[str, Dict[str, Any]]) -> int:
        """Calculate overall threat score (0-100)."""
        
        # Base score from confidence
        threat_score = confidence
        
        # Correlation impact
        if correlations:
            high_threat_correlations = [c for c in correlations if c.get("threat_level") in ["high", "critical"]]
            threat_score += len(high_threat_correlations) * 5
        
        # Tool results impact
        for result in tool_results.values():
            if not result.get("success", False):
                continue
                
            if result.get("is_malicious", False) or result.get("reputation") == "malicious":
                threat_score += 20
            elif result.get("is_suspicious", False) or result.get("reputation") == "suspicious":
                threat_score += 10
        
        return max(0, min(100, threat_score))

    async def _generate_conclusion(self, confidence: int, threat_score: int, 
                                 reasoning_history: List[Dict[str, Any]]) -> str:
        """Generate analysis conclusion."""
        
        if threat_score >= 80:
            return "HIGH THREAT: Strong evidence indicates malicious activity requiring immediate response"
        elif threat_score >= 60:
            return "MEDIUM THREAT: Suspicious activity detected, investigation and monitoring recommended"
        elif threat_score >= 40:
            return "LOW THREAT: Some suspicious indicators present, continued monitoring advised"
        else:
            return "MINIMAL THREAT: Evidence suggests benign activity or false positive"

    async def _generate_recommended_actions(self, confidence: int, threat_score: int, 
                                          alert: Dict[str, Any], tool_results: Dict[str, Dict[str, Any]]) -> List[str]:
        """Generate recommended actions based on analysis."""
        
        actions = []
        
        if threat_score >= 80:
            actions.extend([
                "Immediate containment: Isolate affected systems",
                "Escalate to incident response team",
                "Block malicious IPs/domains at network perimeter",
                "Initiate forensic investigation"
            ])
        elif threat_score >= 60:
            actions.extend([
                "Enhanced monitoring of affected systems",
                "Block suspicious indicators as precaution",
                "Schedule deeper investigation within 4 hours",
                "Notify security team lead"
            ])
        elif threat_score >= 40:
            actions.extend([
                "Add to watchlist for continued monitoring",
                "Review similar alerts for patterns",
                "Document findings for trend analysis"
            ])
        else:
            actions.extend([
                "Close as false positive",
                "Update detection rules to reduce noise",
                "Document for tuning purposes"
            ])
        
        # Add specific actions based on tool results
        for result in tool_results.values():
            if result.get("success", False):
                if result.get("is_malicious", False) and "hash" in result:
                    actions.append(f"Add hash {result['hash']} to blacklist")
                elif result.get("reputation") == "malicious" and "ip" in result:
                    actions.append(f"Block IP {result['ip']} at firewall")
        
        return actions

    # Validation methods
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
            required_fields = ["confidence_score", "analysis_conclusion", "triage_status"]
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing output field: {field}")
                    return False

            # Check confidence score range
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

            # Cleanup tool orchestrator
            if self.tool_orchestrator:
                # Tool orchestrator cleanup if needed
                pass

            # Cleanup LLM client
            if self.llm_client:
                self.llm_client = None

            self.logger.info("Analysis agent cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during analysis agent cleanup: {e}")

    async def health_check(self) -> bool:
        """Check if the analysis agent is healthy."""
        try:
            if not self.initialized:
                return False

            # Check LLM client if enabled
            if self.enable_llm_reasoning and not self.llm_client:
                return False

            # Check tool orchestrator if enabled
            if self.enable_tool_orchestration and not self.tool_orchestrator:
                return False

            # Run a simple test
            test_state = {
                "alert_id": "health_check",
                "raw_alert": {"id": "test", "severity": "low"},
                "confidence_score": 50
            }

            if not await self.validate_input(test_state):
                return False

            return True

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get analysis agent metrics."""
        base_metrics = super().get_metrics()

        analysis_metrics = {
            "max_iterations": self.max_iterations,
            "min_confidence_threshold": self.min_confidence_threshold,
            "max_confidence_threshold": self.max_confidence_threshold,
            "tool_orchestration_enabled": self.enable_tool_orchestration,
            "llm_reasoning_enabled": self.enable_llm_reasoning,
            "parallel_tool_execution": self.parallel_tool_execution,
            "max_parallel_tools": self.max_parallel_tools,
            "current_iteration": self.current_iteration,
            "reasoning_steps_completed": len(self.reasoning_history),
            "tools_executed": len(self.tool_results),
        }

        base_metrics.update(analysis_metrics)
        return base_metrics