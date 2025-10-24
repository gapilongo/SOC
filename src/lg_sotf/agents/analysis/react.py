"""
ReAct reasoning implementation for analysis agent.
"""

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.utils.llm import get_llm_client


class ReActReasoner:
    """Implements ReAct (Reasoning and Acting) pattern for threat analysis"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.llm_client = None

        # ReAct configuration
        self.max_iterations = config.get("max_iterations", 5)
        self.reasoning_temperature = config.get("reasoning_temperature", 0.3)
        self.action_temperature = config.get("action_temperature", 0.1)

        # Enhanced retry and resilience settings
        self.max_action_retries = config.get("max_action_retries", 3)
        self.enable_fallback_analysis = config.get("enable_fallback_analysis", True)
        self.min_iterations_before_stop = config.get("min_iterations_before_stop", 2)
        self.confidence_stop_threshold = config.get("confidence_stop_threshold", 95)

    async def initialize(self):
        """Initialize ReAct reasoner."""
        try:
            config_manager = ConfigManager()
            self.llm_client = get_llm_client(config_manager)
            self.logger.info("ReAct reasoner initialized")
        except Exception as e:
            self.logger.error(f"ReAct reasoner initialization failed: {e}")
            raise

    async def reason_and_act(
        self,
        context: Dict[str, Any],
        available_tools: List[str],
        execute_action_callback: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """Execute ReAct reasoning loop"""

        thoughts = []
        actions = []
        observations = []
        action_results = {}
        consecutive_failures = 0
        successful_iterations = 0

        # Ensure we always have some tools available
        effective_tools = self._ensure_minimum_tools(available_tools)

        for iteration in range(self.max_iterations):
            iteration_success = False

            try:
                # Reasoning step - with error handling
                thought = await self._generate_thought_with_retry(
                    context, thoughts, actions, observations, effective_tools
                )
                thoughts.append({"iteration": iteration + 1, "thought": thought})

                # Robust action generation with multiple fallbacks
                action = await self._generate_action_with_fallbacks(
                    thought, effective_tools, context, iteration
                )

                # Always continue, even without action
                if action:
                    actions.append({"iteration": iteration + 1, "action": action})
                    consecutive_failures = 0
                    iteration_success = True
                else:
                    # Create a rule-based analysis action instead of stopping
                    action = self._create_fallback_action(thought, context, iteration)
                    actions.append(
                        {"iteration": iteration + 1, "action": action, "fallback": True}
                    )
                    consecutive_failures += 1

                # Observation step with enhanced error handling
                observation = await self._execute_observation_with_retry(
                    action, execute_action_callback, context, iteration
                )
                observations.append(
                    {"iteration": iteration + 1, "observation": observation}
                )

                # Store results
                action_results[f"action_{iteration}"] = observation

                if iteration_success:
                    successful_iterations += 1

                # Improved stopping logic
                should_stop = await self._should_stop_reasoning_enhanced(
                    thought,
                    action,
                    observation,
                    context,
                    iteration,
                    consecutive_failures,
                    successful_iterations,
                )

                if should_stop:
                    self.logger.info(
                        f"ReAct reasoning completed after {iteration + 1} iterations"
                    )
                    break

            except Exception as e:
                self.logger.error(f"ReAct iteration {iteration} failed: {e}")
                consecutive_failures += 1

                # Add error observation
                error_observation = {"error": str(e), "iteration_failed": True}
                observations.append(
                    {"iteration": iteration + 1, "observation": error_observation}
                )

                # Continue unless too many consecutive failures
                if consecutive_failures >= self.max_action_retries:
                    self.logger.warning(
                        f"Too many consecutive failures ({consecutive_failures}), but continuing with rule-based analysis"
                    )
                    # Reset and continue with simplified approach
                    consecutive_failures = 0
                    effective_tools = ["rule_based_analysis"]

        return {
            "thoughts": thoughts,
            "actions": actions,
            "observations": observations,
            "action_results": action_results,
            "final_reasoning": thoughts[-1]["thought"]
            if thoughts
            else "No reasoning completed",
            "iterations_completed": len(thoughts),
            "successful_iterations": successful_iterations,
            "total_failures": sum(
                1
                for obs in observations
                if isinstance(obs.get("observation"), dict)
                and obs["observation"].get("error")
            ),
        }

    def _ensure_minimum_tools(self, available_tools: List[str]) -> List[str]:
        """Ensure we always have minimum viable tools."""
        if not available_tools:
            self.logger.warning("No tools available, using built-in analysis tools")
            return [
                "rule_based_analysis",
                "confidence_assessment",
                "pattern_matching",
                "threat_classification",
            ]

        # Ensure rule-based fallback is always available
        if "rule_based_analysis" not in available_tools:
            available_tools.append("rule_based_analysis")

        return available_tools

    async def _generate_thought_with_retry(
        self,
        context: Dict[str, Any],
        thoughts: List[Dict],
        actions: List[Dict],
        observations: List[Dict],
        available_tools: List[str],
    ) -> str:
        """Generate reasoning thought with retry logic."""

        for attempt in range(self.max_action_retries):
            try:
                prompt = self._build_thought_prompt(
                    context, thoughts, actions, observations, available_tools
                )
                response = await self.llm_client.ainvoke(prompt)

                # Handle both string and list responses (Gemini can return lists)
                if isinstance(response.content, list):
                    thought = " ".join(str(item) for item in response.content).strip()
                else:
                    thought = response.content.strip()

                if thought and len(thought) > 10:  # Basic validation
                    return thought

            except Exception as e:
                self.logger.warning(
                    f"LLM thought generation attempt {attempt + 1} failed: {e}"
                )
                if attempt == self.max_action_retries - 1:
                    # Final fallback
                    return self._generate_fallback_thought(context, len(thoughts))

        return self._generate_fallback_thought(context, len(thoughts))

    async def _generate_action_with_fallbacks(
        self,
        thought: str,
        available_tools: List[str],
        context: Dict[str, Any],
        iteration: int,
    ) -> Optional[Dict[str, Any]]:
        """Generate action with multiple fallback strategies."""

        # Attempt 1: Standard LLM action generation
        action = await self._generate_action_standard(thought, available_tools, context)
        if action and self._validate_action_enhanced(action, available_tools):
            return action

        # Attempt 2: Simplified prompt with fewer tools
        simplified_tools = (
            available_tools[:3] if len(available_tools) > 3 else available_tools
        )
        action = await self._generate_action_simplified(
            thought, simplified_tools, context
        )
        if action and self._validate_action_enhanced(action, simplified_tools):
            return action

        # Attempt 3: Pattern-based action extraction from thought
        action = self._extract_action_from_thought(thought, available_tools)
        if action and self._validate_action_enhanced(action, available_tools):
            return action

        # Attempt 4: Heuristic action based on context
        action = self._generate_heuristic_action(
            thought, available_tools, context, iteration
        )
        if action and self._validate_action_enhanced(action, available_tools):
            return action

        # All attempts failed - this is handled by caller
        self.logger.warning(
            f"All action generation attempts failed for iteration {iteration}"
        )
        return None

    async def _generate_action_standard(
        self, thought: str, available_tools: List[str], context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Standard action generation with robust parsing."""
        try:
            prompt = self._build_action_prompt(thought, available_tools, context)
            response = await self.llm_client.ainvoke(prompt)

            # Handle both string and list responses
            content = response.content
            if isinstance(content, list):
                content = " ".join(str(item) for item in content)

            return self._parse_action_robust(content, available_tools)
        except Exception as e:
            self.logger.debug(f"Standard action generation failed: {e}")
            return None

    async def _generate_action_simplified(
        self, thought: str, available_tools: List[str], context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Simplified action generation for when standard fails."""
        try:
            # Simplified prompt focusing on just tool selection
            simplified_prompt = f"""
Based on this analysis: "{thought}"

Available tools: {', '.join(available_tools)}

Choose the most appropriate tool and target. Respond with just:
Tool: [tool_name]
Target: [what_to_analyze]
"""
            response = await self.llm_client.ainvoke(simplified_prompt)

            # Handle both string and list responses
            content = response.content
            if isinstance(content, list):
                content = " ".join(str(item) for item in content)

            return self._parse_simple_action(content, available_tools)
        except Exception as e:
            self.logger.debug(f"Simplified action generation failed: {e}")
            return None

    def _extract_action_from_thought(
        self, thought: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Extract action hints from thought text."""
        thought_lower = thought.lower()

        # Look for tool mentions in thought
        for tool in available_tools:
            if (
                tool.lower() in thought_lower
                or tool.replace("_", " ").lower() in thought_lower
            ):
                # Extract potential target from thought
                target = self._extract_target_from_thought(thought, tool)
                return {
                    "tool": tool,
                    "target": target,
                    "reason": f"Inferred from thought analysis mentioning {tool}",
                    "extracted": True,
                }

        return None

    def _generate_heuristic_action(
        self,
        thought: str,
        available_tools: List[str],
        context: Dict[str, Any],
        iteration: int,
    ) -> Optional[Dict[str, Any]]:
        """Generate action based on context heuristics."""

        # Get alert data for heuristics
        alert = context.get("alert", {})
        raw_data = alert.get("raw_data", {})

        # Priority-based tool selection
        if "ip_analysis" in available_tools and (
            raw_data.get("source_ip") or raw_data.get("destination_ip")
        ):
            return {
                "tool": "ip_analysis",
                "target": raw_data.get("source_ip") or raw_data.get("destination_ip"),
                "reason": "IP address detected in alert data",
                "heuristic": True,
            }

        if "hash_analysis" in available_tools and raw_data.get("file_hash"):
            return {
                "tool": "hash_analysis",
                "target": raw_data.get("file_hash"),
                "reason": "File hash detected in alert data",
                "heuristic": True,
            }

        if "process_analysis" in available_tools and raw_data.get("process_name"):
            return {
                "tool": "process_analysis",
                "target": raw_data.get("process_name"),
                "reason": "Process name detected in alert data",
                "heuristic": True,
            }

        # Fallback to rule-based analysis
        if "rule_based_analysis" in available_tools:
            return {
                "tool": "rule_based_analysis",
                "target": "comprehensive_analysis",
                "reason": f"Heuristic fallback at iteration {iteration}",
                "heuristic": True,
            }

        return None

    def _create_fallback_action(
        self, thought: str, context: Dict[str, Any], iteration: int
    ) -> Dict[str, Any]:
        """Create a fallback action when all generation methods fail."""
        return {
            "tool": "rule_based_analysis",
            "target": "fallback_analysis",
            "reason": f"Fallback action for iteration {iteration} after generation failures",
            "fallback": True,
        }

    async def _execute_observation_with_retry(
        self,
        action: Dict[str, Any],
        execute_action_callback: Optional[Callable],
        context: Dict[str, Any],
        iteration: int,
    ) -> Any:
        """Execute observation with retry logic."""

        if not execute_action_callback:
            return f"Action {action.get('tool', 'unknown')} completed with target {action.get('target', 'N/A')}"

        # Try executing the action with retries
        for attempt in range(self.max_action_retries):
            try:
                observation = await execute_action_callback(
                    action, context.get("alert", {}), context.get("state", {})
                )

                # Validate observation
                if observation is not None:
                    return observation

            except Exception as e:
                self.logger.warning(
                    f"Action execution attempt {attempt + 1} failed: {e}"
                )
                if attempt == self.max_action_retries - 1:
                    # Return error observation instead of failing
                    return {
                        "error": str(e),
                        "action": action,
                        "iteration": iteration,
                        "fallback_executed": True,
                    }

        # Fallback observation
        return {
            "message": f"Action {action.get('tool')} completed with fallback handling",
            "tool": action.get("tool"),
            "target": action.get("target"),
            "iteration": iteration,
        }

    def _parse_action_robust(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Robust action parsing with multiple strategies."""

        # Strategy 1: Standard JSON parsing
        action = self._parse_action_standard(response, available_tools)
        if action:
            return action

        # Strategy 2: Extract JSON from markdown blocks
        action = self._parse_action_from_markdown(response, available_tools)
        if action:
            return action

        # Strategy 3: Key-value pair extraction
        action = self._parse_action_key_value(response, available_tools)
        if action:
            return action

        # Strategy 4: Regex-based extraction
        action = self._parse_action_regex(response, available_tools)
        if action:
            return action

        return None

    def _parse_action_standard(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Standard JSON parsing with cleanup."""
        try:
            # Clean response
            content = response.strip()

            # Remove common markdown formatting
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]

            content = content.strip()

            # Parse JSON
            action = json.loads(content)

            if isinstance(action, dict) and "tool" in action:
                if action.get("tool") == "none":
                    return None
                if action.get("tool") in available_tools:
                    return action

        except Exception as e:
            self.logger.debug(f"Standard JSON parsing failed: {e}")

        return None

    def _parse_action_from_markdown(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Extract JSON from markdown code blocks."""
        try:
            # Look for JSON in various markdown formats
            json_patterns = [
                r"```json\s*(\{.*?\})\s*```",
                r"```\s*(\{.*?\})\s*```",
                r"`(\{.*?\})`",
                r'(\{[^}]*"tool"[^}]*\})',
            ]

            for pattern in json_patterns:
                matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    try:
                        action = json.loads(match.strip())
                        if (
                            isinstance(action, dict)
                            and action.get("tool") in available_tools
                        ):
                            return action
                    except:
                        continue

        except Exception as e:
            self.logger.debug(f"Markdown parsing failed: {e}")

        return None

    def _parse_action_key_value(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Parse action from key-value format."""
        try:
            action = {}
            lines = response.strip().split("\n")

            for line in lines:
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip().strip("\"'")

                    if key in ["tool", "target", "reason"]:
                        action[key] = value

            if action.get("tool") in available_tools:
                return action

        except Exception as e:
            self.logger.debug(f"Key-value parsing failed: {e}")

        return None

    def _parse_action_regex(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Extract action using regex patterns."""
        try:
            # Look for tool mentions
            for tool in available_tools:
                # Pattern: "use X tool" or "run X analysis"
                pattern = rf'\b(?:use|run|execute|perform)\s+({re.escape(tool)}|{re.escape(tool.replace("_", " "))})'
                match = re.search(pattern, response, re.IGNORECASE)

                if match:
                    # Look for target nearby
                    target_patterns = [
                        rf"(?:on|for|with|target)\s+([^\s\.,;]+)",
                        rf"target[:\s]+([^\s\.,;]+)",
                        rf"analyze\s+([^\s\.,;]+)",
                    ]

                    target = "default_target"
                    for target_pattern in target_patterns:
                        target_match = re.search(
                            target_pattern, response, re.IGNORECASE
                        )
                        if target_match:
                            target = target_match.group(1)
                            break

                    return {
                        "tool": tool,
                        "target": target,
                        "reason": "Extracted from regex pattern matching",
                        "regex_extracted": True,
                    }

        except Exception as e:
            self.logger.debug(f"Regex parsing failed: {e}")

        return None

    def _parse_simple_action(
        self, response: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Parse simple Tool:/Target: format."""
        try:
            action = {}
            lines = response.strip().split("\n")

            for line in lines:
                line = line.strip()
                if line.startswith("Tool:"):
                    tool = line.replace("Tool:", "").strip()
                    if tool in available_tools:
                        action["tool"] = tool
                elif line.startswith("Target:"):
                    action["target"] = line.replace("Target:", "").strip()

            if "tool" in action:
                action.setdefault("target", "default_target")
                action["reason"] = "Parsed from simplified format"
                return action

        except Exception as e:
            self.logger.debug(f"Simple parsing failed: {e}")

        return None

    def _validate_action_enhanced(
        self, action: Dict[str, Any], available_tools: List[str]
    ) -> bool:
        """Enhanced action validation."""
        if not isinstance(action, dict):
            return False

        tool = action.get("tool")
        if not tool or not isinstance(tool, str):
            return False

        # Exact match first
        if tool in available_tools:
            return True

        # Fuzzy matching for minor variations
        tool_lower = tool.lower().replace("-", "_").replace(" ", "_")
        for available_tool in available_tools:
            available_lower = available_tool.lower().replace("-", "_").replace(" ", "_")
            if tool_lower == available_lower:
                # Update action with correct tool name
                action["tool"] = available_tool
                return True

        return False

    def _extract_target_from_thought(self, thought: str, tool: str) -> str:
        """Extract analysis target from thought text."""
        # Look for common patterns
        patterns = [
            r"(?:analyze|check|investigate|examine)\s+([^\s\.,;]+)",
            r"(?:IP|hash|process|file)\s+([^\s\.,;]+)",
            r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",  # IP addresses
            r"([a-fA-F0-9]{32,64})",  # Hashes
            r"([a-zA-Z0-9_.-]+\.exe)",  # Executables
        ]

        for pattern in patterns:
            match = re.search(pattern, thought, re.IGNORECASE)
            if match:
                return match.group(1)

        return "inferred_target"

    async def _should_stop_reasoning_enhanced(
        self,
        thought: str,
        action: Optional[Dict],
        observation: Any,
        context: Optional[Dict],
        iteration: int,
        consecutive_failures: int,
        successful_iterations: int,
    ) -> bool:
        """Enhanced stopping logic for security analysis."""

        # Never stop before minimum iterations (unless critical error)
        if (
            iteration < self.min_iterations_before_stop
            and consecutive_failures < self.max_action_retries
        ):
            return False

        # Stop if too many consecutive failures and we've tried enough
        if consecutive_failures >= self.max_action_retries and iteration >= 2:
            self.logger.warning("Stopping due to consecutive failures")
            return True

        # Stop at max iterations
        if iteration >= self.max_iterations - 1:
            return True

        thought_lower = thought.lower() if thought else ""

        # Much more restrictive confidence-based stopping
        context_conf = context.get("confidence_score", None) if context else None
        if context_conf is not None:
            if context_conf >= self.confidence_stop_threshold:  # Default 95%
                self.logger.info(
                    f"Stopping reasoning: very high confidence ({context_conf}%)"
                )
                return True
            if context_conf <= 2:  # Much lower threshold
                self.logger.info(
                    f"Stopping reasoning: extremely low confidence ({context_conf}%)"
                )
                return True

        # Only stop on very definitive completion phrases
        definitive_completion_triggers = [
            "analysis complete and no further investigation needed",
            "investigation concluded with final determination",
            "threat assessment finalized",
            "security analysis complete with high confidence",
        ]

        if any(phrase in thought_lower for phrase in definitive_completion_triggers):
            self.logger.info(
                f"Stopping reasoning: definitive completion phrase detected"
            )
            return True

        # Observation-based stopping (more restrictive)
        if isinstance(observation, dict):
            if (
                observation.get("analysis_complete")
                and observation.get("confidence", 0) > 90
            ):
                return True

        # Continue by default - let the reasoner work
        return False

    def _generate_fallback_thought(
        self, context: Dict[str, Any], iteration: int
    ) -> str:
        """Generate fallback thought when LLM fails."""
        confidence = context.get("state", {}).get("confidence_score", 50)

        if iteration == 0:
            return f"Beginning security analysis with {confidence}% initial confidence. Investigating key indicators to determine threat level."
        else:
            return f"Continuing analysis to resolve uncertainties. Current assessment requires additional evidence gathering at iteration {iteration + 1}."

    # Keep original method signatures for compatibility
    async def _generate_thought(
        self,
        context: Dict[str, Any],
        thoughts: List[Dict],
        actions: List[Dict],
        observations: List[Dict],
        available_tools: List[str],
    ) -> str:
        """Generate reasoning thought - delegates to robust version."""
        return await self._generate_thought_with_retry(
            context, thoughts, actions, observations, available_tools
        )

    async def _generate_action(
        self, thought: str, available_tools: List[str], context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate action - delegates to robust version."""
        return await self._generate_action_with_fallbacks(
            thought, available_tools, context, 0
        )

    def _parse_action(
        self, response_content: str, available_tools: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Parse action - delegates to robust version."""
        return self._parse_action_robust(response_content, available_tools)

    async def _should_stop_reasoning(
        self,
        thought: str,
        action: Optional[Dict],
        observation: Any,
        context: Optional[Dict] = None,
    ) -> bool:
        """Stop reasoning check - delegates to enhanced version."""
        return await self._should_stop_reasoning_enhanced(
            thought, action, observation, context, 0, 0, 1
        )

    # Keep existing prompt building methods unchanged
    def _build_thought_prompt(
        self,
        context: Dict[str, Any],
        thoughts: List[Dict],
        actions: List[Dict],
        observations: List[Dict],
        available_tools: List[str],
    ) -> str:
        """Build reasoning prompt for LLM."""

        previous_context = ""
        if thoughts:
            previous_context = "\n\nPREVIOUS REASONING:\n"
            for i, (thought, action, obs) in enumerate(
                zip(thoughts, actions, observations)
            ):
                previous_context += f"Iteration {i+1}:\n"
                previous_context += f"Thought: {thought['thought']}\n"
                if action:
                    previous_context += f"Action: {action['action']}\n"
                previous_context += f"Observation: {obs['observation']}\n\n"

        return f"""You are a cybersecurity analyst performing deep threat analysis. Based on the current evidence, reason about what this alert represents and what additional investigation is needed.

CURRENT ALERT:
{json.dumps(context, indent=2)}

AVAILABLE TOOLS:
{', '.join(available_tools)}

{previous_context}

Based on all available evidence, provide your reasoning about:
1. What type of threat this likely represents
2. Key evidence supporting or refuting the threat hypothesis
3. What additional information would help confirm or deny the threat
4. Confidence level in current assessment

Keep your reasoning concise but thorough. Focus on evidence-based analysis."""

    def _build_action_prompt(
        self, thought: str, available_tools: List[str], context: Dict[str, Any]
    ) -> str:
        """Build action prompt with detailed tool descriptions."""

        # Tool descriptions to guide LLM
        tool_guide = {
            "ip_analysis": "Analyze IP addresses (source_ip, destination_ip) for reputation, geolocation, and threat intelligence. Use when you see IP addresses in the alert.",
            "hash_analysis": "Check file hashes (MD5, SHA1, SHA256) against malware databases. Use when you see file_hash or checksum in the alert.",
            "process_analysis": "Analyze process behavior and command lines. Use when you see process_name, command_line, or executable paths.",
            "network_analysis": "Analyze network connections, traffic volume, and beaconing patterns. Use when investigating C2 communication or data exfiltration.",
            "temporal_analysis": "Find related events before/after this alert. Use to establish attack timeline, find precursor events, or identify follow-up actions."
        }

        # Build tool list with descriptions
        tools_with_desc = []
        for tool in available_tools:
            desc = tool_guide.get(tool, f"Tool: {tool}")
            tools_with_desc.append(f"  - {tool}: {desc}")

        tools_formatted = "\n".join(tools_with_desc)

        # Extract alert details for context
        alert_id = context.get("id", "unknown")
        alert_title = context.get("title", "")
        alert_category = context.get("category", "")

        return f"""You are analyzing security alert: {alert_id}
Title: {alert_title}
Category: {alert_category}

Your reasoning: "{thought}"

Available Tools:
{tools_formatted}

Alert Data Summary:
{self._summarize_alert_data(context)}

Think step-by-step:
1. What specific information am I missing to assess this threat?
2. Which tool provides that information?
3. What should I ask the tool to analyze?

Respond in JSON format:
{{
    "tool": "tool_name",
    "target": "what to analyze (IP, hash, username, etc.)",
    "reason": "why this tool will help"
}}

If analysis is complete: {{"tool": "none", "reason": "sufficient evidence collected"}}

Examples:
- If you see suspicious IP 23.95.97.18 → {{"tool": "ip_analysis", "target": "23.95.97.18", "reason": "Check IP reputation"}}
- If you see concurrent logins → {{"tool": "temporal_analysis", "target": {{"username": "john", "timestamp": "...", "time_window_minutes": 60}}, "reason": "Find related authentication events"}}
- If you see unknown process.exe → {{"tool": "process_analysis", "target": "process.exe", "reason": "Analyze process behavior"}}"""

    def _summarize_alert_data(self, context: Dict[str, Any]) -> str:
        """Summarize key alert data for LLM."""
        summary_parts = []

        raw_data = context.get("raw_data", {})
        entities = context.get("entities", [])

        # Extract key indicators
        if raw_data:
            for key in ["source_ip", "destination_ip", "username", "process_name", "file_hash"]:
                if key in raw_data and raw_data[key]:
                    summary_parts.append(f"  - {key}: {raw_data[key]}")

        # Add entities
        for entity in entities[:5]:  # First 5 entities
            entity_type = entity.get("type", "unknown")
            entity_value = entity.get("value", "")
            if entity_value:
                summary_parts.append(f"  - {entity_type}: {entity_value}")

        return "\n".join(summary_parts) if summary_parts else "  (no specific indicators extracted)"
