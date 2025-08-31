"""
ReAct reasoning implementation for analysis agent.
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.utils.llm import get_llm_client


class ReActReasoner:
    """Implements ReAct (Reasoning and Acting) pattern for threat analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.llm_client = None
        
        # ReAct configuration
        self.max_iterations = config.get("max_iterations", 5)
        self.reasoning_temperature = config.get("reasoning_temperature", 0.3)
        self.action_temperature = config.get("action_temperature", 0.1)
        
    async def initialize(self):
        """Initialize ReAct reasoner."""
        try:
            config_manager = ConfigManager()
            self.llm_client = get_llm_client(config_manager)
            self.logger.info("ReAct reasoner initialized")
        except Exception as e:
            self.logger.error(f"ReAct reasoner initialization failed: {e}")
            raise
    
    async def reason_and_act(self, context: Dict[str, Any], available_tools: List[str],
                             execute_action_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute ReAct reasoning loop."""
        
        thoughts = []
        actions = []
        observations = []
        action_results = {}
        
        for iteration in range(self.max_iterations):
            # Reasoning step
            thought = await self._generate_thought(context, thoughts, actions, observations, available_tools)
            thoughts.append({"iteration": iteration + 1, "thought": thought})
            
            # Action step
            action = await self._generate_action(thought, available_tools, context)
            if not action:
                break
                
            actions.append({"iteration": iteration + 1, "action": action})
            
           # Observation step: Execute action if callback provided
            if execute_action_callback:
                try:
                    observation = await execute_action_callback(action, context.get("alert", {}), context.get("state", {}))
                    observations.append({"iteration": iteration + 1, "observation": observation})
                    action_results[f"action_{iteration}"] = observation  # Store result
                except Exception as e:
                    observation = {"error": str(e)}
                    observations.append({"iteration": iteration + 1, "observation": observation})
            else:
                observation = f"Action {action['tool']} completed with target {action.get('target', 'N/A')}"
                observations.append({"iteration": iteration + 1, "observation": observation})
            
            # Check if we should continue
            if await self._should_stop_reasoning(thought, action, observation):
                break
        
        return {
            "thoughts": thoughts,
            "actions": actions, 
            "observations": observations,
            "action_results": action_results,  # New: Return executed results
            "final_reasoning": thoughts[-1]["thought"] if thoughts else "No reasoning completed",
            "iterations_completed": len(thoughts)
        }
    
    async def _generate_thought(self, context: Dict[str, Any], thoughts: List[Dict], 
                               actions: List[Dict], observations: List[Dict], 
                               available_tools: List[str]) -> str:
        """Generate reasoning thought."""
        
        prompt = self._build_thought_prompt(context, thoughts, actions, observations, available_tools)
        
        try:
            response = await self.llm_client.ainvoke(prompt)
            return response.content.strip()
        except Exception as e:
            self.logger.warning(f"LLM thought generation failed: {e}")
            return self._fallback_thought(context, len(thoughts))
    
    async def _generate_action(self, thought: str, available_tools: List[str], 
                             context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate action based on thought."""
        
        prompt = self._build_action_prompt(thought, available_tools, context)
        
        try:
            response = await self.llm_client.ainvoke(prompt)
            return self._parse_action(response.content, available_tools)
        except Exception as e:
            self.logger.warning(f"LLM action generation failed: {e}")
            return self._fallback_action(available_tools, context)
    
    def _build_thought_prompt(self, context: Dict[str, Any], thoughts: List[Dict], 
                             actions: List[Dict], observations: List[Dict], 
                             available_tools: List[str]) -> str:
        """Build prompt for thought generation."""
        
        previous_context = ""
        if thoughts:
            previous_context = "\n\nPrevious reasoning:\n"
            for i, (thought, action, obs) in enumerate(zip(thoughts, actions, observations)):
                previous_context += f"Iteration {i+1}:\n"
                previous_context += f"Thought: {thought['thought']}\n"
                previous_context += f"Action: {action['action']}\n"
                previous_context += f"Observation: {obs['observation']}\n\n"
        
        return f"""You are analyzing a security alert using the ReAct (Reasoning and Acting) framework.

ALERT CONTEXT:
{json.dumps(context, indent=2)}

AVAILABLE TOOLS:
{', '.join(available_tools)}

{previous_context}

Based on the context and any previous analysis, what do you think about this alert? 
Consider:
1. What type of threat this might be
2. What evidence supports or contradicts this hypothesis  
3. What additional information would be helpful
4. Your confidence level in the current assessment

Provide your reasoning in 2-3 sentences focusing on the most important aspects."""
    
    def _build_action_prompt(self, thought: str, available_tools: List[str], 
                           context: Dict[str, Any]) -> str:
        """Build prompt for action generation."""
        
        return f"""Based on your reasoning: "{thought}"

Available tools: {', '.join(available_tools)}

Context: {json.dumps(context, indent=2)}

What tool should be used next to gather more information? Respond in JSON format:
{{
    "tool": "tool_name",
    "target": "what to analyze",
    "reason": "why this tool/target"
}}

If no further analysis is needed, respond with: {{"tool": "none", "reason": "analysis complete"}}"""
    
    def _parse_action(self, response: str, available_tools: List[str]) -> Optional[Dict[str, Any]]:
        """Parse action from LLM response."""
        try:
            # Clean response
            content = response.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            
            action = json.loads(content)
            
            if action.get("tool") == "none":
                return None
                
            if action.get("tool") not in available_tools:
                return None
                
            return action
            
        except Exception as e:
            self.logger.warning(f"Failed to parse action: {e}")
            return None
    
    def _fallback_thought(self, context: Dict[str, Any], iteration: int) -> str:
        """Fallback thought generation."""
        confidence = context.get("confidence_score", 50)
        
        if iteration == 0:
            return f"Initial assessment shows {confidence}% confidence. Need to investigate key indicators."
        else:
            return f"Continuing analysis to resolve remaining uncertainties in threat assessment."
    
    def _fallback_action(self, available_tools: List[str], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fallback action generation."""
        raw_data = context.get("raw_alert", {}).get("raw_data", {})
        
        # Simple heuristics for tool selection
        if "ip_analysis" in available_tools and (raw_data.get("source_ip") or raw_data.get("destination_ip")):
            return {
                "tool": "ip_analysis",
                "target": raw_data.get("source_ip") or raw_data.get("destination_ip"),
                "reason": "Analyze IP reputation"
            }
        elif "hash_analysis" in available_tools and raw_data.get("file_hash"):
            return {
                "tool": "hash_analysis", 
                "target": raw_data.get("file_hash"),
                "reason": "Check file hash reputation"
            }
        
        return None
    
    async def _should_stop_reasoning(
        self, thought: str, action: Optional[Dict], observation: Any, context: Optional[Dict] = None
    ) -> bool:
        """Determine if reasoning should stop with improved logic."""
        
        if not action:
            self.logger.info("Stopping reasoning: no action generated")
            return True

        thought_lower = thought.lower()
        context_conf = context.get("confidence_score", None) if context else None

        # 1. Confidence-based stopping
        if context_conf is not None:
            if context_conf >= 95:
                self.logger.info(f"Stopping reasoning: high numeric confidence ({context_conf}%)")
                return True
            if context_conf <= 10:
                self.logger.info(f"Stopping reasoning: very low numeric confidence ({context_conf}%)")
                return True

        # 2. Text-based reasoning with negation check
        high_conf_triggers = ["high confidence", "certain", "definitely"]
        low_conf_triggers = ["false positive", "benign", "no threat"]

        if any(phrase in thought_lower for phrase in high_conf_triggers):
            self.logger.info(f"Stopping reasoning: high confidence phrase in thought -> {thought}")
            return True

        for phrase in low_conf_triggers:
            if phrase in thought_lower:
                # Negation-aware: ignore "not a false positive" etc.
                if any(neg in thought_lower for neg in ["not", "unlikely", "improbable"]):
                    self.logger.debug(f"Ignoring negated low-confidence phrase '{phrase}' in thought -> {thought}")
                    continue
                self.logger.info(f"Stopping reasoning: low confidence/benign phrase in thought -> {thought}")
                return True

        # 3. Observation-based stopping
        if isinstance(observation, str) and any(
            kw in observation.lower() for kw in ["analysis complete", "no threat found", "no further action"]
        ):
            self.logger.info(f"Stopping reasoning: observation indicates completion -> {observation}")
            return True

        self.logger.debug("Continuing reasoning: no stop condition met")
        return False


