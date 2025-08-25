"""
Edge router implementation for LG-SOTF.

This module provides the main edge routing functionality,
including conditional routing and policy-based decisions.
"""

from typing import Any, Dict, List

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import RoutingError
from lg_sotf.core.state.model import SOCState, TriageStatus
from lg_sotf.core.edges.conditions import RoutingConditions
from lg_sotf.core.edges.fallback import FallbackHandler
from lg_sotf.core.edges.policies import RoutingPolicies


class EdgeRouter:
    """Handles edge routing decisions in the workflow."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.conditions = RoutingConditions(config_manager)
        self.policies = RoutingPolicies(config_manager)
        self.fallback = FallbackHandler(config_manager)
    
    async def route_after_ingestion(self, state: Dict[str, Any]) -> str:
        """Route after ingestion node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if alert is valid
            if not self._is_valid_alert(soc_state):
                return "close"
            
            # Check if alert requires immediate processing
            if self._is_high_priority(soc_state):
                return "triage"
            
            return "triage"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after ingestion: {str(e)}")
    
    async def route_after_triage(self, state: Dict[str, Any]) -> str:
        """Route after triage node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if alert should be closed
            if await self.conditions.should_close_alert(soc_state):
                return "close"
            
            # Check if correlation is needed
            if await self.conditions.needs_correlation(soc_state):
                return "correlation"
            
            # Check if analysis is needed
            if await self.conditions.needs_analysis(soc_state):
                return "analysis"
            
            # Default to human loop
            return "human_loop"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after triage: {str(e)}")
    
    async def route_after_correlation(self, state: Dict[str, Any]) -> str:
        """Route after correlation node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if alert should be closed
            if await self.conditions.should_close_alert(soc_state):
                return "close"
            
            # Check if analysis is needed
            if await self.conditions.needs_analysis(soc_state):
                return "analysis"
            
            # Default to human loop
            return "human_loop"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after correlation: {str(e)}")
    
    async def route_after_analysis(self, state: Dict[str, Any]) -> str:
        """Route after analysis node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if alert should be closed
            if await self.conditions.should_close_alert(soc_state):
                return "close"
            
            # Check if human review is needed
            if await self.conditions.needs_human_review(soc_state):
                return "human_loop"
            
            # Check if response is needed
            if await self.conditions.needs_response(soc_state):
                return "response"
            
            # Default to close
            return "close"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after analysis: {str(e)}")
    
    async def route_after_human_loop(self, state: Dict[str, Any]) -> str:
        """Route after human loop node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if alert should be closed
            if await self.conditions.should_close_alert(soc_state):
                return "close"
            
            # Check if additional analysis is needed
            if await self.conditions.needs_analysis(soc_state):
                return "analysis"
            
            # Check if response is needed
            if await self.conditions.needs_response(soc_state):
                return "response"
            
            # Default to close
            return "close"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after human loop: {str(e)}")
    
    async def route_after_response(self, state: Dict[str, Any]) -> str:
        """Route after response node."""
        try:
            soc_state = SOCState.parse_obj(state)
            
            # Check if learning is needed
            if await self.conditions.needs_learning(soc_state):
                return "learning"
            
            # Default to close
            return "close"
            
        except Exception as e:
            raise RoutingError(f"Failed to route after response: {str(e)}")
    
    def _is_valid_alert(self, state: SOCState) -> bool:
        """Check if alert is valid."""
        return (
            state.alert_id and
            state.raw_alert and
            state.triage_status == TriageStatus.INGESTED
        )
    
    def _is_high_priority(self, state: SOCState) -> bool:
        """Check if alert is high priority."""
        return (
            state.priority_level <= 2 or  # Priority 1 or 2
            state.confidence_score >= 80 or  # High confidence
            any('critical' in indicator.lower() for indicator in state.tp_indicators)
        )