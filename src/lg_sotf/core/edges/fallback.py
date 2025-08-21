"""
Fallback handler for LG-SOTF workflow edges.

This module provides fallback mechanisms when primary routing
or processing fails, ensuring system resilience.
"""

import asyncio
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..config.manager import ConfigManager
from ..exceptions import RoutingError
from ..state.model import SOCState, TriageStatus


class FallbackHandler:
    """Handles fallback scenarios in workflow execution."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.fallback_config = config_manager.get('fallback', {})
        self.fallback_history = []
    
    async def handle_agent_failure(self, agent_name: str, error: Exception, 
                                 state: SOCState) -> Dict[str, Any]:
        """Handle agent execution failure.
        
        Args:
            agent_name: Name of the failed agent
            error: Exception that occurred
            state: Current state
            
        Returns:
            Fallback state with error handling information
        """
        try:
            # Log the failure
            fallback_entry = {
                'timestamp': datetime.utcnow(),
                'agent_name': agent_name,
                'error_type': type(error).__name__,
                'error_message': str(error),
                'state_id': state.alert_id,
                'fallback_action': 'agent_failure'
            }
            self.fallback_history.append(fallback_entry)
            
            # Get fallback configuration for this agent
            agent_fallback_config = self.fallback_config.get('agents', {}).get(agent_name, {})
            
            # Determine fallback strategy
            fallback_strategy = agent_fallback_config.get('strategy', 'continue')
            
            if fallback_strategy == 'retry':
                return await self._retry_agent(agent_name, state, agent_fallback_config)
            elif fallback_strategy == 'skip':
                return await self._skip_agent(agent_name, state, agent_fallback_config)
            elif fallback_strategy == 'escalate':
                return await self._escalate_failure(agent_name, state, agent_fallback_config)
            else:
                return await self._continue_processing(agent_name, state, agent_fallback_config)
                
        except Exception as e:
            raise RoutingError(f"Error handling agent failure: {e}")
    
    async def handle_routing_failure(self, error: Exception, state: SOCState) -> str:
        """Handle routing decision failure.
        
        Args:
            error: Exception that occurred
            state: Current state
            
        Returns:
            Fallback routing decision
        """
        try:
            # Log the failure
            fallback_entry = {
                'timestamp': datetime.utcnow(),
                'error_type': type(error).__name__,
                'error_message': str(error),
                'state_id': state.alert_id,
                'fallback_action': 'routing_failure'
            }
            self.fallback_history.append(fallback_entry)
            
            # Get fallback configuration for routing
            routing_fallback_config = self.fallback_config.get('routing', {})
            
            # Determine fallback routing
            fallback_route = routing_fallback_config.get('default_route', 'human_loop')
            
            # Check if we should use a different route based on error type
            error_type = type(error).__name__
            error_routes = routing_fallback_config.get('error_routes', {})
            
            if error_type in error_routes:
                fallback_route = error_routes[error_type]
            
            return fallback_route
            
        except Exception as e:
            raise RoutingError(f"Error handling routing failure: {e}")
    
    async def handle_system_overload(self, state: SOCState) -> Dict[str, Any]:
        """Handle system overload scenarios.
        
        Args:
            state: Current state
            
        Returns:
            Fallback state with overload handling information
        """
        try:
            # Log the overload
            fallback_entry = {
                'timestamp': datetime.utcnow(),
                'error_type': 'SystemOverload',
                'error_message': 'System resources overloaded',
                'state_id': state.alert_id,
                'fallback_action': 'system_overload'
            }
            self.fallback_history.append(fallback_entry)
            
            # Get overload configuration
            overload_config = self.fallback_config.get('overload', {})
            
            # Determine overload strategy
            overload_strategy = overload_config.get('strategy', 'queue')
            
            if overload_strategy == 'queue':
                return await self._queue_alert(state, overload_config)
            elif overload_strategy == 'throttle':
                return await self._throttle_processing(state, overload_config)
            elif overload_strategy == 'reject':
                return await self._reject_alert(state, overload_config)
            else:
                return await self._continue_with_reduced_priority(state, overload_config)
                
        except Exception as e:
            raise RoutingError(f"Error handling system overload: {e}")
    
    async def _retry_agent(self, agent_name: str, state: SOCState, 
                          config: Dict[str, Any]) -> Dict[str, Any]:
        """Retry agent execution with backoff."""
        max_retries = config.get('max_retries', 3)
        backoff_seconds = config.get('backoff_seconds', 5)
        
        for attempt in range(max_retries):
            try:
                # Add delay for backoff
                if attempt > 0:
                    await asyncio.sleep(backoff_seconds * (2 ** attempt))
                
                # Try to get and execute agent
                from ...agents.registry import agent_registry
                agent = agent_registry.get_agent(agent_name)
                result = await agent.execute(state.dict())
                
                # Add retry information to state
                result['retry_info'] = {
                    'attempts': attempt + 1,
                    'max_retries': max_retries,
                    'agent_name': agent_name,
                    'fallback_used': 'retry'
                }
                
                return result
                
            except Exception as e:
                if attempt == max_retries - 1:
                    # Last attempt failed, escalate
                    return await self._escalate_failure(agent_name, state, config)
                continue
        
        # This should not be reached, but just in case
        return await self._escalate_failure(agent_name, state, config)
    
    async def _skip_agent(self, agent_name: str, state: SOCState, 
                        config: Dict[str, Any]) -> Dict[str, Any]:
        """Skip agent execution and continue."""
        # Add skip information to state
        state_dict = state.dict()
        state_dict['skip_info'] = {
            'skipped_agent': agent_name,
            'fallback_used': 'skip',
            'reason': 'Agent execution skipped due to failure'
        }
        
        return state_dict
    
    async def _escalate_failure(self, agent_name: str, state: SOCState, 
                               config: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate agent failure to human review."""
        # Escalate to human loop
        state_dict = state.dict()
        state_dict['escalation_info'] = {
            'failed_agent': agent_name,
            'fallback_used': 'escalate',
            'reason': 'Agent failure escalated to human review',
            'escalation_level': state.escalation_level + 1
        }
        
        # Update triage status
        state_dict['triage_status'] = TriageStatus.ESCALATED
        
        return state_dict
    
    async def _continue_processing(self, agent_name: str, state: SOCState, 
                                 config: Dict[str, Any]) -> Dict[str, Any]:
        """Continue processing without the failed agent."""
        # Add continue information to state
        state_dict = state.dict()
        state_dict['continue_info'] = {
            'failed_agent': agent_name,
            'fallback_used': 'continue',
            'reason': 'Continuing processing without failed agent'
        }
        
        return state_dict
    
    async def _queue_alert(self, state: SOCState, config: Dict[str, Any]) -> Dict[str, Any]:
        """Queue alert for later processing."""
        queue_delay = config.get('queue_delay_seconds', 60)
        
        state_dict = state.dict()
        state_dict['queue_info'] = {
            'fallback_used': 'queue',
            'reason': 'Alert queued due to system overload',
            'queue_delay': queue_delay,
            'queued_until': (datetime.utcnow() + timedelta(seconds=queue_delay)).isoformat()
        }
        
        return state_dict
    
    async def _throttle_processing(self, state: SOCState, config: Dict[str, Any]) -> Dict[str, Any]:
        """Throttle alert processing."""
        throttle_delay = config.get('throttle_delay_seconds', 30)
        
        state_dict = state.dict()
        state_dict['throttle_info'] = {
            'fallback_used': 'throttle',
            'reason': 'Processing throttled due to system overload',
            'throttle_delay': throttle_delay,
            'throttle_until': (datetime.utcnow() + timedelta(seconds=throttle_delay)).isoformat()
        }
        
        return state_dict
    
    async def _reject_alert(self, state: SOCState, config: Dict[str, Any]) -> Dict[str, Any]:
        """Reject alert due to system overload."""
        state_dict = state.dict()
        state_dict['reject_info'] = {
            'fallback_used': 'reject',
            'reason': 'Alert rejected due to system overload',
            'rejection_time': datetime.utcnow().isoformat()
        }
        
        # Close the alert
        state_dict['triage_status'] = TriageStatus.CLOSED
        
        return state_dict
    
    async def _continue_with_reduced_priority(self, state: SOCState, 
                                            config: Dict[str, Any]) -> Dict[str, Any]:
        """Continue processing with reduced priority."""
        priority_reduction = config.get('priority_reduction', 1)
        
        state_dict = state.dict()
        state_dict['priority_reduction_info'] = {
            'fallback_used': 'priority_reduction',
            'reason': 'Priority reduced due to system overload',
            'original_priority': state.priority_level,
            'reduced_priority': max(1, state.priority_level - priority_reduction)
        }
        
        # Update priority
        state_dict['priority_level'] = max(1, state.priority_level - priority_reduction)
        
        return state_dict
    
    def get_fallback_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get fallback history.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of fallback history entries
        """
        return self.fallback_history[-limit:]
    
    def get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback statistics.
        
        Returns:
            Dictionary with fallback statistics
        """
        if not self.fallback_history:
            return {
                'total_fallbacks': 0,
                'by_type': {},
                'by_agent': {},
                'by_hour': {}
            }
        
        stats = {
            'total_fallbacks': len(self.fallback_history),
            'by_type': {},
            'by_agent': {},
            'by_hour': {}
        }
        
        # Count by type
        for entry in self.fallback_history:
            fallback_type = entry['fallback_action']
            stats['by_type'][fallback_type] = stats['by_type'].get(fallback_type, 0) + 1
        
        # Count by agent
        for entry in self.fallback_history:
            if 'agent_name' in entry:
                agent_name = entry['agent_name']
                stats['by_agent'][agent_name] = stats['by_agent'].get(agent_name, 0) + 1
        
        # Count by hour
        for entry in self.fallback_history:
            hour = entry['timestamp'].hour
            stats['by_hour'][hour] = stats['by_hour'].get(hour, 0) + 1
        
        return stats
    
    def clear_fallback_history(self):
        """Clear fallback history."""
        self.fallback_history.clear()