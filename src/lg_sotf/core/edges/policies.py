"""
Routing policies for LG-SOTF workflow edges.

This module provides policy-based routing decisions that can be
configured and customized based on organizational requirements.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config.manager import ConfigManager
from ..exceptions import RoutingError
from ..state.model import SOCState, TriageStatus


class RoutingPolicies:
    """Handles policy-based routing decisions."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.policies_config = config_manager.get('policies', {})
        self.policies = self._load_policies()
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load routing policies from configuration."""
        return {
            'escalation': self.policies_config.get('escalation', {}),
            'throttling': self.policies_config.get('throttling', {}),
            'prioritization': self.policies_config.get('prioritization', {}),
            'time_based': self.policies_config.get('time_based', {}),
            'resource_based': self.policies_config.get('resource_based', {})
        }
    
    async def apply_escalation_policy(self, state: SOCState) -> Dict[str, Any]:
        """Apply escalation policy to determine routing.
        
        Args:
            state: Current SOC state
            
        Returns:
            Policy decision with routing information
        """
        try:
            escalation_config = self.policies['escalation']
            
            # Get current escalation level
            current_level = state.escalation_level
            
            # Check if escalation is needed
            escalation_rules = escalation_config.get('rules', [])
            
            for rule in escalation_rules:
                if self._matches_escalation_rule(state, rule):
                    return {
                        'escalate': True,
                        'target_level': rule.get('target_level', current_level + 1),
                        'reason': rule.get('reason', 'Escalation rule matched'),
                        'policy': 'escalation'
                    }
            
            return {
                'escalate': False,
                'target_level': current_level,
                'reason': 'No escalation rule matched',
                'policy': 'escalation'
            }
            
        except Exception as e:
            raise RoutingError(f"Error applying escalation policy: {e}")
    
    async def apply_throttling_policy(self, state: SOCState) -> Dict[str, Any]:
        """Apply throttling policy to manage alert processing rate.
        
        Args:
            state: Current SOC state
            
        Returns:
            Policy decision with throttling information
        """
        try:
            throttling_config = self.policies['throttling']
            
            # Check if throttling is enabled
            if not throttling_config.get('enabled', False):
                return {
                    'throttle': False,
                    'delay': 0,
                    'reason': 'Throttling disabled',
                    'policy': 'throttling'
                }
            
            # Get current processing metrics
            current_load = self._get_current_load()
            max_load = throttling_config.get('max_load', 100)
            
            # Apply throttling if load is high
            if current_load > max_load:
                delay = throttling_config.get('delay_seconds', 30)
                return {
                    'throttle': True,
                    'delay': delay,
                    'reason': f'High load: {current_load}% > {max_load}%',
                    'policy': 'throttling'
                }
            
            return {
                'throttle': False,
                'delay': 0,
                'reason': f'Load acceptable: {current_load}% <= {max_load}%',
                'policy': 'throttling'
            }
            
        except Exception as e:
            raise RoutingError(f"Error applying throttling policy: {e}")
    
    async def apply_prioritization_policy(self, state: SOCState) -> Dict[str, Any]:
        """Apply prioritization policy to determine alert priority.
        
        Args:
            state: Current SOC state
            
        Returns:
            Policy decision with priority information
        """
        try:
            prioritization_config = self.policies['prioritization']
            
            # Calculate base priority
            base_priority = state.priority_level
            
            # Apply priority adjustments
            adjustments = prioritization_config.get('adjustments', [])
            
            adjustment = 0
            adjustment_reasons = []
            
            for adjustment_rule in adjustments:
                if self._matches_priority_rule(state, adjustment_rule):
                    adjustment += adjustment_rule.get('adjustment', 0)
                    adjustment_reasons.append(adjustment_rule.get('reason', 'Priority adjustment'))
            
            # Calculate final priority
            final_priority = max(1, min(5, base_priority + adjustment))
            
            return {
                'base_priority': base_priority,
                'adjustment': adjustment,
                'final_priority': final_priority,
                'reasons': adjustment_reasons,
                'policy': 'prioritization'
            }
            
        except Exception as e:
            raise RoutingError(f"Error applying prioritization policy: {e}")
    
    async def apply_time_based_policy(self, state: SOCState) -> Dict[str, Any]:
        """Apply time-based routing policies.
        
        Args:
            state: Current SOC state
            
        Returns:
            Policy decision with time-based routing information
        """
        try:
            time_config = self.policies['time_based']
            
            # Get current time
            now = datetime.utcnow()
            current_hour = now.hour
            current_day = now.weekday()
            
            # Check time-based rules
            time_rules = time_config.get('rules', [])
            
            for rule in time_rules:
                if self._matches_time_rule(current_hour, current_day, rule):
                    return {
                        'apply_time_policy': True,
                        'action': rule.get('action', 'no_action'),
                        'reason': rule.get('reason', 'Time-based rule matched'),
                        'policy': 'time_based'
                    }
            
            return {
                'apply_time_policy': False,
                'action': 'no_action',
                'reason': 'No time-based rule matched',
                'policy': 'time_based'
            }
            
        except Exception as e:
            raise RoutingError(f"Error applying time-based policy: {e}")
    
    async def apply_resource_based_policy(self, state: SOCState) -> Dict[str, Any]:
        """Apply resource-based routing policies.
        
        Args:
            state: Current SOC state
            
        Returns:
            Policy decision with resource-based routing information
        """
        try:
            resource_config = self.policies['resource_based']
            
            # Get current resource usage
            resource_usage = self._get_resource_usage()
            
            # Check resource-based rules
            resource_rules = resource_config.get('rules', [])
            
            for rule in resource_rules:
                if self._matches_resource_rule(resource_usage, rule):
                    return {
                        'apply_resource_policy': True,
                        'action': rule.get('action', 'no_action'),
                        'reason': rule.get('reason', 'Resource-based rule matched'),
                        'policy': 'resource_based'
                    }
            
            return {
                'apply_resource_policy': False,
                'action': 'no_action',
                'reason': 'No resource-based rule matched',
                'policy': 'resource_based'
            }
            
        except Exception as e:
            raise RoutingError(f"Error applying resource-based policy: {e}")
    
    def _matches_escalation_rule(self, state: SOCState, rule: Dict[str, Any]) -> bool:
        """Check if state matches escalation rule."""
        conditions = rule.get('conditions', {})
        
        # Check confidence score condition
        if 'confidence_score' in conditions:
            conf_condition = conditions['confidence_score']
            if not self._matches_range(state.confidence_score, conf_condition):
                return False
        
        # Check priority condition
        if 'priority_level' in conditions:
            priority_condition = conditions['priority_level']
            if not self._matches_range(state.priority_level, priority_condition):
                return False
        
        # Check escalation level condition
        if 'escalation_level' in conditions:
            escalation_condition = conditions['escalation_level']
            if not self._matches_range(state.escalation_level, escalation_condition):
                return False
        
        # Check indicator conditions
        if 'tp_indicators' in conditions:
            tp_condition = conditions['tp_indicators']
            if not self._matches_indicators(state.tp_indicators, tp_condition):
                return False
        
        return True
    
    def _matches_priority_rule(self, state: SOCState, rule: Dict[str, Any]) -> bool:
        """Check if state matches priority rule."""
        conditions = rule.get('conditions', {})
        
        # Check time-based conditions
        if 'time_hours' in conditions:
            time_condition = conditions['time_hours']
            current_hour = datetime.utcnow().hour
            if current_hour not in time_condition:
                return False
        
        # Check severity conditions
        if 'severity' in conditions:
            severity_condition = conditions['severity']
            if state.raw_alert.get('severity') not in severity_condition:
                return False
        
        # Check indicator conditions
        if 'indicators' in conditions:
            indicator_condition = conditions['indicators']
            all_indicators = state.tp_indicators + state.fp_indicators
            if not self._matches_indicators(all_indicators, indicator_condition):
                return False
        
        return True
    
    def _matches_time_rule(self, hour: int, day: int, rule: Dict[str, Any]) -> bool:
        """Check if time matches time rule."""
        conditions = rule.get('conditions', {})
        
        # Check hour conditions
        if 'hours' in conditions:
            if hour not in conditions['hours']:
                return False
        
        # Check day conditions
        if 'days' in conditions:
            if day not in conditions['days']:
                return False
        
        return True
    
    def _matches_resource_rule(self, resource_usage: Dict[str, float], rule: Dict[str, Any]) -> bool:
        """Check if resource usage matches resource rule."""
        conditions = rule.get('conditions', {})
        
        # Check CPU usage
        if 'cpu_usage' in conditions:
            cpu_condition = conditions['cpu_usage']
            if not self._matches_range(resource_usage.get('cpu', 0), cpu_condition):
                return False
        
        # Check memory usage
        if 'memory_usage' in conditions:
            memory_condition = conditions['memory_usage']
            if not self._matches_range(resource_usage.get('memory', 0), memory_condition):
                return False
        
        # Check disk usage
        if 'disk_usage' in conditions:
            disk_condition = conditions['disk_usage']
            if not self._matches_range(resource_usage.get('disk', 0), disk_condition):
                return False
        
        return True
    
    def _matches_range(self, value: float, condition: Dict[str, Any]) -> bool:
        """Check if value matches range condition."""
        if 'min' in condition and value < condition['min']:
            return False
        
        if 'max' in condition and value > condition['max']:
            return False
        
        if 'values' in condition and value not in condition['values']:
            return False
        
        return True
    
    def _matches_indicators(self, indicators: List[str], condition: Dict[str, Any]) -> bool:
        """Check if indicators match condition."""
        if 'contains' in condition:
            required_indicators = condition['contains']
            return all(indicator in indicators for indicator in required_indicators)
        
        if 'contains_any' in condition:
            any_indicators = condition['contains_any']
            return any(indicator in indicators for indicator in any_indicators)
        
        if 'count' in condition:
            count_condition = condition['count']
            return self._matches_range(len(indicators), count_condition)
        
        return True
    
    def _get_current_load(self) -> float:
        """Get current system load percentage."""
        # This is a simplified implementation
        # In production, this would query actual system metrics
        import random
        return random.uniform(0, 100)
    
    def _get_resource_usage(self) -> Dict[str, float]:
        """Get current resource usage percentages."""
        # This is a simplified implementation
        # In production, this would query actual system metrics
        import random
        return {
            'cpu': random.uniform(0, 100),
            'memory': random.uniform(0, 100),
            'disk': random.uniform(0, 100)
        }