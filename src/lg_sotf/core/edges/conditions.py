"""
Routing conditions for LG-SOTF workflow edges.

This module provides the conditional logic for determining workflow routing
based on alert characteristics and system state.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List

from ..config.manager import ConfigManager
from ..exceptions import RoutingError
from ..state.model import SOCState, TriageStatus


class RoutingConditions:
    """Handles routing condition evaluation for workflow edges."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.routing_config = config_manager.get('routing', {})
    
    async def should_close_alert(self, state: SOCState) -> bool:
        """Determine if an alert should be closed.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if alert should be closed, False otherwise
        """
        try:
            # Close if already closed
            if state.triage_status == TriageStatus.CLOSED:
                return True
            
            # Close if confidence score indicates clear false positive
            if state.confidence_score <= 10 and len(state.fp_indicators) >= 2:
                return True
            
            # Close if alert is too old (configurable threshold)
            alert_age = self._calculate_alert_age(state)
            max_age_hours = self.routing_config.get('max_alert_age_hours', 72)
            if alert_age > max_age_hours:
                return True
            
            # Close if explicitly marked for closure
            if state.metadata.get('marked_for_closure', False):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating close condition: {e}")
    
    async def needs_correlation(self, state: SOCState) -> bool:
        """Determine if an alert needs correlation.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if correlation is needed, False otherwise
        """
        try:
            # Skip correlation if already correlated
            if state.triage_status in [TriageStatus.CORRELATED, TriageStatus.ANALYZED, TriageStatus.ESCALATED]:
                return False
            
            # Need correlation if confidence score is in grey zone
            grey_zone_min = self.routing_config.get('correlation_grey_zone_min', 30)
            grey_zone_max = self.routing_config.get('correlation_grey_zone_max', 70)
            
            if grey_zone_min <= state.confidence_score <= grey_zone_max:
                return True
            
            # Need correlation if alert has network indicators
            raw_alert = state.raw_alert
            if self._has_network_indicators(raw_alert):
                return True
            
            # Need correlation if alert has user indicators
            if self._has_user_indicators(raw_alert):
                return True
            
            # Need correlation if explicitly requested
            if state.metadata.get('request_correlation', False):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating correlation condition: {e}")
    
    async def needs_analysis(self, state: SOCState) -> bool:
        """Determine if an alert needs analysis.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if analysis is needed, False otherwise
        """
        try:
            # Skip analysis if already analyzed
            if state.triage_status in [TriageStatus.ANALYZED, TriageStatus.ESCALATED]:
                return False
            
            # Need analysis if confidence score is low
            analysis_threshold = self.routing_config.get('analysis_threshold', 40)
            if state.confidence_score < analysis_threshold:
                return True
            
            # Need analysis if alert has file indicators
            raw_alert = state.raw_alert
            if self._has_file_indicators(raw_alert):
                return True
            
            # Need analysis if alert has process indicators
            if self._has_process_indicators(raw_alert):
                return True
            
            # Need analysis if explicitly requested
            if state.metadata.get('request_analysis', False):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating analysis condition: {e}")
    
    async def needs_human_review(self, state: SOCState) -> bool:
        """Determine if an alert needs human review.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if human review is needed, False otherwise
        """
        try:
            # Need human review if already escalated
            if state.triage_status == TriageStatus.ESCALATED:
                return True
            
            # Need human review if confidence score is in human review zone
            human_review_min = self.routing_config.get('human_review_min', 20)
            human_review_max = self.routing_config.get('human_review_max', 60)
            
            if human_review_min <= state.confidence_score <= human_review_max:
                return True
            
            # Need human review if alert is high priority
            if state.priority_level <= 2:  # Priority 1 or 2
                return True
            
            # Need human review if alert has critical indicators
            if self._has_critical_indicators(state):
                return True
            
            # Need human review if explicitly requested
            if state.metadata.get('request_human_review', False):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating human review condition: {e}")
    
    async def needs_response(self, state: SOCState) -> bool:
        """Determine if an alert needs response.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if response is needed, False otherwise
        """
        try:
            # Need response if alert is confirmed threat
            response_threshold = self.routing_config.get('response_threshold', 80)
            if state.confidence_score >= response_threshold:
                return True
            
            # Need response if explicitly marked for response
            if state.metadata.get('marked_for_response', False):
                return True
            
            # Need response if human confirmed threat
            if (state.human_feedback and 
                state.human_feedback.feedback_type == 'confirmed_tp'):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating response condition: {e}")
    
    async def needs_learning(self, state: SOCState) -> bool:
        """Determine if an alert needs learning.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if learning is needed, False otherwise
        """
        try:
            # Need learning if there's human feedback
            if state.human_feedback:
                return True
            
            # Need learning if explicitly requested
            if state.metadata.get('request_learning', False):
                return True
            
            # Need learning if alert has learning indicators
            if self._has_learning_indicators(state):
                return True
            
            return False
            
        except Exception as e:
            raise RoutingError(f"Error evaluating learning condition: {e}")
    
    def _calculate_alert_age(self, state: SOCState) -> float:
        """Calculate alert age in hours.
        
        Args:
            state: Current SOC state
            
        Returns:
            Alert age in hours
        """
        if not state.created_at:
            return 0.0
        
        created_time = state.created_at
        if isinstance(created_time, str):
            created_time = datetime.fromisoformat(created_time.replace('Z', '+00:00'))
        
        now = datetime.utcnow()
        age = (now - created_time).total_seconds()
        return age / 3600  # Convert to hours
    
    def _has_network_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has network indicators.
        
        Args:
            raw_alert: Raw alert data
            
        Returns:
            True if network indicators are present
        """
        network_keywords = ['ip', 'port', 'connection', 'network', 'socket', 'dns']
        
        alert_str = str(raw_alert).lower()
        return any(keyword in alert_str for keyword in network_keywords)
    
    def _has_user_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has user indicators.
        
        Args:
            raw_alert: Raw alert data
            
        Returns:
            True if user indicators are present
        """
        user_keywords = ['user', 'account', 'login', 'authentication', 'credential']
        
        alert_str = str(raw_alert).lower()
        return any(keyword in alert_str for keyword in user_keywords)
    
    def _has_file_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has file indicators.
        
        Args:
            raw_alert: Raw alert data
            
        Returns:
            True if file indicators are present
        """
        file_keywords = ['file', 'hash', 'path', 'extension', 'executable']
        
        alert_str = str(raw_alert).lower()
        return any(keyword in alert_str for keyword in file_keywords)
    
    def _has_process_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has process indicators.
        
        Args:
            raw_alert: Raw alert data
            
        Returns:
            True if process indicators are present
        """
        process_keywords = ['process', 'pid', 'executable', 'command', 'argument']
        
        alert_str = str(raw_alert).lower()
        return any(keyword in alert_str for keyword in process_keywords)
    
    def _has_critical_indicators(self, state: SOCState) -> bool:
        """Check if alert has critical indicators.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if critical indicators are present
        """
        # Check for critical severity
        if state.priority_level == 1:
            return True
        
        # Check for critical TP indicators
        critical_tp_indicators = [
            'malware', 'trojan', 'backdoor', 'exploit', 'breach'
        ]
        
        return any(
            indicator.lower() in critical_tp_indicators
            for indicator in state.tp_indicators
        )
    
    def _has_learning_indicators(self, state: SOCState) -> bool:
        """Check if alert has learning indicators.
        
        Args:
            state: Current SOC state
            
        Returns:
            True if learning indicators are present
        """
        # Check for unusual patterns
        if state.metadata.get('unusual_pattern', False):
            return True
        
        # Check for low confidence with conflicting indicators
        if (state.confidence_score < 50 and 
            len(state.fp_indicators) > 0 and 
            len(state.tp_indicators) > 0):
            return True
        
        return False