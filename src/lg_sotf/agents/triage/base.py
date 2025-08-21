"""
Basic triage agent implementation.
"""

from datetime import datetime
from typing import Any, Dict, List

from ..base import BaseAgent


class TriageAgent(BaseAgent):
    """Basic triage agent for SOC alert processing."""
    
    async def initialize(self):
        """Initialize the triage agent."""
        self.initialized = True
    
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute triage logic."""
        # Basic triage implementation
        alert = state.get('raw_alert', {})
        
        # Simple confidence scoring
        confidence_score = self._calculate_confidence(alert)
        
        # Basic indicator detection
        fp_indicators = self._get_fp_indicators(alert)
        tp_indicators = self._get_tp_indicators(alert)
        
        # Update state
        updated_state = state.copy()
        updated_state.update({
            'confidence_score': confidence_score,
            'fp_indicators': fp_indicators,
            'tp_indicators': tp_indicators,
            'triage_status': 'triaged',
            'last_updated': datetime.utcnow().isoformat()
        })
        
        return updated_state
    
    async def cleanup(self):
        """Cleanup resources."""
        pass
    
    def _calculate_confidence(self, alert: Dict[str, Any]) -> int:
        """Calculate basic confidence score."""
        score = 50  # Base score
        
        # Severity scoring
        severity = alert.get('severity', '').lower()
        if severity == 'high':
            score += 20
        elif severity == 'critical':
            score += 30
        elif severity == 'low':
            score -= 20
        
        # Content analysis
        content = str(alert).lower()
        if 'malware' in content:
            score += 25
        if 'test' in content:
            score -= 30
        
        return max(0, min(100, score))
    
    def _get_fp_indicators(self, alert: Dict[str, Any]) -> List[str]:
        """Get false positive indicators."""
        indicators = []
        content = str(alert).lower()
        
        if 'test' in content:
            indicators.append('test_environment')
        if 'scheduled' in content:
            indicators.append('scheduled_activity')
        
        return indicators
    
    def _get_tp_indicators(self, alert: Dict[str, Any]) -> List[str]:
        """Get true positive indicators."""
        indicators = []
        content = str(alert).lower()
        
        if 'malware' in content:
            indicators.append('malware_detected')
        if 'suspicious' in content:
            indicators.append('suspicious_activity')
        
        return indicators