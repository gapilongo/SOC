"""
Enhanced triage agent implementation.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List

from lg_sotf.agents.base import BaseAgent


class TriageAgent(BaseAgent):
    """Enhanced triage agent for SOC alert processing."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the triage agent."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Triage configuration
        self.confidence_threshold = self.get_config('confidence_threshold', 70)
        self.enable_ml_scoring = self.get_config('enable_ml_scoring', False)
        self.ml_model_path = self.get_config('ml_model_path', '')
        
        # Scoring weights
        self.severity_weights = {
            'critical': 30,
            'high': 20,
            'medium': 10,
            'low': -10,
            'info': -20
        }
        
        self.keyword_weights = {
            'malware': 25,
            'trojan': 25,
            'backdoor': 30,
            'exploit': 20,
            'suspicious': 15,
            'anomaly': 10,
            'test': -30,
            'scheduled': -20,
            'maintenance': -25
        }
    
    async def initialize(self):
        """Initialize the triage agent."""
        try:
            self.logger.info("Initializing triage agent")
            
            # Load ML model if enabled
            if self.enable_ml_scoring and self.ml_model_path:
                await self._load_ml_model()
            
            # Initialize any other resources
            await self._initialize_resources()
            
            self.initialized = True
            self.logger.info("Triage agent initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize triage agent: {e}")
            raise
    
    async def _load_ml_model(self):
        """Load ML model for scoring (placeholder)."""
        try:
            # Placeholder for ML model loading
            # In a real implementation, this would load a trained model
            self.logger.info(f"Loading ML model from {self.ml_model_path}")
            # self.ml_model = load_model(self.ml_model_path)
            self.ml_model = None  # Placeholder
            
        except Exception as e:
            self.logger.warning(f"Failed to load ML model: {e}, falling back to rule-based scoring")
            self.enable_ml_scoring = False
    
    async def _initialize_resources(self):
        """Initialize additional resources."""
        # Placeholder for initializing threat intelligence feeds,
        # databases, or other resources needed for triage
        pass
    
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute triage logic."""
        try:
            self.logger.info(f"Executing triage for alert {state.get('alert_id', 'unknown')}")
            
            # Validate input
            if not await self.validate_input(state):
                raise ValueError("Invalid input state for triage")
            
            # Extract alert data
            alert = state.get('raw_alert', {})
            if not alert:
                raise ValueError("No raw alert data provided")
            
            # Perform triage analysis
            confidence_score = await self._calculate_confidence_score(alert, state)
            fp_indicators, tp_indicators = await self._analyze_indicators(alert, state)
            priority_level = await self._determine_priority(alert, confidence_score)
            
            # Create enriched data
            enriched_data = await self._enrich_alert_data(alert, state)
            
            # Build result state
            result_state = state.copy()
            result_state.update({
                'confidence_score': confidence_score,
                'fp_indicators': fp_indicators,
                'tp_indicators': tp_indicators,
                'priority_level': priority_level,
                'triage_status': 'triaged',
                'last_updated': datetime.utcnow().isoformat(),
                'enriched_data': {
                    **state.get('enriched_data', {}),
                    **enriched_data
                },
                'metadata': {
                    **state.get('metadata', {}),
                    'triage_method': 'ml' if self.enable_ml_scoring else 'rule_based',
                    'triage_timestamp': datetime.utcnow().isoformat(),
                    'triage_agent_version': '1.0.0'
                }
            })
            
            # Validate output
            if not await self.validate_output(result_state):
                raise ValueError("Invalid output state from triage")
            
            self.logger.info(f"Triage completed for alert {state.get('alert_id')} with confidence {confidence_score}")
            
            return result_state
            
        except Exception as e:
            self.logger.error(f"Triage execution failed: {e}")
            # Return state with error information
            error_state = state.copy()
            error_state.update({
                'triage_status': 'triage_failed',
                'last_updated': datetime.utcnow().isoformat(),
                'metadata': {
                    **state.get('metadata', {}),
                    'triage_error': str(e),
                    'triage_timestamp': datetime.utcnow().isoformat()
                }
            })
            return error_state
    
    async def _calculate_confidence_score(self, alert: Dict[str, Any], state: Dict[str, Any]) -> int:
        """Calculate confidence score for the alert."""
        try:
            if self.enable_ml_scoring and hasattr(self, 'ml_model') and self.ml_model:
                return await self._ml_confidence_score(alert, state)
            else:
                return await self._rule_based_confidence_score(alert, state)
                
        except Exception as e:
            self.logger.warning(f"Error calculating confidence score: {e}, using default")
            return 50  # Default neutral score
    
    async def _ml_confidence_score(self, alert: Dict[str, Any], state: Dict[str, Any]) -> int:
        """Calculate confidence score using ML model."""
        # Placeholder for ML-based scoring
        # In a real implementation, this would:
        # 1. Extract features from the alert
        # 2. Apply the ML model
        # 3. Return confidence score
        
        # For now, fall back to rule-based scoring
        return await self._rule_based_confidence_score(alert, state)
    
    async def _rule_based_confidence_score(self, alert: Dict[str, Any], state: Dict[str, Any]) -> int:
        """Calculate confidence score using rules."""
        score = 50  # Base score
        
        try:
            # Severity scoring
            severity = alert.get('severity', '').lower()
            if severity in self.severity_weights:
                score += self.severity_weights[severity]
                self.logger.debug(f"Severity '{severity}' adjusted score by {self.severity_weights[severity]}")
            
            # Content analysis
            alert_content = str(alert).lower()
            for keyword, weight in self.keyword_weights.items():
                if keyword in alert_content:
                    score += weight
                    self.logger.debug(f"Keyword '{keyword}' adjusted score by {weight}")
            
            # Source reliability scoring
            source = alert.get('source', '').lower()
            if 'test' in source or 'dev' in source:
                score -= 25
                self.logger.debug("Test/dev source detected, reducing score by 25")
            
            # Time-based scoring
            score += await self._time_based_scoring(alert)
            
            # Historical context scoring
            score += await self._historical_context_scoring(alert, state)
            
            # Ensure score is within bounds
            final_score = max(0, min(100, score))
            
            self.logger.debug(f"Final confidence score: {final_score}")
            return final_score
            
        except Exception as e:
            self.logger.warning(f"Error in rule-based scoring: {e}")
            return 50
    
    async def _time_based_scoring(self, alert: Dict[str, Any]) -> int:
        """Apply time-based scoring adjustments."""
        try:
            # Check if alert is during business hours vs off-hours
            # Off-hours events might be more suspicious
            timestamp = alert.get('timestamp', '')
            if timestamp:
                # Parse timestamp and check if it's during off-hours
                # This is a simplified example
                from datetime import datetime
                try:
                    alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = alert_time.hour
                    
                    # Off-hours (6 PM to 6 AM) might be more suspicious
                    if hour < 6 or hour >= 18:
                        return 5
                except:
                    pass
            
            return 0
            
        except Exception as e:
            self.logger.debug(f"Error in time-based scoring: {e}")
            return 0
    
    async def _historical_context_scoring(self, alert: Dict[str, Any], state: Dict[str, Any]) -> int:
        """Apply historical context scoring."""
        try:
            # Check for similar alerts in the past
            # This would typically query a database of historical alerts
            # For now, return a small adjustment
            
            # Placeholder logic: if we have enriched data suggesting similar past events
            enriched = state.get('enriched_data', {})
            if enriched.get('similar_alerts_count', 0) > 5:
                return 10  # Many similar alerts suggest this might be a known pattern
            elif enriched.get('first_time_seen', False):
                return 15  # First time seeing this pattern might be more suspicious
            
            return 0
            
        except Exception as e:
            self.logger.debug(f"Error in historical context scoring: {e}")
            return 0
    
    async def _analyze_indicators(self, alert: Dict[str, Any], state: Dict[str, Any]) -> tuple:
        """Analyze alert for false positive and true positive indicators."""
        fp_indicators = []
        tp_indicators = []
        
        try:
            alert_content = str(alert).lower()
            
            # False positive indicators
            fp_keywords = [
                'test', 'testing', 'scheduled', 'maintenance', 'update',
                'backup', 'scan', 'health_check', 'monitoring'
            ]
            
            for keyword in fp_keywords:
                if keyword in alert_content:
                    fp_indicators.append(f"{keyword}_detected")
            
            # Check source for test/dev environments
            source = alert.get('source', '').lower()
            if any(env in source for env in ['test', 'dev', 'staging', 'qa']):
                fp_indicators.append('test_environment')
            
            # True positive indicators
            tp_keywords = [
                'malware', 'trojan', 'backdoor', 'exploit', 'suspicious',
                'anomaly', 'breach', 'intrusion', 'attack', 'threat'
            ]
            
            for keyword in tp_keywords:
                if keyword in alert_content:
                    tp_indicators.append(f"{keyword}_detected")
            
            # Check for known bad indicators
            if alert.get('raw_data', {}).get('file_hash'):
                tp_indicators.append('file_hash_present')
            
            if alert.get('raw_data', {}).get('destination_ip'):
                # In a real implementation, check against threat intelligence
                tp_indicators.append('network_connection')
            
            # Advanced pattern analysis
            fp_indicators.extend(await self._analyze_fp_patterns(alert))
            tp_indicators.extend(await self._analyze_tp_patterns(alert))
            
            self.logger.debug(f"Identified {len(fp_indicators)} FP and {len(tp_indicators)} TP indicators")
            
            return fp_indicators, tp_indicators
            
        except Exception as e:
            self.logger.warning(f"Error analyzing indicators: {e}")
            return [], []
    
    async def _analyze_fp_patterns(self, alert: Dict[str, Any]) -> List[str]:
        """Analyze patterns that suggest false positives."""
        patterns = []
        
        try:
            # Check for regular timing (scheduled activities)
            timestamp = alert.get('timestamp', '')
            if timestamp and 'scheduled' in str(alert).lower():
                patterns.append('scheduled_pattern')
            
            # Check for automated tools patterns
            user_agent = alert.get('raw_data', {}).get('user_agent', '')
            if any(tool in user_agent.lower() for tool in ['scanner', 'bot', 'crawler']):
                patterns.append('automated_tool')
            
            return patterns
            
        except Exception as e:
            self.logger.debug(f"Error in FP pattern analysis: {e}")
            return []
    
    async def _analyze_tp_patterns(self, alert: Dict[str, Any]) -> List[str]:
        """Analyze patterns that suggest true positives."""
        patterns = []
        
        try:
            raw_data = alert.get('raw_data', {})
            
            # Check for suspicious network activity
            if raw_data.get('destination_port') in [4444, 6666, 31337]:
                patterns.append('suspicious_port')
            
            # Check for file operations
            if raw_data.get('event_type') == 'file_creation' and raw_data.get('file_path', '').endswith('.exe'):
                patterns.append('executable_creation')
            
            # Check for privilege escalation
            if 'privilege' in str(alert).lower() and 'escalation' in str(alert).lower():
                patterns.append('privilege_escalation')
            
            return patterns
            
        except Exception as e:
            self.logger.debug(f"Error in TP pattern analysis: {e}")
            return []
    
    async def _determine_priority(self, alert: Dict[str, Any], confidence_score: int) -> int:
        """Determine priority level based on alert characteristics and confidence."""
        try:
            # Base priority from severity
            severity = alert.get('severity', 'medium').lower()
            priority_map = {
                'critical': 1,
                'high': 2,
                'medium': 3,
                'low': 4,
                'info': 5
            }
            
            base_priority = priority_map.get(severity, 3)
            
            # Adjust based on confidence score
            if confidence_score >= 90:
                priority_adjustment = -1  # Higher priority
            elif confidence_score >= 70:
                priority_adjustment = 0   # Keep same
            elif confidence_score >= 50:
                priority_adjustment = 1   # Lower priority
            else:
                priority_adjustment = 2   # Much lower priority
            
            # Calculate final priority
            final_priority = max(1, min(5, base_priority + priority_adjustment))
            
            self.logger.debug(f"Priority determined: {final_priority} (base: {base_priority}, adjustment: {priority_adjustment})")
            
            return final_priority
            
        except Exception as e:
            self.logger.warning(f"Error determining priority: {e}")
            return 3  # Default to medium priority
    
    async def _enrich_alert_data(self, alert: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich alert data with additional context."""
        enriched = {}
        
        try:
            # Add triage metadata
            enriched['triage_metadata'] = {
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'analysis_method': 'ml' if self.enable_ml_scoring else 'rule_based',
                'agent_version': '1.0.0'
            }
            
            # Add source analysis
            source = alert.get('source', '')
            enriched['source_analysis'] = {
                'source_name': source,
                'is_test_environment': any(env in source.lower() for env in ['test', 'dev', 'staging']),
                'source_reliability': self._assess_source_reliability(source)
            }
            
            # Add temporal analysis
            enriched['temporal_analysis'] = await self._analyze_temporal_context(alert)
            
            return enriched
            
        except Exception as e:
            self.logger.warning(f"Error enriching alert data: {e}")
            return {}
    
    def _assess_source_reliability(self, source: str) -> str:
        """Assess the reliability of the alert source."""
        source_lower = source.lower()
        
        if any(env in source_lower for env in ['test', 'dev', 'staging']):
            return 'low'
        elif any(prod_env in source_lower for prod_env in ['prod', 'production']):  # ← Fixed variable name
            return 'high'
        else:
            return 'medium'
    
    async def _analyze_temporal_context(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal context of the alert."""
        try:
            timestamp = alert.get('timestamp', '')
            if not timestamp:
                return {}
            
            alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            now = datetime.utcnow()
            
            return {
                'alert_age_seconds': (now - alert_time).total_seconds(),
                'is_business_hours': 6 <= alert_time.hour < 18,
                'is_weekend': alert_time.weekday() >= 5,
                'hour_of_day': alert_time.hour
            }
            
        except Exception as e:
            self.logger.debug(f"Error in temporal analysis: {e}")
            return {}
    
    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state."""
        try:
            # Check required fields
            required_fields = ['alert_id', 'raw_alert']
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing required field: {field}")
                    return False
            
            # Check that raw_alert is not empty
            if not state['raw_alert']:
                self.logger.error("Raw alert data is empty")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating input: {e}")
            return False
    
    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state."""
        try:
            # Check that required fields are present
            required_fields = ['confidence_score', 'fp_indicators', 'tp_indicators', 'triage_status']
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing output field: {field}")
                    return False
            
            # Check confidence score range
            confidence = state.get('confidence_score', 0)
            if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 100:
                self.logger.error(f"Invalid confidence score: {confidence}")
                return False
            
            # Check that indicators are lists
            for indicator_field in ['fp_indicators', 'tp_indicators']:
                if not isinstance(state.get(indicator_field, []), list):
                    self.logger.error(f"Invalid {indicator_field}: must be a list")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating output: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup triage agent resources."""
        try:
            self.logger.info("Cleaning up triage agent")
            
            # Cleanup ML model if loaded
            if hasattr(self, 'ml_model') and self.ml_model:
                del self.ml_model
            
            # Cleanup any other resources
            
            self.logger.info("Triage agent cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during triage agent cleanup: {e}")
    
    async def health_check(self) -> bool:
        """Check if the triage agent is healthy."""
        try:
            # Check if agent is initialized
            if not self.initialized:
                return False
            
            # Check ML model if enabled
            if self.enable_ml_scoring:
                if not hasattr(self, 'ml_model'):
                    return False
            
            # Run a simple test
            test_alert = {
                'id': 'health_check',
                'severity': 'low',
                'description': 'Health check test'
            }
            
            test_state = {
                'alert_id': 'health_check',
                'raw_alert': test_alert
            }
            
            # Validate input works
            if not await self.validate_input(test_state):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get triage agent metrics."""
        base_metrics = super().get_metrics()
        
        triage_metrics = {
            'confidence_threshold': self.confidence_threshold,
            'ml_scoring_enabled': self.enable_ml_scoring,
            'ml_model_loaded': hasattr(self, 'ml_model') and self.ml_model is not None,
            'severity_weights': self.severity_weights,
            'keyword_weights_count': len(self.keyword_weights)
        }
        
        base_metrics.update(triage_metrics)
        return base_metrics