"""
Correlation agent implementation with integrated LLM capabilities.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

from lg_sotf.agents.base import BaseAgent
from lg_sotf.utils.llm import get_llm_client
from lg_sotf.core.config.manager import ConfigManager


class CorrelationAgent(BaseAgent):
    """Production-grade correlation agent for SOC alert processing with integrated LLM capabilities."""

    def __init__(self, config: Dict[str, Any], state_manager=None, redis_storage=None, tool_orchestrator=None):
        """Initialize the correlation agent."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Dependency injection for real data sources
        self.state_manager = state_manager
        self.redis_storage = redis_storage
        self.tool_orchestrator = tool_orchestrator

        # Core correlation configuration
        self.correlation_window = self.get_config("correlation_window_minutes", 60)
        self.similarity_threshold = self.get_config("similarity_threshold", 0.7)
        self.max_correlations = self.get_config("max_correlations", 10)
        self.enable_llm_correlation = self.get_config("enable_llm_correlation", True)

        # External enrichment configuration
        self.enable_threat_intel = self.get_config("enable_threat_intel", True)
        self.enable_siem_queries = self.get_config("enable_siem_queries", True)
        self.enable_burst_detection = self.get_config("enable_burst_detection", True)

        # LLM integration
        self.llm_client = None
        self.llm_weight = self.get_config("llm_weight", 0.3)  # 30% LLM, 70% rules

        # Correlation patterns
        self.ip_correlation_weight = 25
        self.hash_correlation_weight = 30
        self.user_correlation_weight = 20
        self.temporal_correlation_weight = 15
        self.behavioral_correlation_weight = 10

    async def initialize(self):
        """Initialize the correlation agent."""
        try:
            self.logger.info("Initializing correlation agent")

            # Validate dependencies
            if not self.state_manager:
                self.logger.warning("StateManager not provided - historical queries disabled")

            if not self.redis_storage:
                self.logger.warning("RedisStorage not provided - pattern detection disabled")

            if not self.tool_orchestrator:
                self.logger.warning("ToolOrchestrator not provided - external enrichment disabled")

            # Initialize LLM client
            if self.enable_llm_correlation:
                await self._initialize_llm_client()

            # Initialize correlation storage/cache
            await self._initialize_correlation_storage()

            self.initialized = True
            self.logger.info("Correlation agent initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize correlation agent: {e}")
            raise

    async def _initialize_llm_client(self):
        """Initialize LLM client for correlation analysis."""
        try:
            

            config_manager = ConfigManager()
            self.llm_client = get_llm_client(config_manager)
            self.logger.info("LLM client initialized for correlation analysis")
        except Exception as e:
            self.logger.warning(
                f"LLM client initialization failed: {e}, falling back to rule-based correlation"
            )
            self.enable_llm_correlation = False

    async def _initialize_correlation_storage(self):
        """Initialize correlation storage/cache."""
        # In a full implementation, this would initialize:
        # - Historical alert cache
        # - Pattern storage
        # - Correlation rule engine
        pass

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute correlation logic.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            self.logger.info(
                f"Executing correlation for alert {state.get('alert_id', 'unknown')}"
            )

            # Validate input
            if not await self.validate_input(state):
                raise ValueError("Invalid input state for correlation")

            # Extract alert data
            alert = state.get("raw_alert", {})
            if not alert:
                raise ValueError("No raw alert data provided")

            # Perform correlation analysis
            correlations = await self._find_correlations(alert, state)
            correlation_score = await self._calculate_correlation_score(
                correlations, state
            )
            enriched_data = await self._enrich_with_correlations(
                alert, correlations, state
            )

            # Update confidence based on correlations
            updated_confidence = await self._update_confidence_with_correlations(
                state.get("confidence_score", 0), correlations, state
            )

            # Build updates dict (return only changes, not full state)
            updates = {
                "correlations": correlations,
                "correlation_score": correlation_score,
                "confidence_score": updated_confidence,
                "triage_status": "correlated",
                "last_updated": datetime.utcnow().isoformat(),
                "enriched_data": enriched_data,  # Only new enriched data
                "metadata": {
                    "correlation_method": self._get_correlation_method(),
                    "correlation_timestamp": datetime.utcnow().isoformat(),
                    "correlation_agent_version": "1.0.0",
                    "correlations_found": len(correlations),
                }
            }

            # Validate output
            if not await self.validate_output({**state, **updates}):
                raise ValueError("Invalid output state from correlation")

            self.logger.info(
                f"Correlation completed for alert {state.get('alert_id')} with {len(correlations)} correlations found"
            )

            return updates

        except Exception as e:
            self.logger.error(f"Correlation execution failed: {e}")
            # Return only error updates
            return {
                "triage_status": "correlation_failed",
                "last_updated": datetime.utcnow().isoformat(),
                "metadata": {
                    "correlation_error": str(e),
                    "correlation_timestamp": datetime.utcnow().isoformat(),
                }
            }

    def _get_correlation_method(self) -> str:
        """Get the active correlation method."""
        if self.enable_llm_correlation and self.llm_client:
            return "llm_integrated"
        else:
            return "rule_based"

    async def _find_correlations(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations for the alert."""
        try:
            # Get rule-based correlations
            rule_correlations = await self._find_rule_based_correlations(alert, state)

            # Integrate LLM correlations if available
            if self.enable_llm_correlation and self.llm_client:
                llm_correlations = await self._find_llm_correlations(alert, state)

                # Merge and deduplicate correlations
                all_correlations = self._merge_correlations(
                    rule_correlations, llm_correlations
                )

                self.logger.info(f"Correlation Results:")
                self.logger.info(f"  Rule-based: {len(rule_correlations)} correlations")
                self.logger.info(f"  LLM-based: {len(llm_correlations)} correlations")
                self.logger.info(
                    f"  Total unique: {len(all_correlations)} correlations"
                )

                return all_correlations[: self.max_correlations]

            return rule_correlations[: self.max_correlations]

        except Exception as e:
            self.logger.warning(f"Error finding correlations: {e}")
            return []

    async def _find_rule_based_correlations(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations using rule-based analysis with real data sources."""
        correlations = []

        try:
            raw_data = alert.get("raw_data", {})

            # Stage 1: Historical database correlations (if available)
            if self.state_manager:
                historical_correlations = await self._find_historical_correlations(raw_data, alert)
                correlations.extend(historical_correlations)

            # Stage 2: Real-time pattern detection (if available)
            if self.redis_storage:
                pattern_correlations = await self._find_pattern_correlations(raw_data, alert)
                correlations.extend(pattern_correlations)

            # Stage 3: External tool enrichment (if available)
            if self.tool_orchestrator:
                external_correlations = await self._find_external_correlations(raw_data, alert)
                correlations.extend(external_correlations)

            # Fallback: Mock correlations if no data sources available
            if not self.state_manager and not self.redis_storage and not self.tool_orchestrator:
                # IP-based correlations (mock)
                if raw_data.get("source_ip") or raw_data.get("destination_ip"):
                    ip_correlations = await self._find_ip_correlations(raw_data, alert)
                    correlations.extend(ip_correlations)

                # Hash-based correlations (mock)
                if raw_data.get("file_hash"):
                    hash_correlations = await self._find_hash_correlations(raw_data, alert)
                    correlations.extend(hash_correlations)

                # User-based correlations (mock)
                if raw_data.get("user") or raw_data.get("username"):
                    user_correlations = await self._find_user_correlations(raw_data, alert)
                    correlations.extend(user_correlations)

                # Process-based correlations (mock)
                if raw_data.get("process_name"):
                    process_correlations = await self._find_process_correlations(
                        raw_data, alert
                    )
                    correlations.extend(process_correlations)

                # Temporal correlations (mock)
                temporal_correlations = await self._find_temporal_correlations(alert, state)
                correlations.extend(temporal_correlations)

            self.logger.debug(f"Found {len(correlations)} rule-based correlations")
            return correlations

        except Exception as e:
            self.logger.warning(f"Error in rule-based correlation: {e}")
            return []

    async def _find_llm_correlations(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations using LLM analysis."""
        try:
            analysis_result = await self._analyze_correlations_with_llm(alert, state)
            return analysis_result.get("correlations", [])
        except Exception as e:
            self.logger.warning(f"LLM correlation analysis failed: {e}")
            return []

    async def _analyze_correlations_with_llm(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze correlations using LLM."""
        try:
            prompt = self._build_correlation_prompt(alert, state)

            start_time = time.time()
            response = await self.llm_client.ainvoke(prompt)
            analysis_time = time.time() - start_time

            # Record metrics
            if hasattr(self, "metrics"):
                try:
                    self.metrics.record_timing(
                        "llm_correlation_duration", analysis_time
                    )
                    self.metrics.increment_counter("llm_correlations_completed")
                except Exception as metrics_error:
                    self.logger.debug(f"Metrics recording failed: {metrics_error}")

            # Parse LLM response
            analysis_result = self._parse_llm_correlation_response(response.content)

            # Log detailed LLM results
            correlations = analysis_result.get("correlations", [])
            self.logger.info(f"LLM Correlation Analysis Results:")
            self.logger.info(f"  Correlations found: {len(correlations)}")
            self.logger.info(
                f"  Correlation confidence: {analysis_result.get('correlation_confidence')}"
            )
            self.logger.info(
                f"  Attack campaign indicators: {analysis_result.get('attack_campaign_indicators', [])}"
            )
            self.logger.info(
                f"  Threat actor patterns: {analysis_result.get('threat_actor_patterns', [])}"
            )

            self.logger.debug(
                f"LLM correlation analysis completed in {analysis_time:.2f}s"
            )

            return analysis_result

        except Exception as e:
            self.logger.warning(f"LLM correlation analysis failed: {e}")
            try:
                if hasattr(self, "metrics"):
                    self.metrics.increment_counter("llm_correlation_failures")
            except Exception as metrics_error:
                self.logger.debug(f"Metrics recording failed: {metrics_error}")
            return self._get_default_correlation_analysis()

    def _build_correlation_prompt(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> str:
        """Build correlation analysis prompt for LLM."""
        existing_indicators = {
            "fp_indicators": state.get("fp_indicators", []),
            "tp_indicators": state.get("tp_indicators", []),
        }

        return f"""You are a cybersecurity analyst performing correlation analysis. Analyze this alert for potential correlations with other security events.

CURRENT ALERT:
{json.dumps(alert, indent=2)}

EXISTING ANALYSIS:
{json.dumps(existing_indicators, indent=2)}

Based on the alert data, identify potential correlations and patterns. Provide your analysis in JSON format:

{{
    "correlations": [
        {{
            "type": "ip_correlation|hash_correlation|user_correlation|temporal_correlation|behavioral_correlation",
            "indicator": "the specific indicator that correlates",
            "description": "description of the correlation",
            "confidence": <integer 0-100>,
            "weight": <integer 0-100>,
            "threat_level": "low|medium|high|critical"
        }}
    ],
    "correlation_confidence": <integer 0-100>,
    "attack_campaign_indicators": ["indicator1", "indicator2"],
    "threat_actor_patterns": ["pattern1", "pattern2"],
    "temporal_patterns": ["pattern1", "pattern2"],
    "behavioral_anomalies": ["anomaly1", "anomaly2"],
    "correlation_reasoning": "Brief explanation of correlation logic"
}}

Focus on:
- IP addresses and network indicators
- File hashes and malware signatures
- User account patterns
- Temporal attack sequences
- Behavioral anomalies
- Known attack campaigns or threat actor TTPs
- Infrastructure overlaps"""

    def _parse_llm_correlation_response(self, response_content: str) -> Dict[str, Any]:
        """Parse LLM correlation response into structured data."""
        try:
            # Clean response content
            content = response_content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]

            analysis = json.loads(content)

            # Validate and sanitize correlations
            correlations = analysis.get("correlations", [])
            validated_correlations = []

            for corr in correlations:
                if all(key in corr for key in ["type", "indicator", "confidence"]):
                    corr["confidence"] = max(0, min(100, corr.get("confidence", 50)))
                    corr["weight"] = max(0, min(100, corr.get("weight", 50)))
                    validated_correlations.append(corr)

            return {
                "correlations": validated_correlations,
                "correlation_confidence": max(
                    0, min(100, analysis.get("correlation_confidence", 50))
                ),
                "attack_campaign_indicators": analysis.get(
                    "attack_campaign_indicators", []
                ),
                "threat_actor_patterns": analysis.get("threat_actor_patterns", []),
                "temporal_patterns": analysis.get("temporal_patterns", []),
                "behavioral_anomalies": analysis.get("behavioral_anomalies", []),
                "correlation_reasoning": analysis.get(
                    "correlation_reasoning", "No reasoning provided"
                ),
            }

        except (json.JSONDecodeError, ValueError) as e:
            self.logger.warning(f"Failed to parse LLM correlation response: {e}")
            return self._get_default_correlation_analysis()

    def _get_default_correlation_analysis(self) -> Dict[str, Any]:
        """Get default correlation analysis when LLM fails."""
        return {
            "correlations": [],
            "correlation_confidence": 50,
            "attack_campaign_indicators": [],
            "threat_actor_patterns": [],
            "temporal_patterns": [],
            "behavioral_anomalies": [],
            "correlation_reasoning": "LLM analysis unavailable, using rule-based correlation only",
        }

    # ==========================================
    # REAL DATA SOURCE CORRELATION METHODS
    # ==========================================

    async def _find_historical_correlations(
        self,
        raw_data: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations from historical alerts in database."""
        correlations = []

        try:
            indicator_types = ['source_ip', 'destination_ip', 'file_hash', 'user', 'username']

            for indicator_type in indicator_types:
                indicator_value = raw_data.get(indicator_type)
                if not indicator_value:
                    continue

                # Query historical alerts
                historical_alerts = await self.state_manager.query_alerts_by_indicator(
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    time_window_minutes=self.correlation_window,
                    limit=20
                )

                if historical_alerts:
                    # Get frequency stats
                    freq_stats = await self.state_manager.get_alert_frequency(
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        time_window_minutes=self.correlation_window
                    )

                    correlations.append({
                        "type": f"{indicator_type}_historical",
                        "indicator": indicator_value,
                        "description": f"Found {len(historical_alerts)} historical alerts with {indicator_type}={indicator_value}",
                        "confidence": min(90, 50 + len(historical_alerts) * 5),
                        "weight": self._get_indicator_weight(indicator_type),
                        "threat_level": self._assess_threat_from_frequency(freq_stats),
                        "historical_count": len(historical_alerts),
                        "frequency_stats": freq_stats
                    })

            return correlations

        except Exception as e:
            self.logger.warning(f"Error in historical correlation: {e}")
            return []

    async def _find_pattern_correlations(
        self,
        raw_data: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations from real-time patterns in Redis - dynamically extracts ALL indicators."""
        correlations = []

        try:
            alert_id = alert.get("id", "unknown")
            alert_timestamp = alert.get("timestamp")

            # DEBUG: Check dependencies
            self.logger.debug(f"Pattern correlation for {alert_id}")
            self.logger.debug(f"Redis storage available: {self.redis_storage is not None}")
            self.logger.debug(f"Burst detection enabled: {self.enable_burst_detection}")
            self.logger.debug(f"Alert timestamp: {alert_timestamp}")

            # Dynamically extract ALL fields from BOTH raw_data AND top-level alert fields
            # This handles both JSON alerts (data in raw_data) and CSV alerts (data at top level)
            ignore_fields = {'id', 'timestamp', 'created_at', 'updated_at', 'metadata', 'description', 'title', 'source', 'severity', 'category', 'entities', 'alert_hash'}

            extracted_indicators = []

            # First, try raw_data (for JSON alerts)
            if raw_data:
                for field_name, field_value in raw_data.items():
                    if field_name in ignore_fields:
                        continue
                    if not field_value or field_value == "":
                        continue
                    # Only track string/number values, not complex objects
                    if isinstance(field_value, (str, int, float)):
                        extracted_indicators.append({
                            'field_name': field_name,
                            'field_value': str(field_value)
                        })

            # Then, extract from top-level alert fields (for CSV alerts)
            # Common correlatable fields after CSV normalization
            correlatable_fields = ['source_ip', 'destination_ip', 'user', 'username', 'host', 'device_name',
                                  'source_address', 'destination_address', 'protocol', 'port', 'destination_port',
                                  'action', 'country', 'process_name', 'file_hash', 'domain', 'url']

            for field in correlatable_fields:
                if field in alert and alert[field]:
                    field_value = alert[field]
                    if field_value and field_value != "" and field_value != "N/A":
                        # Avoid duplicates from raw_data
                        if not any(i['field_name'] == field for i in extracted_indicators):
                            if isinstance(field_value, (str, int, float)):
                                extracted_indicators.append({
                                    'field_name': field,
                                    'field_value': str(field_value)
                                })

            indicator_list = [f"{i['field_name']}={i['field_value']}" for i in extracted_indicators]
            self.logger.debug(f"Extracted {len(extracted_indicators)} indicators from alert {alert_id}: {indicator_list}")

            # Process each extracted indicator
            for idx, indicator in enumerate(extracted_indicators):
                field_name = indicator['field_name']
                field_value = indicator['field_value']

                self.logger.debug(f"Processing indicator {idx+1}/{len(extracted_indicators)}: {field_name}={field_value}")

                # Calculate consistent TTL for all indicator tracking
                # Use 24 hours for production (86400 seconds) to maintain correlation context
                indicator_ttl = 86400  # 24 hours - consistent across count, timeline, and pairs

                # Increment counter and get count
                try:
                    count = await self.redis_storage.increment_indicator_count(
                        indicator_type=field_name,
                        indicator_value=field_value,
                        window_seconds=indicator_ttl,
                        alert_id=alert_id  # Pass alert_id for tracking
                    )
                    self.logger.debug(f"Incremented count for {field_name}={field_value}, new count: {count}, alert_id: {alert_id}")
                except Exception as e:
                    self.logger.error(f"Failed to increment count: {e}")
                    continue

                # Record timestamp for burst detection
                self.logger.debug(f"Checking burst detection: enabled={self.enable_burst_detection}")
                if self.enable_burst_detection:
                    try:
                        parsed_timestamp = None
                        use_current_time = False

                        if alert_timestamp:
                            parsed_timestamp = datetime.fromisoformat(alert_timestamp.replace("Z", "+00:00"))
                            self.logger.debug(f"Parsed timestamp: {parsed_timestamp}")

                            # Check if timestamp is historical (older than 1 hour)
                            time_diff = datetime.utcnow() - parsed_timestamp.replace(tzinfo=None)
                            if time_diff.total_seconds() > 3600:  # More than 1 hour old
                                self.logger.debug(f"Alert is historical (age: {time_diff.days} days, {time_diff.seconds//3600} hours) - using current time for burst detection")
                                use_current_time = True
                            else:
                                self.logger.debug(f"Alert is recent - using alert timestamp for burst detection")
                        else:
                            self.logger.warning(f"Alert timestamp is None, using current time")
                            use_current_time = True

                        # Use current time for historical alerts, alert time for recent alerts
                        tracking_timestamp = datetime.utcnow() if use_current_time else parsed_timestamp.replace(tzinfo=None)

                        await self.redis_storage.record_alert_timestamp(
                            indicator_type=field_name,
                            indicator_value=field_value,
                            timestamp=tracking_timestamp,
                            ttl=indicator_ttl,
                            alert_id=alert_id  # Pass alert_id for tracking
                        )
                        self.logger.debug(f"Recorded timestamp for {field_name}={field_value} (timestamp: {tracking_timestamp}, historical: {use_current_time}, alert_id: {alert_id})")

                        # Get burst statistics
                        burst_stats = await self.redis_storage.get_alert_burst_stats(
                            indicator_type=field_name,
                            indicator_value=field_value,
                            time_window_minutes=self.correlation_window
                        )
                        self.logger.debug(f"Burst stats: {burst_stats}")
                    except Exception as e:
                        self.logger.error(f"Failed to record timestamp: {e}")
                        burst_stats = {'is_burst': False}

                    # If burst detected, add correlation
                    if burst_stats['is_burst']:
                        correlations.append({
                            "type": f"{field_name}_burst",
                            "indicator": field_value,
                            "description": f"Burst detected: {burst_stats['events_per_minute']} events/min for {field_name}={field_value}",
                            "confidence": min(95, 60 + int(burst_stats['events_per_minute'] * 2)),
                            "weight": self._get_indicator_weight(field_name) + 10,
                            "threat_level": burst_stats['burst_severity'],
                            "burst_stats": burst_stats
                        })

                # Track indicator pairs for relationship detection
                self.logger.debug(f"Tracking indicator pairs for {field_name}={field_value}")
                pair_count = 0
                for other_indicator in extracted_indicators:
                    if other_indicator['field_name'] != field_name:
                        try:
                            await self.redis_storage.track_indicator_pair(
                                field_name, field_value,
                                other_indicator['field_name'], other_indicator['field_value'],
                                ttl=indicator_ttl
                            )
                            pair_count += 1
                        except Exception as e:
                            self.logger.error(f"Failed to track pair {field_name}={field_value} <-> {other_indicator['field_name']}={other_indicator['field_value']}: {e}")
                self.logger.debug(f"Tracked {pair_count} indicator pairs")

                # Get related indicators
                related = await self.redis_storage.get_related_indicators(
                    indicator_type=field_name,
                    indicator_value=field_value,
                    min_count=2
                )

                for rel in related:
                    correlations.append({
                        "type": "indicator_relationship",
                        "indicator": field_value,
                        "description": f"{field_name}={field_value} frequently seen with {rel['related_indicator_type']}={rel['related_indicator_value']} ({rel['co_occurrence_count']} times)",
                        "confidence": min(80, 40 + rel['co_occurrence_count'] * 10),
                        "weight": 15,
                        "threat_level": "medium",
                        "related_indicator": rel
                    })

            return correlations

        except Exception as e:
            self.logger.warning(f"Error in pattern correlation: {e}")
            return []

    async def _find_external_correlations(
        self,
        raw_data: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find correlations from external tools (SIEM, threat intel)."""
        correlations = []

        try:
            # Build parallel tool queries
            tool_queries = []

            # IP-based queries
            source_ip = raw_data.get("source_ip")
            if source_ip and self.enable_threat_intel:
                tool_queries.append({
                    "tool_name": "virustotal_ip",
                    "tool_args": {"ip": source_ip}
                })

            # Hash-based queries
            file_hash = raw_data.get("file_hash")
            if file_hash and self.enable_threat_intel:
                tool_queries.append({
                    "tool_name": "virustotal_hash",
                    "tool_args": {"hash": file_hash}
                })

            # SIEM queries for context
            if self.enable_siem_queries and (source_ip or file_hash):
                tool_queries.append({
                    "tool_name": "splunk_search",
                    "tool_args": {
                        "query": f"source_ip={source_ip}" if source_ip else f"file_hash={file_hash}",
                        "time_range": f"{self.correlation_window}m"
                    }
                })

            # Execute tools in parallel if available
            if tool_queries:
                results = await self.tool_orchestrator.execute_tools_parallel(
                    tool_queries,
                    context={"alert_id": alert.get("id")}
                )

                # Process results into correlations
                for result in results:
                    if result.get('success'):
                        correlations.extend(
                            self._process_tool_result_to_correlations(result)
                        )

            return correlations

        except Exception as e:
            self.logger.warning(f"Error in external correlation: {e}")
            return []

    def _process_tool_result_to_correlations(
        self,
        tool_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process tool results into correlation format."""
        correlations = []

        try:
            tool_name = tool_result.get('tool_name', 'unknown')
            data = tool_result.get('result', {})

            # Process based on tool type
            if 'virustotal' in tool_name:
                # Process VirusTotal results
                if data.get('malicious'):
                    correlations.append({
                        "type": "threat_intel_match",
                        "indicator": data.get('indicator'),
                        "description": f"VirusTotal: {data.get('positives', 0)}/{data.get('total', 0)} engines flagged as malicious",
                        "confidence": min(95, 50 + (data.get('positives', 0) * 5)),
                        "weight": 35,
                        "threat_level": "high" if data.get('positives', 0) > 10 else "medium",
                        "external_data": data
                    })

            elif 'splunk' in tool_name:
                # Process SIEM results
                event_count = data.get('event_count', 0)
                if event_count > 0:
                    correlations.append({
                        "type": "siem_correlation",
                        "indicator": data.get('query'),
                        "description": f"SIEM found {event_count} related events in last {self.correlation_window} minutes",
                        "confidence": min(85, 40 + event_count * 3),
                        "weight": 25,
                        "threat_level": "medium" if event_count > 10 else "low",
                        "external_data": data
                    })

            return correlations

        except Exception as e:
            self.logger.warning(f"Error processing tool result: {e}")
            return []

    def _get_indicator_weight(self, indicator_type: str) -> int:
        """Get weight for indicator type."""
        weights = {
            'source_ip': self.ip_correlation_weight,
            'destination_ip': self.ip_correlation_weight,
            'file_hash': self.hash_correlation_weight,
            'user': self.user_correlation_weight,
            'username': self.user_correlation_weight,
            'process_name': self.behavioral_correlation_weight
        }
        return weights.get(indicator_type, 10)

    def _assess_threat_from_frequency(self, freq_stats: Dict[str, Any]) -> str:
        """Assess threat level from frequency statistics."""
        alerts_per_hour = freq_stats.get('alerts_per_hour', 0)

        if alerts_per_hour > 50:
            return 'critical'
        elif alerts_per_hour > 20:
            return 'high'
        elif alerts_per_hour > 5:
            return 'medium'
        else:
            return 'low'

    # ==========================================
    # MOCK CORRELATION METHODS (FALLBACK)
    # ==========================================

    async def _find_ip_correlations(
        self, raw_data: Dict[str, Any], alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find IP-based correlations."""
        correlations = []

        source_ip = raw_data.get("source_ip")
        dest_ip = raw_data.get("destination_ip")

        if source_ip:
            # Check for known bad IPs (mock implementation)
            if self._is_suspicious_ip(source_ip):
                correlations.append(
                    {
                        "type": "ip_correlation",
                        "indicator": source_ip,
                        "description": f"Source IP {source_ip} matches known suspicious IP patterns",
                        "confidence": 80,
                        "weight": self.ip_correlation_weight,
                        "threat_level": "medium",
                    }
                )

        if dest_ip:
            # Check for internal vs external communications
            if self._is_external_ip(dest_ip):
                correlations.append(
                    {
                        "type": "ip_correlation",
                        "indicator": dest_ip,
                        "description": f"Communication to external IP {dest_ip}",
                        "confidence": 60,
                        "weight": self.ip_correlation_weight,
                        "threat_level": "low",
                    }
                )

        return correlations

    async def _find_hash_correlations(
        self, raw_data: Dict[str, Any], alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find hash-based correlations."""
        correlations = []

        file_hash = raw_data.get("file_hash")
        if file_hash:
            # Mock hash reputation check
            if self._is_suspicious_hash(file_hash):
                correlations.append(
                    {
                        "type": "hash_correlation",
                        "indicator": file_hash,
                        "description": f"File hash {file_hash} matches known malware signatures",
                        "confidence": 90,
                        "weight": self.hash_correlation_weight,
                        "threat_level": "high",
                    }
                )

        return correlations

    async def _find_user_correlations(
        self, raw_data: Dict[str, Any], alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find user-based correlations."""
        correlations = []

        user = raw_data.get("user") or raw_data.get("username")
        if user:
            # Check for privileged accounts
            if self._is_privileged_user(user):
                correlations.append(
                    {
                        "type": "user_correlation",
                        "indicator": user,
                        "description": f"Activity from privileged user {user}",
                        "confidence": 70,
                        "weight": self.user_correlation_weight,
                        "threat_level": "medium",
                    }
                )

        return correlations

    async def _find_process_correlations(
        self, raw_data: Dict[str, Any], alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find process-based correlations."""
        correlations = []

        process_name = raw_data.get("process_name")
        if process_name:
            # Check for suspicious processes
            if self._is_suspicious_process(process_name):
                correlations.append(
                    {
                        "type": "behavioral_correlation",
                        "indicator": process_name,
                        "description": f"Suspicious process {process_name} detected",
                        "confidence": 75,
                        "weight": self.behavioral_correlation_weight,
                        "threat_level": "medium",
                    }
                )

        return correlations

    async def _find_temporal_correlations(
        self, alert: Dict[str, Any], state: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find temporal correlations."""
        correlations = []

        alert_time = alert.get("timestamp")
        if alert_time:
            # Check for off-hours activity
            try:
                timestamp = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
                if timestamp.hour < 6 or timestamp.hour > 22:  # Outside business hours
                    correlations.append(
                        {
                            "type": "temporal_correlation",
                            "indicator": f"off_hours_{timestamp.hour}",
                            "description": f"Activity detected outside business hours at {timestamp.hour}:00",
                            "confidence": 60,
                            "weight": self.temporal_correlation_weight,
                            "threat_level": "low",
                        }
                    )
            except Exception:
                pass

        return correlations

    def _merge_correlations(
        self,
        rule_correlations: List[Dict[str, Any]],
        llm_correlations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge and deduplicate correlations from different sources."""
        all_correlations = rule_correlations.copy()

        # Add LLM correlations that don't duplicate rule-based ones
        existing_indicators = {corr["indicator"] for corr in rule_correlations}

        for llm_corr in llm_correlations:
            if llm_corr["indicator"] not in existing_indicators:
                all_correlations.append(llm_corr)
            else:
                # Enhance existing correlation with LLM insights
                for existing_corr in all_correlations:
                    if existing_corr["indicator"] == llm_corr["indicator"]:
                        # Combine confidence scores
                        combined_confidence = int(
                            (existing_corr["confidence"] * (1 - self.llm_weight))
                            + (llm_corr["confidence"] * self.llm_weight)
                        )
                        existing_corr["confidence"] = max(
                            0, min(100, combined_confidence)
                        )
                        existing_corr["llm_enhanced"] = True
                        break

        # Sort by confidence score descending
        return sorted(all_correlations, key=lambda x: x["confidence"], reverse=True)

    async def _calculate_correlation_score(
        self, correlations: List[Dict[str, Any]], state: Dict[str, Any]
    ) -> int:
        """Calculate overall correlation score."""
        if not correlations:
            return 0

        # Weighted average of correlation confidences
        total_weight = 0
        weighted_sum = 0

        for corr in correlations:
            weight = corr.get("weight", 50)
            confidence = corr.get("confidence", 50)
            weighted_sum += confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0

        correlation_score = int(weighted_sum / total_weight)
        return max(0, min(100, correlation_score))

    async def _update_confidence_with_correlations(
        self,
        base_confidence: int,
        correlations: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> int:
        """Update confidence score based on correlations."""
        if not correlations:
            return base_confidence

        # Calculate correlation bonus/penalty
        correlation_adjustment = 0

        high_confidence_correlations = [
            c for c in correlations if c.get("confidence", 0) > 80
        ]
        medium_confidence_correlations = [
            c for c in correlations if 50 <= c.get("confidence", 0) <= 80
        ]

        # Boost confidence for high-confidence correlations
        correlation_adjustment += len(high_confidence_correlations) * 10
        correlation_adjustment += len(medium_confidence_correlations) * 5

        # Threat level adjustments
        critical_threats = [
            c for c in correlations if c.get("threat_level") == "critical"
        ]
        high_threats = [c for c in correlations if c.get("threat_level") == "high"]

        correlation_adjustment += len(critical_threats) * 15
        correlation_adjustment += len(high_threats) * 10

        # Apply adjustment with limits
        updated_confidence = base_confidence + correlation_adjustment
        final_confidence = max(0, min(100, updated_confidence))

        self.logger.debug(
            f"Confidence update: base={base_confidence}, adjustment=+{correlation_adjustment}, final={final_confidence}"
        )

        return final_confidence

    async def _enrich_with_correlations(
        self,
        alert: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enrich alert data with correlation information."""
        enriched = {}

        try:
            # Correlation metadata
            enriched["correlation_metadata"] = {
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "correlation_method": self._get_correlation_method(),
                "total_correlations": len(correlations),
                "high_confidence_correlations": len(
                    [c for c in correlations if c.get("confidence", 0) > 80]
                ),
                "agent_version": "1.0.0",
            }

            # Correlation summary
            enriched["correlation_summary"] = {
                "correlation_types": list(
                    set(c.get("type", "unknown") for c in correlations)
                ),
                "threat_levels": list(
                    set(c.get("threat_level", "unknown") for c in correlations)
                ),
                "avg_confidence": sum(c.get("confidence", 0) for c in correlations)
                / len(correlations)
                if correlations
                else 0,
                "max_confidence": max(
                    (c.get("confidence", 0) for c in correlations), default=0
                ),
            }

            # Attack campaign indicators (from LLM if available)
            if self.enable_llm_correlation and self.llm_client:
                try:
                    llm_analysis = await self._analyze_correlations_with_llm(
                        alert, state
                    )
                    enriched["attack_intelligence"] = {
                        "campaign_indicators": llm_analysis.get(
                            "attack_campaign_indicators", []
                        ),
                        "threat_actor_patterns": llm_analysis.get(
                            "threat_actor_patterns", []
                        ),
                        "temporal_patterns": llm_analysis.get("temporal_patterns", []),
                        "behavioral_anomalies": llm_analysis.get(
                            "behavioral_anomalies", []
                        ),
                    }
                except Exception as e:
                    self.logger.debug(f"LLM enrichment failed: {e}")

            return enriched

        except Exception as e:
            self.logger.warning(f"Error enriching with correlations: {e}")
            return {}

    # Helper methods for correlation rules
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious (mock implementation)."""
        # In real implementation, this would check threat intelligence feeds
        suspicious_ranges = ["185.220.", "45.133.", "192.168."]
        return any(ip.startswith(range_) for range_ in suspicious_ranges)

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external."""
        internal_ranges = ["10.", "172.16.", "192.168.", "127."]
        return not any(ip.startswith(range_) for range_ in internal_ranges)

    def _is_suspicious_hash(self, file_hash: str) -> bool:
        """Check if hash is suspicious (mock implementation)."""
        # In real implementation, this would check malware databases
        suspicious_hashes = ["a1b2c3d4e5f6789", "d41d8cd98f00b204e9800998ecf8427e"]
        return file_hash in suspicious_hashes

    def _is_privileged_user(self, user: str) -> bool:
        """Check if user has privileged access."""
        privileged_users = ["administrator", "admin", "root", "system"]
        return user.lower() in privileged_users

    def _is_suspicious_process(self, process: str) -> bool:
        """Check if process is suspicious."""
        suspicious_processes = ["update.exe", "svchost.exe", "powershell.exe"]
        return process.lower() in suspicious_processes

    # Validation methods
    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state."""
        try:
            required_fields = ["alert_id", "raw_alert"]
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing required field: {field}")
                    return False

            if not state["raw_alert"]:
                self.logger.error("Raw alert data is empty")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating input: {e}")
            return False

    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state."""
        try:
            required_fields = ["correlations", "correlation_score", "triage_status"]
            for field in required_fields:
                if field not in state:
                    self.logger.error(f"Missing output field: {field}")
                    return False

            # Check correlation score range
            correlation_score = state.get("correlation_score", 0)
            if (
                not isinstance(correlation_score, (int, float))
                or not 0 <= correlation_score <= 100
            ):
                self.logger.error(f"Invalid correlation score: {correlation_score}")
                return False

            # Check that correlations is a list
            if not isinstance(state.get("correlations", []), list):
                self.logger.error("Invalid correlations: must be a list")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating output: {e}")
            return False

    async def cleanup(self):
        """Cleanup correlation agent resources."""
        try:
            self.logger.info("Cleaning up correlation agent")

            # Cleanup LLM client
            if self.llm_client:
                self.llm_client = None

            self.logger.info("Correlation agent cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during correlation agent cleanup: {e}")

    async def health_check(self) -> bool:
        """Check if the correlation agent is healthy."""
        try:
            if not self.initialized:
                return False

            # Check LLM client if enabled
            if self.enable_llm_correlation:
                if not self.llm_client:
                    return False

            # Run a simple test
            test_alert = {
                "id": "health_check",
                "severity": "low",
                "description": "Health check test",
                "raw_data": {"source_ip": "192.168.1.1"},
            }

            test_state = {"alert_id": "health_check", "raw_alert": test_alert}

            if not await self.validate_input(test_state):
                return False

            return True

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get correlation agent metrics."""
        base_metrics = super().get_metrics()

        correlation_metrics = {
            "correlation_window_minutes": self.correlation_window,
            "similarity_threshold": self.similarity_threshold,
            "max_correlations": self.max_correlations,
            "llm_correlation_enabled": self.enable_llm_correlation,
            "llm_client_active": self.llm_client is not None,
            "llm_weight": self.llm_weight,
            "correlation_method": self._get_correlation_method(),
        }

        base_metrics.update(correlation_metrics)
        return base_metrics
