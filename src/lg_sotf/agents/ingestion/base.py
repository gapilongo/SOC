"""
Ingestion Agent implementation for LG-SOTF.

This module provides the ingestion agent that pulls alerts from various sources
(SIEM, EDR, Cloud providers, etc.) and normalizes them into a common format.
Supports plugin architecture for easy extensibility.
"""

import asyncio
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from lg_sotf.agents.base import BaseAgent
from lg_sotf.agents.ingestion.plugins.base import IngestionPlugin
from lg_sotf.agents.ingestion.plugins.registry import plugin_registry
from lg_sotf.core.exceptions import AgentError


class AlertNormalizer:
    """Normalizes alerts from different sources into common format."""

    @staticmethod
    def normalize(raw_alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize alert to common format.
        
        Args:
            raw_alert: Raw alert data from source
            source: Source system name
            
        Returns:
            Normalized alert dictionary
        """
        # Extract filename from alert metadata if available
        filename = raw_alert.get("_metadata", {}).get("filename") or raw_alert.get("filename")
        source = AlertNormalizer._extract_source_from_filename(raw_alert, source, filename)
        
        # Extract common fields with source-specific mappings
        normalized = {
            "id": AlertNormalizer._extract_id(raw_alert, source),
            "timestamp": AlertNormalizer._extract_timestamp(raw_alert, source),
            "source": source,
            "severity": AlertNormalizer._extract_severity(raw_alert, source),
            "title": AlertNormalizer._extract_title(raw_alert, source),
            "description": AlertNormalizer._extract_description(raw_alert, source),
            "category": AlertNormalizer._extract_category(raw_alert, source),
            "raw_data": AlertNormalizer._extract_raw_data(raw_alert, source),
            "entities": AlertNormalizer._extract_entities(raw_alert, source),
            "metadata": {
                "source_system": source,
                "ingestion_timestamp": datetime.utcnow().isoformat(),
                "original_format": type(raw_alert).__name__,
                "normalization_version": "1.0.0"
            }
        }
        
        # Add alert hash for deduplication
        normalized["alert_hash"] = AlertNormalizer._generate_alert_hash(normalized)
        
        return normalized

    @staticmethod
    def _extract_id(alert: Dict[str, Any], source: str) -> str:
        """Extract alert ID."""
        # Common field mappings
        id_fields = ["id", "alert_id", "alertId", "event_id", "eventId", "_id", "uuid"]
        
        for field in id_fields:
            if field in alert and alert[field]:
                return str(alert[field])
        
        # Source-specific extractions
        if source == "splunk" and "result" in alert:
            return alert["result"].get("_raw", {}).get("id", "")
        elif source == "qradar" and "id" in alert:
            return str(alert["id"])
        elif source == "sentinel" and "properties" in alert:
            return alert["properties"].get("systemAlertId", "")
        elif source == "crowdstrike" and "event" in alert:
            return alert["event"].get("DetectId", "")
        
        # Generate ID if not found
        return f"{source}_{hashlib.md5(str(alert).encode()).hexdigest()[:16]}"

    @staticmethod
    def _extract_timestamp(alert: Dict[str, Any], source: str) -> str:
        """Extract timestamp."""
        timestamp_fields = [
            "timestamp", "@timestamp", "time", "created_time", "createdTime",
            "event_time", "eventTime", "detection_time", "detectionTime"
        ]
        
        for field in timestamp_fields:
            if field in alert and alert[field]:
                return AlertNormalizer._parse_timestamp(alert[field])
        
        # Source-specific
        if source == "splunk" and "_time" in alert:
            return AlertNormalizer._parse_timestamp(alert["_time"])
        elif source == "qradar" and "start_time" in alert:
            return AlertNormalizer._parse_timestamp(alert["start_time"])
        elif source == "sentinel" and "properties" in alert:
            ts = alert["properties"].get("timeGenerated", "")
            if ts:
                return AlertNormalizer._parse_timestamp(ts)
        
        # Default to current time
        return datetime.utcnow().isoformat()
    
    @staticmethod
    def _extract_source_from_filename(alert: Dict[str, Any], source: str, filename: str = None) -> str:
        """Extract source from filename or data."""
        
        # If we have a filename, extract source from it
        if filename and source == "file":
            # crowdstrike_detections.json → crowdstrike
            # siem_firewall_alerts.csv → firewall
            # authentication_events.json → authentication
            
            filename_lower = filename.lower()
            
            # Common patterns
            source_patterns = {
                'crowdstrike': 'crowdstrike',
                'sentinel': 'sentinel',
                'splunk': 'splunk',
                'qradar': 'qradar',
                'firewall': 'firewall',
                'authentication': 'authentication',
                'auth': 'authentication',
                'wazuh': 'wazuh',
                'ids': 'ids',
                'ips': 'ips',
                'edr': 'edr',
                'siem': 'siem'
            }
            
            for pattern, source_name in source_patterns.items():
                if pattern in filename_lower:
                    return source_name
        
        # Fallback: check explicit source field in data
        if "source" in alert and alert["source"] != "file":
            return alert["source"]
        
        return source

    @staticmethod
    def _parse_timestamp(ts: Any) -> str:
        """Parse various timestamp formats.

        Returns current time as fallback if parsing fails.
        """
        if isinstance(ts, str):
            try:
                # Try ISO format
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                return dt.isoformat()
            except (ValueError, AttributeError) as e:
                # Log failed parse but don't raise - continue to fallback
                import logging
                logging.getLogger(__name__).debug(
                    f"Failed to parse timestamp string '{ts}': {e}"
                )
        elif isinstance(ts, (int, float)):
            # Unix timestamp
            try:
                dt = datetime.utcfromtimestamp(ts)
                return dt.isoformat()
            except (ValueError, OSError, OverflowError) as e:
                # Unix timestamp out of range or invalid
                import logging
                logging.getLogger(__name__).debug(
                    f"Failed to parse unix timestamp {ts}: {e}"
                )
        elif isinstance(ts, datetime):
            return ts.isoformat()

        # Fallback to current time if all parsing attempts failed
        return datetime.utcnow().isoformat()

    @staticmethod
    def _extract_severity(alert: Dict[str, Any], source: str) -> str:
        """Extract and normalize severity."""
        severity_fields = ["severity", "priority", "level", "risk_score"]
        
        severity_value = None
        for field in severity_fields:
            if field in alert:
                severity_value = alert[field]
                break
        
        # Source-specific
        if not severity_value:
            if source == "qradar" and "magnitude" in alert:
                severity_value = alert["magnitude"]
            elif source == "sentinel" and "properties" in alert:
                severity_value = alert["properties"].get("severity", "")
            elif source == "crowdstrike" and "event" in alert:
                severity_value = alert["event"].get("Severity", "")
        
        # Normalize to standard levels
        return AlertNormalizer._normalize_severity(severity_value)

    @staticmethod
    def _normalize_severity(severity: Any) -> str:
        """Normalize severity to standard levels."""
        if not severity:
            return "medium"
        
        severity_str = str(severity).lower()
        
        # Map numeric values
        if isinstance(severity, (int, float)):
            if severity >= 80:
                return "critical"
            elif severity >= 60:
                return "high"
            elif severity >= 40:
                return "medium"
            elif severity >= 20:
                return "low"
            else:
                return "info"
        
        # Map string values
        if any(word in severity_str for word in ["critical", "crit", "emergency"]):
            return "critical"
        elif any(word in severity_str for word in ["high", "severe"]):
            return "high"
        elif any(word in severity_str for word in ["medium", "moderate", "warning"]):
            return "medium"
        elif any(word in severity_str for word in ["low", "minor"]):
            return "low"
        elif any(word in severity_str for word in ["info", "informational"]):
            return "info"
        
        return "medium"

    @staticmethod
    def _extract_title(alert: Dict[str, Any], source: str) -> str:
        """Extract alert title."""
        title_fields = ["title", "name", "alert_name", "alertName", "rule_name", "ruleName"]
        
        for field in title_fields:
            if field in alert and alert[field]:
                return str(alert[field])
        
        # Source-specific
        if source == "splunk" and "search_name" in alert:
            return alert["search_name"]
        elif source == "qradar" and "offense_type" in alert:
            return f"QRadar: {alert['offense_type']}"
        elif source == "sentinel" and "properties" in alert:
            return alert["properties"].get("alertDisplayName", "")
        
        return f"Alert from {source}"

    @staticmethod
    def _extract_description(alert: Dict[str, Any], source: str) -> str:
        """Extract alert description."""
        desc_fields = ["description", "message", "details", "summary"]
        
        for field in desc_fields:
            if field in alert and alert[field]:
                return str(alert[field])
        
        # Source-specific
        if source == "sentinel" and "properties" in alert:
            return alert["properties"].get("description", "")
        
        return ""

    @staticmethod
    def _extract_category(alert: Dict[str, Any], source: str) -> str:
        """Extract alert category."""
        category_fields = ["category", "type", "classification", "tactic"]
        
        for field in category_fields:
            if field in alert and alert[field]:
                return str(alert[field])
        
        return "unknown"

    @staticmethod
    def _extract_raw_data(alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Extract relevant raw data fields."""
        # If alert is already normalized and has raw_data, return it as-is
        if "raw_data" in alert and isinstance(alert["raw_data"], dict) and alert["raw_data"]:
            return alert["raw_data"]

        raw_data = {}

        # Network fields
        network_fields = [
            "source_ip", "src_ip", "sourceIP", "destination_ip", "dst_ip", "destinationIP",
            "source_port", "src_port", "destination_port", "dst_port",
            "protocol", "bytes_transferred"
        ]
        
        # File fields
        file_fields = [
            "file_name", "fileName", "file_path", "filePath", "file_hash", "fileHash",
            "md5", "sha1", "sha256"
        ]
        
        # Process fields
        process_fields = [
            "process_name", "processName", "process_id", "pid", "command_line",
            "parent_process", "parentProcess"
        ]
        
        # User fields
        user_fields = [
            "user", "username", "account", "user_id", "userId"
        ]
        
        # Host fields
        host_fields = [
            "host", "hostname", "computer_name", "computerName", "device_name"
        ]
        
        all_fields = network_fields + file_fields + process_fields + user_fields + host_fields
        
        for field in all_fields:
            if field in alert and alert[field]:
                raw_data[field] = alert[field]

        # Source-specific extractions
        if source == "crowdstrike" and "event" in alert:
            event = alert["event"]
            raw_data.update({
                "process_name": event.get("FileName", ""),
                "file_path": event.get("FilePath", ""),
                "command_line": event.get("CommandLine", ""),
                "user": event.get("UserName", ""),
                "host": event.get("ComputerName", "")
            })
        
        return raw_data

    @staticmethod
    def _extract_entities(alert: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
        """Extract entities from alert."""
        entities = []
        
        # Check for entities field
        if "entities" in alert and isinstance(alert["entities"], list):
            return alert["entities"]
        
        # Source-specific entity extraction
        if source == "sentinel" and "properties" in alert:
            props = alert["properties"]
            if "entities" in props:
                return props["entities"]
        
        # Extract from raw data
        raw_data = AlertNormalizer._extract_raw_data(alert, source)
        
        # IP entities
        for field in ["source_ip", "destination_ip"]:
            if field in raw_data:
                entities.append({
                    "type": "ip",
                    "value": raw_data[field],
                    "role": field.replace("_", " ")
                })
        
        # File entities
        for field in ["file_hash", "md5", "sha256"]:
            if field in raw_data:
                entities.append({
                    "type": "file_hash",
                    "value": raw_data[field],
                    "hash_type": field
                })
        
        # User entities
        if "user" in raw_data or "username" in raw_data:
            user_value = raw_data.get("user") or raw_data.get("username")
            entities.append({
                "type": "user",
                "value": user_value
            })
        
        # Host entities
        for field in ["host", "hostname"]:
            if field in raw_data:
                entities.append({
                    "type": "host",
                    "value": raw_data[field]
                })
        
        return entities

    @staticmethod
    def _generate_alert_hash(normalized_alert: Dict[str, Any]) -> str:
        """Generate hash for alert deduplication."""
        # Use key fields for hashing
        hash_fields = [
            normalized_alert.get("source", ""),
            normalized_alert.get("title", ""),
            normalized_alert.get("severity", ""),
            str(normalized_alert.get("raw_data", {}))
        ]
        
        hash_string = "|".join(hash_fields)
        return hashlib.sha256(hash_string.encode()).hexdigest()


class IngestionAgent(BaseAgent):
    """Ingestion agent for pulling alerts from various sources."""

    def __init__(self, config: Dict[str, Any], redis_storage=None):
        """Initialize the ingestion agent.

        Args:
            config: Agent configuration
            redis_storage: Optional RedisStorage instance for distributed dedup/rate limiting
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Ingestion configuration
        self.batch_size = self.get_config("batch_size", 100)
        self.polling_interval = self.get_config("polling_interval", 60)
        self.max_concurrent_alerts = self.get_config("max_concurrent_alerts", 50)
        self.deduplication_window_hours = self.get_config("deduplication_window_hours", 24)
        self.enable_deduplication = self.get_config("enable_deduplication", True)
        self.alert_retention_days = self.get_config("alert_retention_days", 90)

        # Source configuration
        self.enabled_sources = self.get_config("enabled_sources", [])
        self.source_priorities = self.get_config("source_priorities", {})

        # Rate limiting
        self.rate_limit_enabled = self.get_config("rate_limit_enabled", True)
        self.max_alerts_per_minute = self.get_config("max_alerts_per_minute", 1000)
        self.max_alerts_per_source_minute = self.get_config("max_alerts_per_source_minute", 100)

        # Redis for distributed deduplication and rate limiting (production-ready)
        self.redis_storage = redis_storage

        # Components
        self.plugins: Dict[str, IngestionPlugin] = {}
        self.normalizer = AlertNormalizer()

        # State tracking (fallback when Redis unavailable)
        self.seen_alert_hashes: Set[str] = set()
        self.alert_rate_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self.ingestion_stats = {
            "total_ingested": 0,
            "total_deduplicated": 0,
            "total_errors": 0,
            "by_source": defaultdict(lambda: {
                "ingested": 0,
                "deduplicated": 0,
                "errors": 0
            })
        }

        # Last successful poll times
        self.last_poll_times: Dict[str, datetime] = {}

    async def initialize(self):
        """Initialize the ingestion agent."""
        try:
            self.logger.info("Initializing ingestion agent")

            # Load and initialize plugins
            await self._load_plugins()

            # Initialize deduplication cache
            await self._initialize_deduplication()

            # Perform health checks on all plugins
            await self._health_check_plugins()

            self.initialized = True
            self.logger.info(f"Ingestion agent initialized with {len(self.plugins)} sources")

        except Exception as e:
            self.logger.error(f"Failed to initialize ingestion agent: {e}")
            # Don't raise - continue with available plugins
            self.logger.warning("Continuing with available plugins")
            self.initialized = True

    async def _load_plugins(self):
        """Load and initialize ingestion plugins."""
        sources_config = self.get_config("sources", {})
        
        for source_name, source_config in sources_config.items():
            # Skip if not enabled
            if not source_config.get("enabled", True):
                self.logger.info(f"Source {source_name} is disabled, skipping")
                continue
            
            try:
                # Get plugin class from registry
                plugin_class = plugin_registry.get_plugin(source_name)
                
                if not plugin_class:
                    self.logger.warning(f"No plugin found for source {source_name}")
                    continue
                
                # Create plugin instance
                plugin = plugin_class(source_config)
                
                # Initialize plugin
                await plugin.initialize()
                
                # Store plugin
                self.plugins[source_name] = plugin
                self.enabled_sources.append(source_name)
                
                self.logger.info(f"Loaded plugin for source: {source_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to load plugin for {source_name}: {e}")
                self.ingestion_stats["by_source"][source_name]["errors"] += 1

    async def _initialize_deduplication(self):
        """Initialize deduplication cache."""
        if self.enable_deduplication:
            # In production, this would use Redis or similar
            # For now, using in-memory set with TTL management
            self.seen_alert_hashes.clear()
            self.logger.info("Deduplication cache initialized")

    async def _health_check_plugins(self):
        """Perform health checks on all plugins."""
        healthy_plugins = []
        unhealthy_plugins = []
        
        for source_name, plugin in self.plugins.items():
            try:
                is_healthy = await plugin.health_check()
                if is_healthy:
                    healthy_plugins.append(source_name)
                else:
                    unhealthy_plugins.append(source_name)
                    self.logger.warning(f"Plugin {source_name} failed health check")
            except Exception as e:
                unhealthy_plugins.append(source_name)
                self.logger.error(f"Health check failed for {source_name}: {e}")
        
        self.logger.info(
            f"Plugin health check: {len(healthy_plugins)} healthy, "
            f"{len(unhealthy_plugins)} unhealthy"
        )

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ingestion for a specific alert or batch poll.
        
        Args:
            state: Workflow state (may contain specific source/query)
            
        Returns:
            Updated state with ingested alerts
        """
        try:
            self.logger.info("Executing ingestion agent")

            # Check if this is a specific alert ingestion or batch poll
            if "raw_alert" in state and state["raw_alert"]:
                # Single alert ingestion (from webhook or direct input)
                return await self._ingest_single_alert(state)
            else:
                # Batch ingestion from sources
                return await self._ingest_batch(state)

        except Exception as e:
            self.logger.error(f"Ingestion execution failed: {e}")
            return await self._create_error_state(state, str(e))

    async def _ingest_single_alert(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a single alert.

        Returns only state updates, following LangGraph best practices.
        """
        raw_alert = state["raw_alert"]
        source = state.get("source", "unknown")

        try:
            # Normalize alert
            normalized_alert = self.normalizer.normalize(raw_alert, source)

            # Check deduplication
            if self.enable_deduplication:
                if await self._is_duplicate(normalized_alert):
                    self.logger.info(f"Duplicate alert detected: {normalized_alert['id']}")
                    self.ingestion_stats["total_deduplicated"] += 1
                    self.ingestion_stats["by_source"][source]["deduplicated"] += 1

                    # Return only updates (not full state)
                    return {
                        "ingestion_status": "duplicate",
                        "triage_status": "ingested",
                        "current_node": "ingestion",
                        "metadata": {
                            "duplicate_detected": True,
                            "original_hash": normalized_alert["alert_hash"]
                        }
                    }

            # Track as seen
            await self._track_alert(normalized_alert)

            # Update stats
            self.ingestion_stats["total_ingested"] += 1
            self.ingestion_stats["by_source"][source]["ingested"] += 1

            # Return only updates (not full state)
            return {
                "raw_alert": normalized_alert,
                "ingestion_status": "success",
                "triage_status": "ingested",
                "current_node": "ingestion",
                "enriched_data": {
                    "ingestion_metadata": {
                        "source": source,
                        "ingestion_time": datetime.utcnow().isoformat(),
                        "normalized": True,
                        "alert_hash": normalized_alert["alert_hash"]
                    }
                },
                "metadata": {
                    "ingestion_timestamp": datetime.utcnow().isoformat(),
                    "source_system": source
                }
            }

        except Exception as e:
            self.logger.error(f"Failed to ingest single alert: {e}")
            self.ingestion_stats["total_errors"] += 1
            self.ingestion_stats["by_source"][source]["errors"] += 1
            return {
                "ingestion_status": "error",
                "triage_status": "ingestion_failed",
                "current_node": "ingestion",
                "ingestion_error": str(e),
                "metadata": {
                    "ingestion_error": str(e),
                    "ingestion_timestamp": datetime.utcnow().isoformat()
                }
            }

    async def _ingest_batch(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest batch of alerts from all sources.

        Returns only state updates, following LangGraph best practices.
        """
        try:
            all_alerts = []
            source_results = {}

            # Poll each source
            for source_name, plugin in self.plugins.items():
                try:
                    # Check rate limits
                    if not await self._check_rate_limit(source_name):
                        self.logger.warning(f"Rate limit exceeded for {source_name}, skipping")
                        continue

                    # Get time range for polling
                    since_time = self._get_last_poll_time(source_name)

                    # Fetch alerts from source
                    self.logger.debug(f"Polling {source_name} for alerts since {since_time}")
                    raw_alerts = await plugin.fetch_alerts(
                        since=since_time,
                        limit=self.batch_size
                    )

                    # Normalize alerts
                    normalized_alerts = []
                    deduplicated_count = 0

                    for raw_alert in raw_alerts:
                        try:
                            normalized = self.normalizer.normalize(raw_alert, source_name)

                            # Check deduplication
                            if self.enable_deduplication and await self._is_duplicate(normalized):
                                deduplicated_count += 1
                                continue

                            # Track and add
                            await self._track_alert(normalized)
                            normalized_alerts.append(normalized)

                        except Exception as e:
                            self.logger.error(f"Failed to normalize alert from {source_name}: {e}")
                            self.ingestion_stats["by_source"][source_name]["errors"] += 1

                    # Update stats
                    self.ingestion_stats["total_ingested"] += len(normalized_alerts)
                    self.ingestion_stats["total_deduplicated"] += deduplicated_count
                    self.ingestion_stats["by_source"][source_name]["ingested"] += len(normalized_alerts)
                    self.ingestion_stats["by_source"][source_name]["deduplicated"] += deduplicated_count

                    # Store results
                    source_results[source_name] = {
                        "fetched": len(raw_alerts),
                        "normalized": len(normalized_alerts),
                        "deduplicated": deduplicated_count
                    }

                    all_alerts.extend(normalized_alerts)

                    # Update last poll time
                    self.last_poll_times[source_name] = datetime.utcnow()

                    self.logger.info(
                        f"Polled {source_name}: {len(raw_alerts)} fetched, "
                        f"{len(normalized_alerts)} ingested, {deduplicated_count} deduplicated"
                    )

                except Exception as e:
                    self.logger.error(f"Failed to poll {source_name}: {e}")
                    self.ingestion_stats["by_source"][source_name]["errors"] += 1
                    source_results[source_name] = {"error": str(e)}

            # Sort by priority and timestamp (FIXED: proper sorting)
            all_alerts.sort(
                key=lambda a: (
                    self.source_priorities.get(a["source"], 999),  # Lower priority = process first
                    -self._timestamp_to_unix(a["timestamp"])  # Negative for newest first
                )
            )

            # Return only updates (not full state)
            return {
                "ingestion_status": "batch_complete",
                "triage_status": "ingested",
                "current_node": "ingestion",
                "batch_results": {
                    "total_alerts": len(all_alerts),
                    "sources_polled": len(source_results),
                    "source_details": source_results,
                    "polling_timestamp": datetime.utcnow().isoformat()
                },
                "ingested_alerts": all_alerts[:self.max_concurrent_alerts],  # Limit concurrent processing
                "metadata": {
                    "batch_ingestion": True,
                    "ingestion_stats": self.ingestion_stats
                }
            }

        except Exception as e:
            self.logger.error(f"Batch ingestion failed: {e}")
            self.ingestion_stats["total_errors"] += 1
            return {
                "ingestion_status": "error",
                "triage_status": "ingestion_failed",
                "current_node": "ingestion",
                "ingestion_error": str(e),
                "metadata": {
                    "ingestion_error": str(e),
                    "ingestion_timestamp": datetime.utcnow().isoformat()
                }
            }

    async def _is_duplicate(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is a duplicate using Redis (distributed) or in-memory (fallback).

        Args:
            alert: Normalized alert dictionary with alert_hash

        Returns:
            True if alert is duplicate, False otherwise
        """
        alert_hash = alert.get("alert_hash", "")
        if not alert_hash:
            return False

        # Use Redis if available (production-ready, distributed)
        if self.redis_storage:
            try:
                return await self.redis_storage.is_duplicate_alert(
                    alert_hash,
                    ttl_hours=self.deduplication_window_hours
                )
            except Exception as e:
                self.logger.warning(f"Redis deduplication check failed, using fallback: {e}")
                # Fall through to in-memory check

        # Fallback to in-memory (for development/testing)
        return alert_hash in self.seen_alert_hashes

    async def _track_alert(self, alert: Dict[str, Any]):
        """Track alert for deduplication using Redis (distributed) or in-memory (fallback).

        Args:
            alert: Normalized alert dictionary with alert_hash
        """
        alert_hash = alert.get("alert_hash", "")
        alert_id = alert.get("id", "unknown")

        if not alert_hash:
            return

        # Use Redis if available (production-ready, distributed)
        if self.redis_storage:
            try:
                await self.redis_storage.track_alert_hash(
                    alert_hash,
                    alert_id,
                    ttl_hours=self.deduplication_window_hours
                )
                # No need for manual cleanup - Redis handles TTL automatically
                return
            except Exception as e:
                self.logger.warning(f"Redis alert tracking failed, using fallback: {e}")
                # Fall through to in-memory tracking

        # Fallback to in-memory (for development/testing)
        self.seen_alert_hashes.add(alert_hash)

        # Track for rate limiting
        source = alert.get("source", "unknown")
        self.alert_rate_tracker[source].append(datetime.utcnow())

        # Cleanup old entries (beyond deduplication window)
        self._cleanup_tracking()

    def _cleanup_tracking(self):
        """Cleanup old tracking data."""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.deduplication_window_hours)
        
        # Cleanup rate tracker
        for source in list(self.alert_rate_tracker.keys()):
            self.alert_rate_tracker[source] = [
                ts for ts in self.alert_rate_tracker[source]
                if ts > cutoff_time
            ]
            if not self.alert_rate_tracker[source]:
                del self.alert_rate_tracker[source]

    async def _check_rate_limit(self, source: str) -> bool:
        """Check if rate limit allows ingestion using Redis (distributed) or in-memory (fallback).

        Returns True if ingestion is allowed, False if rate limit exceeded.
        """
        if not self.rate_limit_enabled:
            return True

        # Use Redis if available (production-ready, distributed)
        if self.redis_storage:
            try:
                # Check source-specific rate limit
                source_allowed = await self.redis_storage.check_rate_limit(
                    source=source,
                    max_per_minute=self.max_alerts_per_source_minute,
                    window_seconds=60
                )

                if not source_allowed:
                    self.logger.warning(
                        f"Source rate limit exceeded for {source}: "
                        f"max {self.max_alerts_per_source_minute}/min"
                    )
                    return False

                # Check global rate limit
                global_allowed = await self.redis_storage.check_rate_limit(
                    source="global",
                    max_per_minute=self.max_alerts_per_minute,
                    window_seconds=60
                )

                if not global_allowed:
                    self.logger.warning(
                        f"Global rate limit exceeded: max {self.max_alerts_per_minute}/min"
                    )
                    return False

                return True

            except Exception as e:
                self.logger.warning(f"Redis rate limit check failed, using fallback: {e}")
                # Fall through to in-memory fallback

        # Fallback to in-memory rate limiting (for development/testing)
        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)

        # Count alerts in last minute
        recent_alerts = [
            ts for ts in self.alert_rate_tracker.get(source, [])
            if ts > one_minute_ago
        ]

        # Check source-specific limit
        if len(recent_alerts) >= self.max_alerts_per_source_minute:
            self.logger.warning(
                f"[Fallback] Source rate limit exceeded for {source}: "
                f"{len(recent_alerts)}/{self.max_alerts_per_source_minute} per minute"
            )
            return False

        # Check global limit
        total_recent = sum(
            len([ts for ts in timestamps if ts > one_minute_ago])
            for timestamps in self.alert_rate_tracker.values()
        )

        if total_recent >= self.max_alerts_per_minute:
            self.logger.warning(
                f"[Fallback] Global rate limit exceeded: "
                f"{total_recent}/{self.max_alerts_per_minute} per minute"
            )
            return False

        return True

    def _get_last_poll_time(self, source: str) -> Optional[datetime]:
        """Get last successful poll time for source."""
        return self.last_poll_times.get(source)

    def _timestamp_to_unix(self, timestamp_str: str) -> float:
        """Convert ISO timestamp string to unix timestamp for sorting."""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return 0.0

    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state."""
        # For ingestion, minimal validation required
        if not isinstance(state, dict):
            return False
        
        # If raw_alert present, validate its structure
        if "raw_alert" in state and state["raw_alert"]:
            if not isinstance(state["raw_alert"], dict):
                return False
        
        return True

    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state."""
        if not isinstance(state, dict):
            return False
        
        # Ensure ingestion status is set
        if "ingestion_status" not in state:
            return False
        
        return True

    async def cleanup(self):
        """Cleanup ingestion agent resources."""
        try:
            self.logger.info("Cleaning up ingestion agent")

            # Cleanup all plugins
            for source_name, plugin in self.plugins.items():
                try:
                    await plugin.cleanup()
                except Exception as e:
                    self.logger.warning(f"Error cleaning up plugin {source_name}: {e}")

            # Clear caches
            self.seen_alert_hashes.clear()
            self.alert_rate_tracker.clear()
            
            self.logger.info("Ingestion agent cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during ingestion agent cleanup: {e}")

    async def health_check(self) -> bool:
        """Enhanced health check for ingestion agent with detailed status reporting.

        Returns True if at least one plugin is healthy, False otherwise.
        Logs detailed status for each component.
        """
        try:
            if not self.initialized:
                self.logger.warning("Ingestion agent health check: not initialized")
                return False

            # Check if we have any healthy plugins with detailed status
            healthy_count = 0
            total_count = len(self.plugins)
            plugin_statuses = {}

            for plugin_name, plugin in self.plugins.items():
                try:
                    is_healthy = await plugin.health_check()
                    plugin_statuses[plugin_name] = "healthy" if is_healthy else "unhealthy"
                    if is_healthy:
                        healthy_count += 1
                except Exception as e:
                    # Log but continue checking other plugins
                    plugin_statuses[plugin_name] = f"error: {str(e)}"
                    self.logger.debug(
                        f"Plugin '{plugin_name}' health check failed: {e}"
                    )

            # Log detailed status
            is_healthy = healthy_count > 0
            self.logger.info(
                f"Ingestion agent health check: {healthy_count}/{total_count} plugins healthy - "
                f"Status: {'HEALTHY' if is_healthy else 'UNHEALTHY'} | "
                f"Details: {plugin_statuses}"
            )

            # Additional diagnostics
            if self.redis_storage:
                try:
                    redis_healthy = await self.redis_storage.health_check()
                    self.logger.debug(f"Redis storage: {'HEALTHY' if redis_healthy else 'UNHEALTHY'}")
                except Exception as e:
                    self.logger.debug(f"Redis storage health check failed: {e}")

            # Consider healthy if at least one plugin is working
            return is_healthy

        except Exception as e:
            self.logger.error(f"Health check failed with exception: {e}")
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get ingestion metrics."""
        base_metrics = super().get_metrics()

        ingestion_metrics = {
            "batch_size": self.batch_size,
            "polling_interval": self.polling_interval,
            "enabled_sources": self.enabled_sources,
            "active_plugins": len(self.plugins),
            "deduplication_enabled": self.enable_deduplication,
            "rate_limiting_enabled": self.rate_limit_enabled,
            "ingestion_stats": self.ingestion_stats,
            "seen_alert_count": len(self.seen_alert_hashes),
            "last_poll_times": {
                source: time.isoformat()
                for source, time in self.last_poll_times.items()
            }
        }

        base_metrics.update(ingestion_metrics)
        return base_metrics

    async def poll_sources(self) -> List[Dict[str, Any]]:
        """Public method to poll all sources (for scheduled polling)."""
        state = {"alert_id": f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"}
        result = await self._ingest_batch(state)
        return result.get("ingested_alerts", [])

    def get_source_stats(self) -> Dict[str, Any]:
        """Get detailed statistics by source."""
        return {
            "by_source": dict(self.ingestion_stats["by_source"]),
            "total_ingested": self.ingestion_stats["total_ingested"],
            "total_deduplicated": self.ingestion_stats["total_deduplicated"],
            "total_errors": self.ingestion_stats["total_errors"]
        }