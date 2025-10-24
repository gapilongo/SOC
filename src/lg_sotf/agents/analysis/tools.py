"""
Analysis tools for the analysis agent.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from lg_sotf.tools.adapters.base import BaseToolAdapter


class IPAnalysisTool(BaseToolAdapter):
    """Tool for IP address analysis and reputation checking."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # IP classification patterns
        self.private_ranges = [
            "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
            "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.", "127.", "169.254."
        ]
        
        self.suspicious_ranges = [
            "185.220.", "45.133.", "31.220.", "89.248.", "193.176."
        ]
        
        self.malicious_ips = [
            "185.220.101.44", "45.133.1.87", "31.220.43.99"
        ]
    
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute IP analysis."""
        try:
            target_ip = args.get("target", "")
            analysis_type = args.get("analysis_type", "reputation")
            
            if not target_ip or not self._is_valid_ip(target_ip):
                return {
                    "success": False,
                    "error": f"Invalid IP address: {target_ip}",
                    "analysis_type": analysis_type
                }
            
            # Perform analysis
            result = {
                "success": True,
                "ip": target_ip,
                "analysis_type": analysis_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Classification analysis
            result.update(await self._classify_ip(target_ip))
            
            # Reputation analysis
            if analysis_type == "reputation" or analysis_type == "ip_reputation":
                result.update(await self._check_reputation(target_ip))
            
            # Geolocation analysis (basic)
            result.update(await self._geolocate_ip(target_ip))
            
            return result
            
        except Exception as e:
            self.logger.error(f"IP analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": args.get("analysis_type", "unknown")
            }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    async def _classify_ip(self, ip: str) -> Dict[str, Any]:
        """Classify IP address type."""
        
        is_private = any(ip.startswith(prefix) for prefix in self.private_ranges)
        is_suspicious_range = any(ip.startswith(prefix) for prefix in self.suspicious_ranges)
        is_malicious = ip in self.malicious_ips
        
        classification = "private" if is_private else "public"
        if is_malicious:
            classification = "malicious"
        elif is_suspicious_range:
            classification = "suspicious"
        
        return {
            "is_private": is_private,
            "is_public": not is_private,
            "is_suspicious_range": is_suspicious_range,
            "classification": classification
        }
    
    async def _check_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation."""
        
        # Simple reputation based on known patterns
        reputation = "clean"
        confidence = 0.7
        sources = []
        
        if ip in self.malicious_ips:
            reputation = "malicious"
            confidence = 0.95
            sources = ["internal_threat_intel"]
        elif any(ip.startswith(prefix) for prefix in self.suspicious_ranges):
            reputation = "suspicious" 
            confidence = 0.8
            sources = ["pattern_analysis"]
        elif any(ip.startswith(prefix) for prefix in self.private_ranges):
            reputation = "private"
            confidence = 0.99
            sources = ["rfc1918"]
        
        return {
            "reputation": reputation,
            "reputation_confidence": confidence,
            "reputation_sources": sources,
            "threat_categories": ["c2", "malware"] if reputation == "malicious" else []
        }
    
    async def _geolocate_ip(self, ip: str) -> Dict[str, Any]:
        """Basic IP geolocation."""
        
        # Simple geolocation based on known ranges
        country = "Unknown"
        region = "Unknown"
        
        if ip.startswith("185.220."):
            country = "Germany"
            region = "Europe"
        elif ip.startswith("45.133."):
            country = "Netherlands"
            region = "Europe"
        elif any(ip.startswith(prefix) for prefix in self.private_ranges):
            country = "Private"
            region = "RFC1918"
        
        return {
            "country": country,
            "region": region,
            "is_tor": False,  # Would require real Tor exit node list
            "is_vpn": False   # Would require real VPN detection
        }


class HashAnalysisTool(BaseToolAdapter):
    """Tool for file hash analysis and malware detection."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Known malicious hashes
        self.malicious_hashes = {
            "a1b2c3d4e5f6789": {"family": "TrojanGeneric", "confidence": 0.95},
            "d41d8cd98f00b204e9800998ecf8427e": {"family": "EmptyFile", "confidence": 0.99},
            "5f4dcc3b5aa765d61d8327deb882cf99": {"family": "WeakPassword", "confidence": 0.8}
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            "deadbeef", "cafebabe", "feedface"
        ]
    
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute hash analysis."""
        try:
            target_hash = args.get("target", "").lower()
            analysis_type = args.get("analysis_type", "malware_analysis")
            
            if not target_hash:
                return {
                    "success": False,
                    "error": "No hash provided",
                    "analysis_type": analysis_type
                }
            
            result = {
                "success": True,
                "hash": target_hash,
                "analysis_type": analysis_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Malware detection
            result.update(await self._check_malware_reputation(target_hash))
            
            # Hash characteristics
            result.update(self._analyze_hash_characteristics(target_hash))
            
            return result
            
        except Exception as e:
            self.logger.error(f"Hash analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": args.get("analysis_type", "unknown")
            }
    
    async def _check_malware_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check hash against malware databases."""
        
        is_malicious = file_hash in self.malicious_hashes
        is_suspicious = any(pattern in file_hash for pattern in self.suspicious_patterns)
        
        if is_malicious:
            malware_info = self.malicious_hashes[file_hash]
            return {
                "is_malicious": True,
                "malware_family": malware_info["family"],
                "detection_confidence": malware_info["confidence"],
                "detection_sources": ["internal_db"],
                "first_seen": "2024-01-01",
                "threat_level": "high"
            }
        elif is_suspicious:
            return {
                "is_malicious": False,
                "is_suspicious": True,
                "detection_confidence": 0.6,
                "detection_sources": ["pattern_analysis"],
                "threat_level": "medium"
            }
        else:
            return {
                "is_malicious": False,
                "is_suspicious": False,
                "detection_confidence": 0.1,
                "detection_sources": [],
                "threat_level": "low"
            }
    
    def _analyze_hash_characteristics(self, file_hash: str) -> Dict[str, Any]:
        """Analyze hash characteristics."""
        
        hash_type = "unknown"
        if len(file_hash) == 32:
            hash_type = "md5"
        elif len(file_hash) == 40:
            hash_type = "sha1" 
        elif len(file_hash) == 64:
            hash_type = "sha256"
        
        return {
            "hash_type": hash_type,
            "hash_length": len(file_hash),
            "is_valid_format": bool(re.match(r'^[a-fA-F0-9]+$', file_hash))
        }


class ProcessAnalysisTool(BaseToolAdapter):
    """Tool for process behavior analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        self.suspicious_processes = {
            "update.exe": {"risk": "high", "reason": "Common masquerading name"},
            "svchost.exe": {"risk": "medium", "reason": "Legitimate but often abused"},
            "powershell.exe": {"risk": "medium", "reason": "Often used in attacks"},
            "cmd.exe": {"risk": "low", "reason": "Legitimate system process"}
        }
        
        self.legitimate_locations = [
            "c:\\windows\\system32",
            "c:\\windows\\syswow64",
            "c:\\program files",
            "c:\\program files (x86)"
        ]
    
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute process analysis."""
        try:
            process_name = args.get("target", "").lower()
            analysis_type = args.get("analysis_type", "behavior_analysis")
            
            # Extract additional context from alert
            alert_context = args.get("alert_context", {})
            raw_data = alert_context.get("raw_data", {})
            process_path = raw_data.get("file_path", "").lower()
            
            result = {
                "success": True,
                "process": process_name,
                "process_path": process_path,
                "analysis_type": analysis_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Process reputation analysis
            result.update(self._analyze_process_reputation(process_name))
            
            # Path analysis
            if process_path:
                result.update(self._analyze_process_path(process_path))
            
            # Behavioral indicators
            result.update(self._analyze_behavioral_indicators(raw_data))
            
            return result
            
        except Exception as e:
            self.logger.error(f"Process analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": args.get("analysis_type", "unknown")
            }
    
    def _analyze_process_reputation(self, process_name: str) -> Dict[str, Any]:
        """Analyze process reputation."""
        
        if process_name in self.suspicious_processes:
            process_info = self.suspicious_processes[process_name]
            return {
                "is_suspicious": process_info["risk"] in ["high", "medium"],
                "risk_level": process_info["risk"],
                "reputation_reason": process_info["reason"],
                "is_known_process": True
            }
        else:
            return {
                "is_suspicious": False,
                "risk_level": "unknown",
                "reputation_reason": "Unknown process",
                "is_known_process": False
            }
    
    def _analyze_process_path(self, process_path: str) -> Dict[str, Any]:
        """Analyze process execution path."""
        
        is_legitimate_location = any(
            process_path.startswith(location) for location in self.legitimate_locations
        )
        
        is_temp_location = any(
            temp_dir in process_path for temp_dir in ["\\temp\\", "\\tmp\\", "\\downloads\\"]
        )
        
        return {
            "is_legitimate_location": is_legitimate_location,
            "is_temp_location": is_temp_location,
            "path_risk": "high" if is_temp_location else "low" if is_legitimate_location else "medium"
        }
    
    def _analyze_behavioral_indicators(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral indicators."""
        
        indicators = []
        
        # Network activity
        if raw_data.get("destination_ip"):
            indicators.append("network_communication")
        
        # Privilege level
        user = raw_data.get("user", "").lower()
        if user in ["system", "administrator"]:
            indicators.append("high_privileges")
        
        # Command line analysis
        command_line = raw_data.get("command_line", "").lower()
        if command_line:
            if any(flag in command_line for flag in ["-c", "--command", "/c"]):
                indicators.append("command_execution")
            if any(keyword in command_line for keyword in ["powershell", "cmd", "wscript"]):
                indicators.append("script_execution")
        
        return {
            "behavioral_indicators": indicators,
            "behavior_count": len(indicators),
            "has_network_activity": "network_communication" in indicators,
            "has_high_privileges": "high_privileges" in indicators
        }


class NetworkAnalysisTool(BaseToolAdapter):
    """Tool for network behavior analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        self.suspicious_ports = {
            4444: {"risk": "high", "description": "Common reverse shell port"},
            6666: {"risk": "high", "description": "Common trojan port"},
            31337: {"risk": "high", "description": "Elite hacker port"},
            8080: {"risk": "medium", "description": "HTTP proxy port"},
            3389: {"risk": "medium", "description": "RDP port"}
        }
    
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute network analysis."""
        try:
            target = args.get("target", "")
            analysis_type = args.get("analysis_type", "network_behavior")
            
            # Parse target (IP:port format)
            ip, port = self._parse_target(target)
            
            # Get additional context
            alert_context = args.get("alert_context", {})
            raw_data = alert_context.get("raw_data", {})
            
            result = {
                "success": True,
                "target": target,
                "ip": ip,
                "port": port,
                "analysis_type": analysis_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Port analysis
            if port:
                result.update(self._analyze_port(port))
            
            # Traffic analysis
            result.update(self._analyze_traffic_patterns(raw_data))
            
            # Protocol analysis
            result.update(self._analyze_protocol_indicators(raw_data))
            
            return result
            
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": args.get("analysis_type", "unknown")
            }
    
    def _parse_target(self, target) -> tuple:
        """Parse IP:port target from string or dict (handle LLM output variations).

        The LLM may return target in different formats:
        - String: "192.168.1.1:445"
        - Dict: {"ip": "192.168.1.1", "port": 445}
        - Dict with alternative keys: {"source_ip": "...", "destination_port": ...}
        """
        # Handle dict input from LLM or alert context
        if isinstance(target, dict):
            # Try common field names for IP
            ip = (
                target.get("ip") or
                target.get("source_ip") or
                target.get("destination_ip") or
                target.get("host") or
                ""
            )
            # Try common field names for port
            port = (
                target.get("port") or
                target.get("destination_port") or
                target.get("source_port")
            )
            # Normalize port to int
            if port:
                if isinstance(port, str) and port.isdigit():
                    port = int(port)
                elif not isinstance(port, int):
                    port = None

            return str(ip) if ip else "", port if isinstance(port, int) else None

        # Handle string input (IP:port format)
        if isinstance(target, str):
            if not target:
                return "", None
            if ":" in target:
                parts = target.split(":")
                ip = parts[0]
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                return ip, port
            # Just IP, no port
            return target, None

        # Fallback for unexpected types
        self.logger.warning(f"Unexpected target type: {type(target)}, value: {target}")
        return str(target) if target else "", None
    
    def _analyze_port(self, port: int) -> Dict[str, Any]:
        """Analyze port characteristics."""
        
        if port in self.suspicious_ports:
            port_info = self.suspicious_ports[port]
            return {
                "is_suspicious_port": True,
                "port_risk": port_info["risk"],
                "port_description": port_info["description"],
                "is_known_port": True
            }
        elif port < 1024:
            return {
                "is_suspicious_port": False,
                "port_risk": "low",
                "port_description": "Well-known port",
                "is_known_port": True,
                "is_system_port": True
            }
        elif port >= 49152:
            return {
                "is_suspicious_port": False,
                "port_risk": "low",
                "port_description": "Dynamic/ephemeral port",
                "is_known_port": False,
                "is_ephemeral_port": True
            }
        else:
            return {
                "is_suspicious_port": False,
                "port_risk": "medium",
                "port_description": "Registered port",
                "is_known_port": False
            }
    
    def _analyze_traffic_patterns(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network traffic patterns."""

        # Ensure numeric types - convert strings to integers
        try:
            bytes_transferred = int(raw_data.get("bytes_transferred", 0))
        except (ValueError, TypeError):
            bytes_transferred = 0

        try:
            duration = int(raw_data.get("duration_seconds", 0))
        except (ValueError, TypeError):
            duration = 0

        # Traffic volume analysis
        volume_category = "low"
        if bytes_transferred > 10000000:  # > 10MB
            volume_category = "high"
        elif bytes_transferred > 1000000:  # > 1MB
            volume_category = "medium"

        # Duration analysis
        duration_category = "short"
        if duration > 300:  # > 5 minutes
            duration_category = "long"
        elif duration > 60:  # > 1 minute
            duration_category = "medium"

        return {
            "bytes_transferred": bytes_transferred,
            "duration_seconds": duration,
            "volume_category": volume_category,
            "duration_category": duration_category,
            "is_bulk_transfer": bytes_transferred > 5000000,  # > 5MB
            "is_persistent_connection": duration > 180  # > 3 minutes
        }

    def _analyze_protocol_indicators(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze protocol-level indicators."""

        indicators = []

        # Check for encrypted traffic
        if raw_data.get("encryption") == "enabled":
            indicators.append("encrypted_traffic")

        # Check for beaconing patterns
        if raw_data.get("pattern") == "regular":
            indicators.append("regular_beaconing")

        # Check for data exfiltration indicators - ensure numeric type
        try:
            bytes_transferred = int(raw_data.get("bytes_transferred", 0))
        except (ValueError, TypeError):
            bytes_transferred = 0

        if bytes_transferred > 1000000:  # > 1MB
            indicators.append("large_data_transfer")

        return {
            "protocol_indicators": indicators,
            "has_encryption": "encrypted_traffic" in indicators,
            "has_beaconing": "regular_beaconing" in indicators,
            "has_large_transfer": "large_data_transfer" in indicators
        }


class TemporalAnalysisTool(BaseToolAdapter):
    """Tool for temporal pattern analysis and historical event correlation.

    Analyzes events before/after an alert to establish timeline and find
    related activity (precursor events, follow-up actions, etc.)
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.state_manager = None  # Will be injected if available
    
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute temporal analysis - find events before/after alert."""
        try:
            # Extract parameters flexibly
            target = args.get("target", {})
            analysis_type = args.get("analysis_type", "general")

            # Handle different input formats
            if isinstance(target, dict):
                timestamp = target.get("timestamp")
                username = target.get("username")
                time_window = target.get("time_window_minutes", 60)
            elif isinstance(target, str):
                # String format: "username, timestamp" or just timestamp
                parts = [p.strip() for p in target.split(',')]
                if len(parts) == 2:
                    username = parts[0]
                    timestamp = parts[1]
                else:
                    username = None
                    timestamp = target
                time_window = 60
            else:
                username = args.get("username")
                timestamp = args.get("timestamp")
                time_window = args.get("time_window_minutes", 60)

            # Parse timestamp
            parsed_time = self._parse_timestamp(timestamp) if timestamp else None

            result = {
                "success": True,
                "analysis_type": analysis_type,
                "timestamp_analyzed": datetime.utcnow().isoformat()
            }

            # If we have state_manager, query historical events
            if self.state_manager and parsed_time:
                historical_events = await self._query_historical_events(
                    parsed_time, username, time_window
                )
                result["historical_events"] = historical_events
                result["events_found"] = len(historical_events)

            # Basic timing analysis
            if parsed_time:
                result.update(self._analyze_timing(parsed_time))
                result.update(self._analyze_business_hours(parsed_time))
            else:
                result["warning"] = "No valid timestamp provided for timing analysis"

            return result
            
        except Exception as e:
            self.logger.error(f"Temporal analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": args.get("analysis_type", "unknown")
            }
    
    async def _query_historical_events(self, timestamp: datetime, username: Optional[str], time_window_minutes: int) -> List[Dict[str, Any]]:
        """Query database for events around the given timestamp."""
        if not self.state_manager:
            return []

        try:
            from datetime import timedelta

            # Calculate time range
            start_time = timestamp - timedelta(minutes=time_window_minutes)
            end_time = timestamp + timedelta(minutes=time_window_minutes)

            # Query database (using state_manager's connection)
            # This is a simplified version - adapt to your actual state_manager API
            events = []

            # Try to get connection from state_manager
            if hasattr(self.state_manager, 'db_pool') and self.state_manager.db_pool:
                async with self.state_manager.db_pool.acquire() as conn:
                    query = """
                        SELECT
                            alert_id,
                            state_data->>'timestamp' as timestamp,
                            state_data->'raw_alert'->>'title' as title,
                            state_data->'raw_alert'->>'severity' as severity,
                            state_data->'raw_alert'->>'category' as category,
                            created_at
                        FROM states
                        WHERE state_data->'raw_alert'->>'timestamp' BETWEEN $1 AND $2
                    """

                    if username:
                        query += " AND state_data->'raw_alert'->'raw_data'->>'username' = $3"
                        rows = await conn.fetch(query, start_time.isoformat(), end_time.isoformat(), username)
                    else:
                        rows = await conn.fetch(query, start_time.isoformat(), end_time.isoformat())

                    for row in rows:
                        events.append({
                            "alert_id": row['alert_id'],
                            "timestamp": row['timestamp'],
                            "title": row['title'],
                            "severity": row['severity'],
                            "category": row['category']
                        })

            return events[:20]  # Limit to 20 events

        except Exception as e:
            self.logger.warning(f"Failed to query historical events: {e}")
            return []

    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """Parse timestamp string."""
        try:
            # Handle various timestamp formats
            if timestamp.endswith('Z'):
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(timestamp)
        except Exception:
            return None
    
    def _analyze_timing(self, dt: datetime) -> Dict[str, Any]:
        """Analyze timing characteristics."""
        
        return {
            "hour": dt.hour,
            "day_of_week": dt.weekday(),
            "day_name": dt.strftime("%A"),
            "month": dt.month,
            "year": dt.year,
            "is_weekend": dt.weekday() >= 5
        }
    
    def _analyze_business_hours(self, dt: datetime) -> Dict[str, Any]:
        """Analyze business hours context."""
        
        is_business_hours = 9 <= dt.hour < 17  # 9 AM to 5 PM
        is_extended_hours = 7 <= dt.hour < 19  # 7 AM to 7 PM
        is_night_time = dt.hour < 6 or dt.hour >= 22  # Before 6 AM or after 10 PM
        
        risk_level = "low"
        if is_night_time:
            risk_level = "medium"
        elif not is_business_hours and not dt.weekday() >= 5:
            risk_level = "low-medium"
        
        return {
            "is_business_hours": is_business_hours,
            "is_extended_hours": is_extended_hours,
            "is_night_time": is_night_time,
            "temporal_risk": risk_level,
            "timing_context": self._get_timing_context(dt.hour)
        }
    
    def _analyze_temporal_patterns(self, dt: datetime) -> Dict[str, Any]:
        """Analyze temporal patterns."""
        
        patterns = []
        
        # Maintenance window detection
        if 2 <= dt.hour <= 5:
            patterns.append("maintenance_window")
        
        # Peak hours detection
        if 10 <= dt.hour <= 14:
            patterns.append("peak_hours")
        
        # Off-hours detection
        if dt.hour < 7 or dt.hour > 19:
            patterns.append("off_hours")
        
        return {
            "temporal_patterns": patterns,
            "is_maintenance_window": "maintenance_window" in patterns,
            "is_peak_hours": "peak_hours" in patterns,
            "is_off_hours": "off_hours" in patterns
        }
    
    def _get_timing_context(self, hour: int) -> str:
        """Get human-readable timing context."""
        
        if 0 <= hour < 6:
            return "late_night"
        elif 6 <= hour < 9:
            return "early_morning"
        elif 9 <= hour < 12:
            return "morning"
        elif 12 <= hour < 17:
            return "afternoon"
        elif 17 <= hour < 20:
            return "evening"
        else:
            return "night"