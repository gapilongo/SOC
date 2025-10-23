"""
Response playbook system for automated threat response.

This module defines playbooks for different threat scenarios, mapping
threat types to appropriate automated response actions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(Enum):
    """Supported response action types."""

    # Network actions
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"

    # EDR actions
    ISOLATE_HOST = "isolate_host"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"

    # Identity actions
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    REVOKE_SESSIONS = "revoke_sessions"

    # Email actions
    DELETE_EMAIL = "delete_email"
    BLOCK_SENDER = "block_sender"

    # Notification actions
    SEND_ALERT = "send_alert"
    CREATE_TICKET = "create_ticket"

    # Investigation actions
    COLLECT_FORENSICS = "collect_forensics"
    TAKE_SNAPSHOT = "take_snapshot"


class RiskLevel(Enum):
    """Risk level for response actions."""

    LOW = "low"           # Safe to execute automatically
    MEDIUM = "medium"     # May impact operations, use caution
    HIGH = "high"         # Requires approval in production
    CRITICAL = "critical" # Should never auto-execute in production


@dataclass
class ResponseAction:
    """Individual response action with parameters."""

    action_type: ActionType
    tool_name: str  # Which tool to use (e.g., "crowdstrike", "firewall", "ad")
    tool_method: str  # Method to call on the tool
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    timeout: int = 30  # Execution timeout in seconds
    retry_on_failure: bool = True
    max_retries: int = 3
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "action_type": self.action_type.value,
            "tool_name": self.tool_name,
            "tool_method": self.tool_method,
            "parameters": self.parameters,
            "risk_level": self.risk_level.value,
            "timeout": self.timeout,
            "retry_on_failure": self.retry_on_failure,
            "max_retries": self.max_retries,
            "description": self.description
        }


@dataclass
class ResponsePlaybook:
    """Response playbook for a specific threat scenario."""

    name: str
    description: str
    threat_types: List[str]  # Which threat types this applies to
    actions: List[ResponseAction] = field(default_factory=list)
    parallel_execution: bool = False  # Execute actions in parallel or sequentially
    stop_on_failure: bool = True  # Stop if an action fails
    requires_approval: bool = False  # Require human approval before execution
    min_confidence: int = 80  # Minimum confidence score to auto-execute

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "name": self.name,
            "description": self.description,
            "threat_types": self.threat_types,
            "actions": [a.to_dict() for a in self.actions],
            "parallel_execution": self.parallel_execution,
            "stop_on_failure": self.stop_on_failure,
            "requires_approval": self.requires_approval,
            "min_confidence": self.min_confidence
        }


class PlaybookRegistry:
    """Registry of response playbooks."""

    def __init__(self):
        """Initialize playbook registry with default playbooks."""
        self._playbooks: Dict[str, ResponsePlaybook] = {}
        self._load_default_playbooks()

    def _load_default_playbooks(self):
        """Load default response playbooks."""

        # Malware C2 / Callback Playbook
        self.register(ResponsePlaybook(
            name="malware_c2_response",
            description="Response to malware command and control communication",
            threat_types=["malware_callback", "c2_communication", "malware_detected"],
            min_confidence=85,
            stop_on_failure=False,  # Continue even if some actions fail
            actions=[
                ResponseAction(
                    action_type=ActionType.ISOLATE_HOST,
                    tool_name="edr",
                    tool_method="isolate_host",
                    parameters={"isolation_type": "full"},
                    risk_level=RiskLevel.HIGH,
                    timeout=60,
                    description="Isolate infected host from network"
                ),
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    tool_name="firewall",
                    tool_method="block_ip",
                    parameters={"direction": "both", "duration": "permanent"},
                    risk_level=RiskLevel.MEDIUM,
                    description="Block C2 destination IP"
                ),
                ResponseAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    tool_name="edr",
                    tool_method="kill_process",
                    parameters={"force": True},
                    risk_level=RiskLevel.MEDIUM,
                    description="Terminate malicious process"
                ),
                ResponseAction(
                    action_type=ActionType.QUARANTINE_FILE,
                    tool_name="edr",
                    tool_method="quarantine_file",
                    parameters={},
                    risk_level=RiskLevel.LOW,
                    description="Quarantine malicious file"
                ),
                ResponseAction(
                    action_type=ActionType.COLLECT_FORENSICS,
                    tool_name="edr",
                    tool_method="collect_forensics",
                    parameters={"include_memory": True, "include_network": True},
                    risk_level=RiskLevel.LOW,
                    timeout=300,
                    description="Collect forensic evidence"
                ),
                ResponseAction(
                    action_type=ActionType.CREATE_TICKET,
                    tool_name="ticketing",
                    tool_method="create_ticket",
                    parameters={"priority": "critical", "category": "malware"},
                    risk_level=RiskLevel.LOW,
                    description="Create incident ticket for SOC team"
                )
            ]
        ))

        # Port Scan Response
        self.register(ResponsePlaybook(
            name="port_scan_response",
            description="Response to port scanning activity",
            threat_types=["port_scan", "network_scan", "reconnaissance"],
            min_confidence=70,
            stop_on_failure=False,
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    tool_name="firewall",
                    tool_method="block_ip",
                    parameters={"direction": "inbound", "duration": 86400},  # 24 hours
                    risk_level=RiskLevel.LOW,
                    description="Temporarily block scanning source IP"
                ),
                ResponseAction(
                    action_type=ActionType.SEND_ALERT,
                    tool_name="notification",
                    tool_method="send_alert",
                    parameters={"severity": "medium", "channel": "slack"},
                    risk_level=RiskLevel.LOW,
                    description="Notify SOC team"
                )
            ]
        ))

        # SQL Injection Response
        self.register(ResponsePlaybook(
            name="sql_injection_response",
            description="Response to SQL injection attempts",
            threat_types=["sql_injection_attempt", "sql_injection", "web_attack"],
            min_confidence=80,
            stop_on_failure=False,
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    tool_name="firewall",
                    tool_method="block_ip",
                    parameters={"direction": "inbound", "duration": "permanent"},
                    risk_level=RiskLevel.MEDIUM,
                    description="Block attacker source IP"
                ),
                ResponseAction(
                    action_type=ActionType.SEND_ALERT,
                    tool_name="notification",
                    tool_method="send_alert",
                    parameters={
                        "severity": "high",
                        "channel": "pagerduty",
                        "include_details": True
                    },
                    risk_level=RiskLevel.LOW,
                    description="Page on-call engineer"
                ),
                ResponseAction(
                    action_type=ActionType.CREATE_TICKET,
                    tool_name="ticketing",
                    tool_method="create_ticket",
                    parameters={"priority": "high", "category": "web_attack"},
                    risk_level=RiskLevel.LOW,
                    description="Create investigation ticket"
                )
            ]
        ))

        # Lateral Movement Response
        self.register(ResponsePlaybook(
            name="lateral_movement_response",
            description="Response to lateral movement attempts",
            threat_types=["lateral_movement", "privilege_escalation", "unauthorized_access"],
            min_confidence=85,
            requires_approval=True,  # High impact, require approval
            actions=[
                ResponseAction(
                    action_type=ActionType.ISOLATE_HOST,
                    tool_name="edr",
                    tool_method="isolate_host",
                    parameters={"isolation_type": "full"},
                    risk_level=RiskLevel.HIGH,
                    description="Isolate source host"
                ),
                ResponseAction(
                    action_type=ActionType.ISOLATE_HOST,
                    tool_name="edr",
                    tool_method="isolate_host",
                    parameters={"isolation_type": "full", "target": "destination"},
                    risk_level=RiskLevel.HIGH,
                    description="Isolate destination host"
                ),
                ResponseAction(
                    action_type=ActionType.DISABLE_USER,
                    tool_name="identity",
                    tool_method="disable_account",
                    parameters={"notify_user": False},
                    risk_level=RiskLevel.CRITICAL,
                    description="Disable compromised user account"
                ),
                ResponseAction(
                    action_type=ActionType.CREATE_TICKET,
                    tool_name="ticketing",
                    tool_method="create_ticket",
                    parameters={"priority": "critical", "category": "intrusion"},
                    risk_level=RiskLevel.LOW,
                    description="Create critical incident ticket"
                )
            ]
        ))

        # Credential Access Response
        self.register(ResponsePlaybook(
            name="credential_access_response",
            description="Response to credential theft attempts (e.g., Mimikatz)",
            threat_types=["credential_access", "mimikatz", "credential_dumping"],
            min_confidence=90,
            requires_approval=True,
            actions=[
                ResponseAction(
                    action_type=ActionType.ISOLATE_HOST,
                    tool_name="edr",
                    tool_method="isolate_host",
                    parameters={"isolation_type": "full"},
                    risk_level=RiskLevel.HIGH,
                    description="Immediately isolate affected host"
                ),
                ResponseAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    tool_name="edr",
                    tool_method="kill_process",
                    parameters={"force": True},
                    risk_level=RiskLevel.MEDIUM,
                    description="Terminate credential dumping process"
                ),
                ResponseAction(
                    action_type=ActionType.RESET_PASSWORD,
                    tool_name="identity",
                    tool_method="force_password_reset",
                    parameters={"scope": "all_users_on_host"},
                    risk_level=RiskLevel.CRITICAL,
                    description="Force password reset for all users on host"
                ),
                ResponseAction(
                    action_type=ActionType.REVOKE_SESSIONS,
                    tool_name="identity",
                    tool_method="revoke_sessions",
                    parameters={"scope": "all_users_on_host"},
                    risk_level=RiskLevel.HIGH,
                    description="Revoke all active sessions"
                ),
                ResponseAction(
                    action_type=ActionType.COLLECT_FORENSICS,
                    tool_name="edr",
                    tool_method="collect_forensics",
                    parameters={"include_memory": True, "priority": "high"},
                    risk_level=RiskLevel.LOW,
                    timeout=300,
                    description="Collect forensic evidence including memory dump"
                )
            ]
        ))

        # Generic High Confidence Threat
        self.register(ResponsePlaybook(
            name="generic_threat_response",
            description="Generic response for high-confidence threats without specific playbook",
            threat_types=["unknown", "generic_threat", "suspicious_activity"],
            min_confidence=85,
            stop_on_failure=False,
            actions=[
                ResponseAction(
                    action_type=ActionType.SEND_ALERT,
                    tool_name="notification",
                    tool_method="send_alert",
                    parameters={"severity": "high", "channel": "slack"},
                    risk_level=RiskLevel.LOW,
                    description="Alert SOC team"
                ),
                ResponseAction(
                    action_type=ActionType.CREATE_TICKET,
                    tool_name="ticketing",
                    tool_method="create_ticket",
                    parameters={"priority": "high", "category": "investigation_required"},
                    risk_level=RiskLevel.LOW,
                    description="Create investigation ticket"
                ),
                ResponseAction(
                    action_type=ActionType.COLLECT_FORENSICS,
                    tool_name="edr",
                    tool_method="collect_forensics",
                    parameters={"include_network": True},
                    risk_level=RiskLevel.LOW,
                    timeout=180,
                    description="Collect evidence for investigation"
                )
            ]
        ))

    def register(self, playbook: ResponsePlaybook):
        """Register a playbook."""
        self._playbooks[playbook.name] = playbook

    def get_playbook(self, name: str) -> Optional[ResponsePlaybook]:
        """Get a playbook by name."""
        return self._playbooks.get(name)

    def get_playbook_for_threat(
        self,
        threat_type: str,
        confidence_score: int
    ) -> Optional[ResponsePlaybook]:
        """Get the best matching playbook for a threat type."""
        # Find playbooks that match the threat type
        matching_playbooks = [
            pb for pb in self._playbooks.values()
            if threat_type.lower() in [tt.lower() for tt in pb.threat_types]
            and confidence_score >= pb.min_confidence
        ]

        if not matching_playbooks:
            # Try generic threat response if confidence is high enough
            generic = self._playbooks.get("generic_threat_response")
            if generic and confidence_score >= generic.min_confidence:
                return generic
            return None

        # Return the most specific playbook (fewest threat types = more specific)
        return min(matching_playbooks, key=lambda pb: len(pb.threat_types))

    def list_playbooks(self) -> List[str]:
        """List all registered playbook names."""
        return list(self._playbooks.keys())

    def get_all_playbooks(self) -> Dict[str, ResponsePlaybook]:
        """Get all registered playbooks."""
        return self._playbooks.copy()
