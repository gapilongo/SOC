"""
Audit logger for LG-SOTF.

This module provides comprehensive audit logging for all
framework operations, ensuring traceability and compliance.
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

import structlog

from ..core.config.manager import ConfigManager


class AuditLogger:
    """Handles audit logging for all framework operations."""
    
    def __init__(self):
        self.config = ConfigManager()
        self.logger = structlog.get_logger("lg_sotf.audit")
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup structured logging."""
        logging_config = self.config.get_logging_config()
        
        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            context_class=dict,
            cache_logger_on_first_use=True,
        )
    
    def log_state_creation(self, state) -> None:
        """Log state creation."""
        # Handle both dict and Pydantic model
        if hasattr(state, 'dict'):
            # It's a Pydantic model
            state_dict = state.dict()
            alert_id = state.alert_id
            workflow_instance_id = state.workflow_instance_id
        else:
            # It's a dict
            state_dict = state
            alert_id = state.get('alert_id')
            workflow_instance_id = state.get('workflow_instance_id')
        
        self.logger.info(
            "state_created",
            alert_id=alert_id,
            workflow_instance_id=workflow_instance_id,
            timestamp=datetime.utcnow().isoformat(),
            event_type="state_creation"
        )

    def log_state_update(self, state, old_state_hash: str) -> None:
        """Log state update."""
        # Handle both dict and Pydantic model
        if hasattr(state, 'dict'):
            # It's a Pydantic model
            state_dict = state.dict()
            alert_id = state.alert_id
            workflow_instance_id = state.workflow_instance_id
            state_version = state.state_version
        else:
            # It's a dict
            state_dict = state
            alert_id = state.get('alert_id')
            workflow_instance_id = state.get('workflow_instance_id')
            state_version = state.get('state_version')
        
        self.logger.info(
            "state_updated",
            alert_id=alert_id,
            workflow_instance_id=workflow_instance_id,
            version=state_version,
            old_state_hash=old_state_hash,
            timestamp=datetime.utcnow().isoformat(),
            event_type="state_update"
        )
        
    def log_node_execution_start(self, node_name: str, execution_id: str, 
                                start_time: datetime, input_state: Dict[str, Any]) -> None:
        """Log node execution start."""
        self.logger.info(
            "node_execution_started",
            node_name=node_name,
            execution_id=execution_id,
            start_time=start_time.isoformat(),
            alert_id=input_state.get('alert_id'),
            workflow_instance_id=input_state.get('workflow_instance_id')
        )
    
    def log_node_execution_end(self, node_name: str, execution_id: str, 
                              end_time: datetime, output_state: Dict[str, Any],
                              error: Optional[Exception] = None) -> None:
        """Log node execution end."""
        log_data = {
            "node_name": node_name,
            "execution_id": execution_id,
            "end_time": end_time.isoformat(),
            "alert_id": output_state.get('alert_id'),
            "workflow_instance_id": output_state.get('workflow_instance_id'),
            "success": error is None
        }
        
        if error:
            log_data["error"] = str(error)
            log_data["error_type"] = type(error).__name__
            self.logger.error("node_execution_failed", **log_data)
        else:
            self.logger.info("node_execution_completed", **log_data)
    
    def log_node_error(self, node_name: str, error: Exception, state: Dict[str, Any]) -> None:
        """Log node error."""
        self.logger.error(
            "node_error",
            node_name=node_name,
            error=str(error),
            error_type=type(error).__name__,
            alert_id=state.get('alert_id'),
            workflow_instance_id=state.get('workflow_instance_id'),
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_tool_execution_start(self, tool_name: str, execution_id: str, 
                                tool_args: Dict[str, Any], context: Dict[str, Any]) -> None:
        """Log tool execution start."""
        self.logger.info(
            "tool_execution_started",
            tool_name=tool_name,
            execution_id=execution_id,
            tool_args=tool_args,
            context=context,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_tool_execution_end(self, tool_name: str, execution_id: str, 
                              result: Dict[str, Any], cached: bool = False) -> None:
        """Log tool execution end."""
        self.logger.info(
            "tool_execution_completed",
            tool_name=tool_name,
            execution_id=execution_id,
            cached=cached,
            result_keys=list(result.keys()) if result else [],
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_tool_error(self, tool_name: str, error: Exception) -> None:
        """Log tool error."""
        self.logger.error(
            "tool_execution_failed",
            tool_name=tool_name,
            error=str(error),
            error_type=type(error).__name__,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_workflow_start(self, workflow_instance_id: str, alert_id: str) -> None:
        """Log workflow start."""
        self.logger.info(
            "workflow_started",
            workflow_instance_id=workflow_instance_id,
            alert_id=alert_id,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_workflow_end(self, workflow_instance_id: str, alert_id: str, 
                        success: bool, duration_seconds: float) -> None:
        """Log workflow end."""
        self.logger.info(
            "workflow_completed",
            workflow_instance_id=workflow_instance_id,
            alert_id=alert_id,
            success=success,
            duration_seconds=duration_seconds,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_security_event(self, event_type: str, severity: str, 
                           description: str, metadata: Dict[str, Any]) -> None:
        """Log security event."""
        self.logger.warning(
            "security_event",
            event_type=event_type,
            severity=severity,
            description=description,
            metadata=metadata,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _hash_state(self, state: Dict[str, Any]) -> str:
        """Create hash of state for comparison."""
        import hashlib
        state_str = json.dumps(state, sort_keys=True)
        return hashlib.sha256(state_str.encode()).hexdigest()
    
    def log_application_start(self, config_path: Optional[str] = None, version: Optional[str] = None) -> None:
        """Log application start."""
        self.logger.info(
            "application_started",
            config_path=config_path,
            version=version,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_application_shutdown(self) -> None:
        """Log application shutdown."""
        self.logger.info(
            "application_shutdown",
            timestamp=datetime.utcnow().isoformat()
        )