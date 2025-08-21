"""
Base node class for LG-SOTF workflow nodes.

This module provides the abstract base class for all workflow nodes,
ensuring consistent behavior and interface across the framework.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

from ..audit.logger import AuditLogger
from ..audit.metrics import MetricsCollector
from ..config.manager import ConfigManager
from ..exceptions import NodeError
from ..state.manager import StateManager


class BaseNode(ABC):
    """Abstract base class for workflow nodes."""
    
    def __init__(self, config_manager: ConfigManager, state_manager: StateManager):
        self.config = config_manager
        self.state_manager = state_manager
        self.audit_logger = AuditLogger()
        self.metrics = MetricsCollector()
        self.node_name = self.__class__.__name__.lower().replace('node', '')
    
    @abstractmethod
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the node's logic."""
        pass
    
    @abstractmethod
    def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state."""
        pass
    
    @abstractmethod
    def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state."""
        pass
    
    async def _log_execution_start(self, state: Dict[str, Any]) -> str:
        """Log execution start."""
        execution_id = self._generate_execution_id()
        start_time = datetime.utcnow()
        
        self.audit_logger.log_node_execution_start(
            node_name=self.node_name,
            execution_id=execution_id,
            start_time=start_time,
            input_state=state
        )
        
        self.metrics.start_execution_timer(self.node_name, execution_id)
        
        return execution_id
    
    async def _log_execution_end(self, execution_id: str, output_state: Dict[str, Any], 
                                error: Optional[Exception] = None):
        """Log execution end."""
        end_time = datetime.utcnow()
        
        self.audit_logger.log_node_execution_end(
            node_name=self.node_name,
            execution_id=execution_id,
            end_time=end_time,
            output_state=output_state,
            error=error
        )
        
        self.metrics.end_execution_timer(self.node_name, execution_id)
        
        if error:
            self.metrics.increment_error_count(self.node_name)
    
    def _generate_execution_id(self) -> str:
        """Generate unique execution ID."""
        import uuid
        return f"{self.node_name}_{uuid.uuid4().hex[:8]}"
    
    def _get_node_config(self) -> Dict[str, Any]:
        """Get node-specific configuration."""
        return self.config.get(f'nodes.{self.node_name}', {})
    
    def _handle_error(self, error: Exception, state: Dict[str, Any]) -> Dict[str, Any]:
        """Handle execution errors."""
        self.audit_logger.log_node_error(
            node_name=self.node_name,
            error=error,
            state=state
        )
        
        # Add error information to state
        error_state = state.copy()
        error_state['error'] = {
            'node': self.node_name,
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return error_state