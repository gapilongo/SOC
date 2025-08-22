"""
Enhanced Base agent class for LG-SOTF.

This module provides the abstract base class that all agents must inherit from,
ensuring consistent interface and behavior across all agent implementations.
"""

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.audit.metrics import MetricsCollector
from lg_sotf.core.exceptions import AgentError


class BaseAgent(ABC):
    """Abstract base class for all LG-SOTF agents."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the agent.
        
        Args:
            config: Configuration dictionary for the agent
        """
        self.config = config
        self.name = self.__class__.__name__
        self.initialized = False
        
        # Enhanced features
        self.agent_id = str(uuid.uuid4())
        self.created_at = datetime.utcnow()
        self.last_execution = None
        self.execution_count = 0
        self.error_count = 0
        self.total_execution_time = 0.0
        
        # Audit and metrics
        self.audit_logger = AuditLogger()
        self.metrics = MetricsCollector()
        
        # State management
        self._execution_history = []
        self._current_execution_id = None
        
        # Timeouts and limits
        self.execution_timeout = self.get_config('execution_timeout', 30)
        self.max_retries = self.get_config('max_retries', 3)
        self.retry_delay = self.get_config('retry_delay', 1.0)
    
    @abstractmethod
    async def initialize(self):
        """Initialize the agent. Called before first execution."""
        pass
    
    @abstractmethod
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's logic.
        
        Args:
            state: Current state dictionary
            
        Returns:
            Updated state dictionary
        """
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Cleanup resources. Called when agent is being shut down."""
        pass
    
    # LangGraph Node Interface
    async def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make agent callable as a LangGraph node.
        
        This allows agents to be used directly in LangGraph workflows.
        """
        return await self.execute_with_monitoring(state)
    
    # Enhanced Execution with Monitoring
    async def execute_with_monitoring(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent with full monitoring, error handling, and retries."""
        execution_id = str(uuid.uuid4())
        self._current_execution_id = execution_id
        start_time = time.time()
        
        try:
            # Pre-execution validation
            if not await self.validate_input(state):
                raise AgentError(f"Input validation failed for agent {self.name}")
            
            # Initialize if needed
            if not self.initialized:
                await self.initialize()
                self.initialized = True
            
            # Log execution start
            self.audit_logger.log_node_execution_start(
                node_name=self.name,
                execution_id=execution_id,
                start_time=datetime.utcnow(),
                input_state=state
            )
            
            # Execute with timeout and retries
            result = await self._execute_with_retries(state)
            
            # Post-execution validation
            if not await self.validate_output(result):
                raise AgentError(f"Output validation failed for agent {self.name}")
            
            # Update execution stats
            execution_time = time.time() - start_time
            self._update_execution_stats(execution_time, True)
            
            # Log execution success
            self.audit_logger.log_node_execution_end(
                node_name=self.name,
                execution_id=execution_id,
                end_time=datetime.utcnow(),
                output_state=result
            )
            
            # Record metrics
            self.metrics.record_agent_execution(
                agent_name=self.name,
                execution_time=execution_time,
                success=True
            )
            
            return result
            
        except Exception as e:
            # Update error stats
            execution_time = time.time() - start_time
            self._update_execution_stats(execution_time, False)
            
            # Log execution error
            self.audit_logger.log_node_execution_end(
                node_name=self.name,
                execution_id=execution_id,
                end_time=datetime.utcnow(),
                output_state=state,
                error=e
            )
            
            # Record error metrics
            self.metrics.record_agent_execution(
                agent_name=self.name,
                execution_time=execution_time,
                success=False
            )
            
            # Handle error gracefully
            return await self._handle_execution_error(e, state)
    
    # Retry Logic
    async def _execute_with_retries(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Execute with timeout
                return await asyncio.wait_for(
                    self.execute(state),
                    timeout=self.execution_timeout
                )
            except asyncio.TimeoutError as e:
                last_exception = AgentError(f"Agent {self.name} execution timed out after {self.execution_timeout}s")
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                raise last_exception
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries and self._should_retry(e):
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    continue
                raise e
        
        raise last_exception
    
    # Error Handling
    async def _handle_execution_error(self, error: Exception, state: Dict[str, Any]) -> Dict[str, Any]:
        """Handle execution errors gracefully."""
        # Create error state
        error_state = state.copy()
        error_state.update({
            'agent_error': {
                'agent_name': self.name,
                'error_type': type(error).__name__,
                'error_message': str(error),
                'timestamp': datetime.utcnow().isoformat(),
                'execution_id': self._current_execution_id
            },
            'error_handled': True
        })
        
        # Check if we should fail fast or continue
        if self.get_config('fail_fast', False):
            raise AgentError(f"Agent {self.name} failed: {error}")
        
        return error_state
    
    # Retry Decision Logic
    def _should_retry(self, error: Exception) -> bool:
        """Determine if an error should trigger a retry."""
        # Don't retry validation errors
        if isinstance(error, AgentError) and 'validation' in str(error).lower():
            return False
        
        # Don't retry configuration errors
        if isinstance(error, (KeyError, ValueError)) and 'config' in str(error).lower():
            return False
        
        # Retry most other errors (network, temporary failures, etc.)
        return True
    
    # Enhanced Validation
    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state with enhanced checks."""
        # Basic validation
        if not isinstance(state, dict):
            return False
        
        # Check required fields
        required_fields = self.get_config('required_input_fields', [])
        for field in required_fields:
            if field not in state:
                return False
        
        # Custom validation hook
        return await self._validate_input_custom(state)
    
    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state with enhanced checks."""
        # Basic validation
        if not isinstance(state, dict):
            return False
        
        # Check required output fields
        required_fields = self.get_config('required_output_fields', [])
        for field in required_fields:
            if field not in state:
                return False
        
        # Custom validation hook
        return await self._validate_output_custom(state)
    
    # Custom Validation Hooks
    async def _validate_input_custom(self, state: Dict[str, Any]) -> bool:
        """Custom input validation - override in subclasses."""
        return True
    
    async def _validate_output_custom(self, state: Dict[str, Any]) -> bool:
        """Custom output validation - override in subclasses."""
        return True
    
    # State Management
    def _update_execution_stats(self, execution_time: float, success: bool):
        """Update execution statistics."""
        self.execution_count += 1
        self.total_execution_time += execution_time
        self.last_execution = datetime.utcnow()
        
        if not success:
            self.error_count += 1
        
        # Store in history (keep last 100)
        self._execution_history.append({
            'execution_id': self._current_execution_id,
            'timestamp': self.last_execution,
            'execution_time': execution_time,
            'success': success
        })
        
        if len(self._execution_history) > 100:
            self._execution_history.pop(0)
    
    # Enhanced Health Check
    async def health_check(self) -> bool:
        """Enhanced health check with detailed status."""
        try:
            # Basic health check
            if not self.initialized:
                return False
            
            # Check error rate (fail if > 50% errors in last 10 executions)
            if self.execution_count >= 10:
                recent_executions = self._execution_history[-10:]
                error_rate = sum(1 for ex in recent_executions if not ex['success']) / len(recent_executions)
                if error_rate > 0.5:
                    return False
            
            # Custom health check hook
            return await self._health_check_custom()
            
        except Exception:
            return False
    
    async def _health_check_custom(self) -> bool:
        """Custom health check - override in subclasses."""
        return True
    
    # Enhanced Metrics
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive agent metrics."""
        avg_execution_time = (
            self.total_execution_time / self.execution_count 
            if self.execution_count > 0 else 0
        )
        
        error_rate = (
            self.error_count / self.execution_count 
            if self.execution_count > 0 else 0
        )
        
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "initialized": self.initialized,
            "created_at": self.created_at.isoformat(),
            "last_execution": self.last_execution.isoformat() if self.last_execution else None,
            "execution_count": self.execution_count,
            "error_count": self.error_count,
            "error_rate": error_rate,
            "avg_execution_time": avg_execution_time,
            "total_execution_time": self.total_execution_time,
            "config_keys": list(self.config.keys()),
            "current_execution_id": self._current_execution_id
        }
    
    # Execution History
    def get_execution_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent execution history."""
        return self._execution_history[-limit:] if self._execution_history else []
    
    # Performance Analysis
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        if not self._execution_history:
            return {"status": "no_executions"}
        
        execution_times = [ex['execution_time'] for ex in self._execution_history]
        
        return {
            "total_executions": len(self._execution_history),
            "avg_execution_time": sum(execution_times) / len(execution_times),
            "min_execution_time": min(execution_times),
            "max_execution_time": max(execution_times),
            "success_rate": sum(1 for ex in self._execution_history if ex['success']) / len(self._execution_history),
            "recent_performance": self._execution_history[-5:] if len(self._execution_history) >= 5 else self._execution_history
        }
    
    # Configuration Validation
    def validate_config(self) -> bool:
        """Validate agent configuration."""
        required_config = self.get_required_config_keys()
        for key in required_config:
            if key not in self.config:
                raise AgentError(f"Required configuration key '{key}' missing for agent {self.name}")
        return True
    
    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys - override in subclasses."""
        return []
    
    # Enhanced config methods
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value with dot notation support."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set_config(self, key: str, value: Any):
        """Set a configuration value with dot notation support."""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    # Agent State Serialization
    def to_dict(self) -> Dict[str, Any]:
        """Serialize agent state to dictionary."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "initialized": self.initialized,
            "config": self.config,
            "created_at": self.created_at.isoformat(),
            "metrics": self.get_metrics()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Deserialize agent from dictionary."""
        agent = cls(data['config'])
        agent.agent_id = data['agent_id']
        agent.initialized = data['initialized']
        agent.created_at = datetime.fromisoformat(data['created_at'])
        return agent