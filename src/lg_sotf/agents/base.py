"""
Base agent class for LG-SOTF.

This module provides the abstract base class that all agents must inherit from,
ensuring consistent interface and behavior across all agent implementations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

from ..core.exceptions import AgentError


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
    
    async def validate_input(self, state: Dict[str, Any]) -> bool:
        """Validate input state.
        
        Args:
            state: Input state to validate
            
        Returns:
            True if input is valid, False otherwise
        """
        return True
    
    async def validate_output(self, state: Dict[str, Any]) -> bool:
        """Validate output state.
        
        Args:
            state: Output state to validate
            
        Returns:
            True if output is valid, False otherwise
        """
        return True
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config.get(key, default)
    
    def set_config(self, key: str, value: Any):
        """Set a configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value
    
    async def health_check(self) -> bool:
        """Check if the agent is healthy.
        
        Returns:
            True if agent is healthy, False otherwise
        """
        return True
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get agent metrics.
        
        Returns:
            Dictionary of metrics
        """
        return {
            "name": self.name,
            "initialized": self.initialized,
            "config_keys": list(self.config.keys())
        }