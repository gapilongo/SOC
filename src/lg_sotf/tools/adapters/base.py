"""
Base tool adapter for LG-SOTF.

This module provides the abstract base class for all tool adapters.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

from lg_sotf.core.exceptions import ToolError


class BaseToolAdapter(ABC):
    """Abstract base class for all tool adapters."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the tool adapter."""
        self.config = config
        self.name = self.__class__.__name__.lower().replace('adapter', '')
        self.initialized = False
    
    @abstractmethod
    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute the tool with given arguments."""
        pass
    
    async def initialize(self):
        """Initialize the tool adapter."""
        self.initialized = True
    
    async def cleanup(self):
        """Cleanup tool adapter resources."""
        pass
    
    async def health_check(self) -> bool:
        """Check if the tool is healthy."""
        return True
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get tool metrics."""
        return {
            "name": self.name,
            "initialized": self.initialized,
            "config_keys": list(self.config.keys())
        }