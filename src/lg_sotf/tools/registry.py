"""
Tool registry for LG-SOTF.

This module provides a registry for managing tool types and instances.
"""

from typing import Any, Dict, Type

from lg_sotf.core.exceptions import ToolError


class ToolRegistry:
    """Registry for managing tool types and instances."""
    
    def __init__(self):
        self._tool_types: Dict[str, Type] = {}
        self._tool_instances: Dict[str, Any] = {}
        self._tool_configs: Dict[str, Dict[str, Any]] = {}
    
    def register_tool(self, name: str, tool_class: Type, config: Dict[str, Any] = None):
        """Register a tool type with the registry."""
        self._tool_types[name] = tool_class
        self._tool_configs[name] = config or {}
    
    def get_tool(self, name: str):
        """Get a tool instance by name."""
        if name not in self._tool_instances:
            if name not in self._tool_types:
                # Create a mock tool for missing implementations
                from .adapters.base import BaseToolAdapter
                
                class MockTool(BaseToolAdapter):
                    async def execute(self, args: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
                        return {"mock": True, "tool": name, "result": "success"}
                
                self._tool_instances[name] = MockTool({})
            else:
                tool_class = self._tool_types[name]
                config = self._tool_configs[name]
                self._tool_instances[name] = tool_class(config)
        
        return self._tool_instances[name]
    
    def list_tools(self) -> list:
        """List all registered tools."""
        return list(self._tool_types.keys())


# Global registry instance
tool_registry = ToolRegistry()