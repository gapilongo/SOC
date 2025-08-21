"""
Agent registry for LG-SOTF.

This module provides a registry for managing agent types and instances,
allowing for dynamic agent discovery and instantiation.
"""

from typing import Any, Dict, Optional, Type

from ..core.exceptions import AgentError
from .base import BaseAgent


class AgentRegistry:
    """Registry for managing agent types and instances."""
    
    def __init__(self):
        self._agent_types: Dict[str, Type] = {}
        self._agent_instances: Dict[str, Any] = {}
        self._agent_configs: Dict[str, Dict[str, Any]] = {}
    
    def register_agent_type(self, name: str, agent_class: Type, config: Dict[str, Any] = None):
        """Register an agent type with the registry.
        
        Args:
            name: Name of the agent type
            agent_class: The agent class
            config: Default configuration for the agent
        """
        if not issubclass(agent_class, BaseAgent):
            raise AgentError(f"Agent class {agent_class} must inherit from BaseAgent")
        
        if name in self._agent_types:
            raise AgentError(f"Agent type {name} is already registered")
        
        self._agent_types[name] = agent_class
        self._agent_configs[name] = config or {}
    
    def create_agent(self, name: str, agent_type: str, config: Dict[str, Any] = None) -> str:
        """Create an agent instance.
        
        Args:
            name: Name for the agent instance
            agent_type: Type of agent to create
            config: Configuration for the agent (overrides default)
            
        Returns:
            The name of the created agent instance
        """
        if agent_type not in self._agent_types:
            raise AgentError(f"Unknown agent type: {agent_type}")
        
        if name in self._agent_instances:
            raise AgentError(f"Agent instance {name} already exists")
        
        # Merge default config with provided config
        default_config = self._agent_configs[agent_type].copy()
        if config:
            default_config.update(config)
        
        # Create agent instance
        agent_class = self._agent_types[agent_type]
        agent_instance = agent_class(default_config)
        
        # Store the instance
        self._agent_instances[name] = agent_instance
        
        return name
    
    def get_agent(self, name: str) -> Any:
        """Get an agent instance by name.
        
        Args:
            name: Name of the agent instance
            
        Returns:
            The agent instance
        """
        if name not in self._agent_instances:
            raise AgentError(f"Agent instance {name} not found")
        
        return self._agent_instances[name]
    
    def list_agent_types(self) -> Dict[str, Type]:
        """List all registered agent types.
        
        Returns:
            Dictionary of agent type names to classes
        """
        return self._agent_types.copy()
    
    def list_agent_instances(self) -> Dict[str, Any]:
        """List all agent instances.
        
        Returns:
            Dictionary of agent instance names to instances
        """
        return self._agent_instances.copy()
    
    def remove_agent(self, name: str):
        """Remove an agent instance.
        
        Args:
            name: Name of the agent instance to remove
        """
        if name not in self._agent_instances:
            raise AgentError(f"Agent instance {name} not found")
        
        del self._agent_instances[name]
    
    def get_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Get the default configuration for an agent type.
        
        Args:
            agent_type: Type of agent
            
        Returns:
            Default configuration for the agent type
        """
        if agent_type not in self._agent_configs:
            raise AgentError(f"Unknown agent type: {agent_type}")
        
        return self._agent_configs[agent_type].copy()
    
    def update_agent_config(self, agent_type: str, config: Dict[str, Any]):
        """Update the default configuration for an agent type.
        
        Args:
            agent_type: Type of agent
            config: New configuration to merge with existing
        """
        if agent_type not in self._agent_configs:
            raise AgentError(f"Unknown agent type: {agent_type}")
        
        self._agent_configs[agent_type].update(config)
    
    def clear(self):
        """Clear all registered agents and instances."""
        self._agent_types.clear()
        self._agent_instances.clear()
        self._agent_configs.clear()


# Global registry instance
agent_registry = AgentRegistry()