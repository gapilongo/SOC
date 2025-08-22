"""
Agent registry for LG-SOTF.

This module provides a registry for managing agent types and instances,
allowing for dynamic agent discovery and instantiation.
"""

import logging
from typing import Any, Dict, Optional, Type

from lg_sotf.agents.base import BaseAgent
from lg_sotf.core.exceptions import AgentError


class AgentRegistry:
    """Registry for managing agent types and instances."""
    
    def __init__(self):
        self._agent_types: Dict[str, Type] = {}
        self._agent_instances: Dict[str, Any] = {}
        self._agent_configs: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_agent_type(self, name: str, agent_class: Type, config: Dict[str, Any] = None):
        """Register an agent type with the registry.
        
        Args:
            name: Name of the agent type
            agent_class: The agent class
            config: Default configuration for the agent
        """
        try:
            if not issubclass(agent_class, BaseAgent):
                raise AgentError(f"Agent class {agent_class} must inherit from BaseAgent")
            
            if name in self._agent_types:
                self.logger.warning(f"Agent type {name} is already registered, overwriting")
            
            self._agent_types[name] = agent_class
            self._agent_configs[name] = config or {}
            
            self.logger.info(f"Agent type '{name}' registered successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to register agent type '{name}': {e}")
            raise AgentError(f"Failed to register agent type {name}: {str(e)}")
    
    def create_agent(self, name: str, agent_type: str, config: Dict[str, Any] = None) -> str:
        """Create an agent instance.
        
        Args:
            name: Name for the agent instance
            agent_type: Type of agent to create
            config: Configuration for the agent (overrides default)
            
        Returns:
            The name of the created agent instance
        """
        try:
            if agent_type not in self._agent_types:
                raise AgentError(f"Unknown agent type: {agent_type}")
            
            if name in self._agent_instances:
                self.logger.warning(f"Agent instance {name} already exists, overwriting")
            
            # Merge default config with provided config
            default_config = self._agent_configs[agent_type].copy()
            if config:
                default_config.update(config)
            
            # Create agent instance
            agent_class = self._agent_types[agent_type]
            agent_instance = agent_class(default_config)
            
            # Store the instance
            self._agent_instances[name] = agent_instance
            
            self.logger.info(f"Agent instance '{name}' of type '{agent_type}' created successfully")
            
            return name
            
        except Exception as e:
            self.logger.error(f"Failed to create agent instance '{name}': {e}")
            raise AgentError(f"Failed to create agent instance {name}: {str(e)}")
    
    def get_agent(self, name: str) -> Any:
        """Get an agent instance by name.
        
        Args:
            name: Name of the agent instance
            
        Returns:
            The agent instance
        """
        if name not in self._agent_instances:
            # Try to auto-create if agent type exists
            if name in self._agent_types:
                self.logger.info(f"Auto-creating agent instance '{name}'")
                self.create_agent(name, name, self._agent_configs.get(name, {}))
            else:
                raise AgentError(f"Agent instance {name} not found and no matching agent type")
        
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
        try:
            if name not in self._agent_instances:
                raise AgentError(f"Agent instance {name} not found")
            
            # Cleanup the agent if it has a cleanup method
            agent = self._agent_instances[name]
            if hasattr(agent, 'cleanup'):
                try:
                    # Handle both sync and async cleanup
                    import asyncio
                    if asyncio.iscoroutinefunction(agent.cleanup):
                        # If we're in an async context, await it
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                # Create a task for cleanup
                                asyncio.create_task(agent.cleanup())
                            else:
                                asyncio.run(agent.cleanup())
                        except:
                            # Fallback - just log the warning
                            self.logger.warning(f"Could not await cleanup for agent {name}")
                    else:
                        agent.cleanup()
                except Exception as cleanup_error:
                    self.logger.warning(f"Error during cleanup of agent {name}: {cleanup_error}")
            
            del self._agent_instances[name]
            self.logger.info(f"Agent instance '{name}' removed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to remove agent instance '{name}': {e}")
            raise AgentError(f"Failed to remove agent instance {name}: {str(e)}")
    
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
        try:
            if agent_type not in self._agent_configs:
                raise AgentError(f"Unknown agent type: {agent_type}")
            
            self._agent_configs[agent_type].update(config)
            self.logger.info(f"Configuration updated for agent type '{agent_type}'")
            
        except Exception as e:
            self.logger.error(f"Failed to update config for agent type '{agent_type}': {e}")
            raise AgentError(f"Failed to update agent config: {str(e)}")
    
    def agent_exists(self, name: str) -> bool:
        """Check if an agent instance exists.
        
        Args:
            name: Name of the agent instance
            
        Returns:
            True if agent exists, False otherwise
        """
        return name in self._agent_instances
    
    def agent_type_exists(self, agent_type: str) -> bool:
        """Check if an agent type exists.
        
        Args:
            agent_type: Type of agent
            
        Returns:
            True if agent type exists, False otherwise
        """
        return agent_type in self._agent_types
    
    async def initialize_all_agents(self):
        """Initialize all registered agent instances."""
        try:
            for name, agent in self._agent_instances.items():
                if hasattr(agent, 'initialized') and not agent.initialized:
                    self.logger.info(f"Initializing agent '{name}'")
                    await agent.initialize()
            
            self.logger.info("All agents initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize all agents: {e}")
            raise AgentError(f"Failed to initialize agents: {str(e)}")
    
    async def cleanup_all_agents(self):
        """Cleanup all registered agent instances."""
        try:
            for name, agent in self._agent_instances.items():
                if hasattr(agent, 'cleanup'):
                    try:
                        self.logger.info(f"Cleaning up agent '{name}'")
                        await agent.cleanup()
                    except Exception as cleanup_error:
                        self.logger.warning(f"Error during cleanup of agent {name}: {cleanup_error}")
            
            self.logger.info("All agents cleaned up")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup all agents: {e}")
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        return {
            "agent_types_count": len(self._agent_types),
            "agent_instances_count": len(self._agent_instances),
            "agent_types": list(self._agent_types.keys()),
            "agent_instances": list(self._agent_instances.keys()),
            "initialized_agents": [
                name for name, agent in self._agent_instances.items()
                if hasattr(agent, 'initialized') and agent.initialized
            ]
        }
    
    def clear(self):
        """Clear all registered agents and instances."""
        try:
            # Try to cleanup agents first
            import asyncio
            try:
                # Attempt cleanup if possible
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create cleanup tasks
                    for name, agent in self._agent_instances.items():
                        if hasattr(agent, 'cleanup'):
                            asyncio.create_task(agent.cleanup())
            except:
                # If we can't do async cleanup, just log
                self.logger.warning("Could not perform async cleanup during clear")
            
            self._agent_types.clear()
            self._agent_instances.clear()
            self._agent_configs.clear()
            
            self.logger.info("Agent registry cleared")
            
        except Exception as e:
            self.logger.error(f"Error during registry clear: {e}")


# Global registry instance
agent_registry = AgentRegistry()