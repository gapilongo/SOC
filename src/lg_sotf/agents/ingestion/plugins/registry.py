"""
Plugin registry for ingestion sources.

This module provides a registry for discovering and instantiating ingestion plugins.
Manages all available ingestion plugins and provides methods to register, retrieve,
and list plugins.
"""

import logging
from typing import Dict, Optional, Type

from lg_sotf.agents.ingestion.plugins.base import IngestionPlugin


class PluginRegistry:
    """Registry for managing ingestion plugins.
    
    This class maintains a registry of all available ingestion plugins
    and provides methods to register new plugins, retrieve existing ones,
    and list all registered plugins.
    
    Example:
        >>> from lg_sotf.agents.ingestion.plugins.registry import plugin_registry
        >>> from lg_sotf.agents.ingestion.plugins.sources import SplunkPlugin
        >>> 
        >>> # Register a plugin
        >>> plugin_registry.register("splunk", SplunkPlugin)
        >>> 
        >>> # Get a plugin class
        >>> plugin_class = plugin_registry.get_plugin("splunk")
        >>> 
        >>> # List all plugins
        >>> plugins = plugin_registry.list_plugins()
    """

    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: Dict[str, Type[IngestionPlugin]] = {}
        self.logger = logging.getLogger(__name__)
        self.logger.info("Plugin registry initialized")

    def register(self, name: str, plugin_class: Type[IngestionPlugin]) -> None:
        """Register a plugin with the registry.
        
        Args:
            name: Unique name for the plugin (e.g., "splunk", "qradar")
            plugin_class: The plugin class to register (must inherit from IngestionPlugin)
            
        Raises:
            ValueError: If plugin_class doesn't inherit from IngestionPlugin
            
        Example:
            >>> plugin_registry.register("splunk", SplunkPlugin)
        """
        # Validate that the plugin class inherits from IngestionPlugin
        if not issubclass(plugin_class, IngestionPlugin):
            error_msg = f"Plugin '{name}' must inherit from IngestionPlugin"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Warn if overwriting existing plugin
        if name in self._plugins:
            self.logger.warning(
                f"Plugin '{name}' is already registered, overwriting with {plugin_class.__name__}"
            )
        
        # Register the plugin
        self._plugins[name] = plugin_class
        self.logger.info(f"Registered plugin: '{name}' ({plugin_class.__name__})")

    def get_plugin(self, name: str) -> Optional[Type[IngestionPlugin]]:
        """Get a plugin class by name.
        
        Args:
            name: Name of the plugin to retrieve
            
        Returns:
            The plugin class if found, None otherwise
            
        Example:
            >>> plugin_class = plugin_registry.get_plugin("splunk")
            >>> if plugin_class:
            ...     plugin = plugin_class(config)
        """
        plugin = self._plugins.get(name)
        
        if plugin:
            self.logger.debug(f"Retrieved plugin: '{name}'")
        else:
            self.logger.warning(f"Plugin '{name}' not found in registry")
        
        return plugin

    def list_plugins(self) -> Dict[str, Type[IngestionPlugin]]:
        """List all registered plugins.
        
        Returns:
            Dictionary mapping plugin names to plugin classes
            
        Example:
            >>> plugins = plugin_registry.list_plugins()
            >>> print(f"Available plugins: {list(plugins.keys())}")
        """
        self.logger.debug(f"Listing {len(self._plugins)} registered plugins")
        return self._plugins.copy()

    def unregister(self, name: str) -> bool:
        """Unregister a plugin from the registry.
        
        Args:
            name: Name of the plugin to unregister
            
        Returns:
            True if plugin was unregistered, False if plugin was not found
            
        Example:
            >>> success = plugin_registry.unregister("splunk")
        """
        if name in self._plugins:
            del self._plugins[name]
            self.logger.info(f"Unregistered plugin: '{name}'")
            return True
        else:
            self.logger.warning(f"Cannot unregister plugin '{name}': not found")
            return False

    def is_registered(self, name: str) -> bool:
        """Check if a plugin is registered.
        
        Args:
            name: Name of the plugin to check
            
        Returns:
            True if plugin is registered, False otherwise
            
        Example:
            >>> if plugin_registry.is_registered("splunk"):
            ...     print("Splunk plugin is available")
        """
        return name in self._plugins

    def get_plugin_count(self) -> int:
        """Get the total number of registered plugins.
        
        Returns:
            Number of registered plugins
            
        Example:
            >>> count = plugin_registry.get_plugin_count()
            >>> print(f"Total plugins: {count}")
        """
        return len(self._plugins)

    def clear(self) -> None:
        """Clear all registered plugins.
        
        Warning:
            This will remove all plugins from the registry. Use with caution.
            
        Example:
            >>> plugin_registry.clear()  # Remove all plugins
        """
        count = len(self._plugins)
        self._plugins.clear()
        self.logger.warning(f"Cleared all {count} plugins from registry")

    def get_registry_info(self) -> Dict[str, any]:
        """Get information about the registry.
        
        Returns:
            Dictionary containing registry statistics and plugin list
            
        Example:
            >>> info = plugin_registry.get_registry_info()
            >>> print(f"Plugins: {info['plugin_names']}")
        """
        return {
            "total_plugins": len(self._plugins),
            "plugin_names": list(self._plugins.keys()),
            "plugin_classes": [cls.__name__ for cls in self._plugins.values()]
        }


# =============================================================================
# Global plugin registry instance
# =============================================================================

# This is the singleton instance that should be used throughout the application
plugin_registry = PluginRegistry()


# =============================================================================
# Utility functions
# =============================================================================

def get_available_plugins() -> list:
    """Get list of available plugin names.
    
    Convenience function to quickly get plugin names.
    
    Returns:
        List of registered plugin names
        
    Example:
        >>> from lg_sotf.agents.ingestion.plugins.registry import get_available_plugins
        >>> plugins = get_available_plugins()
        >>> print(plugins)  # ['splunk', 'qradar', 'sentinel', ...]
    """
    return list(plugin_registry.list_plugins().keys())


def register_plugin(name: str, plugin_class: Type[IngestionPlugin]) -> None:
    """Convenience function to register a plugin.
    
    Args:
        name: Plugin name
        plugin_class: Plugin class
        
    Example:
        >>> from lg_sotf.agents.ingestion.plugins.registry import register_plugin
        >>> register_plugin("custom", CustomPlugin)
    """
    plugin_registry.register(name, plugin_class)


def get_plugin_class(name: str) -> Optional[Type[IngestionPlugin]]:
    """Convenience function to get a plugin class.
    
    Args:
        name: Plugin name
        
    Returns:
        Plugin class or None
        
    Example:
        >>> from lg_sotf.agents.ingestion.plugins.registry import get_plugin_class
        >>> SplunkPlugin = get_plugin_class("splunk")
    """
    return plugin_registry.get_plugin(name)