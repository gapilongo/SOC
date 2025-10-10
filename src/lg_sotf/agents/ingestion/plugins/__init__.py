"""Ingestion plugins package."""
from lg_sotf.agents.ingestion.plugins.base import IngestionPlugin
from lg_sotf.agents.ingestion.plugins.registry import plugin_registry

# Auto-register plugins on import
from lg_sotf.agents.ingestion.plugins.sources import register_all_plugins

register_all_plugins()

__all__ = ["IngestionPlugin", "plugin_registry"]