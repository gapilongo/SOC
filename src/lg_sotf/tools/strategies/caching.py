"""
Caching strategy for tools.
"""

import hashlib
import json
from typing import Any, Dict, Optional

from lg_sotf.core.config.manager import ConfigManager


class CachingStrategy:
    """Handles caching for tool results."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.cache: Dict[str, Any] = {}
        self.enabled = config_manager.get('tools.caching_enabled', True)
        self.ttl = config_manager.get('tools.cache_ttl', 300)
    
    def get_cache_key(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Generate cache key for tool execution."""
        key_data = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available."""
        if not self.enabled:
            return None
        return self.cache.get(cache_key)
    
    async def cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache the result."""
        if self.enabled:
            self.cache[cache_key] = result
